//! Real execution: run each stage's agents (parallel), capture output, parse Findings,
//! persist everything under sessions/<id>/, aggregate a summary.
//! Every session now writes a `session.log` with timestamped entries for all interactions.

use crate::{parse, AgentRun, Config, Stage, Taxonomy};
use sasf_core::{Finding, Severity, Target};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// Global flag: set by SIGINT handler, checked by agent runner to skip current stage.
static SKIP_STAGE: AtomicBool = AtomicBool::new(false);

/// Install SIGINT handler that sets SKIP_STAGE instead of killing the process.
/// Second Ctrl+C within 2s of the first actually terminates (double-tap escape hatch).
pub fn install_sigint_handler() {
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t);
    }
    extern "C" fn sigint_handler(_sig: libc::c_int) {
        use std::sync::atomic::AtomicU64;
        static LAST_SIGINT: AtomicU64 = AtomicU64::new(0);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let prev = LAST_SIGINT.swap(now, Ordering::SeqCst);
        if now.saturating_sub(prev) <= 2 {
            // Double Ctrl+C within 2s: hard exit.
            std::process::exit(130);
        }
        SKIP_STAGE.store(true, Ordering::SeqCst);
        // Re-install (some platforms reset to SIG_DFL after delivery).
        unsafe { libc::signal(libc::SIGINT, sigint_handler as *const () as libc::sighandler_t); }
    }
}

pub struct RunReport {
    pub session_dir: PathBuf,
    pub runs: Vec<AgentRun>,
    pub findings: Vec<Finding>,
}

fn session_id() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ── Session logger ──────────────────────────────────────────────────────────

use std::io::Write;
use std::sync::Mutex;

/// Appends timestamped log lines to `sessions/<id>/session.log`.
pub struct SessionLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl SessionLog {
    pub fn new(session_dir: &Path) -> Self {
        let path = session_dir.join("session.log");
        let log = SessionLog { path, lock: Mutex::new(()) };
        log
    }

    /// Append a timestamped entry. Thread-safe.
    pub fn log(&self, event: &str) {
        let _guard = self.lock.lock().ok();
        let ts = timestamp();
        let line = format!("[{ts}] {event}\n");
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// Log with key-value details.
    pub fn log_kv(&self, event: &str, details: &[(&str, &str)]) {
        let kvs: Vec<String> = details.iter().map(|(k, v)| format!("{k}={v}")).collect();
        self.log(&format!("{event} | {}", kvs.join(" | ")));
    }
}

fn timestamp() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Format as ISO-ish: YYYY-MM-DD HH:MM:SS UTC (from epoch seconds).
    let s = secs;
    let days = s / 86400;
    let time_s = s % 86400;
    let h = time_s / 3600;
    let m = (time_s % 3600) / 60;
    let sec = time_s % 60;
    // Approximate date from days since epoch (good enough for logging).
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{sec:02} UTC")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Civil calendar from days since 1970-01-01 (Rata Die algorithm).
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Run one agent for real: execute claude, capture stdout, persist raw, parse findings.
/// `context` carries a summary of prior-stage findings for resume/continuation.
/// Ctrl+C sets SKIP_STAGE, which kills the child and returns a skipped AgentRun.
fn run_one(cfg: &Config, agent: &str, target: &Target, tax: &Taxonomy, session_dir: &Path, stage: &str, context: Option<&str>, slog: &SessionLog) -> AgentRun {
    slog.log_kv("AGENT_START", &[("stage", stage), ("agent", agent), ("model", &cfg.model)]);
    let mut cmd = crate::build_command_ctx(cfg, agent, target, tax, context);
    let start = SystemTime::now();

    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let prefix = format!("[{stage}/{agent}]");

    match cmd.spawn() {
        Ok(mut child) => {
            // Stderr reader thread: always capture for session.log, print if verbose.
            let stderr = child.stderr.take();
            let verbose = cfg.verbose;
            let stderr_log_path = session_dir.join(format!("{stage}-{agent}.stderr.log"));
            let stderr_handle = stderr.map(|se| {
                let pfx = prefix.clone();
                thread::spawn(move || {
                    let mut stderr_buf = String::new();
                    let reader = BufReader::new(se);
                    for line in reader.lines().flatten() {
                        if verbose { eprintln!("{pfx} {line}"); }
                        stderr_buf.push_str(&line);
                        stderr_buf.push('\n');
                    }
                    // Persist stderr for error tracking.
                    if !stderr_buf.is_empty() {
                        std::fs::write(&stderr_log_path, &stderr_buf).ok();
                    }
                })
            });

            // Stdout: read in a thread so we can poll SKIP_STAGE in parallel.
            let stdout_pipe = child.stdout.take();
            let pfx2 = prefix.clone();
            let stdout_handle = stdout_pipe.map(|so| {
                thread::spawn(move || {
                    let mut buf = String::new();
                    let reader = BufReader::new(so);
                    for line in reader.lines().flatten() {
                        if verbose { eprintln!("{pfx2} {line}"); }
                        buf.push_str(&line);
                        buf.push('\n');
                    }
                    buf
                })
            });

            // Poll: wait for child to finish OR SKIP_STAGE signal.
            loop {
                if SKIP_STAGE.load(Ordering::SeqCst) {
                    eprintln!("\n⏭  Ctrl+C → skipping stage [{stage}] (killing {agent})...");
                    slog.log_kv("AGENT_SKIP", &[("stage", stage), ("agent", agent), ("reason", "SIGINT")]);
                    child.kill().ok();
                    child.wait().ok();
                    if let Some(h) = stderr_handle { h.join().ok(); }
                    // Collect any partial stdout.
                    let partial = stdout_handle.and_then(|h| h.join().ok()).unwrap_or_default();
                    if !partial.is_empty() {
                        let raw_path = session_dir.join(format!("{stage}-{agent}.out.json"));
                        std::fs::write(&raw_path, &partial).ok();
                    }
                    return AgentRun {
                        agent: agent.to_string(),
                        ok: false,
                        output_tail: "skipped (Ctrl+C)".into(),
                        findings: Vec::new(),
                        raw_path: None,
                    };
                }
                // Check if child exited.
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => { thread::sleep(std::time::Duration::from_millis(200)); }
                    Err(_) => break,
                }
            }

            if let Some(h) = stderr_handle { h.join().ok(); }
            let stdout_buf = stdout_handle.and_then(|h| h.join().ok()).unwrap_or_default();
            let elapsed = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);
            let ok = child.wait().map(|s| s.success()).unwrap_or(false);
            let raw_path = session_dir.join(format!("{stage}-{agent}.out.json"));
            std::fs::write(&raw_path, &stdout_buf).ok();
            let findings = parse::extract_findings(&stdout_buf, &target.path);
            let status_str = if ok { "ok" } else { "error" };
            slog.log_kv("AGENT_DONE", &[
                ("stage", stage), ("agent", agent), ("status", status_str),
                ("findings", &findings.len().to_string()),
                ("elapsed_secs", &elapsed.to_string()),
                ("output_bytes", &stdout_buf.len().to_string()),
            ]);
            AgentRun {
                agent: agent.to_string(),
                ok,
                output_tail: format!("{} finding(s)", findings.len()),
                findings,
                raw_path: Some(raw_path.to_string_lossy().into_owned()),
            }
        }
        Err(e) => {
            slog.log_kv("AGENT_ERROR", &[("stage", stage), ("agent", agent), ("error", &e.to_string())]);
            AgentRun {
                agent: agent.to_string(),
                ok: false,
                output_tail: e.to_string(),
                findings: Vec::new(),
                raw_path: None,
            }
        }
    }
}

/// Execute the full staged pipeline. Agents within a stage run in parallel; stages are
/// sequential (later agents see earlier findings via the muster blackboard).
pub fn run_real(cfg: &Config, target: &Target, stages: &[Stage], tax: &Taxonomy) -> anyhow::Result<RunReport> {
    install_sigint_handler();
    // Resume: reuse the given session dir; else create a fresh one.
    let (session_dir, resuming) = match &cfg.resume_dir {
        Some(d) => (d.clone(), true),
        None => (cfg.root.join("sessions").join(session_id().to_string()), false),
    };
    std::fs::create_dir_all(&session_dir)?;
    // Show session ID immediately so the user can reference it for --resume.
    let sid = session_dir.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  SESSION: {:<50}║", sid);
    println!("║  DIR: {:<54}║", session_dir.display());
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    let slog = SessionLog::new(&session_dir);
    if !resuming {
        std::fs::write(session_dir.join("target.json"), serde_json::to_string_pretty(target)?)?;
        slog.log_kv("SESSION_START", &[
            ("target", &target.path), ("format", &target.format), ("arch", &target.arch),
            ("app", &target.app), ("model", &cfg.model),
            ("sha256", target.sha256.as_deref().unwrap_or("N/A")),
            ("md5", target.md5.as_deref().unwrap_or("N/A")),
            ("shielding", &target.shielding.join(",")),
        ]);
    }

    let mut all_runs = Vec::new();
    // Seed accumulator with any findings already recovered from prior stages of this session.
    let mut all_findings: Vec<Finding> = if resuming {
        reparse(&session_dir).ok();
        std::fs::read_to_string(session_dir.join("findings.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if resuming {
        slog.log_kv("SESSION_RESUME", &[("prior_findings", &all_findings.len().to_string())]);
        println!("[resume] session {} — {} prior finding(s) loaded", session_dir.display(), all_findings.len());
    }

    // Helper: persist findings + summary incrementally (after each agent, not just stage).
    let save_progress = |findings: &[Finding], dir: &Path, target: &Target| {
        serde_json::to_string_pretty(findings)
            .ok()
            .map(|j| std::fs::write(dir.join("findings.json"), j));
        std::fs::write(dir.join("summary.md"), summary_md(target, findings)).ok();
    };

    // Helper: check if a specific agent completed SUCCESSFULLY (for per-agent resume).
    // An agent is "done" only if its output file exists AND:
    //   - contains actual findings (parsed findings > 0), OR
    //   - the claude output indicates genuine success (no errors, real content)
    // Error outputs (sleep, network, API errors) are NOT done — re-run.
    let agent_done = |stage_name: &str, agent: &str| -> bool {
        let f = session_dir.join(format!("{stage_name}-{agent}.out.json"));
        let Ok(raw) = std::fs::read_to_string(&f) else { return false };
        if raw.len() < 100 { return false; }
        // Explicit failure markers — never treat as done.
        let failure_markers = [
            "\"is_error\":true",
            "\"terminal_reason\":\"api_error\"",
            "went to sleep",
            "network error",
            "connection reset",
            "timed out",
            "context window full",
            "rate limit",
            "overloaded",
        ];
        let raw_lower = raw.to_lowercase();
        for marker in &failure_markers {
            if raw_lower.contains(&marker.to_lowercase()) {
                return false;
            }
        }
        // Has findings? Done.
        let findings = parse::extract_findings(&raw, &target.path);
        if !findings.is_empty() { return true; }
        // Pipeline roles (reporter, validator, exploit) may not emit findings in the
        // standard format. Check for genuine success with real result content.
        if raw.contains("\"subtype\":\"success\"") && raw.contains("\"terminal_reason\":\"completed\"") {
            return true;
        }
        false
    };

    // Helper: load findings from a single agent's raw output (for partial resume).
    let load_agent_findings = |stage_name: &str, agent: &str| -> Vec<Finding> {
        let f = session_dir.join(format!("{stage_name}-{agent}.out.json"));
        std::fs::read_to_string(&f)
            .ok()
            .map(|raw| parse::extract_findings(&raw, &target.path))
            .unwrap_or_default()
    };

    let slog_ref = &slog;
    for (i, stage) in stages.iter().enumerate() {
        // Per-agent resume: figure out which agents in this stage already finished.
        let (done_agents, pending_agents): (Vec<&String>, Vec<&String>) = stage
            .agents
            .iter()
            .partition(|a| resuming && agent_done(stage.name, a));

        // If all agents done, skip entire stage.
        if pending_agents.is_empty() {
            // Load their findings into the accumulator (may not be loaded yet).
            for a in &done_agents {
                let prior = load_agent_findings(stage.name, a);
                if !prior.is_empty() {
                    // Avoid duplicates: only add if not already in all_findings.
                    let before = all_findings.len();
                    all_findings.extend(prior);
                    all_findings.dedup_by(|a, b| a.title == b.title && a.vuln_class == b.vuln_class);
                    let added = all_findings.len() - before;
                    if added > 0 {
                        slog.log_kv("AGENT_RELOAD", &[("stage", stage.name), ("agent", a), ("findings", &added.to_string())]);
                    }
                }
            }
            slog.log_kv("STAGE_SKIP", &[("stage", stage.name), ("reason", "all agents complete (resume)")]);
            println!("[stage {}/{}] {} — resume: all agents complete, skipping", i + 1, stages.len(), stage.name);
            continue;
        }

        // Some agents already done — load their findings, only run pending ones.
        if !done_agents.is_empty() {
            for a in &done_agents {
                let prior = load_agent_findings(stage.name, a);
                println!("    ✓  {} — resume: {} prior finding(s) loaded", a, prior.len());
                slog.log_kv("AGENT_RESUME_LOADED", &[("stage", stage.name), ("agent", a), ("findings", &prior.len().to_string())]);
                all_findings.extend(prior);
                all_runs.push(AgentRun {
                    agent: a.to_string(), ok: true,
                    output_tail: "resumed (prior run)".into(),
                    findings: Vec::new(), // already loaded above
                    raw_path: Some(session_dir.join(format!("{}-{}.out.json", stage.name, a)).to_string_lossy().into_owned()),
                });
            }
            all_findings.dedup_by(|a, b| a.title == b.title && a.vuln_class == b.vuln_class);
            save_progress(&all_findings, &session_dir, target);
        }

        // Reset skip flag so Ctrl+C from a previous stage doesn't cascade.
        SKIP_STAGE.store(false, Ordering::SeqCst);
        let pending_names: Vec<String> = pending_agents.iter().map(|a| a.to_string()).collect();
        slog.log_kv("STAGE_START", &[("stage", stage.name), ("agents", &pending_names.join(","))]);
        println!("[stage {}/{}] {} — running {} agent(s)  (Ctrl+C = skip stage, 2x = quit)",
            i + 1, stages.len(), stage.name, pending_agents.len());

        // Context summary of everything found so far, fed to this stage's agents.
        let ctx = context_summary(&all_findings);
        let ctx_ref: Option<&str> = if ctx.is_empty() { None } else { Some(&ctx) };
        let sd: &Path = &session_dir;

        // Retry logic: up to 3 attempts. Only re-run agents that haven't succeeded yet.
        const MAX_RETRIES: usize = 3;
        let mut stage_runs: Vec<AgentRun> = Vec::new();
        let mut agents_to_run = pending_names.clone();

        for attempt in 1..=MAX_RETRIES {
            if SKIP_STAGE.load(Ordering::SeqCst) || agents_to_run.is_empty() {
                if SKIP_STAGE.load(Ordering::SeqCst) {
                    slog.log_kv("STAGE_SKIP", &[("stage", stage.name), ("reason", "SIGINT skip")]);
                    println!("    ⏭  stage [{}] skipped by Ctrl+C", stage.name);
                }
                break;
            }
            if attempt > 1 {
                slog.log_kv("STAGE_RETRY", &[("stage", stage.name), ("attempt", &attempt.to_string()),
                    ("agents", &agents_to_run.join(","))]);
                println!("    ↻  retry {attempt}/{MAX_RETRIES} for [{}] — {}", stage.name, agents_to_run.join(", "));
            }
            let run_these = agents_to_run.clone();
            let attempt_runs: Vec<AgentRun> = thread::scope(|s| {
                let handles: Vec<_> = run_these
                    .iter()
                    .map(|agent| s.spawn(move || run_one(cfg, agent, target, tax, sd, stage.name, ctx_ref, slog_ref)))
                    .collect();
                handles.into_iter().filter_map(|h| h.join().ok()).collect()
            });

            // Process results: save each successful agent's findings immediately.
            let mut still_failed: Vec<String> = Vec::new();
            for r in attempt_runs {
                println!("    {} {} — {}", if r.ok { "ok " } else { "err" }, r.agent, r.output_tail);
                if r.ok {
                    all_findings.extend(r.findings.clone());
                    save_progress(&all_findings, &session_dir, target);
                } else if !r.output_tail.contains("skipped") {
                    // Log error snippet for failed agent.
                    let stderr_file = session_dir.join(format!("{}-{}.stderr.log", stage.name, r.agent));
                    let err_snippet = std::fs::read_to_string(&stderr_file)
                        .ok()
                        .map(|s| s.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | "))
                        .unwrap_or_else(|| r.output_tail.clone());
                    slog.log_kv("AGENT_FAIL", &[
                        ("stage", stage.name), ("agent", &r.agent),
                        ("attempt", &attempt.to_string()), ("error", &err_snippet),
                    ]);
                    still_failed.push(r.agent.clone());
                }
                stage_runs.push(r);
            }

            agents_to_run = still_failed;
            if agents_to_run.is_empty() { break; }
            if attempt == MAX_RETRIES {
                slog.log_kv("STAGE_FAIL", &[("stage", stage.name), ("failed_agents", &agents_to_run.join(",")),
                    ("attempts", &MAX_RETRIES.to_string())]);
                eprintln!("    ⚠  [{}] agents {} failed after {MAX_RETRIES} attempts — moving on",
                    stage.name, agents_to_run.join(", "));
            } else {
                thread::sleep(std::time::Duration::from_secs(2));
            }
        }

        all_runs.extend(stage_runs);
        // Final save after stage.
        save_progress(&all_findings, &session_dir, target);
        slog.log_kv("STAGE_DONE", &[("stage", stage.name), ("total_findings", &all_findings.len().to_string())]);
    }

    // Malware-analysis flow ends with validated findings and synthesized graph artifacts.
    if !SKIP_STAGE.load(Ordering::SeqCst) {
        match attack_graph(&session_dir) {
            Ok((nodes, chains)) => {
                slog.log_kv("GRAPH_SYNTH_DONE", &[("nodes", &nodes.to_string()), ("chains", &chains.to_string())]);
                println!("\n[graph] {} nodes, {} chains", nodes, chains);
            }
            Err(e) => {
                slog.log_kv("GRAPH_SYNTH_ERROR", &[("error", &e.to_string())]);
                eprintln!("\n[graph] error: {e}");
            }
        }
        if let Err(e) = write_local_reports(&session_dir, target, &all_findings) {
            slog.log_kv("REPORT_LOCAL_ERROR", &[("error", &e.to_string())]);
        } else {
            slog.log("REPORT_LOCAL_DONE | markdown=analysis-report.md | html=analysis-report.html");
        }
    }

    slog.log_kv("SESSION_DONE", &[("total_findings", &all_findings.len().to_string()), ("stages_run", &stages.len().to_string())]);
    println!("\nsession: {}", session_dir.display());
    println!("total findings: {}", all_findings.len());
    Ok(RunReport { session_dir, runs: all_runs, findings: all_findings })
}

/// Produce deterministic local reports immediately after the evidence graph. The LLM can
/// enrich these later, but the session always has auditable Markdown and HTML artifacts.
fn write_local_reports(session_dir: &Path, target: &Target, findings: &[Finding]) -> anyhow::Result<()> {
    let mut md = format!("# Malvex Analysis\n\n- Artifact: `{}`\n- Format: `{}`\n- Architecture: `{}`\n- Findings: `{}`\n\n", target.path, target.format, target.arch, findings.len());
    let mut html = format!("<!doctype html><meta charset=utf-8><title>Malvex Analysis</title><style>body{{background:#0b0d12;color:#e7ebf3;font:15px system-ui;max-width:1000px;margin:40px auto;padding:0 20px}}article{{background:#151b25;border:1px solid #2b3850;border-radius:10px;padding:18px;margin:14px 0}}code,pre{{font-family:ui-monospace,monospace}}.sev{{color:#82a9ff}}.ev{{color:#65d39a}}</style><h1>Malvex Analysis</h1><p><b>Artifact:</b> {}<br><b>Format:</b> {} · <b>Architecture:</b> {}<br><b>Findings:</b> {}</p>", escape_html(&target.path), escape_html(&target.format), escape_html(&target.arch), findings.len());
    for (i, finding) in findings.iter().enumerate() {
        md.push_str(&format!("## {}. {}\n\n- Class: `{}`\n- Severity: `{:?}`\n- Verdict: `{:?}`\n- Confidence basis: evidence listed below\n\n{}\n", i + 1, finding.title, finding.vuln_class, finding.severity, finding.verdict, finding.summary));
        html.push_str(&format!("<article><h2>{}. {}</h2><p class=sev><b>{:?}</b> · {:?} · <code>{}</code></p><p>{}</p><h3>Evidence</h3><ul>", i + 1, escape_html(&finding.title), finding.severity, finding.verdict, escape_html(&finding.vuln_class), escape_html(&finding.summary)));
        for evidence in &finding.evidence {
            md.push_str(&format!("- Evidence `{}` at `{}`: {}\n", format!("{:?}", evidence.kind), evidence.locus.as_deref().unwrap_or("n/a"), evidence.detail));
            html.push_str(&format!("<li class=ev><code>{:?}</code> @ <code>{}</code>: {}</li>", evidence.kind, escape_html(evidence.locus.as_deref().unwrap_or("n/a")), escape_html(&evidence.detail)));
        }
        md.push('\n'); html.push_str("</ul></article>");
    }
    html.push_str("</body>");
    std::fs::write(session_dir.join("analysis-report.md"), md)?;
    std::fs::write(session_dir.join("analysis-report.html"), html)?;
    Ok(())
}

fn escape_html(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Compact summary of findings so far, for feeding as prior-stage context.
fn context_summary(findings: &[Finding]) -> String {
    if findings.is_empty() { return String::new(); }
    let mut lines = Vec::new();
    for f in findings.iter().take(40) {
        let locus = f.evidence.iter().find_map(|e| e.locus.clone()).unwrap_or_default();
        lines.push(format!("- {} [{:?}] {} {}", f.vuln_class, f.severity, f.title, if locus.is_empty() { String::new() } else { format!("@{locus}") }));
    }
    lines.join("\n")
}

/// Build the attack graph from a session's findings: chained exploitation paths where one
/// vuln enables the next. Writes attack-graph.md (mermaid) + attack-graph.json. Nothing is
/// isolated — a chain turns a set of medium findings into one critical end-to-end path.
pub fn attack_graph(session_dir: &Path) -> anyhow::Result<(usize, usize)> {
    use std::collections::BTreeMap;
    let slog = SessionLog::new(session_dir);
    let target: Target = serde_json::from_str(&std::fs::read_to_string(session_dir.join("target.json"))?)?;
    let findings: Vec<Finding> = serde_json::from_str(&std::fs::read_to_string(session_dir.join("findings.json"))?)?;
    slog.log_kv("GRAPH_START", &[("findings", &findings.len().to_string()), ("app", &target.app)]);

    let classes: Vec<String> = findings.iter().map(|f| f.vuln_class.clone()).collect();
    // Collect chains (from explicit chain fields) as ordered step lists.
    let mut chains: Vec<(Vec<String>, Option<f32>, String)> = Vec::new();
    for f in &findings {
        for raw in &f.chain {
            let score = sniff_score(raw);
            let normalized = raw.replace('→', "->").replace("=>", "->");
            let steps: Vec<String> = normalized
                .split("->")
                .map(clean_step)
                .filter(|s| !s.is_empty())
                .map(|s| canonical_step(&s, &classes))
                .collect();
            if steps.len() >= 2 {
                chains.push((steps, score, f.vuln_class.clone()));
            }
        }
    }
    // Seed curated library chains whose steps are present in these findings (>=2 present),
    // so the graph is robust even when agents under-report chaining.
    let present: std::collections::HashSet<&str> = classes.iter().map(|s| s.as_str()).collect();
    if let Some(root) = session_dir.parent().and_then(|p| p.parent()) {
        for c in crate::chains::ChainLib::load_or_empty(root).chains {
            let hits: Vec<String> = c.steps.iter().filter(|s| present.contains(s.as_str())).cloned().collect();
            if hits.len() >= 2 {
                // draw the full library path (it shows the enabling steps even if not all found)
                let already = chains.iter().any(|(_, _, from)| from == &c.id);
                if !already {
                    chains.push((c.steps.clone(), c.composite_cvss, c.id.clone()));
                }
            }
        }
    }

    // Node set: every chain step + every finding's vuln_class (so isolated findings show too).
    let mut ids: BTreeMap<String, usize> = BTreeMap::new();
    let id_of = |label: &str, ids: &mut BTreeMap<String, usize>| -> usize {
        let n = ids.len();
        *ids.entry(label.to_string()).or_insert(n)
    };
    for f in &findings {
        id_of(&f.vuln_class, &mut ids);
    }
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for (steps, _, _) in &chains {
        for w in steps.windows(2) {
            let a = id_of(&w[0], &mut ids);
            let b = id_of(&w[1], &mut ids);
            if !edges.contains(&(a, b)) {
                edges.push((a, b));
            }
        }
    }

    // mermaid
    let mut md = format!("# Attack graph — {}\n\napp {} / {} / {}\n\n```mermaid\nflowchart LR\n",
        target.path, target.app, target.format, target.arch);
    let mut label_by_id: Vec<(usize, String)> = ids.iter().map(|(k, v)| (*v, k.clone())).collect();
    label_by_id.sort();
    for (id, label) in &label_by_id {
        md.push_str(&format!("  n{id}[\"{}\"]\n", label.replace('"', "'")));
    }
    for (a, b) in &edges {
        md.push_str(&format!("  n{a} --> n{b}\n"));
    }
    md.push_str("```\n\n## Chains (nothing is isolated)\n\n");
    if chains.is_empty() {
        md.push_str("_No explicit chains emitted by agents. Findings stand alone; re-run with chain-aware agents._\n");
    }
    for (steps, score, from) in &chains {
        md.push_str(&format!("- **[{}]** {}  _(from {})_\n",
            score.map(|s| format!("CVSS ~{s}")).unwrap_or_else(|| "chain".into()),
            steps.join(" → "), from));
    }

    std::fs::write(session_dir.join("attack-graph.md"), &md)?;
    let json = serde_json::json!({
        "target": target.path,
        "nodes": label_by_id.iter().map(|(i, l)| serde_json::json!({"id": i, "label": l})).collect::<Vec<_>>(),
        "edges": edges.iter().map(|(a, b)| serde_json::json!({"from": a, "to": b})).collect::<Vec<_>>(),
        "chains": chains.iter().map(|(s, sc, f)| serde_json::json!({"steps": s, "cvss": sc, "from": f})).collect::<Vec<_>>(),
    });
    std::fs::write(session_dir.join("attack-graph.json"), serde_json::to_string_pretty(&json)?)?;
    slog.log_kv("GRAPH_DONE", &[("nodes", &ids.len().to_string()), ("chains", &chains.len().to_string()), ("edges", &edges.len().to_string())]);
    Ok((ids.len(), chains.len()))
}

/// Map a free-form chain step to a canonical vuln_class node when it clearly refers to one,
/// so the graph links chain steps to finding nodes instead of orphaning them.
fn canonical_step(step: &str, classes: &[String]) -> String {
    let norm = |s: &str| s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
    let ks = norm(step);
    if ks.len() < 6 {
        return step.to_string();
    }
    for c in classes {
        let kc = norm(c);
        if kc.contains(&ks) || ks.contains(&kc) {
            return c.clone();
        }
    }
    step.to_string()
}

fn clean_step(s: &str) -> String {
    let s = s.split(" = ").next().unwrap_or(s);
    let s = s.split(" (").next().unwrap_or(s);
    s.trim().trim_matches(|c| c == '+' || c == '~').trim().to_string()
}

fn sniff_score(s: &str) -> Option<f32> {
    // pull a trailing "~9.0" / "= 9.1" style number.
    s.rsplit(['=', '~', ' ']).find_map(|tok| tok.trim().parse::<f32>().ok().filter(|n| *n >= 1.0 && *n <= 10.0))
}

/// Re-derive findings.json + summary.md from a session's raw agent outputs, using the
/// current parser. No LLM spend — use after a parser fix to recover dropped evidence.
pub fn reparse(session_dir: &Path) -> anyhow::Result<usize> {
    let target: Target = serde_json::from_str(&std::fs::read_to_string(session_dir.join("target.json"))?)?;
    let mut findings = Vec::new();
    for e in std::fs::read_dir(session_dir)?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".out.json") && name != "report.out.json" && name != "exploit.out.json" {
            if let Ok(raw) = std::fs::read_to_string(e.path()) {
                findings.extend(parse::extract_findings(&raw, &target.path));
            }
        }
    }
    std::fs::write(session_dir.join("findings.json"), serde_json::to_string_pretty(&findings)?)?;
    std::fs::write(session_dir.join("summary.md"), summary_md(&target, &findings))?;
    Ok(findings.len())
}

/// Run the LLM-driven chain discovery agent: analyzes all findings and discovers composite
/// exploit chains where multiple vulnerabilities combine into more severe attacks.
pub fn run_chain_discovery(cfg: &Config, session_dir: &Path) -> anyhow::Result<AgentRun> {
    let findings_json = session_dir.join("findings.json");
    if !findings_json.is_file() {
        anyhow::bail!("no findings.json in {}", session_dir.display());
    }
    let slog = SessionLog::new(session_dir);
    slog.log("CHAIN_DISCOVERY_START");

    let agent_file = cfg.root.join("agents").join("chain-discovery.md");
    let agent_flag = if agent_file.is_file() {
        format!("--append-system-prompt {}", agent_file.display())
    } else {
        String::new()
    };
    let target_json = session_dir.join("target.json");
    let target_info = std::fs::read_to_string(&target_json).unwrap_or_default();

    let prompt = format!(
        "You are the chain-discovery agent. Analyze the findings at {} and discover exploit \
         chains — sequences of vulnerabilities that combine into more severe attacks.\n\n\
         Target info: {}\n\n\
         For each chain discovered, create a finding with vuln_class='chain-<name>', \
         severity = highest in chain or escalated, and chain_members listing the IDs.\n\n\
         Write chain-findings.json (JSON array) and chain-analysis.md to {}.\n\n\
         Focus on realistic, feasible chains. Output ONLY valid JSON arrays.",
        findings_json.display(), target_info, session_dir.display()
    );

    println!("[chain-discovery] analyzing {} for exploit chains", session_dir.display());
    let mut cmd = std::process::Command::new("claude");
    cmd.args(["--model", &cfg.model, "-p", &prompt, "--output-format", "json"]);
    if !agent_flag.is_empty() {
        for part in agent_flag.split_whitespace() { cmd.arg(part); }
    }
    cmd.env("IS_SANDBOX", "1").arg("--dangerously-skip-permissions");

    let out = cmd.output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let tail = stdout.chars().rev().take(300).collect::<String>().chars().rev().collect::<String>();
    std::fs::write(session_dir.join("chain-discovery.out.json"), &stdout).ok();

    let chain_findings: Vec<Finding> = parse::extract_findings(&stdout, "");
    let n = chain_findings.len();
    if n > 0 {
        slog.log_kv("CHAIN_DISCOVERY_DONE", &[("chains_found", &n.to_string())]);
        println!("[chain-discovery] discovered {} exploit chains", n);
        let existing: Vec<Finding> = std::fs::read_to_string(&findings_json)
            .ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let mut merged = existing;
        for f in &chain_findings { merged.push(f.clone()); }
        merged.dedup_by(|a, b| a.title == b.title && a.vuln_class == b.vuln_class);
        std::fs::write(&findings_json, serde_json::to_string_pretty(&merged).unwrap_or_default()).ok();
    } else {
        slog.log("CHAIN_DISCOVERY_DONE | no chains discovered");
    }

    Ok(AgentRun {
        agent: "chain-discovery".into(), ok: out.status.success(), output_tail: tail,
        findings: chain_findings,
        raw_path: Some(session_dir.join("chain-discovery.out.json").to_string_lossy().into_owned()),
    })
}

/// Run the exploit agent over a session: generate a runnable PoC script per finding under
/// <session>/poc/, and write back findings.json annotated with poc paths. Scripts are
/// generated for the analyst to run later — the agent does not execute destructive PoCs.
pub fn run_exploit(cfg: &Config, session_dir: &Path) -> anyhow::Result<AgentRun> {
    let findings_json = session_dir.join("findings.json");
    if !findings_json.is_file() {
        anyhow::bail!("no findings.json in {}", session_dir.display());
    }
    let poc_dir = session_dir.join("poc");
    std::fs::create_dir_all(&poc_dir).ok();
    let agent_file = cfg.root.join("agents").join("exploit.md");
    let prompt = format!(
        "Read the findings at {} (JSON array of sasf-core::Finding). For EACH finding with \
         verdict plausible or confirmed, generate a concrete, runnable PoC script under {} named \
         <vuln_class>.<ext> (.py/.sh/.m/.c/.js as fits the vector). The script must be real and \
         self-contained enough for an analyst to run against the target after review — reuse/adapt \
         the reference PoCs cited in the matching skills/<vuln_class>/SKILL.md 'PoC hint'. Do NOT \
         execute destructive steps yourself; only WRITE the scripts. Then rewrite {} with each \
         finding's `poc` field set to the script path you created, and drop (or mark refuted) any \
         finding you cannot back with a PoC or concrete evidence. Return a JSON summary of what you wrote.",
        findings_json.display(), poc_dir.display(), findings_json.display()
    );
    let mut cmd = std::process::Command::new("claude");
    cmd.arg("-p").arg(prompt)
        .arg("--model").arg(&cfg.model)
        .arg("--fallback-model").arg(cfg.fallbacks.join(","))
        .arg("--dangerously-skip-permissions")
        .arg("--append-system-prompt-file").arg(agent_file)
        .arg("--add-dir").arg(&cfg.root)
        .arg("--output-format").arg(&cfg.output_format)
        .env("IS_SANDBOX", "1")
        .stdin(std::process::Stdio::null());
    let slog = SessionLog::new(session_dir);
    slog.log_kv("EXPLOIT_START", &[("model", &cfg.model)]);
    println!("[exploit] generating PoCs for {}", session_dir.display());
    let start = SystemTime::now();
    let out = cmd.output()?;
    let elapsed = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    std::fs::write(session_dir.join("exploit.out.json"), &stdout).ok();
    slog.log_kv("EXPLOIT_AGENT_DONE", &[
        ("status", if out.status.success() { "ok" } else { "error" }),
        ("elapsed_secs", &elapsed.to_string()),
        ("output_bytes", &stdout.len().to_string()),
    ]);
    // Resilience: annotate findings.json from whatever PoC scripts landed in poc/, even if
    // the agent died before rewriting findings.json itself. Match poc/<vuln_class>.* by stem.
    annotate_pocs_from_dir(&findings_json, &poc_dir);
    // Compile-validate + auto-fix loop: compile every PoC; feed the ones that fail back to the
    // LLM to repair, up to 2 rounds. A PoC that only fails from a missing SDK is left as-is.
    slog.log("POC_VALIDATE_START");
    fix_poc_loop(cfg, &poc_dir, 2);
    // Fill empty PoC dirs with verification scripts, then copy into session dir.
    if let Some(root) = session_dir.parent().and_then(|p| p.parent()) {
        let poc_root = root.join("poc-out");
        if poc_root.is_dir() {
            // Need target for fill_empty_poc_dirs.
            if let Ok(target) = std::fs::read_to_string(session_dir.join("target.json"))
                .and_then(|s| serde_json::from_str::<Target>(&s).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))
            {
                fill_empty_poc_dirs(&poc_root, &target, &slog);
            }
        }
        copy_poc_to_session(root, session_dir, &slog);
    }
    // Count PoCs
    let poc_count = std::fs::read_dir(&poc_dir).map(|rd| rd.flatten().filter(|e| e.path().is_file()).count()).unwrap_or(0);
    slog.log_kv("EXPLOIT_DONE", &[("poc_count", &poc_count.to_string())]);
    let tail = parse::unwrap_claude_json(&stdout);
    let tail = tail.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" ");
    Ok(AgentRun { agent: "exploit".into(), ok: out.status.success(), output_tail: tail, findings: Vec::new(), raw_path: Some(session_dir.join("exploit.out.json").to_string_lossy().into_owned()) })
}

/// Annotate each finding's `poc` field with a matching script in poc/ (stem == vuln_class),
/// so a PoC that landed on disk is linked even if the agent never rewrote findings.json.
fn annotate_pocs_from_dir(findings_json: &Path, poc_dir: &Path) {
    let Ok(raw) = std::fs::read_to_string(findings_json) else { return };
    let Ok(mut findings) = serde_json::from_str::<Vec<Finding>>(&raw) else { return };
    // Map vuln_class stem -> first matching poc path.
    let mut by_stem: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Ok(rd) = std::fs::read_dir(poc_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if let Some(stem) = p.file_stem().map(|s| s.to_string_lossy().into_owned()) {
                by_stem.entry(stem).or_insert_with(|| p.to_string_lossy().into_owned());
            }
        }
    }
    let mut changed = false;
    for f in &mut findings {
        if f.poc.is_none() {
            if let Some(p) = by_stem.get(&f.vuln_class) {
                f.poc = Some(p.clone());
                changed = true;
            }
        }
    }
    if changed {
        if let Ok(s) = serde_json::to_string_pretty(&findings) {
            std::fs::write(findings_json, s).ok();
        }
    }
}

/// Compile-validate every PoC and, for those that fail with a real code error (not a missing
/// SDK/limitation), ask the LLM to repair the file, then recompile. Repeats up to `rounds`.
pub fn fix_poc_loop(cfg: &Config, poc_dir: &Path, rounds: usize) {
    let session_dir = poc_dir.parent().unwrap_or(Path::new("."));
    for round in 1..=rounds {
        let results = match crate::pocval::validate(session_dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        let failed: Vec<_> = results.iter().filter(|r| r.status == "failed").collect();
        if failed.is_empty() {
            let ok = results.iter().filter(|r| r.status == "compiled" || r.status == "syntax-ok").count();
            println!("[exploit] PoC validation: {ok}/{} ok, 0 failing", results.len());
            return;
        }
        println!("[exploit] PoC fix round {round}: {} failing, repairing via LLM", failed.len());
        for r in &failed {
            let path = &r.file;
            let src = std::fs::read_to_string(path).unwrap_or_default();
            let prompt = format!(
                "This proof-of-concept fails to compile. Fix ONLY the compile errors and rewrite the \
                 complete corrected file to the SAME path. Keep the exploit logic intact; add missing \
                 includes/declarations, fix syntax. This is authorized pentest tooling.\n\
                 File: {path}\nCompiler error: {}\n\n--- current source ---\n{src}\n\n\
                 Write the corrected file with the Write tool to {path}. Reply only 'fixed' or 'cannot'.",
                r.detail
            );
            let mut cmd = std::process::Command::new("claude");
            cmd.arg("-p").arg(prompt)
                .arg("--model").arg(&cfg.model)
                .arg("--fallback-model").arg(cfg.fallbacks.join(","))
                .arg("--dangerously-skip-permissions")
                .arg("--add-dir").arg(&cfg.root)
                .arg("--output-format").arg("json")
                .env("IS_SANDBOX", "1")
                .stdin(std::process::Stdio::null());
            let _ = cmd.output();
        }
    }
    // final validation pass to refresh compile-report.md
    crate::pocval::validate(session_dir).ok();
}

/// Pull the first existing `*.pdf` path mentioned in the reporter's result text.
fn find_pdf_path(text: &str) -> Option<std::path::PathBuf> {
    // 1. Try to find a PDF path mentioned in the agent output.
    for tok in text.split(|c: char| c.is_whitespace() || matches!(c, '`' | '*' | '"' | '(' | ')' | '<' | '>')) {
        if tok.to_lowercase().ends_with(".pdf") {
            let p = std::path::PathBuf::from(tok);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    // 2. Scan known MCP output directories for the most recent PDF.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let search_dirs = [
        format!("{home}/malvex-reports/dist"),
        format!("{home}/malvex-reports"),
        format!("{home}/reports"),
    ];
    let mut best: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for dir in &search_dirs {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("pdf") {
                    if let Ok(meta) = p.metadata() {
                        let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                        if best.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
                            best = Some((modified, p));
                        }
                    }
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Run the reporter agent over a completed session's findings.json to build the Typst PDF.
pub fn run_reporter(cfg: &Config, session_dir: &Path) -> anyhow::Result<AgentRun> {
    let findings_json = session_dir.join("findings.json");
    if !findings_json.is_file() {
        anyhow::bail!("no findings.json in {}", session_dir.display());
    }
    // Compile-validate PoCs first so the report can cite their status.
    crate::pocval::validate(session_dir).ok();
    let agent_file = cfg.root.join("agents").join("reporter.md");
    // Load target.json to get file hashes for the report.
    let target_info = std::fs::read_to_string(session_dir.join("target.json")).ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    let sha256 = target_info.as_ref().and_then(|v| v.get("sha256").and_then(|x| x.as_str())).unwrap_or("N/A");
    let md5 = target_info.as_ref().and_then(|v| v.get("md5").and_then(|x| x.as_str())).unwrap_or("N/A");
    let target_path = target_info.as_ref().and_then(|v| v.get("path").and_then(|x| x.as_str())).unwrap_or("unknown");
    let target_format = target_info.as_ref().and_then(|v| v.get("format").and_then(|x| x.as_str())).unwrap_or("unknown");
    let target_arch = target_info.as_ref().and_then(|v| v.get("arch").and_then(|x| x.as_str())).unwrap_or("unknown");
    // Build per-binary hash table for the report.
    let bundle_hashes_str = target_info.as_ref()
        .and_then(|v| v.get("bundle_hashes").and_then(|h| h.as_object()))
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| format!("  - {}: SHA-256 = {}", k, v.as_str().unwrap_or("N/A")))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let prompt = format!(
        "Read the findings at {fj} (JSON array of sasf-core::Finding), the attack graph at \
         {sd}/attack-graph.md + attack-graph.json, the PoC scripts under {sd}/poc/, and the PoC \
         compile-validation at {sd}/poc/compile-report.md if present. \
         Assemble the Malvex analysis PDF using the malvex-typst-report-mcp tools \
         (initialize_workspace, create_report, add_version_entry, add_vulnerability, add_evidence, \
         build_report), following your system prompt. You MAY reason freely to enrich the writing — \
         this is authorized pentest reporting.\n\
         FILE IDENTIFICATION (include in the report as 'Identificação do Artefato' table):\n\
         - Arquivo: {tp}\n\
         - Formato: {tf}\n\
         - Arquitetura: {ta}\n\
         - SHA-256 (installer/main): {sha256}\n\
         - MD5 (installer/main): {md5}\n\
         PER-BINARY HASHES (include ALL in the report — one row per binary in the \
         'Identificação do Artefato' table):\n\
         {bundle_hashes}\n\
         These hashes MUST appear verbatim in the PDF report. Never omit or invent hash values. \
         Every binary analyzed must have its SHA-256 listed in the report.\n\
         The report MUST be DEEPLY DETAILED and in Portuguese:\n\
         For EVERY reported finding, the `add_vulnerability` body must contain, as labelled sections:\n\
         1. DESCRIÇÃO TÉCNICA — 2+ paragraphs: what the flaw is, the exact code path/function/address \
            (real IDA loci), how the binary reaches it, and why it is exploitable. Reference the \
            specific binary in the bundle (browserEXE/updaterEXE/libbrowserDLL/etc).\n\
         1b. ROTINAS E TRECHOS DE CÓDIGO — for each finding, include the actual vulnerable subroutine(s): \
            the function name/address (e.g. sub_140023760 @0x1400238EA, checkCertificate:fromChain: @0x100001640), \
            and a real code excerpt — the Hex-Rays PSEUDOCODE from the finding's evidence (decompile), or the \
            key DISASSEMBLY lines, formatted as a monospaced code block. Show the exact instructions/lines that \
            constitute the flaw (the NULL-DACL call, the patchable prologue 55 8B EC, the unchecked xpc handler, \
            the memcmp pin loop). Do NOT paraphrase code you don't have — use the loci/snippets present in the \
            findings evidence; if a snippet is missing, cite the address and name only.\n\
         2. IMPACTO — concrete attacker outcome (credential/token theft, MITM, RCE, injection) tied \
         to the analyzed malware sample and its observed impact.\n\
         3. PROVA DE CONCEITO (MANDATORY — every finding MUST have this section):\n\
            First, scan ALL PoC directories: {sd}/poc/, {sd}/poc-out/, and any poc-out/ subdirs \
            matching the target app. List every .py/.js/.m/.c/.sh/.ps1/.html file you find. \
            For each finding, locate the matching PoC by vuln_class or chain name. \
            Then: embed the ACTUAL PoC source code (paste the key 20-40 lines, not just a filename), \
            give exact build + run steps (e.g. 'frida -U -p <PID> -l script.js', \
            'python3 network_capture.py --target sample.exe'), and state compile/syntax status. \
            If a finding has NO PoC script, state 'PoC pendente — verificação manual necessária' \
            but NEVER skip the section entirely. PoC-less findings go to the end of the report.\n\
         4. MITIGAÇÃO — detailed, actionable remediation: specific API calls/flags/build settings \
            (e.g. SetProcessMitigationPolicy(ProcessSignaturePolicy), /guard:cf, explicit pipe DACL, \
            SecRequirement audit-token check), configuration changes, and a verification step to \
            confirm the fix. Multiple concrete bullets, not a one-liner.\n\
         5. CWE + CVSS vector string.\n\
         Then add a global 'Cadeia de Exploração' section walking each attack chain from \
         attack-graph.json end-to-end (step by step, which vuln enables the next, composite CVSS, \
         with the mermaid diagram). Order findings by descending CVSS. Do not report a finding with \
         no evidence and no PoC.\n\
         DATE: the assessment date is {date}. Use EXACTLY this date on the cover and in the version \
         table — do NOT invent an engagement window or any other date.\n\
         OUTPUT PATH: after build_report produces the PDF, COPY it into this session at \
         {sd}/report.pdf (use the Bash tool: cp <built-pdf> {sd}/report.pdf). The canonical \
         deliverable lives inside the session dir. Return the {sd}/report.pdf path.",
        fj = findings_json.display(), sd = session_dir.display(),
        tp = target_path, tf = target_format, ta = target_arch,
        sha256 = sha256, md5 = md5,
        bundle_hashes = if bundle_hashes_str.is_empty() { "  (no per-binary hashes available)".to_string() } else { bundle_hashes_str },
        date = cfg.report_date.clone().unwrap_or_else(|| "the current date".into())
    );
    let mut cmd = std::process::Command::new("claude");
    cmd.arg("-p").arg(prompt)
        .arg("--model").arg(&cfg.model)
        .arg("--fallback-model").arg(cfg.fallbacks.join(","))
        .arg("--dangerously-skip-permissions")
        .arg("--append-system-prompt-file").arg(agent_file)
        .arg("--add-dir").arg(&cfg.root)
        .arg("--output-format").arg(&cfg.output_format)
        .env("IS_SANDBOX", "1")
        .stdin(std::process::Stdio::null());
    let slog = SessionLog::new(session_dir);
    slog.log_kv("REPORT_START", &[("model", &cfg.model), ("date", cfg.report_date.as_deref().unwrap_or("auto"))]);
    println!("[report] running reporter over {}", session_dir.display());
    let start = SystemTime::now();
    let out = cmd.output()?;
    let elapsed = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    std::fs::write(session_dir.join("report.out.json"), &stdout).ok();
    slog.log_kv("REPORT_AGENT_DONE", &[
        ("status", if out.status.success() { "ok" } else { "error" }),
        ("elapsed_secs", &elapsed.to_string()),
    ]);
    let result = parse::unwrap_claude_json(&stdout);
    // Always copy the latest PDF into session dir — even if an older one exists from a prior run.
    let dest = session_dir.join("report.pdf");
    if let Some(src) = find_pdf_path(&result) {
        // Copy if dest doesn't exist OR source is newer/different size.
        let should_copy = if dest.is_file() {
            let src_size = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
            let dst_size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
            src_size != dst_size
        } else {
            true
        };
        if should_copy {
            std::fs::copy(&src, &dest).ok();
            slog.log_kv("REPORT_PDF_COPY", &[("from", &src.display().to_string()), ("to", &dest.display().to_string())]);
        }
    }
    if dest.is_file() {
        let pdf_size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
        slog.log_kv("REPORT_DONE", &[("pdf", &dest.display().to_string()), ("pdf_bytes", &pdf_size.to_string())]);
        println!("[report] PDF saved in session: {}", dest.display());
    } else {
        slog.log("REPORT_DONE | pdf=NOT_FOUND");
    }
    let tail = result.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" ");
    Ok(AgentRun { agent: "reporter".into(), ok: out.status.success(), output_tail: tail, findings: Vec::new(), raw_path: Some(session_dir.join("report.out.json").to_string_lossy().into_owned()) })
}

/// Run the auditor agent: reviews entire session for errors, missing PoCs, hallucinations,
/// and optionally triggers auto-remediation (re-runs failed stages).
/// Returns the audit report path and a list of stages that need re-running.
pub fn run_auditor(cfg: &Config, session_dir: &Path) -> anyhow::Result<AuditResult> {
    let agent_file = cfg.root.join("agents").join("auditor.md");
    if !agent_file.is_file() {
        anyhow::bail!("auditor agent not found at {}", agent_file.display());
    }
    let slog = SessionLog::new(session_dir);
    slog.log("AUDIT_START");
    println!("[audit] auditing session {}", session_dir.display());

    // Build a comprehensive prompt with all session context.
    let mut context_parts = Vec::new();

    // session.log
    if let Ok(log) = std::fs::read_to_string(session_dir.join("session.log")) {
        context_parts.push(format!("=== session.log ===\n{log}"));
    }

    // All .stderr.log files (last 10 lines each)
    if let Ok(rd) = std::fs::read_dir(session_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".stderr.log") {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    let tail: String = content.lines().rev().take(10).collect::<Vec<_>>()
                        .into_iter().rev().collect::<Vec<_>>().join("\n");
                    if !tail.trim().is_empty() {
                        context_parts.push(format!("=== {name} (last 10 lines) ===\n{tail}"));
                    }
                }
            }
        }
    }

    // All .out.json error summaries
    if let Ok(rd) = std::fs::read_dir(session_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".out.json") {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    let has_error = content.contains("\"is_error\":true")
                        || content.contains("\"terminal_reason\":\"api_error\"");
                    if has_error {
                        // Extract error snippet.
                        let snippet = content.chars().take(500).collect::<String>();
                        context_parts.push(format!("=== {name} (HAS ERROR) ===\n{snippet}..."));
                    } else {
                        // Just note it completed OK.
                        let cost = content.find("\"total_cost_usd\":")
                            .and_then(|i| content[i+17..].split([',', '}']).next())
                            .unwrap_or("?");
                        context_parts.push(format!("=== {name} === status=ok cost=${cost}"));
                    }
                }
            }
        }
    }

    // PoC inventory
    let mut poc_files = Vec::new();
    for base in &["poc-out", "poc"] {
        let dir = session_dir.join(base);
        if dir.is_dir() {
            collect_files_recursive(&dir, &mut poc_files);
        }
    }
    let poc_list: String = poc_files.iter()
        .map(|p| {
            let rel = p.strip_prefix(session_dir).unwrap_or(p);
            let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            format!("  {} ({}B)", rel.display(), size)
        })
        .collect::<Vec<_>>()
        .join("\n");
    context_parts.push(format!("=== PoC inventory ===\n{poc_list}"));

    // findings.json summary
    if let Ok(raw) = std::fs::read_to_string(session_dir.join("findings.json")) {
        if let Ok(findings) = serde_json::from_str::<Vec<Finding>>(&raw) {
            let mut by_sev = std::collections::HashMap::new();
            let mut by_verdict = std::collections::HashMap::new();
            let mut unknowns = 0usize;
            let mut no_evidence = 0usize;
            for f in &findings {
                *by_sev.entry(format!("{:?}", f.severity)).or_insert(0usize) += 1;
                *by_verdict.entry(format!("{:?}", f.verdict)).or_insert(0usize) += 1;
                if f.vuln_class == "unknown" || f.title == "unknown" { unknowns += 1; }
                if f.evidence.is_empty() { no_evidence += 1; }
            }
            context_parts.push(format!(
                "=== findings.json ===\ntotal={} severity={:?} verdict={:?} unknowns={} no_evidence={}",
                findings.len(), by_sev, by_verdict, unknowns, no_evidence
            ));
        }
    }

    let context = context_parts.join("\n\n");
    let prompt = format!(
        "Audit this SASF session at {sd}. Here is the full session context:\n\n{ctx}\n\n\
         Follow your system prompt workflow exactly. Write audit-report.md to {sd}/audit-report.md.\n\
         CRITICAL: If you find stages that FAILED (is_error:true, api_error, sleep, network errors), \
         list them in your output as a JSON object with key 'remediation_needed' containing an array \
         of stage names to re-run. Example: {{\"remediation_needed\": [\"validate\", \"exploit\"]}}.\n\
         If the failure was due to token limits or AI session expiry (context window full, rate limit, \
         overloaded), add 'wait_seconds': 300 to suggest a cooldown before retry.\n\
         If no remediation needed, return {{\"remediation_needed\": []}}.",
        sd = session_dir.display(), ctx = context
    );

    let mut cmd = std::process::Command::new("claude");
    cmd.arg("-p").arg(prompt)
        .arg("--model").arg(&cfg.model)
        .arg("--fallback-model").arg(cfg.fallbacks.join(","))
        .arg("--dangerously-skip-permissions")
        .arg("--append-system-prompt-file").arg(agent_file)
        .arg("--add-dir").arg(&cfg.root)
        .arg("--output-format").arg(&cfg.output_format)
        .env("IS_SANDBOX", "1")
        .stdin(std::process::Stdio::null());

    let start = SystemTime::now();
    let out = cmd.output()?;
    let elapsed = start.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    std::fs::write(session_dir.join("audit-auditor.out.json"), &stdout).ok();
    let result_text = parse::unwrap_claude_json(&stdout);

    // Parse remediation instructions from auditor output.
    let mut stages_to_rerun = Vec::new();
    let mut wait_seconds = 0u64;
    // Look for JSON block with remediation_needed.
    if let Some(start_idx) = result_text.find("\"remediation_needed\"") {
        // Find enclosing braces.
        if let Some(brace_start) = result_text[..start_idx].rfind('{') {
            if let Some(brace_end) = result_text[brace_start..].find('}') {
                let json_str = &result_text[brace_start..brace_start + brace_end + 1];
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                    if let Some(arr) = val.get("remediation_needed").and_then(|v| v.as_array()) {
                        for s in arr {
                            if let Some(name) = s.as_str() {
                                stages_to_rerun.push(name.to_string());
                            }
                        }
                    }
                    if let Some(w) = val.get("wait_seconds").and_then(|v| v.as_u64()) {
                        wait_seconds = w;
                    }
                }
            }
        }
    }

    slog.log_kv("AUDIT_DONE", &[
        ("elapsed_secs", &elapsed.to_string()),
        ("issues_found", &stages_to_rerun.len().to_string()),
        ("remediation", &stages_to_rerun.join(",")),
        ("wait_seconds", &wait_seconds.to_string()),
    ]);

    if session_dir.join("audit-report.md").is_file() {
        println!("[audit] report: {}/audit-report.md", session_dir.display());
    }
    if !stages_to_rerun.is_empty() {
        println!("[audit] remediation needed: {}", stages_to_rerun.join(", "));
        if wait_seconds > 0 {
            println!("[audit] waiting {}s before retry (token/session cooldown)...", wait_seconds);
        }
    } else {
        println!("[audit] pipeline clean — no remediation needed");
    }

    Ok(AuditResult {
        stages_to_rerun,
        wait_seconds,
        audit_path: session_dir.join("audit-report.md"),
    })
}

/// Result from the auditor: which stages need re-running and how long to wait.
pub struct AuditResult {
    pub stages_to_rerun: Vec<String>,
    pub wait_seconds: u64,
    pub audit_path: PathBuf,
}

fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_files_recursive(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

/// Copy `poc-out/` from the repo root into `<session>/poc-out/` so all artifacts live inside
/// the session directory. Only copies subdirectories that match the current target's app name
/// (e.g. `sample-macos`, `sample-windows`) — never cross-platform PoCs from other sessions.
/// Skips if source doesn't exist or destination already has matching content.
pub fn copy_poc_to_session(root: &Path, session_dir: &Path, slog: &SessionLog) {
    let src = root.join("poc-out");
    if !src.is_dir() { return; }
    // Determine target app slug from session's target.json. The exploit agent's task
    // prompt tells it to write to `poc-out/{app}/<vuln-class>/` using the BARE app name
    // (see lib.rs's analysis closing directive) — older sessions may have platform-suffixed dirs
    // directive existed. Build hint candidates for BOTH conventions so a bare-name dir
    // (e.g. "sample") isn't silently skipped just because a suffixed one (e.g. "sample-macos")
    // would also have matched. Without the bare-name candidate, copy_poc_to_session found
    // 0 matching subdirs for a plain-app-name session and every PoC the exploit agent
    // wrote stayed in the repo-root poc-out/, invisible to poc-test which only scans
    // <session>/poc-out/.
    let platform_hints: Vec<String> = std::fs::read_to_string(session_dir.join("target.json")).ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|v| {
            let app = v.get("app").and_then(|a| a.as_str()).unwrap_or("");
            let fmt = v.get("format").and_then(|f| f.as_str()).unwrap_or("");
            let suffix = if fmt.contains("macho") || fmt.contains("dmg") || fmt.contains("app") { "mac" }
                else if fmt.contains("pe") || fmt.contains("exe") || fmt.contains("msi") || fmt.contains("installer") { "win" }
                else if fmt.contains("elf") || fmt.contains("apk") || fmt.contains("dex") { "linux" }
                else { "" };
            let mut hints = Vec::new();
            if !app.is_empty() {
                hints.push(app.to_string());
                if !suffix.is_empty() { hints.push(format!("{app}-{suffix}")); }
            }
            hints
        })
        .unwrap_or_default();
    let dst_base = session_dir.join("poc-out");
    std::fs::create_dir_all(&dst_base).ok();
    let mut total_copied = 0usize;
    // Copy only matching subdirectories from poc-out/.
    if let Ok(rd) = std::fs::read_dir(&src) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !entry.path().is_dir() { continue; }
            // Filter: only copy if it matches one of this session's platform hints.
            let dominated = if platform_hints.is_empty() {
                true // no target.json / no app field? copy everything
            } else {
                platform_hints.iter().any(|hint| name == *hint || name.starts_with(hint.as_str()))
            };
            if !dominated { continue; }
            let dst_dir = dst_base.join(&name);
            if dst_dir.is_dir() && walkdir_count(&dst_dir) >= walkdir_count(&entry.path()) {
                continue; // already up to date
            }
            copy_dir_recursive(&entry.path(), &dst_dir).ok();
            let count = walkdir_count(&dst_dir);
            total_copied += count;
            slog.log_kv("POC_COPY", &[("subdir", &name), ("files", &count.to_string())]);
        }
    }
    if total_copied > 0 {
        println!("[session] PoC artifacts copied to {} ({total_copied} files)", dst_base.display());
    }
}

fn walkdir_count(dir: &Path) -> usize {
    fn count_inner(dir: &Path) -> usize {
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { n += count_inner(&p); } else { n += 1; }
            }
        }
        n
    }
    count_inner(dir)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)?.flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Auto-generate verification PoC scripts for empty poc-out/<app>/<vuln-class>/ dirs.
/// Uses built-in templates for common vuln classes; falls back to a generic verifier.
/// Called after the exploit stage so every finding has at least a verification script.
pub fn fill_empty_poc_dirs(poc_root: &Path, target: &Target, slog: &SessionLog) -> usize {
    let app_slug = &target.app;
    let app_dir = poc_root.join(format!("{app_slug}-mac")); // try <app>-mac first
    let app_dir = if app_dir.is_dir() { app_dir } else { poc_root.join(app_slug) };
    if !app_dir.is_dir() {
        // No poc-out/<app>/ dir yet — nothing to fill.
        return 0;
    }
    // Also try the target path to find the .app bundle for scripts.
    let app_path = &target.path;
    // Walk up from the binary to find the .app bundle.
    let bundle_path = if let Some(idx) = app_path.find(".app/") {
        &app_path[..idx + 4]
    } else {
        app_path.as_str()
    };

    let mut generated = 0;
    let Ok(rd) = std::fs::read_dir(&app_dir) else { return 0 };
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() { continue; }
        // Check if directory is empty.
        let is_empty = std::fs::read_dir(&p).map(|mut rd| rd.next().is_none()).unwrap_or(true);
        if !is_empty { continue; }
        let vuln_class = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let script = poc_template(&vuln_class, bundle_path, app_path);
        if script.is_empty() { continue; }
        let ext = if script.starts_with("#!/usr/bin/env python") { "py" } else { "sh" };
        let script_path = p.join(format!("poc_verify_{vuln_class}.{ext}"));
        if std::fs::write(&script_path, &script).is_ok() {
            // chmod +x
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).ok();
            }
            slog.log_kv("POC_VERIFY_GEN", &[("vuln_class", &vuln_class), ("script", &script_path.to_string_lossy())]);
            generated += 1;
        }
    }
    if generated > 0 {
        println!("[poc-verify] generated {generated} verification script(s) for empty poc dirs");
    }
    generated
}

/// Return a verification script for a given vuln class. Returns empty string if no template.
fn poc_template(vuln_class: &str, bundle_path: &str, binary_path: &str) -> String {
    let header = |desc: &str| format!(
        "#!/bin/bash\n\
         # PoC Verification: {vuln_class}\n\
         # {desc}\n\
         # Generated by SASF poc-verification skill\n\
         # Usage: ./{} [/path/to/App.app]\n\n\
         APP=\"${{1:-{bundle_path}}}\"\n\
         BIN=\"{binary_path}\"\n\
         VULN=0\n\n",
        format!("poc_verify_{vuln_class}.sh")
    );
    let footer = "\n\nif [ \"$VULN\" -gt 0 ]; then\n  echo \"\"\n  echo \"Result: $VULN vulnerability check(s) FAILED\"\n  exit 1\nelse\n  echo \"\"\n  echo \"Result: all checks passed\"\n  exit 0\nfi\n";

    match vuln_class {
        "missing-restrict-segment" => format!(
            "{header}\
             echo \"=== __RESTRICT Segment Check ===\"\n\
             for bin in \"$APP/Contents/MacOS/\"*; do\n\
               [ -f \"$bin\" ] || continue\n\
               name=$(basename \"$bin\")\n\
               count=$(otool -l \"$bin\" 2>/dev/null | grep -c __RESTRICT)\n\
               if [ \"$count\" -eq 0 ]; then\n\
                 echo \"[VULN] $name: NO __RESTRICT segment\"\n\
                 VULN=$((VULN+1))\n\
               else\n\
                 echo \"[OK]   $name: __RESTRICT present\"\n\
               fi\n\
             done\n\
             # Check XPC services\n\
             find \"$APP/Contents/XPCServices\" -type f -perm +111 2>/dev/null | while read xpc; do\n\
               name=$(basename \"$xpc\")\n\
               count=$(otool -l \"$xpc\" 2>/dev/null | grep -c __RESTRICT)\n\
               if [ \"$count\" -eq 0 ]; then\n\
                 echo \"[VULN] $name (XPC): NO __RESTRICT segment\"\n\
                 VULN=$((VULN+1))\n\
               fi\n\
             done\
             {footer}",
            header = header("Verify __RESTRICT segment is missing (enables DYLD_INSERT_LIBRARIES injection)")
        ),

        "no-app-sandbox" => format!(
            "{header}\
             echo \"=== App Sandbox Entitlement Check ===\"\n\
             for bin in \"$APP/Contents/MacOS/\"*; do\n\
               [ -f \"$bin\" ] || continue\n\
               name=$(basename \"$bin\")\n\
               ent=$(codesign -d --entitlements - \"$bin\" 2>/dev/null)\n\
               if echo \"$ent\" | grep -q \"app-sandbox\"; then\n\
                 echo \"[OK]   $name: app-sandbox entitlement present\"\n\
               else\n\
                 echo \"[VULN] $name: NO app-sandbox entitlement\"\n\
                 VULN=$((VULN+1))\n\
               fi\n\
             done\
             {footer}",
            header = header("Verify com.apple.security.app-sandbox is absent")
        ),

        "entitlements-audit" => format!(
            "{header}\
             echo \"=== Full Entitlements Audit ===\"\n\
             for bin in \"$APP/Contents/MacOS/\"*; do\n\
               [ -f \"$bin\" ] || continue\n\
               name=$(basename \"$bin\")\n\
               echo \"--- $name ---\"\n\
               ent=$(codesign -d --entitlements - \"$bin\" 2>/dev/null)\n\
               if [ -z \"$ent\" ]; then\n\
                 echo \"[VULN] $name: ZERO entitlements (unsigned or no entitlements)\"\n\
                 VULN=$((VULN+1))\n\
               else\n\
                 echo \"$ent\" | grep -E \"com\\.apple\" | sed 's/^/  /'\n\
                 # Check for dangerous entitlements\n\
                 if echo \"$ent\" | grep -q \"allow-jit\"; then\n\
                   echo \"[VULN] $name: has allow-jit (enables JIT code generation)\"\n\
                   VULN=$((VULN+1))\n\
                 fi\n\
                 if echo \"$ent\" | grep -q \"disable-library-validation\"; then\n\
                   echo \"[VULN] $name: has disable-library-validation (loads unsigned dylibs)\"\n\
                   VULN=$((VULN+1))\n\
                 fi\n\
               fi\n\
             done\
             {footer}",
            header = header("Dump and audit all entitlements across bundle binaries")
        ),

        "universal-links-missing" => format!(
            "{header}\
             echo \"=== Universal Links (Associated Domains) Check ===\"\n\
             for bin in \"$APP/Contents/MacOS/\"*; do\n\
               [ -f \"$bin\" ] || continue\n\
               name=$(basename \"$bin\")\n\
               ent=$(codesign -d --entitlements - \"$bin\" 2>/dev/null)\n\
               if echo \"$ent\" | grep -q \"associated-domains\"; then\n\
                 echo \"[OK]   $name: has associated-domains entitlement\"\n\
               else\n\
                 echo \"[VULN] $name: NO associated-domains — custom URL schemes hijackable\"\n\
                 VULN=$((VULN+1))\n\
               fi\n\
             done\n\
             # Check Info.plist for URL schemes\n\
             plist=\"$APP/Contents/Info.plist\"\n\
             if [ -f \"$plist\" ]; then\n\
               schemes=$(plutil -extract CFBundleURLTypes raw \"$plist\" 2>/dev/null)\n\
               if [ -n \"$schemes\" ] && [ \"$schemes\" != \"(null)\" ]; then\n\
                 echo \"[VULN] Custom URL schemes registered without Universal Links protection\"\n\
                 VULN=$((VULN+1))\n\
               fi\n\
             fi\
             {footer}",
            header = header("Verify associated-domains entitlement is absent (no Universal Links)")
        ),

        "ats-disabled" => format!(
            "{header}\
             echo \"=== App Transport Security Check ===\"\n\
             plist=\"$APP/Contents/Info.plist\"\n\
             if [ ! -f \"$plist\" ]; then\n\
               echo \"[VULN] Info.plist not found\"\n\
               VULN=$((VULN+1))\n\
             else\n\
               arbitrary=$(plutil -extract NSAppTransportSecurity.NSAllowsArbitraryLoads raw \"$plist\" 2>/dev/null)\n\
               if [ \"$arbitrary\" = \"true\" ] || [ \"$arbitrary\" = \"1\" ]; then\n\
                 echo \"[VULN] NSAllowsArbitraryLoads = true (ATS disabled)\"\n\
                 VULN=$((VULN+1))\n\
               else\n\
                 echo \"[OK]   NSAllowsArbitraryLoads not set or false (ATS enforced)\"\n\
               fi\n\
               local_net=$(plutil -extract NSAppTransportSecurity.NSAllowsLocalNetworking raw \"$plist\" 2>/dev/null)\n\
               if [ \"$local_net\" = \"true\" ]; then\n\
                 echo \"[VULN] NSAllowsLocalNetworking = true\"\n\
                 VULN=$((VULN+1))\n\
               fi\n\
             fi\
             {footer}",
            header = header("Check NSAppTransportSecurity configuration in Info.plist")
        ),

        "algorithm-identification" => format!(
            "{header}\
             echo \"=== Cryptographic Algorithm Check ===\"\n\
             echo \"Scanning binary for weak crypto patterns...\"\n\
             weak_patterns=(\"DES\" \"RC4\" \"MD5\" \"SHA1\" \"ECB\" \"RC2\" \"Blowfish\" \"3DES\")\n\
             for pat in \"${{weak_patterns[@]}}\"; do\n\
               count=$(strings \"$BIN\" 2>/dev/null | grep -ic \"$pat\")\n\
               if [ \"$count\" -gt 0 ]; then\n\
                 echo \"[VULN] Found $count reference(s) to $pat in binary\"\n\
                 strings \"$BIN\" | grep -i \"$pat\" | head -3 | sed 's/^/       /'\n\
                 VULN=$((VULN+1))\n\
               fi\n\
             done\n\
             # Check for CBC without HMAC\n\
             cbc=$(strings \"$BIN\" 2>/dev/null | grep -ic \"CBC\")\n\
             hmac=$(strings \"$BIN\" 2>/dev/null | grep -ic \"HMAC\")\n\
             if [ \"$cbc\" -gt 0 ] && [ \"$hmac\" -eq 0 ]; then\n\
               echo \"[VULN] CBC mode found ($cbc refs) but NO HMAC — unauthenticated encryption\"\n\
               VULN=$((VULN+1))\n\
             fi\
             {footer}",
            header = header("Scan binary for weak cryptographic algorithms and patterns")
        ),

        "import-export-surface" => format!(
            "{header}\
             echo \"=== Dangerous Import Surface Check ===\"\n\
             dangerous=(\"_execl\" \"_execle\" \"_execlp\" \"_execv\" \"_execvp\" \"_system\" \"_popen\" \"_fork\" \"_posix_spawn\" \"_dlopen\")\n\
             for bin in \"$APP/Contents/MacOS/\"* \"$APP/Contents/XPCServices/\"*/Contents/MacOS/*; do\n\
               [ -f \"$bin\" ] || continue\n\
               name=$(basename \"$bin\")\n\
               imports=$(nm -u \"$bin\" 2>/dev/null)\n\
               found=0\n\
               for imp in \"${{dangerous[@]}}\"; do\n\
                 if echo \"$imports\" | grep -q \"$imp\"; then\n\
                   echo \"[VULN] $name imports $imp\"\n\
                   found=$((found+1))\n\
                 fi\n\
               done\n\
               if [ \"$found\" -gt 0 ]; then\n\
                 echo \"       $name: $found dangerous import(s)\"\n\
                 VULN=$((VULN+found))\n\
               else\n\
                 echo \"[OK]   $name: no dangerous exec-family imports\"\n\
               fi\n\
             done\
             {footer}",
            header = header("Check for dangerous exec/spawn/dlopen imports in bundle binaries")
        ),

        "outdated-component-cve" => format!(
            "{header}\
             echo \"=== Outdated Component / Version Check ===\"\n\
             echo \"Scanning for embedded library versions...\"\n\
             # OpenSSL\n\
             openssl_ver=$(strings \"$BIN\" 2>/dev/null | grep -oE 'OpenSSL [0-9]+\\.[0-9]+\\.[0-9]+' | head -1)\n\
             if [ -n \"$openssl_ver\" ]; then\n\
               echo \"[VULN] Found embedded $openssl_ver — check for known CVEs\"\n\
               VULN=$((VULN+1))\n\
             fi\n\
             # libcurl\n\
             curl_ver=$(strings \"$BIN\" 2>/dev/null | grep -oE 'libcurl/[0-9]+\\.[0-9]+\\.[0-9]+' | head -1)\n\
             if [ -n \"$curl_ver\" ]; then\n\
               echo \"[VULN] Found embedded $curl_ver\"\n\
               VULN=$((VULN+1))\n\
             fi\n\
             # CEF/Chromium\n\
             cef_ver=$(strings \"$BIN\" 2>/dev/null | grep -oE 'Chrome/[0-9]+' | head -1)\n\
             if [ -n \"$cef_ver\" ]; then\n\
               echo \"[VULN] Found embedded $cef_ver\"\n\
               VULN=$((VULN+1))\n\
             fi\n\
             # Build paths\n\
             build_paths=$(strings \"$BIN\" 2>/dev/null | grep -E '/tmp/.*[0-9]+\\.[0-9]+' | head -5)\n\
             if [ -n \"$build_paths\" ]; then\n\
               echo \"[VULN] Build path disclosure:\"\n\
               echo \"$build_paths\" | sed 's/^/       /'\n\
               VULN=$((VULN+1))\n\
             fi\
             {footer}",
            header = header("Extract embedded library versions and check for known CVEs")
        ),

        "keychain-acl-probe" => format!(
            "{header}\
             echo \"=== Keychain / Credential Storage Check ===\"\n\
             # Check if app uses Keychain APIs\n\
             keychain_imports=$(nm -u \"$BIN\" 2>/dev/null | grep -c \"SecKeychain\\|SecItem\")\n\
             if [ \"$keychain_imports\" -eq 0 ]; then\n\
               echo \"[VULN] No Keychain API imports (SecKeychain/SecItem) — likely stores secrets elsewhere\"\n\
               VULN=$((VULN+1))\n\
             else\n\
               echo \"[OK]   Keychain APIs imported ($keychain_imports symbols)\"\n\
             fi\n\
             # Check NSUserDefaults usage\n\
             nsud=$(strings \"$BIN\" 2>/dev/null | grep -c \"NSUserDefaults\")\n\
             if [ \"$nsud\" -gt 0 ]; then\n\
               echo \"[VULN] NSUserDefaults references found ($nsud) — tokens may be in plaintext plist\"\n\
               VULN=$((VULN+1))\n\
             fi\n\
             # Check for plist files with potential tokens\n\
             bundle_id=$(plutil -extract CFBundleIdentifier raw \"$APP/Contents/Info.plist\" 2>/dev/null)\n\
             if [ -n \"$bundle_id\" ]; then\n\
               plist_path=\"$HOME/Library/Preferences/$bundle_id.plist\"\n\
               if [ -f \"$plist_path\" ]; then\n\
                 echo \"[VULN] NSUserDefaults plist exists: $plist_path\"\n\
                 VULN=$((VULN+1))\n\
               fi\n\
             fi\
             {footer}",
            header = header("Check credential storage — Keychain vs NSUserDefaults")
        ),

        "updater-weak-integrity" => format!(
            "#!/usr/bin/env python3\n\
             \"\"\"PoC Verification: updater-weak-integrity\n\
             Check Updater binary for weak team validation (containsString: vs isEqualToString:)\n\
             Generated by SASF poc-verification skill\n\
             Usage: python3 poc_verify_updater-weak-integrity.py [/path/to/App.app]\n\"\"\"\n\
             import subprocess, sys, os\n\n\
             app = sys.argv[1] if len(sys.argv) > 1 else \"{bundle_path}\"\n\
             updater = os.path.join(app, 'Contents/MacOS/Updater')\n\
             vuln = 0\n\n\
             if not os.path.exists(updater):\n\
                 print(f'[OK]   No Updater binary found at {{updater}}')\n\
                 sys.exit(0)\n\n\
             print(f'Analyzing: {{updater}}')\n\
             out = subprocess.check_output(['strings', updater], text=True, stderr=subprocess.DEVNULL)\n\n\
             checks = {{\n\
                 'containsString:': ('[VULN]', 'Weak substring match for team validation'),\n\
                 'isEqualToString:': ('[OK]  ', 'Exact string match (good)'),\n\
                 'SecTrustEvaluate': ('[OK]  ', 'TLS trust evaluation present'),\n\
                 'SecTrustEvaluateWithError': ('[OK]  ', 'Modern TLS trust evaluation'),\n\
                 'SecStaticCodeCheckValidity': ('[OK]  ', 'Code signature validation'),\n\
             }}\n\n\
             for sym, (tag, desc) in checks.items():\n\
                 found = sym in out\n\
                 if sym == 'containsString:' and found:\n\
                     print(f'[VULN] {{sym}}: FOUND — {{desc}}')\n\
                     vuln += 1\n\
                 elif sym != 'containsString:' and not found:\n\
                     print(f'[VULN] {{sym}}: ABSENT — missing {{desc}}')\n\
                     vuln += 1\n\
                 else:\n\
                     status = 'present' if found else 'absent'\n\
                     print(f'[OK]   {{sym}}: {{status}}')\n\n\
             sys.exit(1 if vuln > 0 else 0)\n",
        ),

        "disable-library-validation" => format!(
            "{header}\
             echo \"=== Disable Library Validation Check ===\"\n\
             for bin in \"$APP/Contents/MacOS/\"*; do\n\
               [ -f \"$bin\" ] || continue\n\
               name=$(basename \"$bin\")\n\
               ent=$(codesign -d --entitlements - \"$bin\" 2>/dev/null)\n\
               if echo \"$ent\" | grep -q \"disable-library-validation\"; then\n\
                 echo \"[VULN] $name: has disable-library-validation (loads unsigned dylibs)\"\n\
                 VULN=$((VULN+1))\n\
               else\n\
                 echo \"[OK]   $name: disable-library-validation absent\"\n\
               fi\n\
             done\
             {footer}",
            header = header("Check for com.apple.security.cs.disable-library-validation entitlement")
        ),

        // Anti-debug variants
        s if s.contains("anti-debug") || s.contains("root-jailbreak") => format!(
            "{header}\
             echo \"=== Anti-Debug Import Check ===\"\n\
             anti_debug=(\"_ptrace\" \"_sysctl\" \"_csops\" \"_task_get_exception_ports\" \"_isatty\" \"_getppid\")\n\
             for bin in \"$APP/Contents/MacOS/\"*; do\n\
               [ -f \"$bin\" ] || continue\n\
               name=$(basename \"$bin\")\n\
               imports=$(nm -u \"$bin\" 2>/dev/null)\n\
               for sym in \"${{anti_debug[@]}}\"; do\n\
                 if echo \"$imports\" | grep -q \"$sym\"; then\n\
                   echo \"[VULN] $name imports $sym (anti-debug mechanism)\"\n\
                   VULN=$((VULN+1))\n\
                 fi\n\
               done\n\
             done\n\
             # Check for Frida detection\n\
             frida_refs=$(strings \"$BIN\" 2>/dev/null | grep -ic \"frida\")\n\
             if [ \"$frida_refs\" -gt 0 ]; then\n\
               echo \"[OK]   Frida detection present ($frida_refs references)\"\n\
             else\n\
               echo \"[VULN] No Frida detection strings found\"\n\
               VULN=$((VULN+1))\n\
             fi\
             {footer}",
            header = header("Check anti-debug/anti-tamper imports and Frida detection")
        ),

        // Generic fallback
        _ => format!(
            "{header}\
             echo \"=== Generic Verification: {vuln_class} ===\"\n\
             echo \"Scanning binary for patterns related to {vuln_class}...\"\n\
             # Normalize vuln class to search terms\n\
             search_terms=$(echo \"{vuln_class}\" | tr '-' ' ')\n\
             for term in $search_terms; do\n\
               [ \"${{#term}}\" -lt 3 ] && continue\n\
               count=$(strings \"$BIN\" 2>/dev/null | grep -ic \"$term\")\n\
               if [ \"$count\" -gt 0 ]; then\n\
                 echo \"[INFO] Found $count reference(s) to '$term'\"\n\
                 strings \"$BIN\" 2>/dev/null | grep -i \"$term\" | head -3 | sed 's/^/       /'\n\
               fi\n\
             done\n\
             # Basic binary info\n\
             echo \"\"\n\
             echo \"Binary info:\"\n\
             otool -L \"$BIN\" 2>/dev/null | head -10 | sed 's/^/  /'\n\
             echo \"\"\n\
             echo \"Signing:\"\n\
             codesign -dvvv \"$BIN\" 2>&1 | grep -E \"Authority|TeamIdentifier|Identifier|Signature\" | sed 's/^/  /'\n\
             echo \"\"\n\
             echo \"[VULN] Manual review required for {vuln_class}\"\n\
             VULN=$((VULN+1))\
             {footer}",
            header = header(&format!("Generic verification for {vuln_class}"))
        ),
    }
}

fn summary_md(target: &Target, findings: &[Finding]) -> String {
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    let mut out = format!(
        "# SASF run — {}\n\nformat {} / arch {} / app {}\n\n## Severity tally\n\n\
         - Critical: {}\n- High: {}\n- Medium: {}\n- Low: {}\n- Info: {}\n\n## Findings\n\n",
        target.path, target.format, target.arch, target.app,
        count(Severity::Critical), count(Severity::High), count(Severity::Medium),
        count(Severity::Low), count(Severity::Info),
    );
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
    for f in sorted {
        out.push_str(&format!(
            "- **[{:?}]** `{}` — {} ({:?}){}\n",
            f.severity, f.vuln_class, f.title, f.verdict,
            f.prior_ref.as_ref().map(|p| format!(" [re-test {p}]")).unwrap_or_default()
        ));
    }
    out
}
