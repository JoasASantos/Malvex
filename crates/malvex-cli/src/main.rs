//! `malvex` — evidence-driven malware analysis harness CLI.

mod serve;

use clap::{Parser, Subcommand};
use malvex_core::Platform;
use std::io::{self, BufRead, Write};

#[derive(Parser)]
#[command(name = "malvex", version, about = "Malvex — malware analysis and reverse-engineering harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Doctor {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        install: bool,
    },
    Coverage {
        #[arg(long, default_value = ".")]
        root: String,
    },
    Extract {
        installer: String,
    },
    Reparse {
        session: String,
    },
    Graph {
        session: String,
    },
    Sessions {
        #[arg(long, default_value = ".")]
        root: String,
    },
    McpSetup {
        #[arg(long)]
        install: bool,
        #[arg(long)]
        commercial: bool,
        #[arg(long)]
        force: bool,
        #[arg(long, default_value = "~/.malvex/mcp")]
        home: String,
    },
    Setup {
        #[arg(long)]
        commercial: bool,
        #[arg(long, default_value = "~/.malvex/mcp")]
        mcp_home: String,
        #[arg(long)]
        no_mcp: bool,
        #[arg(long)]
        no_tools: bool,
    },
    Run {
        target: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "claude-opus-4-6")]
        model: String,
        #[arg(long, default_value = "claude")]
        runtime: String,
        #[arg(long, default_value = ".")]
        root: String,
        #[arg(long)]
        stages: Option<String>,
        #[arg(long)]
        resume: Option<String>,
        #[arg(long, short = 'v')]
        verbose: bool,
        #[arg(long, short = 'j', default_value = "1")]
        parallel: usize,
        #[arg(long)]
        prompt: Option<String>,
        #[arg(long)]
        prompt_file: Option<String>,
        #[arg(long, value_delimiter = ',')]
        fallback_models: Vec<String>,
        #[arg(long, default_value = "confirm-risky")]
        approval_mode: String,
    },
    Repl {
        session: String,
        #[arg(long, default_value = "claude-opus-4-6")]
        model: String,
        #[arg(long, default_value = "claude")]
        runtime: String,
        #[arg(long, default_value = ".")]
        root: String,
    },
    Serve {
        #[arg(long, default_value = "stdio")]
        transport: String,
        #[arg(long, default_value = "3000")]
        port: u16,
        #[arg(long, default_value = ".")]
        root: String,
    },
    /// Check if this machine is ready to run an analysis — and if not, say exactly what's
    /// missing and how to fix it. Different from `doctor`: preflight answers "will `malvex run`
    /// work right now?". Exits with code 1 if there are blockers.
    Preflight {
        #[arg(long, default_value = ".")]
        root: String,
        #[arg(long)]
        quick: bool,
    },
    /// Threat-intelligence sweep — research current malware landscape, extract IOCs.
    ThreatIntel {
        #[command(subcommand)]
        action: ThreatIntelAction,
    },
    /// On-demand malware/threat-actor lookup by name.
    Lookup {
        query: String,
        #[arg(long, default_value = ".")]
        root: String,
        #[arg(long, default_value = "claude-opus-4-6")]
        model: String,
        #[arg(long, value_delimiter = ',')]
        fallback_models: Vec<String>,
    },
    /// Scan telemetry JSON against all validated YARA rules + known IOCs.
    EventScan {
        events_file: String,
        #[arg(long, default_value = ".")]
        root: String,
        #[arg(long)]
        analyze: bool,
        #[arg(long, default_value = "claude-opus-4-6")]
        model: String,
    },
    /// Validate YARA rules for a session (re-validate without regeneration).
    YaraTest {
        session: String,
        #[arg(long, default_value = ".")]
        root: String,
        #[arg(long, default_value = "claude-opus-4-6")]
        model: String,
    },
    /// Build malicious-process imphash database from MalwareBazaar.
    ProcDb {
        query: String,
        #[arg(long)]
        family: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        merge_into: Option<String>,
    },
    /// Run a single analysis tool against a target and get structured JSON output.
    Tool {
        /// Tool name (ghidra, radare2, yara, strings, capa, pe, elf, macho, hashing, etc.)
        tool_name: String,
        /// Target file to analyze
        target: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Tool-specific options as JSON string
        #[arg(long)]
        options: Option<String>,
    },
    /// List all available analysis tool runners and their status.
    Tools,
}

#[derive(Subcommand)]
enum ThreatIntelAction {
    /// Run a new threat-intelligence sweep.
    Run {
        #[arg(long, default_value = ".")]
        root: String,
        #[arg(long, default_value = "claude-opus-4-6")]
        model: String,
        #[arg(long, value_delimiter = ',')]
        fallback_models: Vec<String>,
    },
    /// List past threat-intel runs.
    List {
        #[arg(long, default_value = ".")]
        root: String,
    },
    /// Show a specific run's report.
    Show {
        run_id: String,
        #[arg(long, default_value = ".")]
        root: String,
    },
    /// Show all known IOCs across runs.
    Iocs {
        #[arg(long, default_value = ".")]
        root: String,
    },
    /// Install a weekly launchd/cron schedule.
    Schedule {
        #[arg(long, default_value = ".")]
        root: String,
    },
    /// Remove the weekly schedule.
    Unschedule,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let platform = Platform::current();
    match cli.cmd {
        Cmd::Doctor { json, install } => doctor(platform, json, install),
        Cmd::Coverage { root } => coverage(root),
        Cmd::Extract { installer } => extract(installer),
        Cmd::Reparse { session } => {
            let n = malvex_orchestrator::exec::reparse(std::path::Path::new(&session))?;
            println!("[reparse] {n} finding(s) -> {session}/findings.json");
            Ok(())
        }
        Cmd::Graph { session } => {
            let (nodes, chains) = malvex_orchestrator::exec::attack_graph(std::path::Path::new(&session))?;
            println!("[graph] {nodes} node(s), {chains} chain(s) -> {session}/attack-graph.md + attack-graph.json");
            Ok(())
        }
        Cmd::Sessions { root } => sessions(root),
        Cmd::McpSetup { install, commercial, force, home } => mcp_setup(install, commercial, force, home),
        Cmd::Setup { commercial, mcp_home, no_mcp, no_tools } => setup(platform, commercial, mcp_home, no_mcp, no_tools),
        Cmd::Run { target, dry_run, model, runtime, root, stages, resume, verbose, parallel, prompt, prompt_file, fallback_models, approval_mode } => {
            run(target, dry_run, model, runtime, root, stages, resume, verbose, parallel, prompt, prompt_file, fallback_models, approval_mode)
        }
        Cmd::Repl { session, model, runtime, root } => repl(session, model, runtime, root),
        Cmd::Serve { transport, port, root } => serve::run(transport, port, root),
        Cmd::Preflight { root, quick } => preflight(root, quick),
        Cmd::ThreatIntel { action } => threat_intel(action),
        Cmd::Lookup { query, root, model, fallback_models } => lookup(query, root, model, fallback_models),
        Cmd::EventScan { events_file, root, analyze, model } => event_scan(events_file, root, analyze, model),
        Cmd::YaraTest { session, root, model } => yara_test(session, root, model),
        Cmd::ProcDb { query, family, api_key, merge_into } => proc_db(query, family, api_key, merge_into),
        Cmd::Tool { tool_name, target, json, options } => tool_run(tool_name, target, json, options),
        Cmd::Tools => tool_list(),
    }
}

fn doctor(platform: Platform, json: bool, do_install: bool) -> anyhow::Result<()> {
    let status = malvex_doctor::scan(platform);
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("Malvex doctor ({})\n", malvex_doctor::host_label(platform));
    println!("  {:<18} {:<18} {:<8} {}", "TOOL", "KIND", "STATUS", "DETAIL");
    println!("  {}", "-".repeat(88));
    for s in &status {
        let status_label = if s.present { "ok" } else { "missing" };
        let detail = if let Some(mcp) = &s.via_mcp {
            format!("via MCP {mcp}")
        } else if let Some(v) = &s.version {
            v.clone()
        } else if let Some(p) = &s.path {
            p.clone()
        } else {
            s.note.clone()
        };
        println!("  {:<18} {:<18} {:<8} {}", s.name, format!("{:?}", s.kind), status_label, truncate(&detail, 64));
    }

    if do_install {
        let plan = malvex_doctor::install_plan(&status);
        if plan.is_empty() {
            println!("\n[install] nothing to install");
        } else {
            println!("\n[install] attempting {} open-source install(s)", plan.len());
            for (name, ok, tail) in malvex_doctor::install(&plan) {
                println!("  [{}] {:<18} {}", if ok { "ok " } else { "err" }, name, truncate(&tail, 64));
            }
        }
        let extra = malvex_doctor::extra_install_plan(platform);
        if !extra.is_empty() {
            println!("\n[kali] detected Kali Linux — attempting {} distro package install(s)", extra.len());
            for (name, ok, tail) in malvex_doctor::install_extra(&extra) {
                println!("  [{}] {:<18} {}", if ok { "ok " } else { "err" }, name, truncate(&tail, 64));
            }
        }
    }
    Ok(())
}

fn coverage(root: String) -> anyhow::Result<()> {
    let cfg = malvex_orchestrator::Config { root: std::path::PathBuf::from(root), ..Default::default() };
    let c = malvex_orchestrator::coverage(&cfg)?;
    println!("Malvex coverage");
    println!("  skills: {}/{}", c.skills_present.len(), c.total_vectors);
    println!("  agents: {}/{}", c.agents_present.len(), c.agents_present.len() + c.agents_missing.len());
    if !c.skills_missing.is_empty() {
        println!("  missing skills: {}", c.skills_missing.join(", "));
    }
    if !c.agents_missing.is_empty() {
        println!("  missing agents: {}", c.agents_missing.join(", "));
    }
    Ok(())
}

fn extract(installer: String) -> anyhow::Result<()> {
    let p = std::path::Path::new(&installer);
    if !p.exists() {
        anyhow::bail!("installer not found: {installer}");
    }
    let (bins, log) = malvex_orchestrator::extract::unpack(p)?;
    for line in &log {
        println!("  {line}");
    }
    println!("\n{} binary(ies) extracted:", bins.len());
    for b in &bins {
        println!("  {b}");
    }
    Ok(())
}

fn sessions(root: String) -> anyhow::Result<()> {
    let dir = std::path::Path::new(&root).join("sessions");
    let mut rows: Vec<(String, String, usize, bool, bool)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let id = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let target = std::fs::read_to_string(p.join("target.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v.get("path").and_then(|x| x.as_str()).map(|s| s.rsplit('/').next().unwrap_or(s).to_string()))
                .unwrap_or_else(|| "?".into());
            let findings = std::fs::read_to_string(p.join("findings.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<serde_json::Value>>(&s).ok())
                .map(|v| v.len())
                .unwrap_or(0);
            rows.push((
                id,
                target,
                findings,
                p.join("attack-graph.json").is_file(),
                p.join("session.log").is_file(),
            ));
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    println!("  {:<16} {:<28} {:>8} {:>6} {:>5}", "SESSION", "TARGET", "FINDINGS", "GRAPH", "LOG");
    println!("  {}", "-".repeat(72));
    for (id, target, findings, graph, log) in rows {
        println!(
            "  {:<16} {:<28} {:>8} {:>6} {:>5}",
            id,
            truncate(&target, 28),
            findings,
            if graph { "y" } else { "-" },
            if log { "y" } else { "-" }
        );
    }
    Ok(())
}

fn mcp_setup(install: bool, commercial: bool, force: bool, home: String) -> anyhow::Result<()> {
    let home = home.replacen('~', &std::env::var("HOME").unwrap_or_else(|_| ".".into()), 1);
    println!("Malvex MCP setup (home: {home}){}{}", if install { "" } else { " — plan only" }, if force { " — force refresh" } else { "" });
    let results = malvex_doctor::mcp::setup(&home, commercial, install, force);
    for r in &results {
        println!("  [{:<8}] {:<18} {}", r.status, r.name, r.detail);
    }
    Ok(())
}

fn setup(platform: Platform, commercial: bool, mcp_home: String, no_mcp: bool, no_tools: bool) -> anyhow::Result<()> {
    let mcp_home = mcp_home.replacen('~', &std::env::var("HOME").unwrap_or_else(|_| ".".into()), 1);
    println!("Malvex setup ({})\n", malvex_doctor::host_label(platform));
    if !no_tools {
        let extra = malvex_doctor::extra_install_plan(platform);
        if !extra.is_empty() {
            println!("[kali] detected Kali Linux — installing {} distro package(s)", extra.len());
            for (name, ok, tail) in malvex_doctor::install_extra(&extra) {
                println!("  [{}] {:<18} {}", if ok { "ok " } else { "err" }, name, truncate(&tail, 64));
            }
            println!();
        }
        let status = malvex_doctor::scan(platform);
        let plan = malvex_doctor::install_plan(&status);
        if plan.is_empty() {
            println!("[tools] nothing to install");
        } else {
            println!("[tools] installing {} missing open-source tool(s)", plan.len());
            for (name, ok, tail) in malvex_doctor::install(&plan) {
                println!("  [{}] {:<18} {}", if ok { "ok " } else { "err" }, name, truncate(&tail, 64));
            }
        }
    }
    if !no_mcp {
        println!("\n[mcp] configuring MCP servers for all detected editors");
        println!("  scanning: Claude Code, Windsurf, Cursor, VS Code, OpenCode\n");
        let results = malvex_doctor::mcp::setup(&mcp_home, commercial, true, false);
        for r in &results {
            println!("  [{:<8}] {:<18} {}", r.status, r.name, truncate(&r.detail, 80));
        }
    }
    println!("\n[rea] checking REA (Reverse Engineer Anything)...");
    if malvex_orchestrator::rea::ReaBridge::ensure_installed() {
        println!("  [ok     ] REA installed and available");
        if malvex_orchestrator::rea::ReaBridge::setup_agents() {
            println!("  [ok     ] REA agent instructions configured for Claude Code");
        } else {
            println!("  [warn   ] REA agent setup skipped (run `npx rea-agents setup` manually)");
        }
    } else {
        println!("  [skip   ] REA not available (requires Node.js/npm)");
        println!("           Install Node.js for full RE capabilities, then: npm install -g rea-agents");
    }
    println!("\nnext:");
    println!("  malvex doctor");
    println!("  malvex run <target> --dry-run");
    println!("  malvex run <target>");
    Ok(())
}

const MAX_PARALLEL: usize = 5;

fn run(
    target: String,
    dry_run: bool,
    model: String,
    runtime: String,
    root: String,
    stages: Option<String>,
    resume: Option<String>,
    verbose: bool,
    parallel: usize,
    prompt: Option<String>,
    prompt_file: Option<String>,
    fallback_models: Vec<String>,
    approval_mode: String,
) -> anyhow::Result<()> {
    let resolved = resolve_target(&target)?;
    if resolved != target {
        eprintln!("[resolve] {target} -> {resolved}");
    }
    let t = identify(&resolved);
    let stage_filter = stages.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    });
    let resume_dir = resume.map(std::path::PathBuf::from);
    let clamped = parallel.clamp(1, MAX_PARALLEL);
    let custom_prompt = match prompt_file {
        Some(path) => Some(std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("failed to read --prompt-file {path}: {e}"))?),
        None => prompt,
    };
    let mut cfg = malvex_orchestrator::Config {
        root: std::path::PathBuf::from(root),
        model,
        dry_run,
        stage_filter,
        resume_dir,
        verbose,
        parallel: clamped,
        custom_prompt,
        runtime,
        approval_mode,
        ..Default::default()
    };
    if !fallback_models.is_empty() {
        cfg.fallbacks = fallback_models;
    }
    malvex_orchestrator::run(&cfg, &t)?;
    Ok(())
}

fn repl(session: String, model: String, runtime: String, root: String) -> anyhow::Result<()> {
    let session_dir = std::path::Path::new(&session);
    if !session_dir.is_dir() {
        anyhow::bail!("session not found: {session}");
    }
    let target: malvex_core::Target = serde_json::from_str(&std::fs::read_to_string(session_dir.join("target.json"))?)?;
    let findings: Vec<malvex_core::Finding> = std::fs::read_to_string(session_dir.join("findings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let context = findings
        .iter()
        .take(40)
        .map(|f| {
            let locus = f.evidence.iter().find_map(|e| e.locus.clone()).unwrap_or_default();
            format!("- {} [{}] {} {}", f.vuln_class, format!("{:?}", f.severity), f.title, locus)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let tax = malvex_orchestrator::Taxonomy::load(&std::path::Path::new(&root).join("vulns").join("taxonomy.yaml"))?;
    println!("Malvex REPL — session {}", session_dir.display());
    println!("Type /exit to quit.\n");
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    loop {
        print!("malvex> ");
        stdout.flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }
        let question = line.trim();
        if question.is_empty() {
            continue;
        }
        if matches!(question, "/exit" | "exit" | "quit") {
            break;
        }
        let cfg = malvex_orchestrator::Config {
            root: std::path::PathBuf::from(&root),
            model: model.clone(),
            runtime: runtime.clone(),
            dry_run: false,
            custom_prompt: Some(format!("Analyst question: {question}")),
            ..Default::default()
        };
        let mut cmd = malvex_orchestrator::build_command_ctx(&cfg, "interactive-repl", &target, &tax, Some(&context));
        let out = cmd.output()?;
        let stdout_text = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr_text = String::from_utf8_lossy(&out.stderr).to_string();
        if cfg.runtime == "claude" {
            println!("{}", malvex_orchestrator::parse::unwrap_claude_json(&stdout_text).trim());
        } else if !stdout_text.trim().is_empty() {
            println!("{}", stdout_text.trim());
        }
        if !stderr_text.trim().is_empty() {
            eprintln!("{}", stderr_text.trim());
        }
        println!();
    }
    Ok(())
}

fn resolve_target(input: &str) -> anyhow::Result<String> {
    let p = std::path::Path::new(input);
    if !p.exists() {
        anyhow::bail!("target not found: {input}");
    }
    if p.is_file() {
        return Ok(input.to_string());
    }
    if input.trim_end_matches('/').ends_with(".app") {
        let plist = p.join("Contents/Info.plist");
        if let Some(exe) = plist_value(&plist, "CFBundleExecutable") {
            let main = p.join("Contents/MacOS").join(&exe);
            if main.is_file() {
                return Ok(main.to_string_lossy().into_owned());
            }
        }
        anyhow::bail!("{input} is a .app but no main executable was found");
    }

    let mut best: Option<(u64, String)> = None;
    fn walk(dir: &std::path::Path, best: &mut Option<(u64, String)>, depth: usize) {
        if depth > 6 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, best, depth + 1);
                continue;
            }
            let mut magic = [0u8; 4];
            use std::io::Read;
            let is_bin = std::fs::File::open(&path)
                .ok()
                .and_then(|mut f| f.read_exact(&mut magic).ok())
                .is_some()
                && matches!(
                    magic,
                    [0x4D, 0x5A, _, _]
                        | [0x7F, 0x45, 0x4C, 0x46]
                        | [0xCF, 0xFA, 0xED, 0xFE]
                        | [0xCE, 0xFA, 0xED, 0xFE]
                        | [0xCA, 0xFE, 0xBA, 0xBE]
                );
            if is_bin {
                let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
                if best.as_ref().map(|(s, _)| sz > *s).unwrap_or(true) {
                    *best = Some((sz, path.to_string_lossy().into_owned()));
                }
            }
        }
    }
    walk(p, &mut best, 0);
    best.map(|(_, p)| p).ok_or_else(|| anyhow::anyhow!("no binary found under directory {input}"))
}

fn plist_value(plist: &std::path::Path, key: &str) -> Option<String> {
    let out = std::process::Command::new("plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .output()
        .ok()?;
    if out.status.success() {
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}

fn compute_hash(linux_cmd: &str, mac_cmd: &str, path: &str) -> Option<String> {
    for cmd_template in [linux_cmd, mac_cmd] {
        let full = format!("{cmd_template} {path:?}");
        if let Ok(out) = std::process::Command::new("sh").arg("-c").arg(&full).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                let hash = text.trim().split_whitespace().next().unwrap_or("").to_lowercase();
                if hash.len() >= 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(hash);
                }
            }
        }
    }
    None
}

pub fn identify(path: &str) -> malvex_core::Target {
    let bytes = std::fs::read(path).unwrap_or_default();
    let sha256 = compute_hash("sha256sum", "shasum -a 256", path);
    let md5 = compute_hash("md5sum", "md5 -q", path);
    let magic = bytes.get(0..4).unwrap_or(&[]);
    let (format, arch) = match magic {
        [0x4D, 0x5A, ..] => ("pe".to_string(), "x86_64|x86".to_string()),
        [0xCF, 0xFA, 0xED, 0xFE] => ("mach-o".to_string(), "arm64|x86_64".to_string()),
        [0xCE, 0xFA, 0xED, 0xFE] => ("mach-o".to_string(), "x86".to_string()),
        [0xCA, 0xFE, 0xBA, 0xBE] => ("fat".to_string(), "universal".to_string()),
        [0x7F, 0x45, 0x4C, 0x46] => ("elf".to_string(), "unknown".to_string()),
        _ => ("unknown".to_string(), "unknown".to_string()),
    };

    let lower = path.to_lowercase();
    let app = if lower.contains("sample") || lower.contains("malware") {
        "sample".into()
    } else {
        "unknown".into()
    };

    let shielding = detect_shielding(&bytes);
    let bundle_binaries = find_bundle_binaries(path);
    let bundle_hashes = compute_bundle_hashes(&bundle_binaries);
    malvex_core::Target { path: path.to_string(), format, arch, shielding, app, sha256, md5, bundle_binaries, bundle_hashes }
}

fn compute_bundle_hashes(binaries: &[String]) -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;
    let mut hashes = HashMap::new();
    for bin_path in binaries {
        if let Some(sha) = compute_hash("sha256sum", "shasum -a 256", bin_path) {
            let name = std::path::Path::new(bin_path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| bin_path.clone());
            hashes.insert(name, sha);
        }
    }
    hashes
}

fn find_bundle_binaries(path: &str) -> Vec<String> {
    let Some(idx) = path.find(".app/") else { return Vec::new() };
    let bundle = &path[..idx + 4];
    let mut found = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<String>, depth: usize) {
        if depth > 8 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out, depth + 1);
            } else if path.parent().and_then(|d| d.file_name()).map(|n| n == "MacOS").unwrap_or(false) {
                out.push(path.to_string_lossy().into_owned());
            }
        }
    }
    walk(std::path::Path::new(bundle), &mut found, 0);
    found.sort();
    found.dedup();
    found
}

fn detect_shielding(bytes: &[u8]) -> Vec<String> {
    let markers: &[(&[u8], &str)] = &[
        (b".vmp0", "vmprotect"),
        (b".vmp1", "vmprotect"),
        (b"VMProtect", "vmprotect"),
        (b"Themida", "themida"),
        (b"UPX!", "upx"),
        (b"Arxan", "arxan"),
        (b"Promon", "promon"),
    ];
    let mut found = Vec::new();
    for (needle, name) in markers {
        if bytes.windows(needle.len()).any(|w| w == *needle) && !found.iter().any(|f| f == name) {
            found.push((*name).to_string());
        }
    }
    found
}

fn preflight(root: String, quick: bool) -> anyhow::Result<()> {
    let root_path = std::path::PathBuf::from(&root);
    println!(
        "Malvex — preflight  (root: {}){}\n",
        root_path.display(),
        if quick { " [quick]" } else { "" }
    );
    let checks = malvex_doctor::preflight::run(&root_path, quick);
    for c in &checks {
        println!("  [{:<8}] {:<24} {}", c.level.tag(), c.name, c.detail);
        if !c.fix.is_empty() {
            for (i, line) in textwrap_simple(&c.fix, 86).into_iter().enumerate() {
                println!(
                    "             {} {}",
                    if i == 0 { ">" } else { " " },
                    line
                );
            }
        }
    }
    let (summary, code) = malvex_doctor::preflight::summarize(&checks);
    println!("\n  {summary}");
    if code == 0 {
        println!("\n  Next steps:");
        println!("    malvex run <target> --dry-run    # check the plan, no LLM cost");
        println!("    malvex run <target>              # real analysis");
    }
    std::process::exit(code);
}

fn textwrap_simple(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn threat_intel(action: ThreatIntelAction) -> anyhow::Result<()> {
    match action {
        ThreatIntelAction::Run { root, model, fallback_models } => {
            let mut cfg = malvex_orchestrator::Config {
                root: std::path::PathBuf::from(root), model, ..Default::default()
            };
            if !fallback_models.is_empty() { cfg.fallbacks = fallback_models; }
            let report = malvex_orchestrator::threatintel::run_threat_intel(&cfg)?;
            println!("[threat-intel] {} family(ies), {} IOC(s)", report.families.len(), report.iocs.len());
            let report_path = report.dir.join("report.md");
            if report_path.is_file() {
                println!("[threat-intel] report: {}", report_path.display());
            }
            Ok(())
        }
        ThreatIntelAction::List { root } => {
            let cfg = malvex_orchestrator::Config { root: std::path::PathBuf::from(root), ..Default::default() };
            let runs = malvex_orchestrator::threatintel::list_runs(&cfg);
            if runs.is_empty() {
                println!("No threat-intel runs found.");
            } else {
                for id in &runs { println!("  {id}"); }
            }
            Ok(())
        }
        ThreatIntelAction::Show { run_id, root } => {
            let cfg = malvex_orchestrator::Config { root: std::path::PathBuf::from(root), ..Default::default() };
            match malvex_orchestrator::threatintel::load_run(&cfg, &run_id) {
                Some(report) => {
                    let md_path = report.dir.join("report.md");
                    if md_path.is_file() {
                        print!("{}", std::fs::read_to_string(&md_path).unwrap_or_default());
                    } else {
                        println!("{} family(ies), {} IOC(s)", report.families.len(), report.iocs.len());
                    }
                }
                None => println!("Run {run_id} not found."),
            }
            Ok(())
        }
        ThreatIntelAction::Iocs { root } => {
            let cfg = malvex_orchestrator::Config { root: std::path::PathBuf::from(root), ..Default::default() };
            let iocs = malvex_orchestrator::threatintel::known_iocs(&cfg);
            if iocs.is_empty() {
                println!("No known IOCs.");
            } else {
                println!("  {:<10} {:<48} {}", "KIND", "VALUE", "FAMILY");
                println!("  {}", "-".repeat(76));
                for ioc in &iocs {
                    println!("  {:<10} {:<48} {}", ioc.kind, truncate(&ioc.value, 48), ioc.family);
                }
            }
            Ok(())
        }
        ThreatIntelAction::Schedule { root } => {
            let malvex_bin = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("malvex"));
            let root_path = std::path::PathBuf::from(root);
            let path = malvex_orchestrator::threatintel::schedule_weekly(&malvex_bin, &root_path)?;
            println!("[schedule] installed: {}", path.display());
            Ok(())
        }
        ThreatIntelAction::Unschedule => {
            malvex_orchestrator::threatintel::unschedule_weekly()?;
            println!("[schedule] removed");
            Ok(())
        }
    }
}

fn lookup(query: String, root: String, model: String, fallback_models: Vec<String>) -> anyhow::Result<()> {
    let mut cfg = malvex_orchestrator::Config {
        root: std::path::PathBuf::from(root), model, ..Default::default()
    };
    if !fallback_models.is_empty() { cfg.fallbacks = fallback_models; }
    let result = malvex_orchestrator::lookup::lookup_malware(&cfg, &query)?;
    if !result.found {
        println!("[lookup] \"{query}\": not found");
    } else {
        println!("[lookup] \"{query}\": {} alias(es), {} IOC(s), {} MITRE technique(s)",
            result.aliases.len(), result.iocs.len(), result.mitre_techniques.len());
    }
    let report_path = result.dir.join("report.md");
    if report_path.is_file() {
        println!("[lookup] report: {}", report_path.display());
    }
    Ok(())
}

fn event_scan(events_file: String, root: String, analyze: bool, model: String) -> anyhow::Result<()> {
    let cfg = malvex_orchestrator::Config {
        root: std::path::PathBuf::from(root), model, ..Default::default()
    };
    let events_path = std::path::Path::new(&events_file);
    if !events_path.is_file() {
        anyhow::bail!("events file not found: {events_file}");
    }
    let (run_id, report) = malvex_orchestrator::eventscan::scan_and_save(&cfg, events_path)?;
    println!("[event-scan] {run_id}: {} event(s) scanned, {} match(es) (rules={}, iocs={})",
        report.total_events, report.matches.len(), report.rules_used, report.iocs_used);
    if analyze && !report.matches.is_empty() {
        println!("[event-scan] running LLM analysis...");
        let analysis = malvex_orchestrator::eventscan::analyze_scan_with_llm(&cfg, &run_id)?;
        println!("[event-scan] analysis: verdict={}, {} detection(s)",
            analysis.overall_verdict, analysis.recommended_detections.len());
    }
    Ok(())
}

fn yara_test(session: String, root: String, model: String) -> anyhow::Result<()> {
    let cfg = malvex_orchestrator::Config {
        root: std::path::PathBuf::from(root), model, ..Default::default()
    };
    let session_dir = std::path::Path::new(&session);
    if !session_dir.is_dir() {
        anyhow::bail!("session not found: {session}");
    }
    let report = malvex_orchestrator::yararun::validate_yara_rules(&cfg, session_dir)?;
    println!("[yara-test] {}/{} rule(s) valid",
        report.results.iter().filter(|r| r.status == "valid").count(),
        report.results.len());
    for r in &report.results {
        println!("  [{:<12}] {} ({})", r.status, r.vuln_class, r.file);
    }
    Ok(())
}

fn proc_db(query: String, family: Option<String>, api_key: Option<String>, merge_path: Option<String>) -> anyhow::Result<()> {
    let key = api_key
        .or_else(|| std::env::var("MALWAREBAZAAR_API_KEY").ok())
        .ok_or_else(|| anyhow::anyhow!("need --api-key or $MALWAREBAZAAR_API_KEY"))?;
    let family_name = family.as_deref().unwrap_or(&query);
    let entry = malvex_orchestrator::procdb::fetch_family(&key, &query, family_name, &query, 100)?;
    println!("[procdb] {}: {} imphash(es), {} sha256, {} executable name(s)",
        entry.family, entry.imphashes.len(), entry.sha256.len(), entry.executable_names.len());
    if let Some(path) = merge_path {
        let db = malvex_orchestrator::procdb::merge_into(std::path::Path::new(&path), &entry)?;
        println!("[procdb] merged into {path} ({} total entries)", db.len());
    } else {
        println!("{}", serde_json::to_string_pretty(&entry)?);
    }
    Ok(())
}

fn tool_run(tool_name: String, target: String, json: bool, options: Option<String>) -> anyhow::Result<()> {
    let opts: serde_json::Value = match options {
        Some(s) => serde_json::from_str(&s)
            .map_err(|e| anyhow::anyhow!("invalid --options JSON: {e}"))?,
        None => serde_json::Value::Object(serde_json::Map::new()),
    };

    let runner = malvex_tools::find_runner(&tool_name)
        .ok_or_else(|| {
            let available: Vec<String> = malvex_tools::all_runners().iter().map(|r| r.name().to_string()).collect();
            anyhow::anyhow!("unknown tool: {tool_name}. Available: {}", available.join(", "))
        })?;

    if !runner.is_available() {
        anyhow::bail!("tool '{}' is not installed or not found in PATH", tool_name);
    }

    let output = runner.run(std::path::Path::new(&target), &opts);

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let status = if output.success { "ok" } else { "FAILED" };
        println!("[{}] {} ({}ms)", status, output.tool, output.duration_ms);
        if !output.errors.is_empty() {
            for e in &output.errors {
                eprintln!("  error: {e}");
            }
        }
        if output.success {
            println!("{}", serde_json::to_string_pretty(&output.data)?);
        }
    }
    Ok(())
}

fn tool_list() -> anyhow::Result<()> {
    println!("  {:<14} {:<10} {}", "TOOL", "STATUS", "TYPE");
    println!("  {}", "-".repeat(44));
    for runner in malvex_tools::all_runners() {
        let status = if runner.is_available() { "ok" } else { "missing" };
        println!("  {:<14} {:<10} {}", runner.name(), status, tool_category(runner.name()));
    }
    Ok(())
}

fn tool_category(name: &str) -> &'static str {
    match name {
        "ghidra" | "ida" | "radare2" => "disassembler",
        "yara" => "detection",
        "strings" | "capa" => "static analysis",
        "volatility" => "memory forensics",
        "frida" => "dynamic instrumentation",
        "binwalk" => "carver/extractor",
        "tshark" => "network analysis",
        "pe" | "elf" | "macho" => "format parser",
        "hashing" => "hashing/fingerprint",
        "sandbox" => "sandbox",
        "osint" => "threat intelligence",
        _ => "other",
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out = s.chars().take(n.saturating_sub(1)).collect::<String>();
        out.push('…');
        out
    }
}
