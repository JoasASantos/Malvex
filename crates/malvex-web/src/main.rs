//! malvex-web — browser front-end for the Malvex reverse-engineering harness.
//!
//! - `/`                       upload a binary, plan (dry-run) or launch a real pipeline run
//! - `/sessions`                dashboard of every session under `<root>/sessions/`
//! - `/session/:id`             detail: live stage progress, findings summary, downloads
//! - `/session/:id/file/:name`  serve one allow-listed artifact (findings.json, attack-graph, ...)
//!
//! Real runs are launched via `tokio::process::Command` and NEVER awaited synchronously —
//! a real analysis takes minutes to hours (parallel Opus agents over IDA/Ghidra/Frida), so
//! the upload handler only waits long enough to read the pipeline's own "SESSION: <id>"
//! startup banner off stdout, then redirects to `/session/:id` and detaches. A background
//! task keeps draining the child's stdout/stderr to EOF (discarded — `session.log`, written
//! by the orchestrator itself, is the source of truth for progress) so the child never blocks
//! on a full pipe, and reaps it on exit.

use axum::{
    extract::{Form, Multipart, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
use malvex_core::{Finding, Severity, Target, Verdict};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
struct AppState {
    root: PathBuf,
    uploads: PathBuf,
}

fn env_first(keys: &[&str], default: &str) -> String {
    keys.iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root = env_first(&["MALVEX_ROOT"], ".");
    let uploads = env_first(&["MALVEX_UPLOADS"], "/tmp/malvex-uploads");
    std::fs::create_dir_all(&uploads).ok();

    let state = Arc::new(AppState { root: root.into(), uploads: uploads.into() });

    // Malware targets are real installers/.app bundles — tens to hundreds of MB, well past
    // axum's default 2MB request-body limit. Without this, any real upload silently failed
    // partway through and rendered as an indistinguishable "no file received".
    const MAX_UPLOAD_BYTES: usize = 2 * 1024 * 1024 * 1024; // 2GB
    let app = Router::new()
        .route("/", get(index))
        .route("/store", get(store))
        .route("/schedule", get(schedule_page).post(create_schedule))
        .route("/settings", get(settings_page))
        .route("/api/doctor", get(api_doctor))
        .route("/api/session/:id", get(api_session))
        .route("/terminal", post(terminal))
        .route("/api/prompt", post(api_prompt))
        .route(
            "/upload",
            post(upload).layer(axum::extract::DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
        )
        .route("/sessions", get(sessions_dashboard))
        .route("/session/:id", get(session_detail))
        .route("/session/:id/resume", post(resume_session))
        .route("/session/:id/edit/:name", get(edit_file).post(save_file))
        .route("/session/:id/file/:name", get(session_file))
        .route("/threatintel", get(threatintel_page))
        .route("/eventscan", get(eventscan_page).post(eventscan_run))
        .route("/lookup", get(lookup_page).post(lookup_run))
        .route("/procdb", get(procdb_page).post(procdb_add))
        .route("/remotebox", get(remotebox_page).post(remotebox_add))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let addr = env_first(&["MALVEX_ADDR"], "127.0.0.1:8787");
    println!("[malvex-web] listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Page shell ───────────────────────────────────────────────────────────────

const STYLE: &str = r#"
:root{--bg:#0b0d12;--ink:#e7ebf3;--dim:#8791a5;--card:#111824;--border:#273043;
      --text:#e8e8e8;--gold:#ffcc33;--pink:#ff3f8e;--violet:#7c3aed;--ok:#3ddc84}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,sans-serif;margin:0;overflow-x:hidden}
.wrap{width:min(1100px,100%);margin:0 auto;padding:1.5rem clamp(1rem,4vw,2.5rem) 4rem}
nav{display:flex;align-items:center;gap:1rem;margin-bottom:2rem;border-bottom:1px solid var(--border);padding:0 0 1rem;flex-wrap:wrap}
nav a{color:var(--dim);text-decoration:none;font-size:.92rem}
nav a.brand{color:var(--ink);font-weight:800;font-size:1.15rem;margin-right:auto;
            display:flex;align-items:center;gap:.4rem}
nav a.brand .dot{width:.5em;height:.5em;border-radius:50%;
    background:radial-gradient(circle at 35% 30%,#fff3c4,var(--gold) 60%)}
nav a.active,nav a:hover{color:var(--ink);font-weight:600}
h1,h2,h3{margin-top:0;color:var(--ink);letter-spacing:-.025em}
.card{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:16px;
      padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 14px 34px -20px rgba(0,0,0,.3)}
.card h3{color:var(--text)}
.card a{color:var(--gold)}
table{width:100%;border-collapse:collapse;font-size:.88rem;color:var(--text)}
th,td{text-align:left;padding:.55rem .75rem;border-bottom:1px solid var(--border);white-space:nowrap}
td.wrap-cell{white-space:normal}
th{color:#8f8f8f;font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em}
tr:hover td{background:#191919}
.scroll{overflow:auto;max-height:520px}
.badge{display:inline-block;padding:.15rem .6rem;border-radius:99px;font-size:.72rem;font-weight:700}
.b-crit{background:#3a1424;color:#ff6fa8}
.b-high{background:#3a2410;color:var(--gold)}
.b-med{background:#332c10;color:#e0d068}
.b-low{background:#122c2a;color:#5ed0c0}
.b-info{background:#1c1c1c;color:var(--dim)}
.b-confirmed{background:#0f3320;color:var(--ok)}
.b-plausible{background:#332c10;color:var(--gold)}
.b-refuted{background:#241318;color:var(--dim)}
.b-pending{background:#1c1c1c;color:var(--dim)}
.b-run{background:#2a2010;color:var(--gold)}
.b-done{background:#0f3320;color:var(--ok)}
.b-pend{background:#1c1c1c;color:var(--dim)}
.stagebar{display:flex;flex-wrap:wrap;gap:.5rem;margin:1rem 0}
.progress-head{display:flex;justify-content:space-between;color:#8f8f8f;font-size:.78rem;margin-top:1rem}.progress-head b{color:var(--ok)}.progress-track{height:6px;background:#252525;border-radius:99px;overflow:hidden;margin:.45rem 0 .8rem}.progress-fill{height:100%;background:linear-gradient(90deg,var(--pink),var(--violet));border-radius:99px;transition:width .4s ease}
.stage{padding:.4rem .8rem;border-radius:8px;font-size:.82rem;border:1px solid var(--border);color:var(--dim)}
.stage.done{background:#0f3320;color:var(--ok);border-color:#1e5a30}
.stage.running{background:#2a2010;color:var(--gold);border-color:#4a3a10;animation:pulse 1.6s ease-in-out infinite}
.stage.pending{color:#666}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
a.btn{display:inline-block;background:linear-gradient(135deg,var(--pink),var(--violet));color:#fff;border:0;
      padding:.55rem 1.2rem;border-radius:999px;font-weight:700;text-decoration:none;font-size:.86rem;
      margin:.2rem .4rem .2rem 0;box-shadow:0 6px 18px -8px rgba(255,63,142,.55)}
a.btn.ghost{background:#1e1e1e;color:var(--text);border:1px solid #333;box-shadow:none}
pre.log{background:#000;color:#9a9a9a;font:12px/1.5 ui-monospace,monospace;padding:1rem;
        border-radius:8px;overflow:auto;max-height:420px;margin:0}
.dim{color:var(--dim)}
"#;

fn layout(title: &str, active: &str, body: &str) -> Html<String> {
    let _ = active;
    Html(format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{title} — Malvex</title><style>{STYLE}</style>\
         <body><div class=wrap>\
         <nav><a class=brand href=\"/\">Malvex<span class=dot></span></a><a href=\"/\">Investigator</a><a href=\"/sessions\">Sessions</a><a href=\"/settings\">Settings</a></nav>\
         {body}\
         </div></body>",
    ))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Extract IOCs (IPs, domains, hashes, URLs) from evidence text using regex.
fn extract_iocs(text: &str) -> Vec<(String, String)> {
    let mut iocs = Vec::new();
    // IPv4
    if let Ok(re) = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b") {
        for cap in re.captures_iter(text) {
            let ip = cap[1].to_string();
            if !ip.starts_with("0.") && !ip.starts_with("127.") && !ip.starts_with("255.") {
                iocs.push(("ip".into(), ip));
            }
        }
    }
    // URLs
    if let Ok(re) = regex::Regex::new(r#"(https?://[^\s<>"'\)]+)"#) {
        for cap in re.captures_iter(text) {
            iocs.push(("url".into(), cap[1].to_string()));
        }
    }
    // Domains (simple heuristic)
    if let Ok(re) = regex::Regex::new(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:com|net|org|io|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|pw|cc|ws|click|link|download|zip|mov|app))\b") {
        for cap in re.captures_iter(text) {
            iocs.push(("domain".into(), cap[1].to_string()));
        }
    }
    // SHA256
    if let Ok(re) = regex::Regex::new(r"\b([a-fA-F0-9]{64})\b") {
        for cap in re.captures_iter(text) {
            iocs.push(("sha256".into(), cap[1].to_string()));
        }
    }
    // SHA1
    if let Ok(re) = regex::Regex::new(r"\b([a-fA-F0-9]{40})\b") {
        for cap in re.captures_iter(text) {
            iocs.push(("sha1".into(), cap[1].to_string()));
        }
    }
    // MD5
    if let Ok(re) = regex::Regex::new(r"\b([a-fA-F0-9]{32})\b") {
        for cap in re.captures_iter(text) {
            iocs.push(("md5".into(), cap[1].to_string()));
        }
    }
    // Deduplicate
    iocs.sort();
    iocs.dedup();
    iocs
}

/// Extract MITRE ATT&CK technique IDs from vuln_class field (e.g. "T1055", "T1059.001")
fn extract_mitre_techniques(vuln_class: &str) -> Vec<String> {
    if let Ok(re) = regex::Regex::new(r"(T\d{4}(?:\.\d{3})?)") {
        re.captures_iter(vuln_class)
            .map(|cap| cap[1].to_string())
            .collect()
    } else {
        Vec::new()
    }
}

// ── Pipeline liveness (PID lock) ─────────────────────────────────────────────
// A session sitting on a stage for hours looks IDENTICAL from session.log alone (an
// AGENT_START with no matching AGENT_DONE) whether the underlying process is genuinely still
// grinding away or has been dead for hours — that ambiguity is exactly what made an actually-
// still-running session look indistinguishable from a silently-killed one. Every spawn (fresh
// upload or resume) drops the child's PID into `<session>/.pipeline.pid`; the dashboard then
// asks the OS directly (`kill -0`) whether that PID is real, rather than guessing from log
// content, and only offers to resume when it can confirm nothing is already running.

fn write_pid_lock(session_dir: &FsPath, pid: u32) {
    std::fs::create_dir_all(session_dir).ok();
    std::fs::write(session_dir.join(".pipeline.pid"), pid.to_string()).ok();
}

fn read_pid_lock(session_dir: &FsPath) -> Option<u32> {
    std::fs::read_to_string(session_dir.join(".pipeline.pid")).ok()?.trim().parse().ok()
}

/// `kill -0 <pid>` sends no signal, just checks whether the OS still has a process at that
/// PID — the standard portable way to ask "is this still alive" without owning the process
/// (we never do — the whole point is these survive independently of the web process).
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fallback for sessions that predate the PID-lock feature (every session that existed before
/// this shipped — including a real production run this was written specifically because of):
/// no `.pipeline.pid` file does NOT mean nothing is running, it can just mean the lock was
/// never written. Search live `malvex run` processes for one whose command line contains this
/// exact target path (present in argv for both a fresh run and a `--resume` run) — if found,
/// write the lock retroactively so future checks are instant, and report it alive. Without
/// this, a legacy session's Resume button would let someone launch a SECOND process racing
/// the still-live one on the same findings.json/session.log.
fn find_and_lock_live_pid(session_dir: &FsPath, target_path: &str) -> Option<u32> {
    let out = std::process::Command::new("pgrep").args(["-f", target_path]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            // pgrep -f matches ANY process with this string in its argv, including e.g. a
            // shell that happens to mention the path (unlikely here, but cheap to guard):
            // confirm the matched process's own command line actually looks like a `malvex run`
            // invocation before trusting it.
            let cmdline = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "command="])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            if cmdline.contains("malvex") && cmdline.contains("run") {
                write_pid_lock(session_dir, pid);
                return Some(pid);
            }
        }
    }
    None
}

// ── Index / upload ───────────────────────────────────────────────────────────

async fn store() -> Html<String> {
    let body = r#"
    <h1>Connector &amp; Skill Store</h1>
    <p class="dim">Extend Malvex with local skills, MCP servers, and authenticated external connectors.</p>
    <div class="card"><h3>AI runtimes</h3><p>Claude and Codex subscriptions use the active local CLI login. API gateways use the custom runtime profile and never receive credentials from Malvex.</p><span class="badge b-confirmed">available</span></div>
    <div class="card"><h3>Investigation skills</h3><p>Malware triage, static RE, unpacking, dynamic analysis, memory, network, ATT&amp;CK, IOC extraction, lineage, and detection engineering.</p><a class="btn" href="/">Use in Investigator</a></div>
    <div class="card"><h3>Connectors</h3><p>Gmail · Jira · GitHub · Slack · SIEM · threat-intelligence feeds</p><p class="dim">Connectors are installed as MCP integrations and require your own OAuth/API credentials. Secrets stay in the local credential store.</p><a class="btn ghost" href="/">Configure from Investigator</a></div>
    <div class="card"><h3>Build a skill</h3><p>Add a <code>skills/&lt;name&gt;/SKILL.md</code> with frontmatter, evidence rules, and verification steps. The next run discovers it automatically.</p></div>
    "#;
    layout("store", "/store", body)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Schedule { name: String, prompt: String, cron: String, runtime: String, models: Vec<String> }

#[derive(serde::Deserialize)]
struct ScheduleRequest { name: String, prompt: String, cron: String, runtime: String, models: String }

async fn schedule_page(State(st): State<Arc<AppState>>) -> Html<String> {
    let path = st.root.join("data/schedules.json");
    let schedules: Vec<Schedule> = std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let rows = if schedules.is_empty() { "<p class=dim>No schedules yet.</p>".to_string() } else { schedules.iter().map(|s| format!("<div class=card><h3>{}</h3><p><code>{}</code></p><p>{}</p><span class=badge>{}</span> <span class=badge>{}</span></div>", html_escape(&s.name), html_escape(&s.cron), html_escape(&s.prompt), html_escape(&s.runtime), html_escape(&s.models.join(", ")))).collect() };
    let body = format!("<h1>Schedules</h1><p class=dim>Persist investigation jobs and review them before enabling execution.</p><div class=card><form method=post action=/schedule><p><input name=name placeholder='Schedule name' required></p><p><input name=cron placeholder='Cron, e.g. 0 9 * * *' required></p><p><input name=prompt placeholder='Prompt or @path/to/sample' required></p><p><select name=runtime><option value=claude>Claude subscription</option><option value=codex>Codex subscription</option><option value=custom>Custom / API</option></select> <input name=models value='claude-opus-4-6,claude-sonnet-4-6'></p><button class=btn type=submit>Save schedule</button></form></div>{rows}<a class='btn ghost' href='/'>Back to Investigator</a>");
    layout("schedules", "/schedule", &body)
}

async fn settings_page() -> Html<String> {
    let body = r##"<h1>Settings</h1><p class=dim>Configure the local Malvex execution boundary.</p>

    <div class=card><h3>Analysis Pipeline</h3>
    <svg viewBox="0 0 800 340" style="width:100%;max-width:800px;font-family:ui-monospace,monospace" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="g1" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ff3f8e"/><stop offset="100%" stop-color="#7c3aed"/></linearGradient>
        <linearGradient id="g2" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#82a9ff"/><stop offset="100%" stop-color="#65d4df"/></linearGradient>
      </defs>
      <style>text{fill:#e7ebf3;font-size:11px}.box{fill:#151a24;stroke:#1e2a3a;stroke-width:1.5;rx:8}.label{font-size:13px;font-weight:700;fill:#82a9ff}.sub{fill:#6b7a90;font-size:10px}.arrow{stroke:#65d4df;stroke-width:2;fill:none;marker-end:url(#ah)}
      <marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10" fill="#65d4df"/></marker>
      </style>
      <rect class="box" x="10" y="20" width="120" height="90"/>
      <text class="label" x="30" y="42">TRIAGE</text>
      <text class="sub" x="20" y="58">hashes, type, packer</text>
      <text class="sub" x="20" y="70">entropy, strings</text>
      <text class="sub" x="20" y="82">IOC surface, exiftool</text>
      <text class="sub" x="20" y="94">pdf-parser, oleid</text>

      <path class="arrow" d="M130,65 L155,65"/>

      <rect class="box" x="160" y="20" width="140" height="90"/>
      <text class="label" x="180" y="42">STATIC</text>
      <text class="sub" x="170" y="58">disassembly, decompile</text>
      <text class="sub" x="170" y="70">capa, radare2, ghidra</text>
      <text class="sub" x="170" y="82">olevba, macro analysis</text>
      <text class="sub" x="170" y="94">imports, exports, CFG</text>

      <path class="arrow" d="M300,65 L325,65"/>

      <rect class="box" x="330" y="20" width="140" height="90"/>
      <text class="label" x="350" y="42">DYNAMIC</text>
      <text class="sub" x="340" y="58">sandbox execution</text>
      <text class="sub" x="340" y="70">memory analysis</text>
      <text class="sub" x="340" y="82">API tracing, frida</text>
      <text class="sub" x="340" y="94">headless browser</text>

      <path class="arrow" d="M400,110 L400,140"/>

      <rect class="box" x="10" y="140" width="140" height="80"/>
      <text class="label" x="30" y="162">NETWORK</text>
      <text class="sub" x="20" y="178">tshark, tcpdump</text>
      <text class="sub" x="20" y="190">mitmproxy, zeek</text>
      <text class="sub" x="20" y="202">DNS/HTTP/TLS capture</text>

      <path class="arrow" d="M150,180 L175,180"/>

      <rect class="box" x="180" y="140" width="140" height="80"/>
      <text class="label" x="200" y="162">INTELLIGENCE</text>
      <text class="sub" x="190" y="178">YARA scanning</text>
      <text class="sub" x="190" y="190">MITRE ATT&amp;CK map</text>
      <text class="sub" x="190" y="202">threat intel, OSINT</text>

      <path class="arrow" d="M320,180 L345,180"/>

      <rect class="box" x="350" y="140" width="140" height="80"/>
      <text class="label" x="370" y="162">VALIDATE</text>
      <text class="sub" x="360" y="178">evidence gate</text>
      <text class="sub" x="360" y="190">PoC compilation</text>
      <text class="sub" x="360" y="202">confidence scoring</text>

      <path class="arrow" d="M420,220 L420,250"/>
      <rect x="370" y="255" width="100" height="30" rx="15" fill="url(#g1)"/>
      <text x="387" y="275" style="fill:#fff;font-weight:700;font-size:12px">REPORT</text>

      <rect class="box" x="530" y="20" width="250" height="270"/>
      <text class="label" x="550" y="42">TOOLS (22)</text>
      <text class="sub" x="540" y="58">RE: ghidra, ida, radare2, capa, binwalk</text>
      <text class="sub" x="540" y="72">Strings: strings, exiftool, hashing</text>
      <text class="sub" x="540" y="86">Binary: pe, elf, macho</text>
      <text class="sub" x="540" y="100">Document: pdf-parser, pdfid, olevba</text>
      <text class="sub" x="540" y="114">Document: oleid, rtfobj</text>
      <text class="sub" x="540" y="128">Dynamic: frida, sandbox, volatility</text>
      <text class="sub" x="540" y="142">Network: tshark</text>
      <text class="sub" x="540" y="156">Detection: yara</text>
      <text class="sub" x="540" y="170">Intel: osint</text>
      <text class="sub" x="540" y="194">HEADLESS CAPABILITIES</text>
      <text class="sub" x="540" y="208">playwright: browser automation</text>
      <text class="sub" x="540" y="222">MCP servers: radare2, re-mcp,</text>
      <text class="sub" x="540" y="236">  ida-pro, ghidra, yaraflux,</text>
      <text class="sub" x="540" y="250">  muster, cutter, frida, x64dbg</text>
      <text class="sub" x="540" y="274">61 skills · 15 agents · 5 runtimes</text>
    </svg>
    </div>

    <div class=card><h3>AI Runtimes</h3>
    <p><b>Claude</b> · subscription via CLI (<code>claude</code>)</p>
    <p><b>Codex</b> · subscription via CLI (<code>codex</code>)</p>
    <p><b>Hermes</b> · local orchestration runtime</p>
    <p><b>Ollama</b> · local models (<code>ollama serve</code>)</p>
    <p><b>Custom</b> · API gateway via <code>MALVEX_CUSTOM_CMD</code></p></div>

    <div class=card><h3>Model Catalog</h3>
    <p class=dim>Claude Opus 5.5 · Opus 4.7 · Opus 4.6 · Sonnet 5.5 · Fable 5.1 · Haiku 4.5<br>GPT-5 · Custom model ID</p></div>

    <div class=card><h3>Headless &amp; MCP</h3>
    <p>Malvex exposes 31 tools via MCP (<code>malvex serve --mcp</code>). Headless analysis runs all tools without UI.</p>
    <p class=dim>Claude Code · Windsurf · Cursor · VS Code · OpenCode</p>
    <p><code>malvex run sample.exe</code> — full headless pipeline</p>
    <p><code>malvex run sample.pdf --dry-run</code> — plan only</p>
    <p><code>malvex tool olevba macro.docm</code> — single tool</p></div>

    <div class=card><h3>Approval Policy</h3><p>Auto mode · Approve risky actions · Human in the loop</p>
    <p class=dim>Destructive commands blocked by REPL safety policy.</p></div>

    <div class=card><h3>Tool Setup</h3>
    <p>Automated installers for all analysis tools. Run the script for your platform:</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:12px 0">
      <div style="background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px">
        <p style="margin:0 0 8px;font-weight:700">🍎 macOS</p>
        <code style="font-size:.85rem;display:block;margin-bottom:8px">bash setup/install-macos.sh</code>
        <p class=dim style="margin:0;font-size:.8rem">Homebrew + pip + GitHub releases</p>
      </div>
      <div style="background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px">
        <p style="margin:0 0 8px;font-weight:700">🐧 Linux</p>
        <code style="font-size:.85rem;display:block;margin-bottom:8px">bash setup/install-linux.sh</code>
        <p class=dim style="margin:0;font-size:.8rem">apt/dnf/pacman + pip + Ghidra</p>
      </div>
      <div style="background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px">
        <p style="margin:0 0 8px;font-weight:700">🪟 Windows</p>
        <code style="font-size:.85rem;display:block;margin-bottom:8px">powershell setup\install-windows.ps1</code>
        <p class=dim style="margin:0;font-size:.8rem">Chocolatey + pip + Sysinternals</p>
      </div>
    </div>
    <p class=dim>After install, run <code>malvex doctor</code> to verify.</p></div>

    <div class=card><h3>Workspace</h3><p><code>/opt/MalvexAI</code></p>
    <a class='btn' href='/'>Investigator</a> <a class='btn ghost' href='/api/doctor'>Tool health</a></div>"##;
    layout("settings", "/settings", body)
}

async fn create_schedule(State(st): State<Arc<AppState>>, Form(req): Form<ScheduleRequest>) -> Redirect {
    let path = st.root.join("data/schedules.json");
    let mut schedules: Vec<Schedule> = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    schedules.push(Schedule { name: req.name.chars().take(120).collect(), prompt: req.prompt.chars().take(4000).collect(), cron: req.cron.chars().take(100).collect(), runtime: req.runtime, models: req.models.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).take(12).collect() });
    if let Some(parent) = path.parent() { let _ = std::fs::create_dir_all(parent); }
    let _ = std::fs::write(path, serde_json::to_string_pretty(&schedules).unwrap_or_else(|_| "[]".into()));
    Redirect::to("/schedule")
}

#[derive(serde::Deserialize)]
struct TerminalRequest { command: String }

#[derive(serde::Serialize)]
struct TerminalResponse { ok: bool, output: String }

async fn api_doctor() -> Json<Vec<malvex_core::tool::ToolStatus>> {
    Json(malvex_doctor::scan(malvex_core::Platform::current()))
}

async fn terminal(State(st): State<Arc<AppState>>, Form(req): Form<TerminalRequest>) -> Json<TerminalResponse> {
    let command = req.command.trim().trim_start_matches('!').trim().to_string();
    if command.is_empty() || command.len() > 4000 {
        return Json(TerminalResponse { ok: false, output: "command must be between 1 and 4000 characters".into() });
    }
    let lower = command.to_ascii_lowercase();
    let blocked = ["rm -rf", "mkfs", "shutdown", "reboot", "sudo ", "dd if=", ":(){", "chmod -r 777"];
    if blocked.iter().any(|needle| lower.contains(needle)) {
        return Json(TerminalResponse { ok: false, output: "blocked by Malvex safety policy; run destructive administration outside the REPL".into() });
    }
    let output = tokio::time::timeout(Duration::from_secs(60), tokio::process::Command::new("/bin/sh")
        .arg("-lc").arg(&command).current_dir(&st.root).output()).await;
    match output {
        Ok(Ok(out)) => {
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            Json(TerminalResponse { ok: out.status.success(), output: text.chars().take(12000).collect() })
        }
        Ok(Err(e)) => Json(TerminalResponse { ok: false, output: format!("terminal spawn failed: {e}") }),
        Err(_) => Json(TerminalResponse { ok: false, output: "terminal command timed out after 60 seconds".into() }),
    }
}

#[derive(serde::Deserialize)]
struct PromptRequest { prompt: String, #[serde(default)] runtime: String, #[serde(default)] model: String }

#[derive(serde::Serialize)]
struct PromptResponse { ok: bool, reply: String, #[serde(skip_serializing_if = "Option::is_none")] tool_output: Option<String> }

async fn api_prompt(State(st): State<Arc<AppState>>, Json(req): Json<PromptRequest>) -> Json<PromptResponse> {
    let prompt = req.prompt.trim().to_string();
    if prompt.is_empty() || prompt.len() > 8000 {
        return Json(PromptResponse { ok: false, reply: "prompt must be 1-8000 chars".into(), tool_output: None });
    }
    let lower = prompt.to_ascii_lowercase();

    // Direct tool invocations: "run <tool> <target>" or "tool <name> <target>"
    if lower.starts_with("run ") || lower.starts_with("tool ") {
        let parts: Vec<&str> = prompt.splitn(3, ' ').collect();
        if parts.len() >= 3 {
            let tool_name = parts[1];
            let target = parts[2].trim_matches(['\'', '"', '`', '@']);
            if let Some(runner) = malvex_tools::find_runner(tool_name) {
                let path = std::path::Path::new(target);
                if path.is_file() {
                    let out = runner.run(path, &serde_json::Value::Null);
                    return Json(PromptResponse {
                        ok: out.success,
                        reply: format!("[{}] {}", tool_name, if out.success { "completed" } else { "failed" }),
                        tool_output: Some(serde_json::to_string_pretty(&out).unwrap_or_default()),
                    });
                }
                return Json(PromptResponse { ok: false, reply: format!("file not found: {target}"), tool_output: None });
            }
        }
    }

    // Doctor check
    if lower.contains("doctor") || lower.contains("health") || lower == "/doctor" {
        let tools = malvex_doctor::scan(malvex_core::Platform::current());
        let available = tools.iter().filter(|t| t.present).count();
        let list: Vec<String> = tools.iter().map(|t| format!("{} {}{}", if t.present {"✓"} else {"✗"}, t.name, if t.via_mcp.is_some() {" (MCP)"} else {""})).collect();
        return Json(PromptResponse { ok: true, reply: format!("Tool health: {}/{} available\n\n{}", available, tools.len(), list.join("\n")), tool_output: None });
    }

    // Hash a file
    if (lower.starts_with("hash ") || lower.starts_with("identify ")) && prompt.split_whitespace().count() <= 3 {
        let target = prompt.split_whitespace().last().unwrap_or("").trim_matches(['\'', '"', '`', '@']);
        let path = std::path::Path::new(target);
        if path.is_file() {
            if let Some(runner) = malvex_tools::find_runner("hashing") {
                let out = runner.run(path, &serde_json::Value::Null);
                return Json(PromptResponse { ok: out.success, reply: format!("File hashes for {target}"), tool_output: Some(serde_json::to_string_pretty(&out).unwrap_or_default()) });
            }
        }
    }

    // List available tools
    if lower.contains("list tool") || lower.contains("available tool") || lower == "tools" {
        let runners = malvex_tools::all_runners();
        let list: Vec<String> = runners.iter().map(|r| format!("{} {}", if r.is_available() {"✓"} else {"✗"}, r.name())).collect();
        return Json(PromptResponse { ok: true, reply: format!("{} tools registered:\n\n{}", runners.len(), list.join("\n")), tool_output: None });
    }

    // Pipeline dry-run on referenced file
    if lower.contains("analyze") || lower.contains("scan") || lower.contains("pipeline") {
        let file_ref = prompt.split_whitespace().find(|w| w.starts_with('@') || std::path::Path::new(w).is_file());
        if let Some(target) = file_ref {
            let clean = target.trim_start_matches('@').trim_matches(['\'', '"', '`']);
            let path = std::path::Path::new(clean);
            if path.is_file() {
                let bin = st.root.join("target/release/malvex");
                if bin.is_file() {
                    let output = tokio::time::timeout(Duration::from_secs(120), tokio::process::Command::new(&bin)
                        .args(["run", clean, "--dry-run"])
                        .current_dir(&st.root).output()).await;
                    match output {
                        Ok(Ok(out)) => {
                            let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
                            return Json(PromptResponse { ok: out.status.success(), reply: format!("Pipeline dry-run on {clean}"), tool_output: Some(text.chars().take(20000).collect()) });
                        }
                        _ => return Json(PromptResponse { ok: false, reply: "pipeline timed out or failed to spawn".into(), tool_output: None }),
                    }
                }
            }
        }
    }

    // Free-form: forward to runtime if available, otherwise echo as pending
    Json(PromptResponse {
        ok: true,
        reply: format!("Prompt received. In headless mode, pipe to your AI runtime:\n\n```\nmalvex prompt \"{}\"\n```\n\nOr attach a sample file for full pipeline analysis.", prompt.chars().take(200).collect::<String>()),
        tool_output: None,
    })
}

async fn index() -> Html<String> {
    Html(REPL_PAGE.to_string())
}

// Debugger + REPL layout inspired by REA: left panel shows binary info (sections, imports,
// strings, findings, IOCs), right panel is a REPL for extending analysis with prompts.
const REPL_PAGE: &str = r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Malvex · Investigator</title>
<style>
:root{--bg:#0a0c10;--panel:#0f1219;--panel2:#151a24;--line:#1e2a3a;--text:#e7ebf3;--muted:#6b7a90;--blue:#82a9ff;--cyan:#65d4df;--green:#3ddc84;--amber:#e8bd71;--red:#ed7777;--pink:#ff3f8e;--violet:#7c3aed;--gold:#ffcc33}
*{box-sizing:border-box;scrollbar-width:thin;scrollbar-color:#2a3548 transparent}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow:hidden}
.app{display:grid;grid-template-columns:1fr 1fr;grid-template-rows:42px 1fr;height:100vh;width:100vw}
.topbar{grid-column:1/-1;background:var(--panel);border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 16px;gap:14px}
.brand{font:700 15px/1 ui-sans-serif,system-ui,sans-serif;color:var(--text);display:flex;align-items:center;gap:6px;letter-spacing:-.02em}
.brand .dot{width:8px;height:8px;border-radius:50%;background:radial-gradient(circle at 35% 30%,#fff3c4,var(--gold) 60%)}
.topbar .sep{width:1px;height:20px;background:var(--line)}
.topbar a{color:var(--muted);text-decoration:none;font:500 12px/1 ui-sans-serif,system-ui,sans-serif}
.topbar a:hover{color:var(--text)}
.topbar .file-info{margin-left:auto;color:var(--muted);font-size:11px}
.debugger{border-right:1px solid var(--line);display:flex;flex-direction:column;min-width:0;overflow:hidden}
.debug-tabs{display:flex;gap:0;border-bottom:1px solid var(--line);background:var(--panel);flex-shrink:0}
.dtab{padding:8px 14px;font-size:11px;font-weight:600;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;background:none;border-top:0;border-left:0;border-right:0;font-family:inherit;white-space:nowrap}
.dtab:hover{color:var(--text)}
.dtab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.debug-content{flex:1;overflow:auto;padding:12px 16px}
.repl-side{display:flex;flex-direction:column;min-width:0;overflow:hidden}
.repl-header{padding:8px 16px;border-bottom:1px solid var(--line);background:var(--panel);font-size:11px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.08em;display:flex;align-items:center;gap:8px;flex-shrink:0}
.repl-header .live{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.thread{flex:1;overflow:auto;padding:14px 16px}
.msg{margin-bottom:14px}
.msg .who{font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px;font-weight:700}
.msg .who.user{color:var(--blue)}
.msg .who.malvex{color:var(--green)}
.msg .who.tool{color:var(--amber)}
.msg .body{color:var(--text);font-size:13px;line-height:1.55;white-space:pre-wrap;word-break:break-word}
.msg .body code{background:var(--panel2);padding:1px 5px;border-radius:3px;font-size:12px}
.composer{border-top:1px solid var(--line);background:var(--panel);padding:10px 14px;flex-shrink:0;display:flex;flex-direction:column;gap:8px}
.composer textarea{width:100%;min-height:64px;resize:none;border:1px solid var(--line);border-radius:8px;background:var(--panel2);color:var(--text);font:14px/1.5 inherit;padding:10px 12px;outline:none}
.composer textarea:focus{border-color:var(--blue);box-shadow:0 0 0 2px #82a9ff18}
.composer textarea::placeholder{color:#4a5568}
.compose-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.cbtn{border:1px solid var(--line);background:var(--panel2);color:var(--muted);border-radius:6px;padding:6px 10px;font:inherit;font-size:11px;cursor:pointer}
.cbtn:hover{color:var(--text);border-color:#536887}
.cbtn.primary{background:linear-gradient(135deg,var(--pink),var(--violet));border:0;color:#fff;font-weight:700;padding:6px 16px}
.cbtn.primary:hover{opacity:.9}
.file-label{color:var(--cyan);font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hidden{display:none}
/* Debugger content styling */
.info-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;margin-bottom:16px}
.info-card{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px}
.info-card .label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:4px}
.info-card .value{font-size:14px;font-weight:700;color:var(--text)}
.info-card .value.green{color:var(--green)}
.info-card .value.amber{color:var(--amber)}
.info-card .value.red{color:var(--red)}
.section-title{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:16px 0 8px;font-weight:700;display:flex;align-items:center;gap:8px}
.section-title:first-child{margin-top:0}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #151a24}
th{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.05em;font-weight:600;position:sticky;top:0;background:var(--bg)}
tr:hover td{background:var(--panel2)}
.badge{display:inline-block;padding:2px 7px;border-radius:99px;font-size:10px;font-weight:700}
.b-crit{background:#2a1020;color:#ff6fa8}
.b-high{background:#2a1e0d;color:var(--gold)}
.b-med{background:#252010;color:#d0c050}
.b-low{background:#0d2220;color:#5ed0c0}
.b-ok{background:#0f3320;color:var(--green)}
.hex{font-size:12px;line-height:1.7;color:var(--muted)}
.hex .offset{color:#4a5568}
.hex .byte{color:var(--text)}
.hex .ascii{color:var(--cyan);margin-left:12px}
.ioc-item{display:flex;gap:8px;padding:4px 0;font-size:12px;align-items:baseline}
.ioc-type{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;width:50px;flex-shrink:0}
.mitre-tag{display:inline-block;padding:3px 7px;border-radius:4px;font-size:11px;font-weight:600;background:#1a1030;color:var(--violet);border:1px solid #2d1f50;margin:2px}
.upload-zone{border:2px dashed var(--line);border-radius:12px;padding:40px 20px;text-align:center;cursor:pointer;transition:border-color .2s}
.upload-zone:hover{border-color:var(--pink)}
.upload-zone h2{font:700 18px/1.3 ui-sans-serif,system-ui,sans-serif;margin:0 0 6px;color:var(--text)}
.upload-zone p{color:var(--muted);font-size:12px;margin:4px 0}
.progress-track{height:4px;background:#1a2030;border-radius:99px;overflow:hidden;margin:6px 0}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--pink),var(--violet));border-radius:99px;transition:width .5s}
.stage-bar{display:flex;gap:4px;flex-wrap:wrap;margin:8px 0}
.stage{padding:3px 8px;border-radius:5px;font-size:11px;font-weight:600;border:1px solid var(--line);color:var(--muted)}
.stage.done{background:#0f3320;color:var(--green);border-color:#1e5a30}
.stage.running{background:#2a2010;color:var(--gold);border-color:#4a3a10;animation:pulse 1.6s ease-in-out infinite}
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--muted);text-align:center;gap:12px;padding:20px}
.empty-state h2{font:700 20px/1.3 ui-sans-serif,system-ui,sans-serif;color:var(--text);margin:0}
.empty-state p{margin:0;max-width:400px;font-size:13px}
@media(max-width:800px){.app{grid-template-columns:1fr;grid-template-rows:42px 40vh 1fr}.debugger{border-right:0;border-bottom:1px solid var(--line)}}
</style>
<div class="app">
<header class="topbar">
  <div class="brand"><span class="dot"></span>malvex</div>
  <span class="sep"></span>
  <a href="/sessions">sessions</a>
  <a href="/settings">settings</a>
  <span class="file-info" id="file-info">no binary loaded</span>
</header>

<section class="debugger">
  <div class="debug-tabs">
    <button class="dtab active" onclick="showDebugTab(this,'tab-overview')">Overview</button>
    <button class="dtab" onclick="showDebugTab(this,'tab-sections')">Sections</button>
    <button class="dtab" onclick="showDebugTab(this,'tab-imports')">Imports</button>
    <button class="dtab" onclick="showDebugTab(this,'tab-strings')">Strings</button>
    <button class="dtab" onclick="showDebugTab(this,'tab-findings')">Findings</button>
    <button class="dtab" onclick="showDebugTab(this,'tab-iocs')">IOCs</button>
    <button class="dtab" onclick="showDebugTab(this,'tab-mitre')">ATT&CK</button>
    <button class="dtab" onclick="showDebugTab(this,'tab-hex')">Hex</button>
  </div>

  <div class="debug-content" id="debug-content">
    <div id="tab-overview">
      <div class="empty-state" id="upload-area">
        <div class="upload-zone" id="drop-zone" onclick="document.getElementById('binary').click()">
          <h2>Drop a file to begin</h2>
          <p>PE · ELF · Mach-O · APK · script · installer · firmware</p>
          <p>PDF · DOC/DOCX · XLS/XLSX · PPT/PPTX · RTF · HWP · OLE · OneNote</p>
          <p style="margin-top:12px;color:var(--cyan)">or type a prompt in the REPL →</p>
        </div>
      </div>
      <div id="binary-overview" class="hidden">
        <div class="info-grid" id="info-grid"></div>
        <div class="section-title">Pipeline</div>
        <div class="progress-track"><div class="progress-fill" id="progress-fill" style="width:0%"></div></div>
        <div class="stage-bar" id="stage-bar"></div>
        <div class="section-title">Session log</div>
        <pre class="hex" id="session-log" style="max-height:300px;overflow:auto;color:#6b7a90">Waiting for analysis...</pre>
      </div>
    </div>
    <div id="tab-sections" class="hidden"><table><tr><th>Name</th><th>VAddr</th><th>Size</th><th>Entropy</th><th>Flags</th></tr><tr><td colspan="5" style="color:var(--muted);text-align:center;padding:40px">Load a binary to view sections</td></tr></table></div>
    <div id="tab-imports" class="hidden"><table><tr><th>Library</th><th>Function</th><th>Ordinal</th></tr><tr><td colspan="3" style="color:var(--muted);text-align:center;padding:40px">Load a binary to view imports</td></tr></table></div>
    <div id="tab-strings" class="hidden"><table><tr><th>Offset</th><th>String</th><th>Type</th></tr><tr><td colspan="3" style="color:var(--muted);text-align:center;padding:40px">Load a binary to view strings</td></tr></table></div>
    <div id="tab-findings" class="hidden"><table><tr><th>Sev</th><th>Finding</th><th>Verdict</th><th>Agent</th></tr><tr><td colspan="4" style="color:var(--muted);text-align:center;padding:40px">Run an analysis to see findings</td></tr></table></div>
    <div id="tab-iocs" class="hidden"><div style="color:var(--muted);text-align:center;padding:40px">Run an analysis to extract IOCs</div></div>
    <div id="tab-mitre" class="hidden"><div style="color:var(--muted);text-align:center;padding:40px">Run an analysis to map ATT&amp;CK techniques</div></div>
    <div id="tab-hex" class="hidden"><div style="color:var(--muted);text-align:center;padding:40px">Load a binary to view hex dump</div></div>
  </div>
</section>

<section class="repl-side">
  <div class="repl-header"><span class="live"></span> Investigation REPL</div>
  <div class="thread" id="thread">
    <div class="msg"><div class="who malvex">malvex</div><div class="body">Ready. Drop a file on the left panel or type a prompt below.

Commands: <code>!cmd</code> terminal, <code>/doctor</code> tool health, <code>/clear</code> reset.

Binary analysis:
  <code>Analyze malware.exe — full triage, static RE, IOCs</code>
  <code>Decompile main and explain the C2 protocol</code>
  <code>List imports and flag suspicious API calls</code>
  <code>What persistence mechanisms does this use?</code>
  <code>Scan with YARA and extract all IOCs</code>

Document analysis:
  <code>Extract and analyze VBA macros from invoice.docm</code>
  <code>Parse this PDF for embedded JavaScript or /Launch</code>
  <code>Check RTF for OLE objects and shellcode</code>

Headless (via Claude Code / OpenCode MCP):
  <code>Use Malvex to analyze suspicious.exe</code>
  <code>Use Malvex to extract macros from doc.xlsm</code>
  <code>Use Malvex to scan sample.bin with YARA</code>
  <code>Use Malvex to triage and map ATT&amp;CK for dropper.dll</code></div></div>
  </div>
  <form class="composer" id="composer" action="/upload" method="post" enctype="multipart/form-data">
    <input class="hidden" id="binary" type="file" name="binary" accept="*/*">
    <textarea id="prompt" name="custom_prompt" placeholder="Ask Malvex to analyze, decompile, scan, extract..."></textarea>
    <div class="compose-bar">
      <button class="cbtn" type="button" id="attach-btn">+ Attach</button>
      <span class="file-label" id="filename">no artifact</span>
      <select class="cbtn" name="runtime" title="AI runtime">
        <option value="claude">Claude</option>
        <option value="codex">Codex</option>
        <option value="custom">Custom</option>
        <option value="hermes">Hermes</option>
        <option value="ollama">Ollama</option>
      </select>
      <select class="cbtn" name="models" multiple title="Models (first=primary, rest=fallback)" style="min-width:140px;height:auto">
        <option value="claude-opus-5-5" selected>Opus 5.5</option>
        <option value="claude-opus-4-7">Opus 4.7</option>
        <option value="claude-opus-4-6">Opus 4.6</option>
        <option value="claude-sonnet-5-5">Sonnet 5.5</option>
        <option value="claude-fable-5-1">Fable 5.1</option>
        <option value="claude-haiku-4-5">Haiku 4.5</option>
        <option value="gpt-5">GPT-5</option>
        <option value="custom">Custom</option>
      </select>
      <select class="cbtn" name="parallel" title="Parallel agents">
        <option value="1">1 agent</option>
        <option value="2">2 agents</option>
        <option value="3" selected>3 agents</option>
        <option value="4">4 agents</option>
        <option value="5">5 agents</option>
      </select>
      <select class="cbtn" name="approval_mode" title="Approval mode">
        <option value="confirm-risky">Approve risky</option>
        <option value="auto">Auto</option>
        <option value="human">Human-in-loop</option>
      </select>
      <button class="cbtn" type="submit" name="mode" value="dry">Plan</button>
      <button class="cbtn primary" type="submit" name="mode" value="real" id="run">Run ↗</button>
    </div>
  </form>
</section>
</div>
<script>
function showDebugTab(btn,id){
  document.querySelectorAll('.debug-content>div').forEach(d=>d.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
  document.querySelectorAll('.dtab').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
}
function apiUrl(path){const l=location;return l.protocol+'//'+l.hostname+(l.port?':'+l.port:'')+path}
const input=document.getElementById('binary'),nameEl=document.getElementById('filename'),thread=document.getElementById('thread'),prompt=document.getElementById('prompt');
const chatKey='malvex-repl-history';let chat;try{chat=JSON.parse(localStorage.getItem(chatKey))||{messages:[]}}catch(e){chat={messages:[]}}
document.getElementById('attach-btn').addEventListener('click',()=>input.click());
input.addEventListener('change',()=>{const f=input.files[0];if(f){nameEl.textContent=f.name+' · '+(f.size/1024/1024).toFixed(1)+'MB';document.getElementById('file-info').textContent=f.name+' · '+(f.size/1024/1024).toFixed(1)+'MB'}});
document.getElementById('composer').addEventListener('submit',async e=>{
  if(prompt.value.trim().startsWith('!')){
    e.preventDefault();const command=prompt.value;
    addMsg('user',command);prompt.value='';
    const r=await fetch(apiUrl('/terminal'),{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({command})});
    const data=await r.json();addMsg('tool',data.output||'(no output)');return;
  }
  if(prompt.value.trim().startsWith('/')){
    e.preventDefault();const cmd=prompt.value.trim();prompt.value='';
    if(cmd==='/clear'){thread.innerHTML='';chat.messages=[];try{localStorage.setItem(chatKey,JSON.stringify(chat))}catch(e){}}
    else if(cmd==='/doctor'){addMsg('user',cmd);const r=await fetch(apiUrl('/api/doctor'));const data=await r.json();const ok=data.filter(x=>x.present).length;addMsg('malvex','Tool health: '+ok+'/'+data.length+' available\n\n'+data.map(x=>(x.present?'✓':'✗')+' '+x.name+(x.via_mcp?' (MCP)':'')).join('\n'))}
    return;
  }
  if(!input.files.length){
    e.preventDefault();
    if(!prompt.value.trim()){addMsg('malvex','Type a prompt or attach a file to begin.');return;}
    const text=prompt.value;addMsg('user',text);prompt.value='';
    try{
      const r=await fetch(apiUrl('/api/prompt'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({prompt:text,runtime:document.querySelector('[name=runtime]')?.value||'claude',model:document.querySelector('[name=model]')?.value||''})});
      const data=await r.json();
      addMsg('malvex',data.reply+(data.tool_output?'\n\n```\n'+data.tool_output+'\n```':''));
    }catch(err){addMsg('malvex','Error: '+err.message)}
    return;
  }
  addMsg('user',prompt.value);
});
function addMsg(who,text){
  const d=document.createElement('div');d.className='msg';
  d.innerHTML='<div class="who '+who+'">'+who+'</div><div class="body">'+text.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'})[c])+'</div>';
  thread.appendChild(d);thread.scrollTop=thread.scrollHeight;
  chat.messages.push({who,text});try{localStorage.setItem(chatKey,JSON.stringify(chat))}catch(e){}
}
if(chat.messages.length){thread.innerHTML='';chat.messages.forEach(m=>addMsg(m.who,m.text))}
prompt.addEventListener('keydown',e=>{if(e.key==='Enter'&&(e.metaKey||e.ctrlKey)){e.preventDefault();document.getElementById('run').click()}});
const activeSession=new URLSearchParams(location.search).get('session');
if(activeSession){
  document.getElementById('upload-area').classList.add('hidden');
  document.getElementById('binary-overview').classList.remove('hidden');
  const refreshLive=async()=>{const r=await fetch(apiUrl('/api/session/'+encodeURIComponent(activeSession)));if(!r.ok)return;const x=await r.json();
    document.getElementById('progress-fill').style.width=x.percent+'%';
    document.getElementById('session-log').textContent=(x.tail||[]).join('\n');
    if(!x.done)setTimeout(refreshLive,1500)};
  refreshLive();
}
const dropZone=document.getElementById('drop-zone');
if(dropZone){
['dragenter','dragover'].forEach(ev=>dropZone.addEventListener(ev,e=>{e.preventDefault();dropZone.style.borderColor='var(--pink)'}));
['dragleave','drop'].forEach(ev=>dropZone.addEventListener(ev,e=>{e.preventDefault();dropZone.style.borderColor=''}));
dropZone.addEventListener('drop',e=>{if(e.dataTransfer.files.length){input.files=e.dataTransfer.files;input.dispatchEvent(new Event('change'))}});
}
</script>
"#;

/// The upload page — a standalone hero, not the `layout()` chrome the rest of the app uses.
/// Structure borrows Google's homepage: near-empty viewport, one centered focal widget, two
/// unequal-weight actions under it (dry-run ≈ "Google Search", real run ≈ "I'm Feeling Lucky").
/// The widget itself — the dark card, the yellow ring, the pink-to-violet gradient action,
/// the rounded-pill dropzone — follows Malvex's visual language.
#[allow(dead_code)]
const INDEX_PAGE: &str = r#"<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Malvex</title>
<style>
:root{--bg:#f7f7f8;--ink:#1a1a1a;--dim:#6b6b6b;--card:#121212;--card2:#1b1b1b;
      --gold:#ffcc33;--pink:#ff3f8e;--violet:#7c3aed;--border:#2a2a2a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,sans-serif;
     min-height:100vh;display:flex;flex-direction:column}
header{display:flex;justify-content:flex-end;padding:1.25rem 1.75rem;gap:1.5rem}
header a{color:var(--dim);text-decoration:none;font-size:.9rem}
header a:hover{color:var(--ink)}
main{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
     padding:2rem 1.25rem 6rem;text-align:center}
.wordmark{font-size:2.6rem;font-weight:800;letter-spacing:-.02em;margin:0 0 .35rem;
          display:flex;align-items:center;gap:.6rem;justify-content:center}
.wordmark .dot{width:.55em;height:.55em;border-radius:50%;
    background:radial-gradient(circle at 35% 30%,#fff3c4,var(--gold) 60%);
    box-shadow:0 0 22px 4px rgba(255,204,51,.55)}
.tag{color:var(--dim);margin:0 0 2.25rem;font-size:.95rem;max-width:34rem}
.card{position:relative;width:min(92vw,560px);background:var(--card);border-radius:20px;
      padding:2.25rem 2rem 1.9rem;box-shadow:0 20px 50px -20px rgba(0,0,0,.35);
      border:1px solid #232323;isolation:isolate;overflow:hidden}
.card::before{content:"";position:absolute;inset:-40% -20% auto auto;width:70%;height:140%;
      background:radial-gradient(circle,rgba(255,204,51,.20),transparent 60%);z-index:-1}
.card::after{content:"";position:absolute;inset:auto auto -50% -20%;width:60%;height:120%;
      background:radial-gradient(circle,rgba(255,63,142,.16),transparent 60%);z-index:-1}
.drop{display:block;position:relative;border:1.5px dashed #3a3a3a;border-radius:16px;
      padding:2rem 1rem;cursor:pointer;transition:border-color .15s,background .15s;color:#e8e8e8}
.drop:hover,.drop.over{border-color:var(--gold);background:#181818}
.drop input{position:absolute;top:0;left:0;width:1px;height:1px;opacity:0;overflow:hidden}
.drop .icon{width:44px;height:44px;margin:0 auto .8rem;border-radius:50%;
      background:linear-gradient(135deg,var(--gold),var(--pink));
      display:flex;align-items:center;justify-content:center;font-size:1.3rem}
.drop .fname{display:block;margin-top:.6rem;font-size:.85rem;color:var(--gold);word-break:break-all}
.drop .hint{display:block;color:#8a8a8a;font-size:.82rem;margin-top:.25rem}
.parallel-row{display:flex;align-items:center;justify-content:center;gap:.6rem;
      margin-top:1.1rem;color:#b8b8b8;font-size:.85rem}
.parallel-row select{background:#1e1e1e;color:#e8e8e8;border:1px solid #333;border-radius:8px;
      padding:.3rem .6rem;font:inherit;font-size:.9rem;cursor:pointer}
.prompt-row{display:block;text-align:left;margin-top:1rem;color:#b8b8b8;font-size:.85rem}
.prompt-row textarea{width:100%;margin-top:.4rem;background:#1e1e1e;color:#e8e8e8;
      border:1px solid #333;border-radius:10px;padding:.6rem .7rem;font:inherit;font-size:.85rem;
      resize:vertical;box-sizing:border-box}
.prompt-row textarea:focus{outline:none;border-color:var(--gold)}
.actions{display:flex;gap:.75rem;justify-content:center;margin-top:1.5rem;flex-wrap:wrap}
button{font:inherit;font-size:.92rem;font-weight:600;border-radius:999px;padding:.65rem 1.5rem;
       cursor:pointer;transition:transform .1s,box-shadow .15s}
button:active{transform:scale(.97)}
.btn-ghost{background:#1e1e1e;color:#e8e8e8;border:1px solid #333}
.btn-ghost:hover{border-color:#555}
.btn-main{background:linear-gradient(135deg,var(--pink),var(--violet));color:#fff;border:0;
          box-shadow:0 8px 24px -8px rgba(255,63,142,.55)}
.btn-main:hover{box-shadow:0 10px 28px -6px rgba(255,63,142,.7)}
button:disabled{opacity:.45;cursor:not-allowed;box-shadow:none}
.note{color:var(--dim);font-size:.82rem;margin-top:1.5rem;max-width:26rem}
.note a{color:inherit}
footer{padding:1.25rem;text-align:center;color:#a5a5a5;font-size:.8rem}
</style>
<header><a href="/sessions">sessions</a></header>
<main>
  <h1 class=wordmark>Malvex<span class=dot></span></h1>
  <p class=tag>Envie uma amostra PE / ELF / Mach-O / script / installer / PDF / DOC / XLS / RTF — a plataforma faz triagem,
  RE, análise dinâmica, macro/VBA, inteligência e validação orientadas por evidência.</p>
  <form class=card action="/upload" method="post" enctype="multipart/form-data" id=f>
    <label class=drop id=drop for=file>
      <span class=icon>⇪</span>
      <span id=label>arraste o binário aqui, ou clique pra escolher</span>
      <span class=fname id=fname></span>
      <span class=hint>.exe · .dll · .sys · .elf · .so · .dylib · .app · script · installer · .pdf · .doc(x) · .xls(x) · .ppt(x) · .rtf · .ole · .onenote</span>
      <input id=file type=file name=binary required accept="*/*"/>
    </label>
    <label class=parallel-row for=parallel>
      Agentes paralelos por estágio
      <select id=parallel name=parallel>
        <option value=1 selected>1</option>
        <option value=2>2</option>
        <option value=3>3</option>
        <option value=4>4</option>
        <option value=5>5</option>
      </select>
    </label>
    <label class=prompt-row for=custom_prompt>
      Contexto / instruções pro analista (opcional)
      <textarea id=custom_prompt name=custom_prompt rows=3
        placeholder="ex: foca no mecanismo de update; assuma atacante com acesso físico ao device; esse build não tem CEF, ignora vetores de web frontend..."></textarea>
    </label>
    <label class=parallel-row>Runtime
      <select name=runtime>
        <option value=claude selected>Claude</option>
        <option value=codex>Codex</option>
        <option value=custom>Custom</option>
        <option value=hermes>Hermes</option>
        <option value=ollama>Ollama</option>
      </select>
    </label>
    <label class=parallel-row>Modelo
      <select name=models multiple style="height:80px">
        <option value=claude-opus-5-5 selected>Opus 5.5</option>
        <option value=claude-opus-4-7>Opus 4.7</option>
        <option value=claude-opus-4-6>Opus 4.6</option>
        <option value=claude-sonnet-5-5>Sonnet 5.5</option>
        <option value=claude-fable-5-1>Fable 5.1</option>
        <option value=claude-haiku-4-5>Haiku 4.5</option>
        <option value=gpt-5>GPT-5</option>
        <option value=custom>Custom</option>
      </select>
    </label>
    <div class=actions>
      <button class=btn-ghost type=submit name=mode value=dry id=btn-dry disabled>Planejar análise</button>
      <button class=btn-main type=submit name=mode value=real id=btn-real disabled>Iniciar análise</button>
    </div>
  </form>
  <p class=note>Dry-run só imprime o plano. Iniciar análise dispara a esteira de triage,
  análise estática, dinâmica, inteligência e validação em background — acompanhe em
  <a href="/sessions">sessions</a>. Máximo 5 agentes paralelos por estágio — acima disso o
  ganho cai e sobe o risco de saturar runtime, API ou tooling local.</p>
</main>
<footer>Malvex · AI Reverse Engineering Harness</footer>
<script>
const inp=document.getElementById('file'),drop=document.getElementById('drop'),
      label=document.getElementById('label'),fname=document.getElementById('fname'),
      bd=document.getElementById('btn-dry'),br=document.getElementById('btn-real');
function chosen(f){
  if(!f){return}
  label.textContent='arquivo selecionado:';
  fname.textContent=f.name;
  bd.disabled=false; br.disabled=false;
}
inp.addEventListener('change',()=>chosen(inp.files[0]));
['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over')}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over')}));
drop.addEventListener('drop',e=>{
  if(e.dataTransfer.files.length){inp.files=e.dataTransfer.files;chosen(inp.files[0])}
});
</script>
"#;

async fn upload(State(st): State<Arc<AppState>>, mut mp: Multipart) -> Response {
    let mut saved: Option<PathBuf> = None;
    let mut real = false;
    // Mirrors malvex-cli's own MAX_PARALLEL clamp (1-5) — enforced here too since a request
    // could reach this handler directly (curl, a stale form) bypassing the <select>'s options.
    let mut parallel: usize = 1;
    let mut custom_prompt: Option<String> = None;
    let mut approval_mode = "confirm-risky".to_string();
    let mut model = "claude-opus-4-6".to_string();
    let mut fallback_models: Vec<String> = Vec::new();
    let mut runtime = "claude".to_string();
    // Real malware-analysis targets (.app bundles, .msi installers, fat samples) routinely run tens to hundreds of
    // MB — well past axum's default 2MB body limit (raised on the /upload route below, but
    // this loop still has to report WHY nothing was saved instead of silently falling through
    // to a generic "no file received", which is what made an oversized/interrupted upload
    // indistinguishable from just forgetting to pick a file.
    let mut error: Option<String> = None;
    loop {
        match mp.next_field().await {
            Ok(Some(field)) => match field.name().unwrap_or("") {
                "mode" => {
                    real = field.text().await.map(|v| v == "real").unwrap_or(false);
                }
                "parallel" => {
                    parallel = field
                        .text()
                        .await
                        .ok()
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(1)
                        .clamp(1, 5);
                }
                "custom_prompt" => {
                    let text = field.text().await.unwrap_or_default();
                    if !text.trim().is_empty() {
                        custom_prompt = Some(text);
                    }
                }
                "model" => {
                    model = field.text().await.unwrap_or_default();
                    if model.trim().is_empty() { model = "claude-opus-4-6".to_string(); }
                }
                "runtime" => {
                    runtime = field.text().await.unwrap_or_default();
                    if runtime.trim().is_empty() { runtime = "claude".to_string(); }
                }
                "models" => {
                    let selected = field.text().await.unwrap_or_default();
                    if !selected.trim().is_empty() {
                        if model == "claude-opus-4-6" && fallback_models.is_empty() { model = selected; }
                        else { fallback_models.push(selected); }
                    }
                }
                "approval_mode" => {
                    let value = field.text().await.unwrap_or_default();
                    if matches!(value.as_str(), "auto" | "confirm-risky" | "human") { approval_mode = value; }
                }
                "binary" => {
                    let fname = field.file_name().unwrap_or("upload.bin").to_string();
                    let safe = fname.replace(['/', '\\', ' '], "_");
                    let dest = st.uploads.join(&safe);
                    match field.bytes().await {
                        Ok(bytes) if !bytes.is_empty() => match std::fs::write(&dest, &bytes) {
                            Ok(()) => saved = Some(dest),
                            Err(e) => error = Some(format!("failed to write upload to disk: {e}")),
                        },
                        Ok(_) => error = Some("received an empty file".to_string()),
                        Err(e) => {
                            error = Some(format!(
                                "upload stream failed while reading the file — likely too large \
                                 for the current body-size limit: {e}"
                            ))
                        }
                    }
                }
                _ => {}
            },
            Ok(None) => break,
            Err(e) => {
                error = Some(format!(
                    "multipart parsing failed — likely too large for the current body-size \
                     limit: {e}"
                ));
                break;
            }
        }
    }

    let saved = saved.or_else(|| {
        let prompt = custom_prompt.as_deref()?;
        let root = std::fs::canonicalize(&st.root).ok()?;
        prompt.split_whitespace().find_map(|token| {
            let raw = token.strip_prefix('@')?.trim_matches(['`', '"', '\'', ',', ')', ']']);
            if raw.is_empty() { return None; }
            let candidate = FsPath::new(raw);
            let candidate = if candidate.is_absolute() { candidate.to_path_buf() } else { root.join(candidate) };
            let canonical = std::fs::canonicalize(candidate).ok()?;
            if canonical.is_file() && canonical.starts_with(&root) { Some(canonical) } else { None }
        })
    });
    let Some(path) = saved else {
        let msg = error.unwrap_or_else(|| "no file field in the submitted form".to_string());
        let body = format!(
            "<div class=card><p>upload failed: {}</p></div><a class=btn href=\"/\">back</a>",
            html_escape(&msg)
        );
        return layout("upload", "/", &body).into_response();
    };

    let bin = st.root.join("target/release/malvex");
    if !bin.is_file() {
        let msg = format!(
            "<div class=card><p>malvex binary not found at <code>{}</code> — build it first: \
             <code>cargo build --release -p malvex-cli</code></p></div><a class=btn href=\"/\">back</a>",
            html_escape(&bin.display().to_string())
        );
        return layout("upload", "/", &msg).into_response();
    }

    if !real {
        // Dry-run: fast, synchronous, just prints the plan.
        let mut cmd = tokio::process::Command::new(&bin);
        cmd.arg("run").arg(&path).arg("--root").arg(&st.root).arg("--dry-run")
            .arg("--parallel").arg(parallel.to_string())
            .arg("--model").arg(&model).arg("--runtime").arg(&runtime)
            .arg("--fallback-models").arg(fallback_models.join(","))
            .arg("--approval-mode").arg(&approval_mode);
        if let Some(p) = &custom_prompt {
            cmd.arg("--prompt").arg(p);
        }
        let out = cmd.output().await;
        let body_text = match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(e) => format!("pipeline invocation failed: {e}"),
        };
        let body = format!(
            "<h2>Pipeline plan — {}</h2><p class=dim>mode: dry-run (plan only)</p>\
             <pre class=log>{}</pre><a class=\"btn ghost\" href=\"/\">&larr; analyze another</a>",
            html_escape(&path.file_name().unwrap_or_default().to_string_lossy()),
            html_escape(&body_text)
        );
        return layout("plan", "/", &body).into_response();
    }

    // Real mode: launch genuinely detached — the analysis can run for hours, well past any
    // single malvex-web process lifetime (a redeploy, a crash, a manual restart while iterating
    // on this very file all happened during testing and silently killed running sessions).
    //
    // The previous version piped the child's stdout/stderr back into THIS process and read
    // them here (to catch the "SESSION: <id>" startup banner, then a background task drained
    // the rest to keep the pipe from filling). That made the child's survival depend on this
    // process staying alive: a pipe's read end is a file descriptor owned by the reading
    // process, so the moment malvex-web exits, that fd closes, the child's next stdout write
    // gets EPIPE, and — since neither `malvex` nor the local runtime necessarily install a custom SIGPIPE handler —
    // the default disposition for SIGPIPE terminates the process outright. No crash log, no
    // stderr, no error status: the stage that was running (once seen stuck on `validate` for
    // hours with an AGENT_START and no AGENT_DONE) just stopped mid-write, orphaned.
    //
    // Fix: redirect stdout/stderr straight to real files on disk at spawn time. Those file
    // descriptors are owned by the KERNEL's open-file table, not by this process — once
    // spawned, the child is fully independent of whether malvex-web is even still running.
    // We recover the session id by polling the log file for the banner instead of blocking
    // on a pipe read; no in-process draining task is needed since the OS handles the rest.
    let log_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stdout_path = st.uploads.join(format!("pipeline-{log_id}.stdout.log"));
    let stderr_path = st.uploads.join(format!("pipeline-{log_id}.stderr.log"));
    let stdout_file = match std::fs::File::create(&stdout_path) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("<div class=card><p>failed to create pipeline log file: {}</p></div><a class=btn href=\"/\">back</a>", html_escape(&e.to_string()));
            return layout("upload", "/", &msg).into_response();
        }
    };
    let stderr_file = match std::fs::File::create(&stderr_path) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("<div class=card><p>failed to create pipeline log file: {}</p></div><a class=btn href=\"/\">back</a>", html_escape(&e.to_string()));
            return layout("upload", "/", &msg).into_response();
        }
    };

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.arg("run").arg(&path).arg("--root").arg(&st.root)
        .arg("--parallel").arg(parallel.to_string())
        .arg("--model").arg(&model).arg("--runtime").arg(&runtime)
        .arg("--fallback-models").arg(fallback_models.join(","))
        .arg("--approval-mode").arg(&approval_mode);
    if let Some(p) = &custom_prompt {
        cmd.arg("--prompt").arg(p);
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::from(stdout_file));
    cmd.stderr(std::process::Stdio::from(stderr_file));
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("<div class=card><p>failed to launch pipeline: {}</p></div><a class=btn href=\"/\">back</a>", html_escape(&e.to_string()));
            return layout("upload", "/", &msg).into_response();
        }
    };
    let pid = child.id();
    // Don't hold the Child (and its stdio handles) hostage to this request's lifetime — drop
    // it explicitly. The process itself is already independent (real file stdio); tokio's
    // runtime reaps it in the background regardless, as long as this server process is up
    // when it exits, which is the common case and not required for the child to keep running.
    drop(child);

    let mut sid: Option<String> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline {
        if let Ok(contents) = tokio::fs::read_to_string(&stdout_path).await {
            if let Some(line) = contents.lines().find_map(|l| l.strip_prefix("║  SESSION:")) {
                sid = Some(line.trim_end_matches('║').trim().to_string());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Now that the session dir exists (the orchestrator creates it and writes target.json
    // before printing the banner), drop a PID lock into it so session_detail() can tell a
    // genuinely still-running session apart from one that stopped/crashed — the whole reason
    // this feature exists is that a session sitting on a stage for hours looks IDENTICAL from
    // session.log alone (an AGENT_START with no AGENT_DONE) whether the process is grinding
    // away or has been dead for hours.
    if let (Some(pid), Some(id)) = (pid, &sid) {
        write_pid_lock(&st.root.join("sessions").join(id), pid);
    }

    match sid {
        Some(id) => Redirect::to(&format!("/?session={id}")).into_response(),
        None => {
            let msg = format!(
                "<div class=card><p>pipeline started but never printed its session banner \
                 within 30s — check the configured runtime, target path, and the launch logs at \
                 Raw output: <code>{}</code></p></div><a class=btn href=\"/\">back</a>",
                html_escape(&stdout_path.display().to_string())
            );
            layout("upload", "/", &msg).into_response()
        }
    }
}

// ── Sessions dashboard ───────────────────────────────────────────────────────

struct SessionRow {
    id: String,
    app: String,
    format: String,
    version: Option<String>,
    total: usize,
    confirmed: usize,
    crit_high: usize,
    done: bool,
}

/// Best-effort version of the analyzed artifact itself (not the Malvex tool), so the dashboard says which build was actually
/// audited. Tries every format this framework targets, cheapest/most-reliable first, all
/// straight off the target's own path (still on disk from when the session ran — target.json
/// never captured this, so it has to be re-derived, not just read back):
///   1. macOS .app bundle       → `plutil` reads Info.plist (CFBundleShortVersionString).
///   2. MSI installer           → `msiinfo export … Property` (ProductVersion row).
///   3. PE .exe/.dll            → self-parsed RT_VERSION resource (VS_FIXEDFILEINFO) — no
///      external tool assumed installed (exiftool/lief are both optional on the analyst
///      machine, and in practice miss plenty of real PEs); walking the resource directory
///      by hand works on anything with a version resource.
///   4. Filename fallback       → a trailing `-1.2.3` / `_v1.2.3` in the file name, for
///      whatever's left (raw ELF, stripped PE, anything else) — weaker signal, last resort.
fn artifact_version(target: &Target) -> Option<String> {
    if let Some(idx) = target.path.find(".app/") {
        if let Some(v) = macos_bundle_version(&target.path[..idx + 4]) {
            return Some(v);
        }
    }
    let lower = target.path.to_lowercase();
    if target.format == "installer" || lower.ends_with(".msi") {
        if let Some(v) = msi_version(&target.path) {
            return Some(v);
        }
    }
    if target.format == "pe" || lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys") {
        if let Ok(bytes) = std::fs::read(&target.path) {
            if let Some(v) = pe_version(&bytes) {
                return Some(v);
            }
        }
    }
    filename_version(&target.path)
}

fn macos_bundle_version(bundle: &str) -> Option<String> {
    let plist = format!("{bundle}/Contents/Info.plist");
    if !FsPath::new(&plist).is_file() {
        return None;
    }
    let out = std::process::Command::new("plutil")
        .args(["-convert", "json", "-o", "-", &plist])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let short = json.get("CFBundleShortVersionString").and_then(|v| v.as_str());
    let build = json.get("CFBundleVersion").and_then(|v| v.as_str());
    match (short, build) {
        (Some(s), Some(b)) if s != b => Some(format!("{s} ({b})")),
        (Some(s), _) => Some(s.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        _ => None,
    }
}

/// `msiinfo export <msi> Property` dumps the MSI Property table as tab-separated
/// `name\tvalue` lines — ProductVersion is a mandatory column in every valid MSI. Note this
/// can legitimately disagree with the filename's version (seen on real-world MSIs in this
/// corpus) — that mismatch is itself worth surfacing, not a reason to prefer the filename.
fn msi_version(path: &str) -> Option<String> {
    let out = std::process::Command::new("msiinfo").args(["export", path, "Property"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().find_map(|l| l.strip_prefix("ProductVersion\t")).map(|v| v.trim().to_string())
}

/// A trailing `-1.2.3`, `_v1.2.3.4`, or `.1.2.3` in the file name — the weakest signal, but
/// installers/artifacts in this framework's own corpus are routinely named exactly
/// this way, so it's a real fallback, not a theoretical one.
fn filename_version(path: &str) -> Option<String> {
    let name = FsPath::new(path).file_stem()?.to_str()?;
    let bytes = name.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] != b'-' && bytes[i] != b'_' && bytes[i] != b'.' {
            continue;
        }
        let rest = &name[i + 1..];
        let digits_and_dots: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let looks_versioned = digits_and_dots.contains('.')
            && digits_and_dots.chars().next().is_some_and(|c| c.is_ascii_digit())
            && digits_and_dots.chars().last().is_some_and(|c| c.is_ascii_digit());
        if looks_versioned {
            return Some(digits_and_dots);
        }
    }
    None
}

// ── PE VERSIONINFO parsing (self-contained — no exiftool/lief dependency assumed) ───────────
// Walks IMAGE_RESOURCE_DIRECTORY (type RT_VERSION=16 -> name -> language) to the raw
// VS_VERSIONINFO block, then reads the fixed-size VS_FIXEDFILEINFO struct that always follows
// the "VS_VERSION_INFO" key string — the numeric FileVersion, no StringFileInfo table needed.
// Version extraction is intentionally format-native and independent of vendor naming.

fn u16le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

struct PeSection {
    va: u32,
    vsize: u32,
    praw: u32,
}

fn rva_to_offset(sections: &[PeSection], rva: u32) -> Option<usize> {
    sections
        .iter()
        .find(|s| rva >= s.va && rva < s.va + s.vsize.max(1))
        .map(|s| (rva - s.va + s.praw) as usize)
}

/// First entry in an IMAGE_RESOURCE_DIRECTORY at `dir_off` matching numeric `id` (checked only
/// against the ID-type entries, i.e. past the named ones) — or, with `id: None`, simply the
/// first entry of either kind (used once we're past the RT_VERSION type level, where we just
/// want whichever name/language is there). Returns the raw OffsetToData/Directory field
/// (high bit set = points to another subdirectory, relative to the resource section root).
fn pe_first_entry(bytes: &[u8], dir_off: usize, id: Option<u32>) -> Option<u32> {
    let named = u16le(bytes, dir_off + 12)? as usize;
    let ided = u16le(bytes, dir_off + 14)? as usize;
    let entries_off = dir_off + 16;
    for i in 0..(named + ided) {
        let e = entries_off + i * 8;
        let name_or_id = u32le(bytes, e)?;
        let offset = u32le(bytes, e + 4)?;
        match id {
            Some(want) if i >= named && name_or_id == want => return Some(offset),
            None => return Some(offset),
            _ => {}
        }
    }
    None
}

fn pe_version(bytes: &[u8]) -> Option<String> {
    const RT_VERSION: u32 = 16;
    const VS_FFI_SIGNATURE: u32 = 0xFEEF_04BD;

    let e_lfanew = u32le(bytes, 0x3C)? as usize;
    if bytes.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let num_sections = u16le(bytes, coff + 2)? as usize;
    let size_opt_hdr = u16le(bytes, coff + 16)? as usize;
    let opt_off = coff + 20;
    let dd_off = match u16le(bytes, opt_off)? {
        0x10b => opt_off + 96,  // PE32
        0x20b => opt_off + 112, // PE32+
        _ => return None,
    };
    let res_rva = u32le(bytes, dd_off + 2 * 8)?; // data directory[2] = resource table
    if res_rva == 0 {
        return None;
    }

    let sec_table_off = opt_off + size_opt_hdr;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_table_off + i * 40;
        sections.push(PeSection {
            va: u32le(bytes, s + 12)?,
            vsize: u32le(bytes, s + 8)?,
            praw: u32le(bytes, s + 20)?,
        });
    }
    let res_base = rva_to_offset(&sections, res_rva)?;

    let type_entry = pe_first_entry(bytes, res_base, Some(RT_VERSION))?;
    let name_dir = res_base + (type_entry & 0x7fff_ffff) as usize;
    if type_entry & 0x8000_0000 == 0 {
        return None;
    }
    let name_entry = pe_first_entry(bytes, name_dir, None)?;
    if name_entry & 0x8000_0000 == 0 {
        return None;
    }
    let lang_dir = res_base + (name_entry & 0x7fff_ffff) as usize;
    let lang_entry = pe_first_entry(bytes, lang_dir, None)?;
    if lang_entry & 0x8000_0000 != 0 {
        return None; // expected a leaf (data entry) here, not another subdirectory
    }
    let data_entry_off = res_base + lang_entry as usize;
    let data_off = rva_to_offset(&sections, u32le(bytes, data_entry_off)?)?;

    // VS_VERSIONINFO: wLength(2) wValueLength(2) wType(2) L"VS_VERSION_INFO\0" (32 bytes),
    // padded to 4 bytes, then VS_FIXEDFILEINFO.
    let value_len = u16le(bytes, data_off + 2)?;
    if value_len == 0 {
        return None;
    }
    let fixed_off = (data_off + 6 + 32 + 3) & !3;
    if u32le(bytes, fixed_off)? != VS_FFI_SIGNATURE {
        return None;
    }
    let ms = u32le(bytes, fixed_off + 8)?;
    let ls = u32le(bytes, fixed_off + 12)?;
    Some(format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff))
}

fn list_sessions(root: &FsPath) -> Vec<SessionRow> {
    let dir = root.join("sessions");
    let mut rows = Vec::new();
    let Ok(rd) = std::fs::read_dir(&dir) else { return rows };
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let id = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let target: Option<Target> = std::fs::read_to_string(p.join("target.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        let findings: Vec<Finding> = std::fs::read_to_string(p.join("findings.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let confirmed = findings.iter().filter(|f| f.verdict == Verdict::Confirmed).count();
        let crit_high = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .count();
        let done = std::fs::read_to_string(p.join("session.log"))
            .map(|l| l.contains("SESSION_DONE"))
            .unwrap_or(false);
        rows.push(SessionRow {
            id,
            app: target.as_ref().map(|t| t.app.clone()).unwrap_or_else(|| "?".into()),
            format: target.as_ref().map(|t| t.format.clone()).unwrap_or_default(),
            version: target.as_ref().and_then(artifact_version),
            total: findings.len(),
            confirmed,
            crit_high,
            done,
        });
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.id.parse::<u64>().unwrap_or(0)));
    rows
}

async fn sessions_dashboard(State(st): State<Arc<AppState>>) -> Html<String> {
    let rows = list_sessions(&st.root);
    let table_rows: String = if rows.is_empty() {
        "<tr><td colspan=8 class=dim>no sessions yet — analyze a binary from the upload page</td></tr>".into()
    } else {
        rows.iter()
            .map(|r| {
                let status = if r.done {
                    "<span class=\"badge b-done\">done</span>"
                } else {
                    "<span class=\"badge b-run\">running</span>"
                };
                let version = r
                    .version
                    .as_deref()
                    .map(html_escape)
                    .unwrap_or_else(|| "<span class=dim>—</span>".into());
                format!(
                    "<tr><td><a href=\"/session/{id}\">{id}</a></td><td>{app}</td><td>{fmt}</td>\
                     <td>{version}</td><td>{total}</td><td>{confirmed}</td><td>{crit}</td><td>{status}</td></tr>",
                    id = html_escape(&r.id),
                    app = html_escape(&r.app),
                    fmt = html_escape(&r.format),
                    version = version,
                    total = r.total,
                    confirmed = r.confirmed,
                    crit = r.crit_high,
                    status = status,
                )
            })
            .collect()
    };
    let body = format!(
        "<h1>Sessions</h1>\
         <div class=card><div class=scroll><table>\
         <tr><th>id</th><th>app</th><th>format</th><th>version</th><th>findings</th><th>confirmed</th>\
         <th>crit/high</th><th>status</th></tr>{table_rows}</table></div></div>"
    );
    layout("sessions", "/sessions", &body)
}

// ── Session detail ───────────────────────────────────────────────────────────

const STAGES: &[&str] = &["triage", "static", "dynamic", "network", "intelligence", "validate"];

struct Progress {
    stage_status: Vec<(String, &'static str)>,
    session_done: bool,
    tail: Vec<String>,
}

fn kv(line: &str, key: &str) -> Option<String> {
    for part in line.split(" | ") {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            return Some(v.to_string());
        }
    }
    None
}

fn read_progress(session_dir: &FsPath) -> Progress {
    let log = std::fs::read_to_string(session_dir.join("session.log")).unwrap_or_default();
    let mut stage_status: Vec<(String, &'static str)> =
        STAGES.iter().map(|s| (s.to_string(), "pending")).collect();
    let mut session_done = false;

    for line in log.lines() {
        if line.contains("STAGE_START") {
            if let Some(name) = kv(line, "stage") {
                if let Some(e) = stage_status.iter_mut().find(|(n, _)| *n == name) {
                    e.1 = "running";
                }
            }
        }
        if line.contains("STAGE_DONE") || line.contains("STAGE_SKIP") {
            if let Some(name) = kv(line, "stage") {
                if let Some(e) = stage_status.iter_mut().find(|(n, _)| *n == name) {
                    e.1 = "done";
                }
            }
        }
        if line.contains("SESSION_DONE") {
            session_done = true;
        }
    }

    let tail: Vec<String> = {
        let mut v: Vec<String> = log.lines().rev().take(25).map(|s| s.to_string()).collect();
        v.reverse();
        v
    };

    Progress { stage_status, session_done, tail }
}

fn severity_badge(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "b-crit",
        Severity::High => "b-high",
        Severity::Medium => "b-med",
        Severity::Low => "b-low",
        Severity::Info => "b-info",
    }
}

fn verdict_badge(v: Verdict) -> &'static str {
    match v {
        Verdict::Confirmed => "b-confirmed",
        Verdict::Plausible => "b-plausible",
        Verdict::Refuted => "b-refuted",
        Verdict::Pending => "b-pending",
    }
}

/// Reject anything that isn't a plain session-id-shaped path component (numeric or `word`
/// chars only) before it ever touches the filesystem — session ids come straight from the
/// URL, so this is the only thing standing between a request and `../../etc/passwd`.
fn safe_component(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Re-invoke `malvex run --resume` for a session that isn't done and has no live PID lock.
/// Same fully-detached spawn as upload()'s real mode (file-backed stdio, PID lock written
/// immediately) — the only difference is the session dir and target path are already known,
/// so there's no banner to wait for; redirect straight back to the (now live again) detail
/// page.
async fn resume_session(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    if !safe_component(&id) {
        return (StatusCode::BAD_REQUEST, "invalid session id").into_response();
    }
    let session_dir = st.root.join("sessions").join(&id);
    if !session_dir.is_dir() {
        return (StatusCode::NOT_FOUND, "session not found").into_response();
    }
    let target: Option<Target> = std::fs::read_to_string(session_dir.join("target.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let Some(target) = target else {
        let msg = "<div class=card><p>no target.json in this session — nothing to resume.</p></div>\
                   <a class=btn href=\"/sessions\">back</a>";
        return layout("session", "/sessions", msg).into_response();
    };

    // Check the lock first; for a session that predates this feature (no lock file yet),
    // fall back to searching live processes by target path before trusting "nothing is
    // running" — see find_and_lock_live_pid's doc comment for why this fallback exists.
    let live = read_pid_lock(&session_dir)
        .filter(|&pid| process_alive(pid))
        .or_else(|| find_and_lock_live_pid(&session_dir, &target.path));
    if let Some(pid) = live {
        let msg = format!(
            "<div class=card><p>refusing to resume — PID {pid} is already running for this \
             session. Starting a second run against the same session dir would race on \
             findings.json/session.log.</p></div><a class=btn href=\"/session/{id}\">back</a>"
        );
        return layout("session", "/sessions", &msg).into_response();
    }

    let bin = st.root.join("target/release/malvex");
    let log_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stdout_path = session_dir.join(format!("resume-{log_id}.stdout.log"));
    let stderr_path = session_dir.join(format!("resume-{log_id}.stderr.log"));
    let (Ok(stdout_file), Ok(stderr_file)) =
        (std::fs::File::create(&stdout_path), std::fs::File::create(&stderr_path))
    else {
        let msg = "<div class=card><p>failed to create resume log files.</p></div>\
                   <a class=btn href=\"/sessions\">back</a>";
        return layout("session", "/sessions", msg).into_response();
    };

    let mut cmd = tokio::process::Command::new(&bin);
    cmd.arg("run").arg(&target.path).arg("--root").arg(&st.root).arg("--resume").arg(&session_dir);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::from(stdout_file));
    cmd.stderr(std::process::Stdio::from(stderr_file));
    match cmd.spawn() {
        Ok(child) => {
            if let Some(pid) = child.id() {
                write_pid_lock(&session_dir, pid);
            }
            drop(child);
            Redirect::to(&format!("/session/{id}")).into_response()
        }
        Err(e) => {
            let msg = format!(
                "<div class=card><p>failed to launch resume: {}</p></div><a class=btn href=\"/session/{id}\">back</a>",
                html_escape(&e.to_string())
            );
            layout("session", "/sessions", &msg).into_response()
        }
    }
}

#[derive(serde::Serialize)]
struct SessionProgressResponse {
    id: String,
    target: String,
    stage: String,
    percent: usize,
    done: bool,
    stages: Vec<(String, String)>,
    tail: Vec<String>,
}

async fn api_session(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    if !safe_component(&id) {
        return (StatusCode::BAD_REQUEST, "invalid session id").into_response();
    }
    let dir = st.root.join("sessions").join(&id);
    if !dir.is_dir() {
        return (StatusCode::NOT_FOUND, "session not found").into_response();
    }
    let progress = read_progress(&dir);
    let done_stages = progress.stage_status.iter().filter(|(_, s)| *s == "done").count();
    let percent = if progress.session_done { 100 } else {
        done_stages * 100 / progress.stage_status.len().max(1)
    };
    let stage = progress.stage_status.iter().find(|(_, s)| *s == "running")
        .map(|(n, _)| n.clone())
        .unwrap_or_else(|| if progress.session_done { "complete".into() } else { "queued".into() });
    let target = std::fs::read_to_string(dir.join("target.json")).ok()
        .and_then(|s| serde_json::from_str::<Target>(&s).ok())
        .map(|t| t.path).unwrap_or_default();
    Json(SessionProgressResponse {
        id, target, stage, percent, done: progress.session_done,
        stages: progress.stage_status.into_iter().map(|(n, s)| (n, s.to_string())).collect(),
        tail: progress.tail,
    }).into_response()
}

async fn session_detail(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    if !safe_component(&id) {
        return (StatusCode::BAD_REQUEST, "invalid session id").into_response();
    }
    let session_dir = st.root.join("sessions").join(&id);
    if !session_dir.is_dir() {
        return (StatusCode::NOT_FOUND, "session not found").into_response();
    }

    let target: Option<Target> = std::fs::read_to_string(session_dir.join("target.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let mut findings: Vec<Finding> = std::fs::read_to_string(session_dir.join("findings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let progress = read_progress(&session_dir);

    let target_block = match &target {
        Some(t) => format!(
            "<p><b>{}</b>{} — {} / {} {}</p>\
             <p class=dim>{}</p>",
            html_escape(&t.app),
            artifact_version(t).map(|v| format!(" <span class=dim>v{}</span>", html_escape(&v))).unwrap_or_default(),
            html_escape(&t.format),
            html_escape(&t.arch),
            if t.shielding.is_empty() { String::new() } else { format!("· shielding: {}", html_escape(&t.shielding.join(", "))) },
            html_escape(&t.path),
        ),
        None => "<p class=dim>target.json not found yet</p>".into(),
    };

    let stage_bar: String = progress
        .stage_status
        .iter()
        .map(|(name, status)| format!("<span class=\"stage {status}\">{name}</span>"))
        .collect();
    let done_stages = progress.stage_status.iter().filter(|(_, status)| *status == "done").count();
    let active_stage = progress.stage_status.iter().find(|(_, status)| *status == "running").map(|(name, _)| name.as_str()).unwrap_or("queued");
    let percent = if progress.session_done { 100 } else { (done_stages * 100) / progress.stage_status.len().max(1) };
    let progress_block = format!("<div class=progress-head><span>Pipeline progress · {active_stage}</span><b>{percent}%</b></div><div class=progress-track><div class=progress-fill style=\"width:{percent}%\"></div></div>");

    // Ground "running" in an actual OS-level liveness check (PID lock + `kill -0`), not just
    // "session.log doesn't say SESSION_DONE yet" — that guess is exactly what made a session
    // sitting on a stage for hours look identical whether the process was genuinely still
    // working or had been dead for hours with nobody able to tell from the browser.
    let live_pid = read_pid_lock(&session_dir)
        .filter(|&pid| process_alive(pid))
        .or_else(|| target.as_ref().and_then(|t| find_and_lock_live_pid(&session_dir, &t.path)));
    let status_line = if progress.session_done {
        "<span class=\"badge b-done\">session done</span>".to_string()
    } else if let Some(pid) = live_pid {
        format!("<span class=\"badge b-run\">running (PID {pid}) — page refreshes every 5s</span>")
    } else {
        format!(
            "<span class=\"badge b-refuted\">not running — no live process for this session</span> \
             <form method=post action=\"/session/{id}/resume\" style=\"display:inline\">\
             <button type=submit class=btn style=\"border:0;cursor:pointer;margin-left:.5rem\">Resume analysis</button>\
             </form>"
        )
    };

    let downloads: String = [
        ("findings.json", "Findings JSON"),
        ("summary.md", "Summary"),
        ("attack-graph.md", "Capability graph"),
        ("attack-graph.json", "Capability graph JSON"),
        ("target.json", "Target metadata"),
        ("session.log", "Raw session log"),
        ("analysis-report.md", "Analysis Markdown"),
        ("analysis-report.html", "Analysis HTML"),
    ]
    .iter()
    .filter(|(fname, _)| session_dir.join(fname).is_file())
    .map(|(fname, label)| {
        let edit = if EDITABLE_FILES.contains(fname) {
            format!(" <a class=\"btn ghost\" href=\"/session/{id}/edit/{fname}\">Edit</a>")
        } else { String::new() };
        format!("<a class=\"btn ghost\" download href=\"/session/{id}/file/{fname}\">{label}</a>{edit}")
    })
    .collect();
    let downloads = if downloads.is_empty() {
        "<p class=dim>no artifacts yet</p>".to_string()
    } else {
        downloads
    };

    // IOC summary panel — extract from all findings' evidence text
    let all_evidence_text: String = findings.iter()
        .flat_map(|f| f.evidence.iter())
        .map(|e| format!("{} {}", e.detail, e.locus.as_deref().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\n");
    let iocs = extract_iocs(&all_evidence_text);
    let ioc_panel = if iocs.is_empty() {
        String::new()
    } else {
        let ioc_rows: String = iocs.iter().map(|(kind, value)| {
            format!("<tr><td>{}</td><td class=wrap-cell><code>{}</code></td></tr>",
                html_escape(kind), html_escape(value))
        }).collect();
        format!(
            "<div class=card><h3>IOC Summary ({n})</h3><div class=scroll><table>\
             <tr><th>type</th><th>value</th></tr>{ioc_rows}</table></div></div>",
            n = iocs.len()
        )
    };

    let findings_rows: String = if findings.is_empty() {
        "<tr><td colspan=6 class=dim>no findings parsed yet</td></tr>".into()
    } else {
        findings
            .iter()
            .map(|f| {
                format!(
                    "<tr><td class=wrap-cell>{title}</td><td>{vc} {mitre}</td>\
                     <td><span class=\"badge {sb}\">{sev:?}</span></td>\
                     <td><span class=\"badge {vb}\">{verdict:?}</span></td><td>{evidence}</td></tr>",
                    title = html_escape(&f.title),
                    vc = html_escape(&f.vuln_class),
                    mitre = extract_mitre_techniques(&f.vuln_class).iter()
                        .map(|t| format!("<span class=\"badge b-info\">{}</span>", html_escape(t)))
                        .collect::<String>(),
                    sb = severity_badge(f.severity),
                    sev = f.severity,
                    vb = verdict_badge(f.verdict),
                    verdict = f.verdict,
                    evidence = f.evidence.len(),
                )
            })
            .collect()
    };

    let log_tail = html_escape(&progress.tail.join("\n"));

    let refresh = if progress.session_done {
        String::new()
    } else {
        "<meta http-equiv=refresh content=5>".to_string()
    };

    let body = format!(
        "{refresh}\
         <h1>Session {id}</h1>\
         <div class=card>{target_block}{status_line}{progress_block}\
         <div class=stagebar>{stage_bar}</div></div>\
         <div class=card><h3>Downloads</h3>{downloads}</div>\
         {ioc_panel}\
         <div class=card><h3>Findings ({n})</h3><div class=scroll><table>\
         <tr><th>title</th><th>domain</th><th>severity</th><th>verdict</th><th>evidence</th></tr>\
         {findings_rows}</table></div></div>\
         <div class=card><h3>Log tail</h3><pre class=log>{log_tail}</pre></div>",
        n = findings.len(),
    );
    layout(&format!("session {id}"), "/sessions", &body).into_response()
}

// ── Threat Intel (aggregated from sessions) ─────────────────────────────────

async fn threatintel_page(State(st): State<Arc<AppState>>) -> Html<String> {
    let sessions_dir = st.root.join("sessions");
    let mut technique_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut family_hypotheses: Vec<String> = Vec::new();
    let mut all_iocs: Vec<(String, String)> = Vec::new();
    let mut session_count = 0usize;

    if let Ok(rd) = std::fs::read_dir(&sessions_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_dir() { continue; }
            let findings: Vec<Finding> = std::fs::read_to_string(p.join("findings.json"))
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            if findings.is_empty() { continue; }
            session_count += 1;

            for f in &findings {
                for tech in extract_mitre_techniques(&f.vuln_class) {
                    *technique_counts.entry(tech).or_insert(0) += 1;
                }
                let vc_lower = f.vuln_class.to_lowercase();
                for keyword in ["trojan", "ransomware", "backdoor", "rootkit", "worm", "spyware",
                                "adware", "dropper", "loader", "stealer", "rat", "botnet", "miner",
                                "keylogger", "infostealer", "banker"] {
                    if vc_lower.contains(keyword) && !family_hypotheses.contains(&keyword.to_string()) {
                        family_hypotheses.push(keyword.to_string());
                    }
                }
                let evidence_text: String = f.evidence.iter()
                    .map(|e| format!("{} {}", e.detail, e.locus.as_deref().unwrap_or("")))
                    .collect::<Vec<_>>().join("\n");
                all_iocs.extend(extract_iocs(&evidence_text));
            }
        }
    }
    all_iocs.sort();
    all_iocs.dedup();

    let mut sorted_techniques: Vec<_> = technique_counts.into_iter().collect();
    sorted_techniques.sort_by(|a, b| b.1.cmp(&a.1));
    let technique_rows: String = if sorted_techniques.is_empty() {
        "<tr><td colspan=2 class=dim>no ATT&amp;CK techniques found yet</td></tr>".into()
    } else {
        sorted_techniques.iter().map(|(tech, count)| {
            format!("<tr><td><a href=\"https://attack.mitre.org/techniques/{t}/\" target=_blank>{t}</a></td><td>{c}</td></tr>",
                t = html_escape(tech), c = count)
        }).collect()
    };

    let family_block = if family_hypotheses.is_empty() {
        "<p class=dim>No malware family hypotheses extracted yet.</p>".to_string()
    } else {
        family_hypotheses.iter()
            .map(|f| format!("<span class=\"badge b-high\">{}</span> ", html_escape(f)))
            .collect()
    };

    let ioc_rows: String = if all_iocs.is_empty() {
        "<tr><td colspan=2 class=dim>no IOCs extracted yet</td></tr>".into()
    } else {
        all_iocs.iter().take(200).map(|(kind, value)| {
            format!("<tr><td>{}</td><td class=wrap-cell><code>{}</code></td></tr>",
                html_escape(kind), html_escape(value))
        }).collect()
    };

    let body = format!(
        "<h1>IOC Feed</h1>\
         <p class=dim>Aggregated indicators of compromise from {session_count} session(s).</p>\
         <div class=card><h3>Malware Family Hypotheses</h3>{family_block}</div>\
         <div class=card><h3>MITRE ATT&amp;CK Techniques</h3><div class=scroll><table>\
         <tr><th>technique</th><th>count</th></tr>{technique_rows}</table></div></div>\
         <div class=card><h3>IOC Summary ({ioc_count})</h3><div class=scroll><table>\
         <tr><th>type</th><th>value</th></tr>{ioc_rows}</table></div></div>",
        ioc_count = all_iocs.len(),
    );
    layout("ioc feed", "/threatintel", &body)
}

// ── Event Scan (YARA/IOC scanning) ──────────────────────────────────────────

#[derive(serde::Deserialize)]
struct EventScanRequest { file_path: String }

async fn eventscan_page() -> Html<String> {
    let yara_available = std::process::Command::new("yara")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let yara_status = if yara_available {
        "<span class=\"badge b-confirmed\">YARA available</span>"
    } else {
        "<span class=\"badge b-refuted\">YARA not found</span> <span class=dim>install YARA to enable rule scanning</span>"
    };
    let body = format!(
        "<h1>YARA Scan</h1>\
         <div class=card><p>Scan a file against YARA rules. Provide a file path on the server \
         filesystem.</p>\
         <p>{yara_status}</p>\
         <form method=post action=\"/eventscan\">\
         <p><input name=file_path placeholder=\"/path/to/sample.exe\" required \
         style=\"width:100%;max-width:500px;padding:.55rem .9rem;border-radius:8px;border:1px solid var(--border);\
         background:var(--card);color:var(--text);font:inherit\"></p>\
         <button class=btn type=submit>Scan</button></form></div>\
         <div id=results></div>"
    );
    layout("yara scan", "/eventscan", &body)
}

async fn eventscan_run(State(st): State<Arc<AppState>>, Form(req): Form<EventScanRequest>) -> Html<String> {
    let file_path = req.file_path.trim().to_string();
    if file_path.is_empty() || !FsPath::new(&file_path).exists() {
        let body = "<div class=card><p>File not found at the specified path.</p></div>\
                    <a class=btn href=\"/eventscan\">back</a>";
        return layout("yara scan", "/eventscan", body);
    }

    let yara_ok = std::process::Command::new("yara")
        .arg("--version").output()
        .map(|o| o.status.success()).unwrap_or(false);

    let mut results = String::new();

    if yara_ok {
        let rules_dirs = [
            st.root.join("data/yara"),
            st.root.join("rules"),
            st.root.join("yara-rules"),
        ];
        let mut rule_files: Vec<PathBuf> = Vec::new();
        for dir in &rules_dirs {
            if dir.is_dir() {
                if let Ok(rd) = std::fs::read_dir(dir) {
                    for entry in rd.flatten() {
                        let p = entry.path();
                        if p.extension().and_then(|e| e.to_str()) == Some("yar")
                            || p.extension().and_then(|e| e.to_str()) == Some("yara") {
                            rule_files.push(p);
                        }
                    }
                }
            }
        }

        if rule_files.is_empty() {
            results.push_str("<div class=card><p class=dim>No YARA rule files (.yar/.yara) found in data/yara/, rules/, or yara-rules/.</p></div>");
        } else {
            let mut rows = String::new();
            let mut match_count = 0usize;
            for rule_file in &rule_files {
                let output = std::process::Command::new("yara")
                    .arg(rule_file)
                    .arg(&file_path)
                    .output();
                match output {
                    Ok(out) if out.status.success() => {
                        let text = String::from_utf8_lossy(&out.stdout);
                        for line in text.lines() {
                            if !line.trim().is_empty() {
                                match_count += 1;
                                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                                let rule_name = parts.first().unwrap_or(&"?");
                                let matched_file = parts.get(1).unwrap_or(&"");
                                rows.push_str(&format!(
                                    "<tr><td>{}</td><td>{}</td><td class=wrap-cell>{}</td></tr>",
                                    html_escape(rule_name),
                                    html_escape(&rule_file.display().to_string()),
                                    html_escape(matched_file),
                                ));
                            }
                        }
                    }
                    Ok(out) => {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        if !stderr.trim().is_empty() {
                            rows.push_str(&format!(
                                "<tr><td class=dim colspan=3>rule file {} error: {}</td></tr>",
                                html_escape(&rule_file.display().to_string()),
                                html_escape(stderr.trim()),
                            ));
                        }
                    }
                    Err(e) => {
                        rows.push_str(&format!(
                            "<tr><td class=dim colspan=3>failed to run YARA: {}</td></tr>",
                            html_escape(&e.to_string()),
                        ));
                    }
                }
            }
            results.push_str(&format!(
                "<div class=card><h3>YARA Results ({match_count} match(es) from {n} rule file(s))</h3>\
                 <div class=scroll><table><tr><th>rule</th><th>rule file</th><th>matched file</th></tr>\
                 {rows}</table></div></div>",
                n = rule_files.len(),
            ));
        }
    } else {
        results.push_str("<div class=card><p><span class=\"badge b-refuted\">YARA not found</span> \
            — install YARA to enable scanning. On macOS: <code>brew install yara</code>.</p></div>");
    }

    let body = format!(
        "<h1>Event Scan Results</h1>\
         <div class=card><p>Scanned: <code>{}</code></p></div>\
         {results}\
         <a class=btn href=\"/eventscan\">back</a>",
        html_escape(&file_path),
    );
    layout("yara scan", "/eventscan", &body)
}

// ── Intel Lookup ────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct LookupRequest { query: String }

async fn lookup_page() -> Html<String> {
    let body = "<h1>Intel Lookup</h1>\
         <div class=card><p>Research a hash, IP, domain, MITRE technique ID, or malware family name. \
         Launches a quick LLM query via the malvex binary for contextual research.</p>\
         <form method=post action=\"/lookup\">\
         <p><input name=query placeholder=\"e.g. T1055, 192.168.1.100, Grandoreiro, SHA256...\" required \
         style=\"width:100%;max-width:500px;padding:.55rem .9rem;border-radius:8px;border:1px solid var(--border);\
         background:var(--card);color:var(--text);font:inherit\"></p>\
         <button class=btn type=submit>Research</button></form></div>";
    layout("intel lookup", "/lookup", body)
}

async fn lookup_run(State(st): State<Arc<AppState>>, Form(req): Form<LookupRequest>) -> Html<String> {
    let query = req.query.trim().to_string();
    if query.is_empty() || query.len() > 500 {
        let body = "<div class=card><p>Query must be between 1 and 500 characters.</p></div>\
                    <a class=btn href=\"/lookup\">back</a>";
        return layout("intel lookup", "/lookup", body);
    }

    let bin = st.root.join("target/release/malvex");
    let result = if bin.is_file() {
        let output = tokio::time::timeout(
            Duration::from_secs(120),
            tokio::process::Command::new(&bin)
                .arg("lookup")
                .arg(&query)
                .arg("--root")
                .arg(&st.root)
                .output()
        ).await;
        match output {
            Ok(Ok(out)) => {
                let mut text = String::from_utf8_lossy(&out.stdout).to_string();
                if !out.stderr.is_empty() {
                    text.push_str("\n--- stderr ---\n");
                    text.push_str(&String::from_utf8_lossy(&out.stderr));
                }
                if text.trim().is_empty() {
                    "No output from malvex lookup. The 'lookup' subcommand may not be implemented yet.".to_string()
                } else {
                    text
                }
            }
            Ok(Err(e)) => format!("Failed to run malvex lookup: {e}"),
            Err(_) => "Lookup timed out after 120 seconds.".to_string(),
        }
    } else {
        "malvex binary not found — build it first: cargo build --release -p malvex-cli".to_string()
    };

    let body = format!(
        "<h1>Intel Lookup</h1>\
         <div class=card><h3>Query: {}</h3><pre class=log>{}</pre></div>\
         <a class=btn href=\"/lookup\">new lookup</a>",
        html_escape(&query),
        html_escape(&result),
    );
    layout("intel lookup", "/lookup", &body)
}

// ── Proc DB (malicious process imphash database) ────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct ProcDbEntry {
    app_name: String,
    family: String,
    #[serde(default)]
    executable_names: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    imphashes: Vec<String>,
    #[serde(default)]
    sha256: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ProcDbAddRequest {
    app_name: String,
    family: String,
    #[serde(default)]
    executable_names: String,
    #[serde(default)]
    tags: String,
    #[serde(default)]
    imphashes: String,
    #[serde(default)]
    sha256: String,
}

#[derive(serde::Deserialize)]
struct ProcDbSearchRequest {
    #[serde(default)]
    q: String,
}

async fn procdb_page(State(st): State<Arc<AppState>>, axum::extract::Query(search): axum::extract::Query<ProcDbSearchRequest>) -> Html<String> {
    let db_path = st.root.join("data/procdb.json");
    let entries: Vec<ProcDbEntry> = std::fs::read_to_string(&db_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let q = search.q.trim().to_lowercase();
    let filtered: Vec<&ProcDbEntry> = if q.is_empty() {
        entries.iter().collect()
    } else {
        entries.iter().filter(|e| {
            e.app_name.to_lowercase().contains(&q)
                || e.family.to_lowercase().contains(&q)
                || e.executable_names.iter().any(|n| n.to_lowercase().contains(&q))
                || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
                || e.imphashes.iter().any(|h| h.to_lowercase().contains(&q))
        }).collect()
    };

    let rows: String = if filtered.is_empty() {
        "<tr><td colspan=6 class=dim>no entries yet — add one below or place data/procdb.json manually</td></tr>".into()
    } else {
        filtered.iter().map(|e| format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&e.app_name),
            html_escape(&e.family),
            html_escape(&e.executable_names.join(", ")),
            html_escape(&e.tags.join(", ")),
            e.imphashes.len(),
            e.sha256.len(),
        )).collect()
    };

    let body = format!(
        "<h1>Sample DB</h1>\
         <p class=dim>Malicious process imphash database. {total} entries total.</p>\
         <div class=card><h3>Search / Filter</h3>\
         <form method=get action=\"/procdb\">\
         <input name=q value=\"{q_esc}\" placeholder=\"filter by name, family, tag, hash...\" \
         style=\"width:100%;max-width:400px;padding:.55rem .9rem;border-radius:8px;border:1px solid var(--border);\
         background:var(--card);color:var(--text);font:inherit\"> \
         <button class=btn type=submit>Filter</button>\
         {clear}</form></div>\
         <div class=card><div class=scroll><table>\
         <tr><th>app name</th><th>family</th><th>executables</th><th>tags</th><th>imphashes</th><th>sha256</th></tr>\
         {rows}</table></div></div>\
         <div class=card><h3>Add Entry</h3>\
         <form method=post action=\"/procdb\">\
         <p><input name=app_name placeholder=\"App name (e.g. Grandoreiro)\" required \
         style=\"padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"> \
         <input name=family placeholder=\"Family (e.g. Banking Trojan)\" required \
         style=\"padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"></p>\
         <p><input name=executable_names placeholder=\"Executable names (comma-separated)\" \
         style=\"width:100%;max-width:500px;padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"></p>\
         <p><input name=tags placeholder=\"Tags (comma-separated)\" \
         style=\"width:100%;max-width:500px;padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"></p>\
         <p><input name=imphashes placeholder=\"Imphashes (comma-separated)\" \
         style=\"width:100%;max-width:500px;padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"></p>\
         <p><input name=sha256 placeholder=\"SHA256 hashes (comma-separated)\" \
         style=\"width:100%;max-width:500px;padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"></p>\
         <button class=btn type=submit>Add entry</button></form></div>",
        total = entries.len(),
        q_esc = html_escape(&search.q),
        clear = if q.is_empty() { String::new() } else { " <a class=\"btn ghost\" href=\"/procdb\">clear</a>".into() },
    );
    layout("sample db", "/procdb", &body)
}

async fn procdb_add(State(st): State<Arc<AppState>>, Form(req): Form<ProcDbAddRequest>) -> Redirect {
    let db_path = st.root.join("data/procdb.json");
    let _ = std::fs::create_dir_all(st.root.join("data"));
    let mut entries: Vec<ProcDbEntry> = std::fs::read_to_string(&db_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let parse_csv = |s: &str| -> Vec<String> {
        s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
    };

    if let Some(existing) = entries.iter_mut().find(|e| e.app_name.eq_ignore_ascii_case(&req.app_name)) {
        for name in parse_csv(&req.executable_names) {
            if !existing.executable_names.contains(&name) { existing.executable_names.push(name); }
        }
        for tag in parse_csv(&req.tags) {
            if !existing.tags.contains(&tag) { existing.tags.push(tag); }
        }
        for hash in parse_csv(&req.imphashes) {
            if !existing.imphashes.contains(&hash) { existing.imphashes.push(hash); }
        }
        for hash in parse_csv(&req.sha256) {
            if !existing.sha256.contains(&hash) { existing.sha256.push(hash); }
        }
    } else {
        entries.push(ProcDbEntry {
            app_name: req.app_name.trim().to_string(),
            family: req.family.trim().to_string(),
            executable_names: parse_csv(&req.executable_names),
            tags: parse_csv(&req.tags),
            imphashes: parse_csv(&req.imphashes),
            sha256: parse_csv(&req.sha256),
        });
    }

    let _ = std::fs::write(&db_path, serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".into()));
    Redirect::to("/procdb")
}

// ── Remote Box (sandbox connector config) ───────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct RemoteBoxConfig {
    name: String,
    url: String,
    api_key: String,
    sandbox_type: String,
}

#[derive(serde::Deserialize)]
struct RemoteBoxAddRequest {
    name: String,
    url: String,
    api_key: String,
    sandbox_type: String,
}

async fn remotebox_page(State(st): State<Arc<AppState>>) -> Html<String> {
    let config_path = st.root.join("data/remotebox.json");
    let configs: Vec<RemoteBoxConfig> = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let rows: String = if configs.is_empty() {
        "<tr><td colspan=4 class=dim>no sandbox endpoints configured yet</td></tr>".into()
    } else {
        configs.iter().map(|c| format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td>\
             <td><code>{}</code></td></tr>",
            html_escape(&c.name),
            html_escape(&c.url),
            html_escape(&c.sandbox_type),
            if c.api_key.len() > 8 {
                format!("{}...{}", &c.api_key[..4], &c.api_key[c.api_key.len()-4..])
            } else {
                "****".to_string()
            },
        )).collect()
    };

    let body = format!(
        "<h1>Sandbox</h1>\
         <p class=dim>Configure remote sandbox endpoints for dynamic analysis.</p>\
         <div class=card><div class=scroll><table>\
         <tr><th>name</th><th>url</th><th>type</th><th>api key</th></tr>\
         {rows}</table></div></div>\
         <div class=card><h3>Add Sandbox Endpoint</h3>\
         <form method=post action=\"/remotebox\">\
         <p><input name=name placeholder=\"Sandbox name\" required \
         style=\"padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"></p>\
         <p><input name=url placeholder=\"https://sandbox.example.com/api/v1\" required \
         style=\"width:100%;max-width:500px;padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"></p>\
         <p><input name=api_key placeholder=\"API key\" type=password \
         style=\"width:100%;max-width:500px;padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\"></p>\
         <p><select name=sandbox_type \
         style=\"padding:.5rem .7rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font:inherit\">\
         <option value=\"cuckoo\">Cuckoo Sandbox</option>\
         <option value=\"cape\">CAPE Sandbox</option>\
         <option value=\"any-run\">ANY.RUN</option>\
         <option value=\"joe-sandbox\">Joe Sandbox</option>\
         <option value=\"hybrid-analysis\">Hybrid Analysis</option>\
         <option value=\"vmray\">VMRay</option>\
         <option value=\"custom\">Custom API</option>\
         </select></p>\
         <button class=btn type=submit>Add endpoint</button></form></div>"
    );
    layout("sandbox", "/remotebox", &body)
}

async fn remotebox_add(State(st): State<Arc<AppState>>, Form(req): Form<RemoteBoxAddRequest>) -> Redirect {
    let config_path = st.root.join("data/remotebox.json");
    let _ = std::fs::create_dir_all(st.root.join("data"));
    let mut configs: Vec<RemoteBoxConfig> = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    configs.push(RemoteBoxConfig {
        name: req.name.trim().chars().take(120).collect(),
        url: req.url.trim().chars().take(500).collect(),
        api_key: req.api_key.trim().to_string(),
        sandbox_type: req.sandbox_type.trim().to_string(),
    });

    let _ = std::fs::write(&config_path, serde_json::to_string_pretty(&configs).unwrap_or_else(|_| "[]".into()));
    Redirect::to("/remotebox")
}

// ── Artifact download ────────────────────────────────────────────────────────

const ALLOWED_FILES: &[&str] = &[
    "findings.json",
    "attack-graph.md",
    "attack-graph.json",
    "session.log",
    "summary.md",
    "target.json",
    "analysis-report.md",
    "analysis-report.html",
];

fn content_type_for(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "pdf" => "application/pdf",
        "json" => "application/json",
        "html" => "text/html; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "log" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

async fn session_file(State(st): State<Arc<AppState>>, Path((id, name)): Path<(String, String)>) -> Response {
    if !safe_component(&id) || !ALLOWED_FILES.contains(&name.as_str()) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let path = st.root.join("sessions").join(&id).join(&name);
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let ct = content_type_for(&name);
            ([(header::CONTENT_TYPE, ct)], bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "file not found").into_response(),
    }
}

const EDITABLE_FILES: &[&str] = &["analysis-report.md", "summary.md", "attack-graph.md"];

async fn edit_file(State(st): State<Arc<AppState>>, Path((id, name)): Path<(String, String)>) -> Response {
    if !safe_component(&id) || !EDITABLE_FILES.contains(&name.as_str()) { return (StatusCode::NOT_FOUND, "not editable").into_response(); }
    let path = st.root.join("sessions").join(&id).join(&name);
    let text = tokio::fs::read_to_string(&path).await.unwrap_or_default();
    let body = format!("<style>body{{background:#0b0d12;color:#e7ebf3;font:14px system-ui;margin:0}}.ide{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px;height:calc(100vh - 120px)}}textarea,.preview{{width:100%;height:100%;box-sizing:border-box;background:#111824;color:#e7ebf3;border:1px solid #33435e;border-radius:8px;padding:16px;font:14px/1.6 ui-monospace,SFMono-Regular,monospace;white-space:pre-wrap;overflow:auto}}.bar{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}}button,a{{background:#82a9ff;color:#07101f;border:0;border-radius:6px;padding:9px 14px;font-weight:700;text-decoration:none}}a{{background:#202b3b;color:#e7ebf3}}@media(max-width:800px){{.ide{{grid-template-columns:1fr;height:auto}}.preview{{min-height:360px}}}}</style><div class=bar><a href='/session/{id}'>← Session</a><b>Mini IDE · {name}</b><button form=editor>Save changes</button><a href='/session/{id}/file/{name}' download>Download</a></div><div class=ide><form id=editor method=post><textarea name=content>{}</textarea></form><pre class=preview>{}</pre></div>", html_escape(&text), html_escape(&text));
    layout(&format!("edit {name}"), "/sessions", &body).into_response()
}

#[derive(serde::Deserialize)]
struct FileEdit { content: String }

async fn save_file(State(st): State<Arc<AppState>>, Path((id, name)): Path<(String, String)>, Form(edit): Form<FileEdit>) -> Response {
    if !safe_component(&id) || !EDITABLE_FILES.contains(&name.as_str()) { return (StatusCode::NOT_FOUND, "not editable").into_response(); }
    let path = st.root.join("sessions").join(&id).join(&name);
    if !path.is_file() { return (StatusCode::NOT_FOUND, "file not found").into_response(); }
    let backup = path.with_extension(format!("{}.bak", path.extension().and_then(|x| x.to_str()).unwrap_or("txt")));
    let _ = tokio::fs::copy(&path, &backup).await;
    if let Err(e) = tokio::fs::write(&path, edit.content.chars().take(2_000_000).collect::<String>()).await { return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(); }
    Redirect::to(&format!("/session/{id}/edit/{name}")).into_response()
}
