use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Command;

const SERVER_NAME: &str = "malvex";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: &str = "2024-11-05";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn has_command(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_cmd(prog: &str, args: &[&str]) -> Result<String, String> {
    if !has_command(prog) {
        return Err(format!("{prog} not installed"));
    }
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("exec {prog}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(format!("{prog} failed: {}", stderr.trim()))
    }
}

fn run_cmd_allow_fail(prog: &str, args: &[&str]) -> String {
    run_cmd(prog, args).unwrap_or_default()
}

fn get_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    get_str(args, key).ok_or_else(|| format!("missing '{key}' parameter"))
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ---------------------------------------------------------------------------
// Tool definitions — REA-style: one MCP tool per analysis primitive
// ---------------------------------------------------------------------------

fn tool_definitions() -> Value {
    json!([
        // ── Pipeline orchestration ────────────────────────────────────
        {
            "name": "malvex_analyze",
            "description": "Run the full Malvex malware analysis pipeline on a target binary. Returns findings with evidence.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary or installer to analyze" },
                    "stages": { "type": "string", "description": "Comma-separated stage filter (triage,static,dynamic,network,intelligence,validate)" },
                    "model": { "type": "string", "description": "LLM model to use", "default": "claude-opus-4-6" },
                    "runtime": { "type": "string", "description": "Runtime backend: claude, codex, custom, hermes, ollama", "default": "claude" },
                    "parallel": { "type": "integer", "description": "Number of parallel shards (1-5)", "default": 1 }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_triage",
            "description": "Quick triage of a target binary: hashes, format, architecture, packer detection, entropy, imports, strings, IOCs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary to triage" },
                    "model": { "type": "string", "description": "LLM model to use", "default": "claude-opus-4-6" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_doctor",
            "description": "Check the Malvex environment: which RE tools, MCP servers, and analysis capabilities are available.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "install": { "type": "boolean", "description": "Install missing open-source tools", "default": false }
                }
            }
        },
        {
            "name": "malvex_sessions",
            "description": "List completed analysis sessions with target, finding count, and artifact status.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "malvex_findings",
            "description": "Retrieve findings from a completed analysis session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session directory path (e.g. sessions/1234567890)" }
                },
                "required": ["session"]
            }
        },
        {
            "name": "malvex_coverage",
            "description": "Show taxonomy coverage: how many analysis vectors have corresponding skills and agents.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "root": { "type": "string", "description": "Repository root containing agents/, skills/, vulns/", "default": "." }
                }
            }
        },
        {
            "name": "malvex_extract",
            "description": "Unpack a Windows installer (MSI/CAB) or archive to extract inner binaries.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "installer": { "type": "string", "description": "Path to the installer or archive" }
                },
                "required": ["installer"]
            }
        },
        {
            "name": "malvex_reparse",
            "description": "Re-derive findings from raw agent output using the current parser. No LLM call, no token spend.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session directory path" }
                },
                "required": ["session"]
            }
        },

        // ── Tool discovery ────────────────────────────────────────────
        {
            "name": "malvex_tools_available",
            "description": "List which analysis tools are installed on this host, with versions. Use this first to understand what capabilities are available.",
            "inputSchema": { "type": "object", "properties": {} }
        },

        // ── Triage primitives ─────────────────────────────────────────
        {
            "name": "malvex_hash",
            "description": "Compute all hashes for a target file: MD5, SHA1, SHA256, ssdeep (fuzzy), imphash (PE), TLSH.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the file" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_strings",
            "description": "Extract strings from a binary with categorization: URLs, IPs, file paths, registry keys, crypto constants, email addresses.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" },
                    "min_length": { "type": "integer", "description": "Minimum string length", "default": 4 },
                    "use_floss": { "type": "boolean", "description": "Use FLOSS for decoded/stack string recovery", "default": true }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_file_type",
            "description": "Identify file type, magic bytes, entropy, section overview, packer detection.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the file" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_capa",
            "description": "Run capa capability detection on a binary. Maps capabilities to MITRE ATT&CK techniques.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" },
                    "format": { "type": "string", "description": "Output format: default, json, vverbose", "default": "json" }
                },
                "required": ["target"]
            }
        },

        // ── Reverse engineering primitives ─────────────────────────────
        {
            "name": "malvex_disasm",
            "description": "Disassemble a function or address range. Uses the best available tool: radare2, Ghidra headless, or IDA.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" },
                    "address": { "type": "string", "description": "Address or function name to disassemble (e.g. 'main', '0x401000')", "default": "main" },
                    "count": { "type": "integer", "description": "Number of instructions", "default": 50 }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_decompile",
            "description": "Decompile a function to pseudocode. Prefers IDA > Ghidra > radare2 (r2dec/r2ghidra).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" },
                    "function": { "type": "string", "description": "Function name or address", "default": "main" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_functions",
            "description": "List all functions in a binary with sizes and addresses.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" },
                    "filter": { "type": "string", "description": "Filter function names (substring match)" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_imports",
            "description": "List imports grouped by library.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_exports",
            "description": "List exported symbols.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_xrefs",
            "description": "Cross-references to and from an address or symbol.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" },
                    "address": { "type": "string", "description": "Address or symbol name" }
                },
                "required": ["target", "address"]
            }
        },
        {
            "name": "malvex_sections",
            "description": "Section details with entropy, virtual size, raw size, permissions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the binary" }
                },
                "required": ["target"]
            }
        },

        // ── Detection ─────────────────────────────────────────────────
        {
            "name": "malvex_yara_scan",
            "description": "Scan a target with YARA rules. Accepts a rules file path or inline rule text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the file to scan" },
                    "rules": { "type": "string", "description": "Path to a .yar rules file" },
                    "inline_rule": { "type": "string", "description": "Inline YARA rule text (used if 'rules' is not provided)" }
                },
                "required": ["target"]
            }
        },
        {
            "name": "malvex_sigma_check",
            "description": "Validate a Sigma detection rule for syntax correctness.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule_path": { "type": "string", "description": "Path to the .yml Sigma rule file" }
                },
                "required": ["rule_path"]
            }
        },
        {
            "name": "malvex_ioc_extract",
            "description": "Extract all IOCs (hashes, IPs, domains, URLs, emails, registry keys, mutexes) from a file or text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to a file to extract IOCs from" },
                    "text": { "type": "string", "description": "Raw text to extract IOCs from (used if target not provided)" }
                }
            }
        },

        // ── Dynamic / instrumentation ─────────────────────────────────
        {
            "name": "malvex_frida_hook",
            "description": "Set a Frida instrumentation hook on a function or address in a running or spawned process.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Process name, PID, or binary path to spawn" },
                    "function": { "type": "string", "description": "Function name or address to hook" },
                    "script": { "type": "string", "description": "Custom Frida JS script (optional — defaults to log-args-and-return)" }
                },
                "required": ["target", "function"]
            }
        },
        {
            "name": "malvex_sandbox_submit",
            "description": "Submit a sample to a local sandbox (CAPE or Cuckoo) for automated behavioral analysis.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path to the sample" },
                    "timeout": { "type": "integer", "description": "Analysis timeout in seconds", "default": 120 },
                    "sandbox": { "type": "string", "description": "Sandbox backend: cape, cuckoo", "default": "cape" }
                },
                "required": ["target"]
            }
        },

        // ── OSINT ─────────────────────────────────────────────────────
        {
            "name": "malvex_vt_lookup",
            "description": "Look up a hash, URL, or domain on VirusTotal. Requires VT_API_KEY environment variable.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Hash (MD5/SHA1/SHA256), URL, or domain" },
                    "type": { "type": "string", "description": "Query type: hash, url, domain", "default": "hash" }
                },
                "required": ["query"]
            }
        },
        {
            "name": "malvex_malware_bazaar",
            "description": "Look up a sample on MalwareBazaar by hash.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hash": { "type": "string", "description": "SHA256, SHA1, or MD5 hash" }
                },
                "required": ["hash"]
            }
        },

        // ── Memory forensics ──────────────────────────────────────────
        {
            "name": "malvex_vol_pslist",
            "description": "List processes in a memory dump using volatility3.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dump": { "type": "string", "description": "Path to the memory dump file" }
                },
                "required": ["dump"]
            }
        },
        {
            "name": "malvex_vol_malfind",
            "description": "Detect injected code regions in a memory dump using volatility3 malfind.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dump": { "type": "string", "description": "Path to the memory dump file" },
                    "pid": { "type": "integer", "description": "Filter to a specific process ID" }
                },
                "required": ["dump"]
            }
        },
        {
            "name": "malvex_vol_dlllist",
            "description": "List loaded DLLs per process in a memory dump using volatility3.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dump": { "type": "string", "description": "Path to the memory dump file" },
                    "pid": { "type": "integer", "description": "Filter to a specific process ID" }
                },
                "required": ["dump"]
            }
        },

        // ── Network ───────────────────────────────────────────────────
        {
            "name": "malvex_pcap_analyze",
            "description": "Analyze a PCAP file: protocol breakdown, connections, DNS queries, HTTP requests, TLS fingerprints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pcap": { "type": "string", "description": "Path to the PCAP file" },
                    "filter": { "type": "string", "description": "BPF display filter (e.g. 'dns', 'http', 'tcp.port==443')" }
                },
                "required": ["pcap"]
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// MCP protocol handlers
// ---------------------------------------------------------------------------

fn handle_initialize(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            }
        }
    })
}

fn handle_tools_list(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "tools": tool_definitions() }
    })
}

fn handle_tools_call(id: &Value, params: &Value, root: &str) -> Value {
    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    let result = match tool_name {
        // Pipeline orchestration
        "malvex_doctor" => call_doctor(&arguments),
        "malvex_sessions" => call_sessions(root),
        "malvex_findings" => call_findings(&arguments),
        "malvex_coverage" => call_coverage(&arguments, root),
        "malvex_extract" => call_extract(&arguments),
        "malvex_reparse" => call_reparse(&arguments),
        "malvex_triage" => call_analyze(&arguments, root, true),
        "malvex_analyze" => call_analyze(&arguments, root, false),

        // Tool discovery
        "malvex_tools_available" => call_tools_available(),

        // Triage primitives
        "malvex_hash" => call_hash(&arguments),
        "malvex_strings" => call_strings(&arguments),
        "malvex_file_type" => call_file_type(&arguments),
        "malvex_capa" => call_capa(&arguments),

        // RE primitives
        "malvex_disasm" => call_disasm(&arguments),
        "malvex_decompile" => call_decompile(&arguments),
        "malvex_functions" => call_functions(&arguments),
        "malvex_imports" => call_imports(&arguments),
        "malvex_exports" => call_exports(&arguments),
        "malvex_xrefs" => call_xrefs(&arguments),
        "malvex_sections" => call_sections(&arguments),

        // Detection
        "malvex_yara_scan" => call_yara_scan(&arguments),
        "malvex_sigma_check" => call_sigma_check(&arguments),
        "malvex_ioc_extract" => call_ioc_extract(&arguments),

        // Dynamic
        "malvex_frida_hook" => call_frida_hook(&arguments),
        "malvex_sandbox_submit" => call_sandbox_submit(&arguments),

        // OSINT
        "malvex_vt_lookup" => call_vt_lookup(&arguments),
        "malvex_malware_bazaar" => call_malware_bazaar(&arguments),

        // Memory forensics
        "malvex_vol_pslist" => call_vol(&arguments, "windows.pslist.PsList"),
        "malvex_vol_malfind" => call_vol(&arguments, "windows.malfind.Malfind"),
        "malvex_vol_dlllist" => call_vol(&arguments, "windows.dlllist.DllList"),

        // Network
        "malvex_pcap_analyze" => call_pcap_analyze(&arguments),

        _ => Err(format!("unknown tool: {tool_name}")),
    };

    match result {
        Ok(content) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{ "type": "text", "text": content }]
            }
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{ "type": "text", "text": format!("Error: {e}") }],
                "isError": true
            }
        }),
    }
}

// ---------------------------------------------------------------------------
// Pipeline-level handlers (unchanged from original)
// ---------------------------------------------------------------------------

fn call_doctor(args: &Value) -> Result<String, String> {
    let do_install = args.get("install").and_then(|v| v.as_bool()).unwrap_or(false);
    let platform = sasf_core::Platform::current();
    let status = sasf_doctor::scan(platform);

    let mut out = format!("Malvex doctor ({})\n\n", sasf_doctor::host_label(platform));
    for s in &status {
        let label = if s.present { "ok" } else { "missing" };
        let detail = s.via_mcp.as_deref()
            .map(|m| format!("via MCP {m}"))
            .or(s.version.clone())
            .or(s.path.clone())
            .unwrap_or_else(|| s.note.clone());
        out.push_str(&format!("  {:<18} {:<18} {:<8} {}\n", s.name, format!("{:?}", s.kind), label, detail));
    }

    if do_install {
        let plan = sasf_doctor::install_plan(&status);
        if plan.is_empty() {
            out.push_str("\nNothing to install.\n");
        } else {
            out.push_str(&format!("\nInstalling {} tool(s)...\n", plan.len()));
            for (name, ok, tail) in sasf_doctor::install(&plan) {
                out.push_str(&format!("  [{}] {} {}\n", if ok { "ok" } else { "err" }, name, tail));
            }
        }
    }

    Ok(out)
}

fn call_sessions(root: &str) -> Result<String, String> {
    let dir = std::path::Path::new(root).join("sessions");
    let mut rows: Vec<(String, String, usize, bool)> = Vec::new();

    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_dir() { continue; }
            let id = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let target = std::fs::read_to_string(p.join("target.json")).ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|v| v.get("path").and_then(|x| x.as_str()).map(|s| s.rsplit('/').next().unwrap_or(s).to_string()))
                .unwrap_or_else(|| "?".into());
            let findings = std::fs::read_to_string(p.join("findings.json")).ok()
                .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
                .map(|v| v.len())
                .unwrap_or(0);
            let has_graph = p.join("attack-graph.json").is_file();
            rows.push((id, target, findings, has_graph));
        }
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));

    let mut out = String::from("Sessions:\n");
    for (id, target, findings, graph) in rows {
        out.push_str(&format!("  {} — {} ({} findings{})\n", id, target, findings, if graph { ", graph" } else { "" }));
    }
    if out == "Sessions:\n" {
        out.push_str("  (none)\n");
    }
    Ok(out)
}

fn call_findings(args: &Value) -> Result<String, String> {
    let session = require_str(args, "session")?;
    let path = std::path::Path::new(session).join("findings.json");
    std::fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))
}

fn call_coverage(args: &Value, default_root: &str) -> Result<String, String> {
    let root = get_str(args, "root").unwrap_or(default_root);
    let cfg = sasf_orchestrator::Config { root: PathBuf::from(root), ..Default::default() };
    let c = sasf_orchestrator::coverage(&cfg).map_err(|e| e.to_string())?;
    let mut out = format!("Coverage: {}/{} skills, {}/{} agents\n",
        c.skills_present.len(), c.total_vectors,
        c.agents_present.len(), c.agents_present.len() + c.agents_missing.len());
    if !c.skills_missing.is_empty() {
        out.push_str(&format!("Missing skills: {}\n", c.skills_missing.join(", ")));
    }
    if !c.agents_missing.is_empty() {
        out.push_str(&format!("Missing agents: {}\n", c.agents_missing.join(", ")));
    }
    Ok(out)
}

fn call_extract(args: &Value) -> Result<String, String> {
    let installer = require_str(args, "installer")?;
    let p = std::path::Path::new(installer);
    if !p.exists() {
        return Err(format!("installer not found: {installer}"));
    }
    let (bins, log) = sasf_orchestrator::extract::unpack(p).map_err(|e| e.to_string())?;
    let mut out = String::new();
    for line in &log { out.push_str(&format!("{line}\n")); }
    out.push_str(&format!("\n{} binary(ies) extracted:\n", bins.len()));
    for b in &bins { out.push_str(&format!("  {b}\n")); }
    Ok(out)
}

fn call_reparse(args: &Value) -> Result<String, String> {
    let session = require_str(args, "session")?;
    let n = sasf_orchestrator::exec::reparse(std::path::Path::new(session)).map_err(|e| e.to_string())?;
    Ok(format!("{n} finding(s) re-derived into {session}/findings.json"))
}

fn call_analyze(args: &Value, root: &str, triage_only: bool) -> Result<String, String> {
    let target_path = require_str(args, "target")?;
    let model = get_str(args, "model").unwrap_or("claude-opus-4-6");
    let runtime = get_str(args, "runtime").unwrap_or("claude");
    let parallel = args.get("parallel").and_then(|v| v.as_u64()).unwrap_or(1) as usize;

    let stage_filter = if triage_only {
        Some(vec!["triage".to_string()])
    } else {
        get_str(args, "stages").map(|s| {
            s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
        })
    };

    let cfg = sasf_orchestrator::Config {
        root: PathBuf::from(root),
        model: model.to_string(),
        runtime: runtime.to_string(),
        dry_run: false,
        stage_filter,
        parallel: parallel.clamp(1, 5),
        ..Default::default()
    };

    let target = crate::identify(target_path);
    let runs = sasf_orchestrator::run(&cfg, &target).map_err(|e| e.to_string())?;

    let total_findings: usize = runs.iter().map(|r| r.findings.len()).sum();
    let failed: Vec<&str> = runs.iter().filter(|r| !r.ok).map(|r| r.agent.as_str()).collect();

    let mut out = format!("Analysis complete: {} agent(s), {} finding(s)\n", runs.len(), total_findings);
    if !failed.is_empty() {
        out.push_str(&format!("Failed agents: {}\n", failed.join(", ")));
    }

    let findings: Vec<&sasf_core::Finding> = runs.iter().flat_map(|r| r.findings.iter()).collect();
    if !findings.is_empty() {
        let findings_json = serde_json::to_string_pretty(&findings).unwrap_or_else(|_| "[]".into());
        out.push_str(&format!("\nFindings:\n{findings_json}"));
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Tool discovery
// ---------------------------------------------------------------------------

fn call_tools_available() -> Result<String, String> {
    let checks: &[(&str, &[&str])] = &[
        ("radare2",         &["r2", "radare2"]),
        ("rizin",           &["rizin", "rz-bin"]),
        ("ghidra",          &["analyzeHeadless", "ghidraRun"]),
        ("ida",             &["idat64", "idat"]),
        ("binary-ninja",    &["binaryninja"]),
        ("cutter",          &["cutter"]),
        ("frida",           &["frida", "frida-trace"]),
        ("gdb",             &["gdb"]),
        ("lldb",            &["lldb"]),
        ("yara",            &["yara"]),
        ("capa",            &["capa"]),
        ("floss",           &["floss"]),
        ("strings",         &["strings"]),
        ("readelf",         &["readelf"]),
        ("objdump",         &["objdump"]),
        ("otool",           &["otool"]),
        ("nm",              &["nm"]),
        ("lief",            &["python3"]),   // checked separately
        ("volatility3",     &["vol", "vol3"]),
        ("tshark",          &["tshark"]),
        ("tcpdump",         &["tcpdump"]),
        ("mitmproxy",       &["mitmdump"]),
        ("binwalk",         &["binwalk"]),
        ("foremost",        &["foremost"]),
        ("ssdeep",          &["ssdeep"]),
        ("exiftool",        &["exiftool"]),
        ("upx",             &["upx"]),
        ("capstone",        &["python3"]),   // checked via import
        ("unicorn",         &["python3"]),
        ("angr",            &["python3"]),
        ("oletools",        &["python3"]),
        ("strace",          &["strace"]),
        ("ltrace",          &["ltrace"]),
        ("apktool",         &["apktool"]),
        ("jadx",            &["jadx"]),
        ("checksec",        &["checksec"]),
        ("sigma-cli",       &["sigma"]),
        ("zeek",            &["zeek"]),
        ("suricata",        &["suricata"]),
        ("docker",          &["docker"]),
    ];

    let python_mods: &[(&str, &str)] = &[
        ("lief", "lief"),
        ("capstone", "capstone"),
        ("unicorn", "unicorn"),
        ("angr", "angr"),
        ("oletools", "oletools"),
        ("volatility3", "volatility3"),
    ];

    let mut out = json!({});
    for (name, cmds) in checks {
        let mut found = false;
        let mut version = String::new();
        for cmd in *cmds {
            if has_command(cmd) {
                found = true;
                let ver = run_cmd(cmd, &["--version"])
                    .or_else(|_| run_cmd(cmd, &["-v"]))
                    .or_else(|_| run_cmd(cmd, &["-V"]))
                    .unwrap_or_default();
                version = ver.lines().next().unwrap_or("").trim().to_string();
                break;
            }
        }
        // For python-only tools, check via import
        if !found {
            if let Some((_, module)) = python_mods.iter().find(|(n, _)| n == name) {
                if has_command("python3") {
                    let check = Command::new("python3")
                        .args(["-c", &format!("import {module}; print({module}.__version__ if hasattr({module}, '__version__') else 'installed')")])
                        .output();
                    if let Ok(o) = check {
                        if o.status.success() {
                            found = true;
                            version = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        }
                    }
                }
            }
        }
        out[name] = json!({ "installed": found, "version": version });
    }

    serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Triage primitives
// ---------------------------------------------------------------------------

fn call_hash(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    if !std::path::Path::new(target).exists() {
        return Err(format!("file not found: {target}"));
    }
    let esc = shell_escape(target);

    let mut hashes = json!({});
    // SHA256
    if let Ok(out) = run_cmd("sh", &["-c", &format!("shasum -a 256 {esc} 2>/dev/null || sha256sum {esc}")]) {
        hashes["sha256"] = json!(out.split_whitespace().next().unwrap_or(""));
    }
    // SHA1
    if let Ok(out) = run_cmd("sh", &["-c", &format!("shasum -a 1 {esc} 2>/dev/null || sha1sum {esc}")]) {
        hashes["sha1"] = json!(out.split_whitespace().next().unwrap_or(""));
    }
    // MD5
    if let Ok(out) = run_cmd("sh", &["-c", &format!("md5 -q {esc} 2>/dev/null || md5sum {esc}")]) {
        let h = out.split_whitespace().next().unwrap_or("").to_lowercase();
        hashes["md5"] = json!(h);
    }
    // ssdeep
    if has_command("ssdeep") {
        if let Ok(out) = run_cmd("ssdeep", &["-b", target]) {
            let line = out.lines().skip(1).next().unwrap_or("").trim();
            if let Some(hash) = line.split(',').next() {
                hashes["ssdeep"] = json!(hash);
            }
        }
    }
    // TLSH
    if has_command("tlsh") {
        if let Ok(out) = run_cmd("tlsh", &["-f", target]) {
            hashes["tlsh"] = json!(out.split_whitespace().next().unwrap_or("").trim());
        }
    }
    // imphash via python/lief
    if has_command("python3") {
        let script = format!(
            "import lief; pe=lief.parse('{}'); print(lief.PE.get_imphash(pe) if pe else '')",
            target.replace('\'', "\\'")
        );
        if let Ok(out) = run_cmd("python3", &["-c", &script]) {
            let h = out.trim();
            if !h.is_empty() { hashes["imphash"] = json!(h); }
        }
    }

    serde_json::to_string_pretty(&hashes).map_err(|e| e.to_string())
}

fn call_strings(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    let min_len = args.get("min_length").and_then(|v| v.as_u64()).unwrap_or(4);
    let use_floss = args.get("use_floss").and_then(|v| v.as_bool()).unwrap_or(true);

    if !std::path::Path::new(target).exists() {
        return Err(format!("file not found: {target}"));
    }

    let mut result = json!({});

    // FLOSS for decoded/stack strings
    if use_floss && has_command("floss") {
        let out = run_cmd("floss", &["--json", target]);
        if let Ok(text) = out {
            if let Ok(parsed) = serde_json::from_str::<Value>(&text) {
                result["floss"] = parsed;
                return serde_json::to_string_pretty(&result).map_err(|e| e.to_string());
            }
        }
    }

    // Fallback to strings
    let min = format!("-n{min_len}");
    let out = run_cmd("strings", &[&min, target])?;
    let lines: Vec<&str> = out.lines().collect();

    let mut categorized = json!({
        "total": lines.len(),
        "urls": [],
        "ips": [],
        "paths": [],
        "registry": [],
        "crypto": [],
        "emails": [],
        "interesting": [],
    });

    for line in &lines {
        let l = line.trim();
        if l.starts_with("http://") || l.starts_with("https://") {
            categorized["urls"].as_array_mut().unwrap().push(json!(l));
        } else if l.contains("HKEY_") || l.contains("HKLM\\") || l.contains("HKCU\\") {
            categorized["registry"].as_array_mut().unwrap().push(json!(l));
        } else if l.contains('@') && l.contains('.') && l.len() > 5 {
            categorized["emails"].as_array_mut().unwrap().push(json!(l));
        } else if (l.starts_with("C:\\") || l.starts_with("/tmp") || l.starts_with("/var") || l.contains(":\\Windows"))
            && l.len() > 4
        {
            categorized["paths"].as_array_mut().unwrap().push(json!(l));
        } else if is_ip_like(l) {
            categorized["ips"].as_array_mut().unwrap().push(json!(l));
        } else if l.contains("AES") || l.contains("RSA") || l.contains("RC4") || l.contains("DES")
            || l.contains("BEGIN") || l.contains("PRIVATE KEY")
        {
            categorized["crypto"].as_array_mut().unwrap().push(json!(l));
        }
    }

    result["strings"] = categorized;
    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
}

fn is_ip_like(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return false; }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn call_file_type(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    if !std::path::Path::new(target).exists() {
        return Err(format!("file not found: {target}"));
    }

    let mut info = json!({});

    // file command
    if let Ok(out) = run_cmd("file", &["-b", target]) {
        info["file_type"] = json!(out.trim());
    }

    // Magic bytes
    let bytes = std::fs::read(target).map_err(|e| e.to_string())?;
    let magic = bytes.get(0..4).unwrap_or(&[]);
    info["magic"] = json!(format!("{:02x} {:02x} {:02x} {:02x}",
        magic.get(0).unwrap_or(&0), magic.get(1).unwrap_or(&0),
        magic.get(2).unwrap_or(&0), magic.get(3).unwrap_or(&0)));
    info["size"] = json!(bytes.len());

    // Entropy
    let entropy = calculate_entropy(&bytes);
    info["entropy"] = json!(format!("{:.4}", entropy));
    info["entropy_assessment"] = json!(if entropy > 7.5 { "high (likely packed/encrypted)" }
        else if entropy > 6.5 { "moderate (compiled binary)" }
        else { "low (text/data)" });

    // DIE for packer detection
    if has_command("diec") {
        if let Ok(out) = run_cmd("diec", &[target]) {
            info["packer"] = json!(out.trim());
        }
    }

    // Sections via r2 or readelf
    if has_command("r2") {
        if let Ok(out) = run_cmd("r2", &["-q", "-c", "iS", target]) {
            info["sections"] = json!(out.trim());
        }
    } else if has_command("readelf") {
        if let Ok(out) = run_cmd("readelf", &["-S", target]) {
            info["sections"] = json!(out.trim());
        }
    }

    serde_json::to_string_pretty(&info).map_err(|e| e.to_string())
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn call_capa(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    let format = get_str(args, "format").unwrap_or("json");
    if !has_command("capa") {
        return Err("capa not installed. Install: pip install flare-capa".into());
    }
    let flag = match format {
        "json" => "-j",
        "vverbose" => "-vv",
        _ => "",
    };
    let mut cmd_args = vec![target];
    if !flag.is_empty() { cmd_args.insert(0, flag); }
    run_cmd("capa", &cmd_args)
}

// ---------------------------------------------------------------------------
// RE primitives
// ---------------------------------------------------------------------------

fn call_disasm(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    let address = get_str(args, "address").unwrap_or("main");
    let count = args.get("count").and_then(|v| v.as_u64()).unwrap_or(50);

    // radare2 (preferred for CLI)
    if has_command("r2") {
        let cmd = format!("aaa; pd {} @ {}", count, address);
        return run_cmd("r2", &["-q", "-c", &cmd, target]);
    }
    // Ghidra headless (script-based)
    if has_command("analyzeHeadless") {
        return Err("Ghidra headless disassembly requires a project. Use malvex_decompile for Ghidra analysis.".into());
    }
    Err("No disassembler available. Install radare2 or Ghidra.".into())
}

fn call_decompile(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    let function = get_str(args, "function").unwrap_or("main");

    // radare2 with r2ghidra or r2dec
    if has_command("r2") {
        // Try r2ghidra first (pdg), fallback to r2dec (pdd)
        let cmd = format!("aaa; s {}; pdg", function);
        let result = run_cmd("r2", &["-q", "-c", &cmd, target]);
        if result.is_ok() { return result; }

        let cmd = format!("aaa; s {}; pdd", function);
        let result = run_cmd("r2", &["-q", "-c", &cmd, target]);
        if result.is_ok() { return result; }

        // Last resort: disassembly
        let cmd = format!("aaa; pdf @ {}", function);
        return run_cmd("r2", &["-q", "-c", &cmd, target]);
    }
    Err("No decompiler available. Install radare2 (with r2ghidra plugin) or use IDA/Ghidra via MCP.".into())
}

fn call_functions(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    let filter = get_str(args, "filter");

    if has_command("r2") {
        let cmd = if let Some(f) = filter {
            format!("aaa; afl~{}", f)
        } else {
            "aaa; afl".to_string()
        };
        return run_cmd("r2", &["-q", "-c", &cmd, target]);
    }
    if has_command("nm") {
        let out = run_cmd("nm", &["-C", target])?;
        if let Some(f) = filter {
            let filtered: String = out.lines()
                .filter(|l| l.contains(f))
                .map(|l| format!("{l}\n"))
                .collect();
            return Ok(filtered);
        }
        return Ok(out);
    }
    Err("No tool available. Install radare2 or nm.".into())
}

fn call_imports(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    if has_command("r2") {
        return run_cmd("r2", &["-q", "-c", "aaa; ii", target]);
    }
    if has_command("readelf") {
        return run_cmd("readelf", &["--dyn-syms", target]);
    }
    if has_command("otool") {
        return run_cmd("otool", &["-L", target]);
    }
    // Python/lief fallback
    if has_command("python3") {
        let script = format!(
            "import lief,json; b=lief.parse('{}'); \
             imps=[{{'lib':i.library if hasattr(i,'library') else '', 'name':i.name}} for i in (b.imports if b else [])]; \
             print(json.dumps(imps,indent=2))",
            target.replace('\'', "\\'")
        );
        return run_cmd("python3", &["-c", &script]);
    }
    Err("No import analysis tool available.".into())
}

fn call_exports(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    if has_command("r2") {
        return run_cmd("r2", &["-q", "-c", "aaa; iE", target]);
    }
    if has_command("nm") {
        return run_cmd("nm", &["-gC", target]);
    }
    if has_command("readelf") {
        return run_cmd("readelf", &["--dyn-syms", target]);
    }
    Err("No export analysis tool available.".into())
}

fn call_xrefs(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    let address = require_str(args, "address")?;
    if has_command("r2") {
        let cmd = format!("aaa; axt @ {address}; axf @ {address}");
        return run_cmd("r2", &["-q", "-c", &cmd, target]);
    }
    Err("radare2 required for xref analysis. Install: brew/apt install radare2".into())
}

fn call_sections(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    if has_command("r2") {
        return run_cmd("r2", &["-q", "-c", "iSj", target]);
    }
    if has_command("readelf") {
        return run_cmd("readelf", &["-S", "-W", target]);
    }
    if has_command("otool") {
        return run_cmd("otool", &["-l", target]);
    }
    // Python/lief
    if has_command("python3") {
        let script = format!(
            "import lief,json; b=lief.parse('{}'); \
             secs=[{{'name':s.name,'vaddr':hex(s.virtual_address),'vsize':s.virtual_size,'size':s.size,'entropy':round(s.entropy,4)}} for s in (b.sections if b else [])]; \
             print(json.dumps(secs,indent=2))",
            target.replace('\'', "\\'")
        );
        return run_cmd("python3", &["-c", &script]);
    }
    Err("No section analysis tool available.".into())
}

// ---------------------------------------------------------------------------
// Detection tools
// ---------------------------------------------------------------------------

fn call_yara_scan(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    if !has_command("yara") {
        return Err("yara not installed. Install: brew/apt install yara".into());
    }

    if let Some(rules) = get_str(args, "rules") {
        return run_cmd("yara", &["-s", rules, target]);
    }

    if let Some(inline) = get_str(args, "inline_rule") {
        let tmp = "/tmp/malvex_yara_tmp.yar";
        std::fs::write(tmp, inline).map_err(|e| e.to_string())?;
        let result = run_cmd("yara", &["-s", tmp, target]);
        let _ = std::fs::remove_file(tmp);
        return result;
    }

    Err("Provide 'rules' (path) or 'inline_rule' (text).".into())
}

fn call_sigma_check(args: &Value) -> Result<String, String> {
    let rule_path = require_str(args, "rule_path")?;
    if has_command("sigma") {
        return run_cmd("sigma", &["check", rule_path]);
    }
    // Fallback: basic YAML parse check
    let content = std::fs::read_to_string(rule_path).map_err(|e| e.to_string())?;
    if content.contains("title:") && content.contains("detection:") && content.contains("logsource:") {
        Ok(format!("Basic structure OK (title, detection, logsource present). Install sigma-cli for full validation."))
    } else {
        Err("Sigma rule missing required fields: title, detection, logsource".into())
    }
}

fn call_ioc_extract(args: &Value) -> Result<String, String> {
    let text = if let Some(target) = get_str(args, "target") {
        std::fs::read_to_string(target).map_err(|e| e.to_string())?
    } else if let Some(t) = get_str(args, "text") {
        t.to_string()
    } else {
        return Err("Provide 'target' (file path) or 'text'.".into());
    };

    let mut iocs = json!({
        "md5": [],
        "sha1": [],
        "sha256": [],
        "ipv4": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "registry": [],
        "mutexes": [],
    });

    for word in text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';') {
        let w = word.trim();
        if w.is_empty() { continue; }

        // Hashes
        if w.len() == 32 && w.chars().all(|c| c.is_ascii_hexdigit()) {
            iocs["md5"].as_array_mut().unwrap().push(json!(w));
        } else if w.len() == 40 && w.chars().all(|c| c.is_ascii_hexdigit()) {
            iocs["sha1"].as_array_mut().unwrap().push(json!(w));
        } else if w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()) {
            iocs["sha256"].as_array_mut().unwrap().push(json!(w));
        }
        // URLs
        else if w.starts_with("http://") || w.starts_with("https://") || w.starts_with("ftp://") {
            iocs["urls"].as_array_mut().unwrap().push(json!(w));
        }
        // IPs
        else if is_ip_like(w) {
            iocs["ipv4"].as_array_mut().unwrap().push(json!(w));
        }
        // Email
        else if w.contains('@') && w.contains('.') && w.len() > 5 && !w.starts_with('@') {
            iocs["emails"].as_array_mut().unwrap().push(json!(w));
        }
        // Registry
        else if w.starts_with("HKEY_") || w.starts_with("HKLM\\") || w.starts_with("HKCU\\") {
            iocs["registry"].as_array_mut().unwrap().push(json!(w));
        }
    }

    // Deduplicate
    for key in ["md5", "sha1", "sha256", "ipv4", "domains", "urls", "emails", "registry", "mutexes"] {
        if let Some(arr) = iocs[key].as_array_mut() {
            arr.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            arr.dedup();
        }
    }

    serde_json::to_string_pretty(&iocs).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Dynamic / instrumentation
// ---------------------------------------------------------------------------

fn call_frida_hook(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    let function = require_str(args, "function")?;
    if !has_command("frida") && !has_command("frida-trace") {
        return Err("frida not installed. Install: pip install frida-tools".into());
    }

    if let Some(script) = get_str(args, "script") {
        let tmp = "/tmp/malvex_frida_hook.js";
        std::fs::write(tmp, script).map_err(|e| e.to_string())?;
        let result = run_cmd("frida", &["-l", tmp, "-f", target, "--no-pause"]);
        let _ = std::fs::remove_file(tmp);
        return result;
    }

    // Default: trace the function
    run_cmd("frida-trace", &["-i", function, "-f", target])
}

fn call_sandbox_submit(args: &Value) -> Result<String, String> {
    let target = require_str(args, "target")?;
    let timeout = args.get("timeout").and_then(|v| v.as_u64()).unwrap_or(120);
    let sandbox = get_str(args, "sandbox").unwrap_or("cape");

    match sandbox {
        "cape" => {
            if has_command("curl") {
                let out = run_cmd("curl", &[
                    "-s", "-F", &format!("file=@{target}"),
                    "-F", &format!("timeout={timeout}"),
                    "http://localhost:8000/api/tasks/create/file/"
                ])?;
                Ok(format!("CAPE submission response:\n{out}"))
            } else {
                Err("curl required for CAPE submission".into())
            }
        }
        "cuckoo" => {
            if has_command("curl") {
                let out = run_cmd("curl", &[
                    "-s", "-F", &format!("file=@{target}"),
                    "-F", &format!("timeout={timeout}"),
                    "http://localhost:8090/tasks/create/file"
                ])?;
                Ok(format!("Cuckoo submission response:\n{out}"))
            } else {
                Err("curl required for Cuckoo submission".into())
            }
        }
        other => Err(format!("unknown sandbox: {other}. Use 'cape' or 'cuckoo'.")),
    }
}

// ---------------------------------------------------------------------------
// OSINT
// ---------------------------------------------------------------------------

fn call_vt_lookup(args: &Value) -> Result<String, String> {
    let query = require_str(args, "query")?;
    let query_type = get_str(args, "type").unwrap_or("hash");

    let api_key = std::env::var("VT_API_KEY")
        .or_else(|_| std::env::var("VIRUSTOTAL_API_KEY"))
        .map_err(|_| "VT_API_KEY environment variable not set".to_string())?;

    // vt-cli preferred
    if has_command("vt") {
        let resource_type = match query_type {
            "url" => "url",
            "domain" => "domain",
            _ => "file",
        };
        return run_cmd("vt", &[resource_type, query, "--apikey", &api_key]);
    }

    // curl fallback
    let endpoint = match query_type {
        "url" => format!("https://www.virustotal.com/api/v3/urls/{}", query),
        "domain" => format!("https://www.virustotal.com/api/v3/domains/{}", query),
        _ => format!("https://www.virustotal.com/api/v3/files/{}", query),
    };

    run_cmd("curl", &["-s", "-H", &format!("x-apikey: {api_key}"), &endpoint])
}

fn call_malware_bazaar(args: &Value) -> Result<String, String> {
    let hash = require_str(args, "hash")?;
    run_cmd("curl", &[
        "-s", "-X", "POST",
        "-d", &format!("query=get_info&hash={hash}"),
        "https://mb-api.abuse.ch/api/v1/"
    ])
}

// ---------------------------------------------------------------------------
// Memory forensics (volatility3)
// ---------------------------------------------------------------------------

fn call_vol(args: &Value, plugin: &str) -> Result<String, String> {
    let dump = require_str(args, "dump")?;
    if !std::path::Path::new(dump).exists() {
        return Err(format!("dump not found: {dump}"));
    }

    let vol_cmd = if has_command("vol") { "vol" }
        else if has_command("vol3") { "vol3" }
        else if has_command("python3") { "python3" }
        else { return Err("volatility3 not installed. Install: pip install volatility3".into()); };

    let mut cmd_args: Vec<&str> = Vec::new();
    if vol_cmd == "python3" {
        cmd_args.extend(&["-m", "volatility3"]);
    }
    cmd_args.extend(&["-f", dump, plugin]);

    if let Some(pid) = args.get("pid").and_then(|v| v.as_u64()) {
        let pid_str = pid.to_string();
        cmd_args.push("--pid");
        // Need to own this string
        let result = Command::new(vol_cmd)
            .args(&cmd_args)
            .arg(&pid_str)
            .output()
            .map_err(|e| format!("exec {vol_cmd}: {e}"))?;
        if result.status.success() {
            return Ok(String::from_utf8_lossy(&result.stdout).into_owned());
        }
        return Err(String::from_utf8_lossy(&result.stderr).trim().to_string());
    }

    run_cmd(vol_cmd, &cmd_args)
}

// ---------------------------------------------------------------------------
// Network analysis
// ---------------------------------------------------------------------------

fn call_pcap_analyze(args: &Value) -> Result<String, String> {
    let pcap = require_str(args, "pcap")?;
    let filter = get_str(args, "filter");

    if !std::path::Path::new(pcap).exists() {
        return Err(format!("pcap not found: {pcap}"));
    }

    if !has_command("tshark") {
        return Err("tshark not installed. Install: brew/apt install wireshark-cli".into());
    }

    let mut out = String::new();

    // Protocol hierarchy
    out.push_str("=== Protocol Hierarchy ===\n");
    out.push_str(&run_cmd_allow_fail("tshark", &["-r", pcap, "-q", "-z", "io,phs"]));

    // Conversations
    out.push_str("\n=== TCP Conversations ===\n");
    out.push_str(&run_cmd_allow_fail("tshark", &["-r", pcap, "-q", "-z", "conv,tcp"]));

    // DNS queries
    out.push_str("\n=== DNS Queries ===\n");
    out.push_str(&run_cmd_allow_fail("tshark", &["-r", pcap, "-Y", "dns.qr==0", "-T", "fields",
        "-e", "dns.qry.name", "-e", "dns.qry.type"]));

    // HTTP requests
    out.push_str("\n=== HTTP Requests ===\n");
    out.push_str(&run_cmd_allow_fail("tshark", &["-r", pcap, "-Y", "http.request",
        "-T", "fields", "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri"]));

    // User filter
    if let Some(f) = filter {
        out.push_str(&format!("\n=== Custom Filter: {} ===\n", f));
        out.push_str(&run_cmd_allow_fail("tshark", &["-r", pcap, "-Y", f]));
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// MCP protocol dispatch
// ---------------------------------------------------------------------------

fn handle_request(request: &Value, root: &str) -> Option<Value> {
    let method = request.get("method")?.as_str()?;
    let id = request.get("id").unwrap_or(&Value::Null);

    match method {
        "initialize" => Some(handle_initialize(id)),
        "notifications/initialized" => None,
        "tools/list" => Some(handle_tools_list(id)),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or(json!({}));
            Some(handle_tools_call(id, &params, root))
        }
        "ping" => Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
        _ => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") }
        })),
    }
}

pub fn run(transport: String, _port: u16, root: String) -> anyhow::Result<()> {
    match transport.as_str() {
        "stdio" => run_stdio(&root),
        "sse" => {
            eprintln!("SSE transport not yet implemented. Use --transport stdio");
            std::process::exit(1);
        }
        other => {
            eprintln!("unknown transport: {other}. Use stdio or sse");
            std::process::exit(1);
        }
    }
}

fn run_stdio(root: &str) -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("parse error: {e}") }
                });
                writeln!(stdout, "{}", serde_json::to_string(&err)?)?;
                stdout.flush()?;
                continue;
            }
        };

        if let Some(response) = handle_request(&request, root) {
            writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
            stdout.flush()?;
        }
    }

    Ok(())
}
