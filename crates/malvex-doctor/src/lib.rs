//! malvex-doctor — detect analysis tools, audit configured MCP servers, and (optionally)
//! install the missing open-source ones. Detect-before-install, idempotent.

mod registry;
pub mod mcp;
pub mod preflight;
pub use registry::TOOLS;

pub fn preflight_account_exhausted(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("\"api_error_status\":429")
        || lower.contains("session limit")
        || lower.contains("usage limit")
}

use malvex_core::tool::{License, ToolStatus};
use malvex_core::Platform;
use std::collections::BTreeSet;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn command_output_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Probe one executable name on PATH via `command -v`. Returns its path.
fn which(name: &str) -> Option<String> {
    let out = command_output_timeout("sh", &["-c", &format!("command -v {name}")], Duration::from_secs(2))?;
    if out.status.success() {
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !p.is_empty() {
            return Some(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let local = std::path::Path::new(&home).join(".local/bin").join(name);
        if local.is_file() {
            return Some(local.display().to_string());
        }
        let py_bins = std::path::Path::new(&home).join("Library/Python");
        if let Ok(rd) = std::fs::read_dir(py_bins) {
            for entry in rd.flatten() {
                let candidate = entry.path().join("bin").join(name);
                if candidate.is_file() {
                    return Some(candidate.display().to_string());
                }
            }
        }
    }
    None
}

/// Probe a python importable module for parser/helper libraries that are not on PATH.
fn python_has(module: &str) -> Option<String> {
    for py in ["python3.12", "python3.11", "python3.10", "python3", "python"] {
        let out = command_output_timeout(
            py,
            &["-c", &format!("import {module}, sys; print({module}.__file__)")],
            Duration::from_secs(3),
        );
        if let Some(o) = out {
            if o.status.success() {
                return Some(format!("{py}:{module}"));
            }
        }
    }
    None
}

/// Best-effort version string (first line).
fn version_of(path: &str, arg: Option<&str>) -> Option<String> {
    let arg = arg?;
    let out = command_output_timeout(path, &[arg], Duration::from_secs(4))?;
    let text = if !out.stdout.is_empty() { out.stdout } else { out.stderr };
    let s = String::from_utf8_lossy(&text);
    s.lines().next().map(|l| l.trim().to_string()).filter(|l| !l.is_empty())
}

/// Raw output of `claude mcp list` (server names + status), used to decide `via_mcp`.
pub fn configured_mcps() -> String {
    let mut combined = String::new();
    if let Some(o) = command_output_timeout("claude", &["mcp", "list"], Duration::from_secs(8)) {
        combined.push_str(&String::from_utf8_lossy(&o.stdout));
        combined.push('\n');
        combined.push_str(&String::from_utf8_lossy(&o.stderr));
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let mut names = BTreeSet::new();
    for path in [
        std::path::Path::new(&home).join(".claude.json"),
        std::path::Path::new(&home).join(".claude/settings.json"),
    ] {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                collect_claude_names(&json, &mut names);
            }
        }
    }
    if !names.is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(&names.into_iter().collect::<Vec<_>>().join("\n"));
    }
    combined
}

fn collect_claude_names(json: &serde_json::Value, names: &mut BTreeSet<String>) {
    if let Some(map) = json.get("mcpServers").and_then(|v| v.as_object()) {
        names.extend(map.keys().cloned());
    }
    if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
        for project in projects.values() {
            if let Some(map) = project.get("mcpServers").and_then(|v| v.as_object()) {
                names.extend(map.keys().cloned());
            }
        }
    }
    if let Some(map) = json.get("enabledPlugins").and_then(|v| v.as_object()) {
        for (plugin, enabled) in map {
            if enabled.as_bool() == Some(true) {
                let base = plugin.split('@').next().unwrap_or(plugin);
                names.insert(base.to_string());
                names.insert(format!("plugin:{base}"));
            }
        }
    }
}

fn mcp_identifiers(name: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let lower = name.to_lowercase();
    ids.insert(lower.clone());
    if let Some(last) = lower.split('/').next_back() {
        ids.insert(last.to_string());
    }
    for part in lower.split(':') {
        if !part.is_empty() {
            ids.insert(part.to_string());
        }
    }
    ids
}

fn probe_detail(path: &str, arg: Option<&str>) -> Option<String> {
    if let Some((py, module)) = path.split_once(':') {
        if py.starts_with("python") && !module.contains('/') {
            return Some(format!("{py}:{module}"));
        }
    }
    version_of(path, arg)
}

fn os_release_value(key: &str) -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")).map(|v| v.trim_matches('"').to_string()))
}

pub fn host_label(platform: Platform) -> String {
    if platform == Platform::Linux {
        os_release_value("PRETTY_NAME").unwrap_or_else(|| "linux".to_string())
    } else {
        platform.as_str().to_string()
    }
}

pub fn is_kali_linux(platform: Platform) -> bool {
    platform == Platform::Linux && matches!(os_release_value("ID").as_deref(), Some("kali"))
}

#[derive(Debug, Clone)]
pub struct ExtraInstall {
    pub name: String,
    pub cmd: String,
    pub note: String,
}

/// Probe every registry tool on this host.
pub fn scan(platform: Platform) -> Vec<ToolStatus> {
    let mcps = configured_mcps().to_lowercase();
    TOOLS
        .iter()
        .map(|t| {
            // 1. PATH probe.
            let mut path = None;
            for p in t.probes {
                if let Some(found) = which(p) {
                    path = Some(found);
                    break;
                }
            }
            // 2. python-import probe for parser libs with no PATH entry.
            if path.is_none() && t.probes.is_empty() {
                let module = match t.name {
                    "lief" => Some("lief"),
                    "capstone" => Some("capstone"),
                    "keystone" => Some("keystone"),
                    "unicorn" => Some("unicorn"),
                    "angr" => Some("angr"),
                    "volatility3" => Some("volatility3"),
                    "pefile-python" => Some("pefile"),
                    "androguard" => Some("androguard"),
                    "qiling" => Some("qiling"),
                    "speakeasy" => Some("speakeasy"),
                    "tlsh" => Some("tlsh"),
                    "imphash" => Some("pefile"),
                    "rich-header-hash" => Some("pefile"),
                    "stix2-validator" => Some("stix2validator"),
                    "taxii2-client" => Some("taxii2client"),
                    "misp-client" => Some("pymisp"),
                    "yeti-client" => Some("pyeti"),
                    "malwarebazaar-cli" => Some("malwarebazaar"),
                    "otx-cli" => Some("OTXv2"),
                    _ => None,
                };
                if let Some(module) = module {
                    path = python_has(module);
                }
            }
            // 3. MCP availability.
            let via_mcp = t.mcp.and_then(|m| {
                let matched = mcp_identifiers(m).into_iter().any(|id| mcps.contains(&id))
                    || mcps.contains(&t.name.to_lowercase());
                if matched {
                    Some(m.to_string())
                } else {
                    None
                }
            });

            let version = path.as_deref().and_then(|p| probe_detail(p, t.version_arg));
            let install_cmd = t.install_cmd(platform).map(String::from);
            let present = path.is_some() || via_mcp.is_some();

            ToolStatus {
                name: t.name.to_string(),
                kind: t.kind,
                license: t.license,
                present,
                path,
                version,
                via_mcp,
                installable: install_cmd.is_some() && t.license == License::Open,
                install_cmd,
                note: t.note.to_string(),
            }
        })
        .collect()
}

/// Tools that are missing AND open-source AND installable on this platform.
pub fn install_plan(status: &[ToolStatus]) -> Vec<&ToolStatus> {
    status.iter().filter(|s| !s.present && s.installable).collect()
}

fn run_install_cmd(name: String, cmd: String) -> (String, bool, String) {
    let cmd = maybe_wrap_brew_cmd(cmd);
    let out = Command::new("sh").arg("-c").arg(&cmd).output();
    match out {
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let stdout = String::from_utf8_lossy(&o.stdout);
            let tail = stderr
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .or_else(|| stdout.lines().rev().find(|l| !l.trim().is_empty()))
                .unwrap_or("")
                .to_string();
            (name, o.status.success(), tail)
        }
        Err(e) => (name, false, e.to_string()),
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn brew_owner() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let uid = command_output_timeout("id", &["-u"], Duration::from_secs(2))?;
    if !uid.status.success() || String::from_utf8_lossy(&uid.stdout).trim() != "0" {
        return None;
    }
    let out = command_output_timeout("stat", &["-f", "%Su", "/opt/homebrew/bin/brew"], Duration::from_secs(2))?;
    if !out.status.success() {
        return None;
    }
    let owner = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if owner.is_empty() {
        None
    } else {
        Some(owner)
    }
}

fn maybe_wrap_brew_cmd(cmd: String) -> String {
    if !cmd.contains("brew ") {
        return cmd;
    }
    let Some(owner) = brew_owner() else {
        return cmd;
    };
    let wrapped = format!("export PATH=/opt/homebrew/bin:$PATH; {cmd}");
    format!("sudo -u {owner} -H /bin/sh -lc {}", shell_quote(&wrapped))
}

/// Run the install commands for the plan. Returns (name, ok, output-tail) per tool.
pub fn install(plan: &[&ToolStatus]) -> Vec<(String, bool, String)> {
    plan.iter()
        .filter_map(|s| s.install_cmd.clone().map(|c| (s.name.clone(), c)))
        .map(|(name, cmd)| run_install_cmd(name, cmd))
        .collect()
}

pub fn extra_install_plan(platform: Platform) -> Vec<ExtraInstall> {
    if !is_kali_linux(platform) {
        return Vec::new();
    }
    [
        ("kali-binutils", "binutils", "GNU binary utilities for readelf/objdump/nm/strings."),
        ("kali-ghidra", "ghidra", "Headless and GUI decompilation tooling."),
        ("kali-radare2", "radare2", "CLI disassembly and analysis."),
        ("kali-rizin", "rizin", "Alternative RE engine backing Cutter."),
        ("kali-cutter", "cutter", "GUI front-end for Rizin."),
        ("kali-binwalk", "binwalk", "Embedded payload and firmware carving."),
        ("kali-cabextract", "cabextract", "CAB extraction for MSI and droppers."),
        ("kali-p7zip", "p7zip-full", "Universal archive and installer unpacking."),
        ("kali-msitools", "msitools", "MSI table and file extraction."),
        ("kali-upx", "upx-ucl", "UPX unpacking."),
        ("kali-die", "detect-it-easy", "Compiler and packer identification."),
        ("kali-yara", "yara", "Signature-based detection and triage."),
        ("kali-gdb", "gdb", "Native debugging."),
        ("kali-lldb", "lldb", "Native debugging for alternate targets."),
        ("kali-strace", "strace", "Syscall tracing."),
        ("kali-ltrace", "ltrace", "Libcall tracing."),
        ("kali-mitmproxy", "mitmproxy", "Intercept and replay network behavior."),
        ("kali-tshark", "tshark", "CLI packet analysis."),
        ("kali-tcpdump", "tcpdump", "Packet capture."),
        ("kali-checksec", "checksec", "Mitigation surface triage."),
        ("kali-patchelf", "patchelf", "ELF patching for controlled replay."),
        ("kali-osslsigncode", "osslsigncode", "Authenticode inspection."),
        ("kali-hashdeep", "hashdeep", "Recursive hashing of extracted trees."),
        ("kali-ssdeep", "ssdeep", "Fuzzy hashing for clustering."),
        ("kali-innoextract", "innoextract", "Inno Setup extraction."),
        ("kali-foremost", "foremost", "Carving from dumps and blobs."),
        ("kali-bulk-extractor", "bulk-extractor", "Bulk artifact extraction."),
        ("kali-exiftool", "libimage-exiftool-perl", "Metadata extraction."),
        ("kali-sqlite3", "sqlite3", "Browser and config database inspection."),
        ("kali-apktool", "apktool", "Android package unpacking when samples include mobile payloads."),
        ("kali-jadx", "jadx", "DEX/JAR decompilation for embedded Android stages."),
        ("kali-python-pip", "python3-pip", "Python package runtime."),
        ("kali-python-venv", "python3-venv", "Isolated Python environments."),
        ("kali-python-lief", "python3-lief", "Binary parsing library from distro repos."),
        ("kali-python-capstone", "python3-capstone", "Disassembly library from distro repos."),
        ("kali-python-unicorn", "python3-unicorn", "CPU emulation library from distro repos."),
        ("kali-python-oletools", "python3-oletools", "OLE and VBA inspection."),
        ("kali-python-frida", "python3-frida", "Frida Python bindings when packaged by distro."),
        ("kali-wine64", "wine64", "Compatibility layer for selected Windows-only tooling."),
    ]
    .into_iter()
    .map(|(name, package, note)| ExtraInstall {
        name: name.to_string(),
        cmd: format!(
            "if command -v apt-cache >/dev/null 2>&1 && apt-cache show {package} >/dev/null 2>&1; then sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {package}; else exit 0; fi"
        ),
        note: note.to_string(),
    })
    .collect()
}

pub fn install_extra(plan: &[ExtraInstall]) -> Vec<(String, bool, String)> {
    plan.iter()
        .map(|p| run_install_cmd(p.name.clone(), p.cmd.clone()))
        .collect()
}
