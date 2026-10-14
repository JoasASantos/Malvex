//! MCP-server registry + auto-installer for Claude Code compatible reverse-engineering
//! backends used by Malvex.
//!
//! Each entry knows how to fetch/prepare a reverse-engineering MCP server and register it
//! with `claude mcp add`. Installs are best-effort and idempotent: if the server is already
//! configured (`claude mcp list`), it's skipped; a failed fetch/build is logged, never fatal.
//! Commercial-backend servers (IDA, Binary Ninja) are registered but require the licensed
//! tool present to actually run.

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

/// How the MCP server is obtained + launched.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum McpKind {
    /// Python package run via uvx/pipx (no clone).
    Python,
    /// Node package run via npx.
    Node,
    /// Git repo that must be cloned + built/installed locally.
    GitBuild,
    /// A plugin loaded inside a GUI tool (Ghidra/Cutter/x64dbg/Binary Ninja); we register the
    /// bridge command but the tool must be installed and the plugin enabled by the analyst.
    ToolPlugin,
}

#[derive(Debug, Clone)]
pub struct McpServer {
    /// Name used with `claude mcp add <name> ...`.
    pub name: &'static str,
    pub repo: &'static str,
    pub kind: McpKind,
    /// Whether the backend tool is commercial (needs a license present).
    pub commercial: bool,
    /// Shell command that fetches/prepares the server (clone/pip/uvx). None if `claude mcp add`
    /// alone is enough (e.g. uvx-from-git). Run before `add`.
    pub prepare: Option<&'static str>,
    /// The `claude mcp add ...` argument tail (everything after `claude mcp add <name>`).
    /// Uses `--` to separate the launch command. Platform-agnostic where possible.
    pub add_args: &'static str,
    pub note: &'static str,
}

/// The RE MCP servers this framework can wire into Claude Code.
pub const MCP_SERVERS: &[McpServer] = &[
    McpServer {
        name: "ida-pro-mcp",
        repo: "https://github.com/mrexodia/ida-pro-mcp",
        kind: McpKind::Python,
        commercial: true,
        prepare: Some("uv tool install ida-pro-mcp || pipx install ida-pro-mcp || pip install --user ida-pro-mcp"),
        add_args: "-e PATH=$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin -- ida-pro-mcp",
        note: "IDA Pro (mrexodia). Needs IDA installed; run `ida-pro-mcp --install` once to add the IDA plugin.",
    },
    McpServer {
        name: "ghidra-mcp",
        repo: "https://github.com/bethington/ghidra-mcp",
        kind: McpKind::GitBuild,
        commercial: false,
        prepare: Some("git clone --depth 1 https://github.com/bethington/ghidra-mcp $MALVEX_MCP/ghidra-mcp 2>/dev/null; pip install --user -r $MALVEX_MCP/ghidra-mcp/requirements.txt 2>/dev/null || true"),
        add_args: "-- python3 $MALVEX_MCP/ghidra-mcp/bridge_mcp_ghidra.py",
        note: "Ghidra (bethington). Load the companion Ghidra plugin + run Ghidra with the bridge.",
    },
    McpServer {
        name: "radare2-mcp",
        repo: "https://github.com/radareorg/radare2-mcp",
        kind: McpKind::GitBuild,
        commercial: false,
        prepare: Some("r2pm -U 2>/dev/null; r2pm -ci r2mcp 2>/dev/null || (git clone --depth 1 https://github.com/radareorg/radare2-mcp $MALVEX_MCP/radare2-mcp && make -C $MALVEX_MCP/radare2-mcp 2>/dev/null); mkdir -p $HOME/.local/bin; if [ -x \"$HOME/.local/share/radare2/prefix/bin/r2mcp\" ]; then ln -sf \"$HOME/.local/share/radare2/prefix/bin/r2mcp\" \"$HOME/.local/bin/r2mcp\"; fi"),
        add_args: "-e PATH=$HOME/.local/bin:$HOME/.local/share/radare2/prefix/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin -- /bin/sh -lc 'exec r2mcp'",
        note: "radare2 (radareorg). Installs via r2pm; needs radare2.",
    },
    McpServer {
        name: "frida-mcp",
        repo: "https://github.com/dnakov/frida-mcp",
        kind: McpKind::Python,
        commercial: false,
        prepare: Some("UV_CACHE_DIR=${UV_CACHE_DIR:-$HOME/.cache/uv} uv tool install --force --python python3.11 -w 'mcp<2' frida-mcp || uv tool install --force -w 'mcp<2' frida-mcp || pip install --user 'mcp<2' frida-mcp"),
        add_args: "-e PATH=$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin -- frida-mcp",
        note: "Frida (dnakov). Runtime instrumentation MCP; needs frida.",
    },
    McpServer {
        name: "x64dbg-mcp",
        repo: "https://github.com/wasdubya/x64dbgmcp",
        kind: McpKind::ToolPlugin,
        commercial: false,
        prepare: Some("git clone --depth 1 https://github.com/wasdubya/x64dbgmcp $MALVEX_MCP/x64dbgmcp 2>/dev/null"),
        add_args: "-- python3 $MALVEX_MCP/x64dbgmcp/x64dbg_mcp_server.py",
        note: "x64dbg (wasdubya). Windows only; load the x64dbg plugin, then this bridge.",
    },
    McpServer {
        name: "re-mcp",
        repo: "https://github.com/jtsylve/re-mcp",
        kind: McpKind::Python,
        commercial: false,
        prepare: Some("UV_CACHE_DIR=${UV_CACHE_DIR:-$HOME/.cache/uv} uv tool install --force --python 3.12 re-mcp-ida || uv tool install --force re-mcp-ida"),
        add_args: "-e PATH=$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin -- /bin/sh -lc 'if [ -z \"$IDADIR\" ] && [ -d /Applications ]; then for app in /Applications/IDA\\ Professional*.app; do if [ -d \"$app/Contents/MacOS\" ]; then export IDADIR=\"$app/Contents/MacOS\"; break; fi; done; fi; exec re-mcp-ida'",
        note: "Headless reverse-engineering MCP (jtsylve). Defaults to the IDA backend on this host; set IDADIR explicitly if auto-discovery misses.",
    },
    McpServer {
        name: "binaryninja-mcp",
        repo: "https://github.com/fosdickio/binary_ninja_mcp",
        kind: McpKind::ToolPlugin,
        commercial: true,
        prepare: Some("git clone --depth 1 https://github.com/fosdickio/binary_ninja_mcp $MALVEX_MCP/binary_ninja_mcp 2>/dev/null; pip install --user -r $MALVEX_MCP/binary_ninja_mcp/requirements.txt 2>/dev/null || true"),
        add_args: "-- python3 $MALVEX_MCP/binary_ninja_mcp/server.py",
        note: "Binary Ninja (fosdickio). Needs a Binary Ninja license + the BN plugin.",
    },
    McpServer {
        name: "cutter-mcp",
        repo: "https://github.com/ap425q/CutterMCP",
        kind: McpKind::ToolPlugin,
        commercial: false,
        prepare: Some("git clone --depth 1 https://github.com/ap425q/CutterMCP $MALVEX_MCP/CutterMCP 2>/dev/null; pip install --user -r $MALVEX_MCP/CutterMCP/requirements.txt 2>/dev/null || true"),
        add_args: "-- python3 $MALVEX_MCP/CutterMCP/cutter_mcp.py",
        note: "Cutter/rizin (ap425q). Load the Cutter plugin, then this bridge.",
    },
    McpServer {
        name: "yaraflux-mcp",
        repo: "https://github.com/ThreatFlux/YaraFlux",
        kind: McpKind::Python,
        commercial: false,
        prepare: None,
        add_args: "-e PATH=$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin -e PYTHONUNBUFFERED=1 -e MALVEX_YARA_RULES=$HOME/.malvex/yaraflux/data/rules -- $HOME/.local/share/uv/tools/yaraflux-mcp-server/bin/python /opt/MalvexAI/tools/yara_mcp.py",
        note: "YARA stdio compatibility MCP (local-only). Uses the YaraFlux runtime when its upstream package is incomplete.",
    },
    McpServer {
        name: "rea",
        repo: "https://github.com/morluto/rea",
        kind: McpKind::Node,
        commercial: false,
        prepare: Some("npm install -g rea-agents 2>/dev/null || true"),
        add_args: "-- npx -y rea",
        note: "REA — Reverse Engineer Anything. Base RE layer: Ghidra, IDA, r2, Frida, .NET, Android, browser/electron. All RE tools orchestrated through one MCP.",
    },
];

/// Editors/tools that support MCP server configuration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Editor {
    ClaudeCode,
    Windsurf,
    Cursor,
    VsCode,
    OpenCode,
}

impl Editor {
    pub fn name(&self) -> &'static str {
        match self {
            Editor::ClaudeCode => "Claude Code",
            Editor::Windsurf => "Windsurf",
            Editor::Cursor => "Cursor",
            Editor::VsCode => "VS Code (Copilot)",
            Editor::OpenCode => "OpenCode",
        }
    }

    pub fn config_path(&self) -> Option<std::path::PathBuf> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let h = std::path::Path::new(&home);
        match self {
            Editor::ClaudeCode => Some(h.join(".claude.json")),
            Editor::Windsurf => Some(h.join(".codeium/windsurf/mcp_config.json")),
            Editor::Cursor => Some(h.join(".cursor/mcp.json")),
            Editor::VsCode => Some(h.join(".vscode/mcp.json")),
            Editor::OpenCode => Some(h.join(".opencode/mcp.json")),
        }
    }

    fn is_available(&self) -> bool {
        match self {
            Editor::ClaudeCode => have("claude"),
            Editor::Windsurf => self.config_path().map(|p| p.parent().map(|d| d.is_dir()).unwrap_or(false)).unwrap_or(false) || have("windsurf"),
            Editor::Cursor => self.config_path().map(|p| p.parent().map(|d| d.is_dir()).unwrap_or(false)).unwrap_or(false) || have("cursor"),
            Editor::VsCode => have("code"),
            Editor::OpenCode => have("opencode"),
        }
    }
}

pub const ALL_EDITORS: &[Editor] = &[
    Editor::ClaudeCode,
    Editor::Windsurf,
    Editor::Cursor,
    Editor::VsCode,
    Editor::OpenCode,
];

fn write_json_mcp_config(editor: &Editor, name: &str, command: &str, args: &[&str]) -> Result<(), String> {
    let path = editor.config_path().ok_or("no config path")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut config: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let servers = config
        .as_object_mut().ok_or("invalid config")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    let entry = serde_json::json!({
        "command": command,
        "args": args,
    });
    servers.as_object_mut().ok_or("invalid mcpServers")?.insert(name.to_string(), entry);
    std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap_or_default())
        .map_err(|e| e.to_string())
}

/// Currently-configured MCP names (lowercased blob of `claude mcp list`).
fn configured() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Some(o) = command_output_timeout("claude", &["mcp", "list"], Duration::from_secs(5)) {
        let text = String::from_utf8_lossy(&o.stdout).to_lowercase() + &String::from_utf8_lossy(&o.stderr).to_lowercase();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_suffix(':') {
                names.insert(name.trim().to_string());
                continue;
            }
            if let Some((name, _)) = line.split_once(':') {
                if !name.contains(' ') && !name.is_empty() {
                    names.insert(name.trim().to_string());
                }
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let cfg_path = std::path::Path::new(&home).join(".claude.json");
    if let Ok(text) = std::fs::read_to_string(cfg_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(map) = json.get("mcpServers").and_then(|v| v.as_object()) {
                names.extend(map.keys().map(|k| k.to_lowercase()));
            }
            if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
                for project in projects.values() {
                    if let Some(map) = project.get("mcpServers").and_then(|v| v.as_object()) {
                        names.extend(map.keys().map(|k| k.to_lowercase()));
                    }
                }
            }
        }
    }
    names
}

fn have(bin: &str) -> bool {
    command_output_timeout("sh", &["-c", &format!("command -v {bin}")], Duration::from_secs(2))
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[derive(Debug)]
pub struct McpInstallResult {
    pub name: String,
    pub status: String, // added | present | skipped | failed
    pub detail: String,
}

/// Register Malvex itself as an MCP server in all detected editors.
/// This is what makes "Use Malvex to analyze malware.exe" work from any MCP-capable tool.
pub fn register_malvex_mcp(malvex_bin: &str, force: bool) -> Vec<McpInstallResult> {
    let mut out = Vec::new();

    for editor in ALL_EDITORS {
        if !editor.is_available() {
            continue;
        }
        match *editor {
            Editor::ClaudeCode => {
                if !force {
                    let cfg = configured();
                    if cfg.contains("malvex") {
                        out.push(McpInstallResult { name: "malvex".into(), status: "present".into(),
                            detail: format!("{} — already configured", editor.name()) });
                        continue;
                    }
                }
                if force {
                    let _ = Command::new("claude").args(["mcp", "remove", "-s", "local", "malvex"]).output();
                }
                let add = format!("claude mcp add -s local malvex -- {} serve --mcp", malvex_bin);
                match Command::new("sh").arg("-c").arg(&add).output() {
                    Ok(o) if o.status.success() => out.push(McpInstallResult {
                        name: "malvex".into(), status: "added".into(),
                        detail: format!("{} — 31 MCP tools for malware analysis", editor.name()),
                    }),
                    Ok(o) => out.push(McpInstallResult { name: "malvex".into(), status: "failed".into(),
                        detail: format!("{} — {}", editor.name(), String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("add failed")) }),
                    Err(e) => out.push(McpInstallResult { name: "malvex".into(), status: "failed".into(),
                        detail: format!("{} — {}", editor.name(), e) }),
                }
            }
            _ => {
                match write_json_mcp_config(editor, "malvex", malvex_bin, &["serve", "--mcp"]) {
                    Ok(()) => out.push(McpInstallResult {
                        name: "malvex".into(), status: "added".into(),
                        detail: format!("{} — {} MCP config updated", editor.name(),
                            editor.config_path().map(|p| p.display().to_string()).unwrap_or_default()),
                    }),
                    Err(e) => out.push(McpInstallResult { name: "malvex".into(), status: "failed".into(),
                        detail: format!("{} — {}", editor.name(), e) }),
                }
            }
        }
    }

    if out.is_empty() {
        out.push(McpInstallResult { name: "malvex".into(), status: "skipped".into(),
            detail: "no MCP-capable editors detected (Claude Code, Windsurf, Cursor, VS Code, OpenCode)".into() });
    }
    out
}

/// Register RE tool MCP servers in non-Claude-Code editors (JSON config format).
fn register_re_servers_json(_mcp_home: &str, servers: &[&McpServer]) -> Vec<McpInstallResult> {
    let mut out = Vec::new();
    for editor in ALL_EDITORS {
        if *editor == Editor::ClaudeCode || !editor.is_available() {
            continue;
        }
        for s in servers {
            let (cmd, args): (&str, Vec<&str>) = match s.kind {
                McpKind::Python => {
                    let bin_name = s.add_args.split("-- ").last().unwrap_or(s.name).trim();
                    let parts: Vec<&str> = bin_name.split_whitespace().collect();
                    if parts.is_empty() { continue; }
                    (parts[0], parts[1..].to_vec())
                }
                McpKind::Node => ("npx", vec!["-y", s.name]),
                _ => continue,
            };
            let args_ref: Vec<&str> = args.iter().copied().collect();
            match write_json_mcp_config(editor, s.name, cmd, &args_ref) {
                Ok(()) => out.push(McpInstallResult { name: s.name.into(), status: "added".into(),
                    detail: format!("{} — {}", editor.name(), s.note) }),
                Err(e) => out.push(McpInstallResult { name: s.name.into(), status: "failed".into(),
                    detail: format!("{} — {}", editor.name(), e) }),
            }
        }
    }
    out
}

/// Install + register the open MCP servers with Claude Code and other editors.
/// `include_commercial` also wires the commercial-backed ones (they need the licensed tool to
/// actually run). Returns per-server results. `mcp_home` is where git-cloned servers live.
pub fn setup(mcp_home: &str, include_commercial: bool, do_install: bool, force: bool) -> Vec<McpInstallResult> {
    std::fs::create_dir_all(mcp_home).ok();
    let mut out = Vec::new();

    // First: register Malvex itself as MCP server in all detected editors
    let malvex_bin = which_malvex();
    out.extend(register_malvex_mcp(&malvex_bin, force));

    // Claude Code MCP registration for RE tools
    if have("claude") {
        let cfg = configured();
        let mut installed_servers: Vec<&McpServer> = Vec::new();

        for s in MCP_SERVERS {
            if s.commercial && !include_commercial {
                out.push(McpInstallResult { name: s.name.into(), status: "skipped".into(),
                    detail: format!("commercial backend ({}) — pass --commercial to wire it", s.repo) });
                continue;
            }
            if cfg.contains(&s.name.to_lowercase()) && !force {
                out.push(McpInstallResult { name: s.name.into(), status: "present".into(), detail: "already configured".into() });
                installed_servers.push(s);
                continue;
            }
            if !do_install {
                out.push(McpInstallResult { name: s.name.into(), status: "skipped".into(),
                    detail: format!("plan only — {}", s.repo) });
                continue;
            }
            if force {
                let remove = Command::new("claude")
                    .args(["mcp", "remove", "-s", "local", s.name])
                    .output();
                if let Ok(o) = remove {
                    if !o.status.success() {
                        let stderr = String::from_utf8_lossy(&o.stderr).to_lowercase();
                        if !stderr.contains("not found") && !stderr.contains("does not exist") {
                            out.push(McpInstallResult { name: s.name.into(), status: "failed".into(),
                                detail: stderr.lines().last().unwrap_or("mcp remove failed").chars().take(80).collect() });
                            continue;
                        }
                    }
                }
            }
            if let Some(prep) = s.prepare {
                let cmd = format!("export MALVEX_MCP={mcp_home:?}; {prep}");
                let _ = Command::new("sh").arg("-c").arg(&cmd).output();
            }
            let add = format!("export MALVEX_MCP={mcp_home:?}; claude mcp add -s local {} {}", s.name, s.add_args);
            match Command::new("sh").arg("-c").arg(&add).output() {
                Ok(o) if o.status.success() => {
                    out.push(McpInstallResult { name: s.name.into(), status: "added".into(), detail: format!("Claude Code — {}", s.note) });
                    installed_servers.push(s);
                }
                Ok(o) => {
                    let e = String::from_utf8_lossy(&o.stderr);
                    out.push(McpInstallResult { name: s.name.into(), status: "failed".into(),
                        detail: e.lines().last().unwrap_or("mcp add failed").chars().take(80).collect() });
                }
                Err(e) => out.push(McpInstallResult { name: s.name.into(), status: "failed".into(), detail: e.to_string() }),
            }
        }

        // Also register successfully installed RE servers in other editors
        if !installed_servers.is_empty() {
            out.extend(register_re_servers_json(mcp_home, &installed_servers));
        }
    } else {
        out.push(McpInstallResult { name: "*".into(), status: "skipped".into(),
            detail: "claude CLI not found — RE MCP servers registered only in editors with JSON config".into() });
    }

    out
}

fn which_malvex() -> String {
    if let Some(o) = command_output_timeout("sh", &["-c", "command -v malvex"], Duration::from_secs(2)) {
        if o.status.success() {
            let path = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !path.is_empty() {
                return path;
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let local_bin = format!("{home}/.local/bin/malvex");
    if std::path::Path::new(&local_bin).is_file() {
        return local_bin;
    }
    "malvex".to_string()
}
