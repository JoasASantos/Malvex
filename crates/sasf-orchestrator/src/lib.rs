//! Orchestrator for the active Malvex workflow.
//!
//! The crate path is legacy, but the active behavior is malware-analysis oriented:
//! evidence-driven triage, reverse engineering, dynamic analysis, detections,
//! threat intelligence, and validation.

pub mod chains;
pub mod eventscan;
pub mod exec;
pub mod extract;
pub mod lookup;
pub mod parse;
pub mod pocrun;
pub mod pocval;
pub mod procdb;
pub mod rea;
pub mod remotebox;
pub mod skillgen;
pub mod taxonomy;
pub mod threatintel;
pub mod yararun;

pub use chains::{AttackChain, ChainLib};
pub use taxonomy::{Taxonomy, Vector};

use sasf_core::{Finding, Target};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Config {
    pub root: PathBuf,
    pub model: String,
    pub fallbacks: Vec<String>,
    pub output_format: String,
    pub dry_run: bool,
    pub stage_filter: Option<Vec<String>>,
    pub resume_dir: Option<PathBuf>,
    /// Legacy compatibility field. Unused by the active flow.
    pub report_date: Option<String>,
    pub verbose: bool,
    pub parallel: usize,
    pub custom_prompt: Option<String>,
    /// Runtime backend: `claude`, `codex`, `custom`, `hermes`, or `ollama`.
    pub runtime: String,
    /// Execution approval policy: auto, confirm-risky, or human.
    pub approval_mode: String,
    /// Hermes provider for fallback/alternative engine (deepseek, qwen, etc.)
    pub hermes_provider: Option<String>,
    /// Hermes model name
    pub hermes_model: Option<String>,
    /// Force hermes as primary engine instead of claude
    pub force_hermes: bool,
    /// Windows VM script for cross-platform dynamic analysis
    pub win_vm_script: Option<PathBuf>,
    /// macOS VM script for cross-platform dynamic analysis
    pub mac_vm_script: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            model: "claude-opus-4-6".into(),
            fallbacks: vec!["claude-opus-4-7".into(), "claude-opus-4-8".into()],
            output_format: "json".into(),
            dry_run: true,
            stage_filter: None,
            resume_dir: None,
            report_date: None,
            verbose: false,
            parallel: 1,
            custom_prompt: None,
            runtime: std::env::var("MALVEX_RUNTIME").unwrap_or_else(|_| "claude".into()),
            approval_mode: std::env::var("MALVEX_APPROVAL_MODE").unwrap_or_else(|_| "confirm-risky".into()),
            hermes_provider: std::env::var("MALVEX_HERMES_PROVIDER").ok(),
            hermes_model: std::env::var("MALVEX_HERMES_MODEL").ok(),
            force_hermes: std::env::var("MALVEX_FORCE_HERMES").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
            win_vm_script: std::env::var("MALVEX_WIN_VM_SCRIPT").ok().map(PathBuf::from),
            mac_vm_script: std::env::var("MALVEX_MAC_VM_SCRIPT").ok().map(PathBuf::from),
        }
    }
}

pub fn claude_on_path() -> bool {
    Command::new("sh")
        .arg("-c")
        .arg("command -v claude")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn claude_missing_error() -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    format!(
        "`claude` CLI not found on this process's PATH.\n\
         Current PATH: {path}\n\
         - Install: curl -fsSL https://claude.ai/install.sh | bash  (installs to ~/.local/bin)\n\
         - Already installed? Process started without your shell's PATH (common with launchd/\
         systemd/cron). Export a PATH that includes the `claude` directory in the service's \
         environment."
    )
}

pub fn is_account_exhausted(output: &str) -> bool {
    let lower = output.to_lowercase();
    let json_signal = lower.contains("\"api_error_status\":429")
        || (lower.contains("\"is_error\":true") && lower.contains("terminal_reason\":\"api_error\""));
    let text_signal = lower.contains("session limit")
        || lower.contains("usage limit")
        || (lower.contains("rate limit") && lower.contains("resets"));
    json_signal || text_signal
}

pub fn build_fallback_command(cfg: &Config, agent_file: &Path, prompt: &str) -> Option<Command> {
    if cfg.runtime == "custom" {
        let mut c = Command::new("sh");
        c.arg("-lc")
            .arg("if [ -z \"$MALVEX_CUSTOM_CMD\" ]; then echo 'MALVEX_CUSTOM_CMD not set' >&2; exit 2; fi; eval \"$MALVEX_CUSTOM_CMD\"")
            .env("MALVEX_PROMPT", prompt)
            .env("MALVEX_MODEL", &cfg.model)
            .env("MALVEX_AGENT", agent_file.to_string_lossy().as_ref())
            .env("MALVEX_ROOT", &cfg.root)
            .stdin(std::process::Stdio::null());
        return Some(c);
    }
    None
}

const HERMES_TOOL_NAMING_NOTE: &str = "\n\n---\nRUNTIME NOTE: you are running under hermes, \
not Claude Code. Any MCP tool this system prompt names with a `mcp__plugin_...__<tool>` prefix \
is the SAME underlying tool here, just under a different prefix (or none) in YOUR toolset — \
check your actual available tools and call the one matching by function/name suffix, not the \
literal `mcp__plugin_...` string. Never skip a step or fall back to a weaker method just \
because that exact literal isn't present.\n---\n";

pub fn build_hermes_command(cfg: &Config, agent_file: &Path, prompt: &str) -> Option<Command> {
    let provider = cfg.hermes_provider.as_deref()?;
    let model = cfg.hermes_model.as_deref()?;
    let agent_prompt = std::fs::read_to_string(agent_file).unwrap_or_default();
    let full_query = format!("{agent_prompt}{HERMES_TOOL_NAMING_NOTE}\n---\n\n{prompt}");
    let mut c = Command::new("hermes");
    c.arg("chat")
        .arg("-q").arg(full_query)
        .arg("--oneshot")
        .arg("-Q")
        .arg("--yolo")
        .arg("--provider").arg(provider)
        .arg("--model").arg(model)
        .arg("--in").arg(&cfg.root)
        .stdin(std::process::Stdio::null());
    Some(c)
}

#[derive(Debug, Clone)]
pub struct Stage {
    pub name: &'static str,
    pub agents: Vec<String>,
    pub gate: Option<&'static str>,
}

fn platform_of(target: &Target) -> &'static str {
    let f = target.format.to_lowercase();
    if f.contains("macho") || f.contains("mach-o") || f.contains("fat") {
        "macos"
    } else if f.contains("pe") || f.contains("coff") {
        "windows"
    } else if f.contains("elf") {
        "linux"
    } else {
        "linux"
    }
}

pub fn plan(target: &Target) -> Vec<Stage> {
    plan_with_parallel(target, 1)
}

pub fn plan_with_parallel(_target: &Target, parallel: usize) -> Vec<Stage> {
    let n = parallel.max(1);
    let shard = |name: &str| -> Vec<String> {
        if n == 1 {
            vec![name.to_string()]
        } else {
            (1..=n).map(|i| format!("{name}.{i}")).collect()
        }
    };

    vec![
        Stage {
            name: "triage",
            agents: vec!["triage".into()],
            gate: None,
        },
        Stage {
            name: "static",
            agents: [shard("static-core"), shard("decompilation"), shard("deobfuscation")].concat(),
            gate: None,
        },
        Stage {
            name: "dynamic",
            agents: vec!["dynamic-analysis".into(), "memory-analysis".into(), "sandbox-analysis".into()],
            gate: Some("native runtime evidence only when the host matches the target platform; otherwise emit a concrete runtime plan"),
        },
        Stage {
            name: "network",
            agents: vec!["network-analysis".into()],
            gate: Some("requires packet capture or network simulation capabilities"),
        },
        Stage {
            name: "intelligence",
            agents: vec!["detection-engineering".into(), "threat-intel".into()],
            gate: None,
        },
        Stage {
            name: "validate",
            agents: vec!["validator".into()],
            gate: None,
        },
    ]
}

fn task_prompt(cfg: &Config, agent: &str, target: &Target, tax: &Taxonomy, context: Option<&str>) -> String {
    let (base_agent, shard) = if let Some(dot) = agent.rfind('.') {
        let suffix = &agent[dot + 1..];
        if let Ok(n) = suffix.parse::<usize>() {
            (&agent[..dot], Some(n))
        } else {
            (agent, None)
        }
    } else {
        (agent, None)
    };

    let all_owned: Vec<String> = tax.for_agent(base_agent).iter().map(|v| v.id.clone()).collect();
    let owned = if let Some(shard_idx) = shard {
        let n = cfg.parallel.max(1);
        let subset: Vec<String> = all_owned
            .iter()
            .enumerate()
            .filter(|(i, _)| (i % n) + 1 == shard_idx)
            .map(|(_, v)| v.clone())
            .collect();
        if subset.is_empty() {
            format!("(shard {shard_idx}/{n} — no assigned vectors)")
        } else {
            format!("{} (shard {shard_idx}/{n})", subset.join(", "))
        }
    } else if all_owned.is_empty() {
        "(pipeline role)".into()
    } else {
        all_owned.join(", ")
    };

    let ctx = context
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\nPRIOR FINDINGS CONTEXT:\n{s}\n"))
        .unwrap_or_default();

    let host = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };
    let target_platform = platform_of(target);
    let platform_note = if host == target_platform {
        format!("\nHOST matches target platform: {target_platform}. Runtime evidence is allowed and preferred where relevant.")
    } else {
        format!(
            "\nHOST is {host} but target platform is {target_platform}. Static analysis is still valid. Any native-runtime-only claim must become a `needs-{target_platform}-runtime` plan with exact steps, hooks, breakpoints, and expected artifacts."
        )
    };

    let bundle_note = if target.bundle_binaries.len() > 1 {
        format!(
            "\nThe sample expands to multiple binaries. Map behavior to the correct module:\n  - {}",
            target.bundle_binaries.join("\n  - ")
        )
    } else {
        String::new()
    };

    let chain_lines: Vec<String> = chains::ChainLib::load_or_empty(&cfg.root)
        .for_platform(target_platform)
        .iter()
        .map(|c| format!("  - {}: {}", c.id, c.steps.join(" -> ")))
        .collect();
    let chain_note = if chain_lines.is_empty() {
        String::new()
    } else {
        format!(
            "\nRelevant capability chains for {target_platform}:\n{}",
            chain_lines.join("\n")
        )
    };

    let hashes = {
        let mut items = Vec::new();
        if let Some(v) = &target.sha256 {
            items.push(format!("sha256={v}"));
        }
        if let Some(v) = &target.md5 {
            items.push(format!("md5={v}"));
        }
        if items.is_empty() {
            String::new()
        } else {
            format!(" [{}]", items.join(", "))
        }
    };

    let dynamic_note = if base_agent == "dynamic-analysis" || base_agent == "memory-analysis" {
        if host == target_platform {
            "\nCollect runtime process, memory, network, and decoded-artifact evidence. Tie runtime observations back to functions, modules, or config blobs when possible.".to_string()
        } else {
            format!(
                "\nDo not fabricate runtime proof. Produce a concrete runtime recipe for a {target_platform} host using Frida, lldb/gdb, x64dbg/WinDbg, strace/ltrace, tcpdump/tshark, or equivalent tooling as appropriate."
            )
        }
    } else {
        String::new()
    };

    let closing = match base_agent {
        "validator" => "Emit a JSON array of sasf-core::Finding. Confirm, downgrade, or refute each claim explicitly. Separate observed behavior from inferred behavior and include confidence in the summary.",
        "detection-engineering" => "Emit a JSON array of sasf-core::Finding focused on detections. Each detection idea must cite the proving artifact or behavior.",
        "threat-intel" => "Emit a JSON array of sasf-core::Finding focused on family overlap, ATT&CK-aligned capability synthesis, and lineage. Similarity is not attribution.",
        "interactive-repl" => "Answer the analyst directly using the session evidence. Cite functions, xrefs, strings, APIs, memory artifacts, traffic, or logs. Mark speculation as hypothesis.",
        _ => "Emit a JSON array of sasf-core::Finding with verdict:plausible. Every finding must answer: what does it do, how does it do it, what evidence proves it, and what confidence is justified. Rename functions when the evidence supports the rename.",
    };

    let analyst_note = cfg
        .custom_prompt
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("\nANALYST GUIDANCE:\n{}\n", s.trim()))
        .unwrap_or_default();

    format!(
        "Analyze target: path={} format={} arch={} app={} shielding=[{}]{}.\n\
         You own these vectors: {}.\n\
         Use the rule: hypothesis -> evidence -> verification -> confidence.\n\
         LLM output is not evidence.\n\
         {}\n{}{}{}{}{}\n\
         {}",
        target.path,
        target.format,
        target.arch,
        target.app,
        target.shielding.join(","),
        hashes,
        owned,
        build_re_directive(&detect_re_tools()),
        ctx,
        platform_note,
        bundle_note,
        chain_note,
        dynamic_note,
        format!("{closing}{analyst_note}")
    )
}

#[derive(Debug)]
struct ReTools {
    ida: bool,
    ghidra: bool,
    r2: bool,
    binja: bool,
    otool: bool,
    lief: bool,
    rizin: bool,
    gdb: bool,
    lldb: bool,
    volatility3: bool,
    capa: bool,
    floss: bool,
    frida: bool,
    strace: bool,
    ltrace: bool,
    tshark: bool,
    tcpdump: bool,
    mitmproxy: bool,
    rea: bool,
}

fn detect_re_tools() -> ReTools {
    let has = |cmd: &str| -> bool {
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {cmd}"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    let py_has = |module: &str| -> bool {
        Command::new("python3")
            .args(["-c", &format!("import {module}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    let ida = std::env::var("HOME")
        .ok()
        .map(|home| {
            let paths = [
                format!("{home}/.claude.json"),
                format!("{home}/.claude/plugins/ida-pro/idalib/package.json"),
            ];
            paths.iter().any(|p| {
                std::fs::read_to_string(p)
                    .ok()
                    .map(|s| s.to_lowercase().contains("ida"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
        || has("idat64")
        || has("idat");

    let rea = has("npx") && Command::new("npx")
        .args(["rea", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    ReTools {
        ida,
        ghidra: has("analyzeHeadless") || has("ghidraRun") || has("ghidra"),
        r2: has("r2") || has("radare2"),
        binja: has("binaryninja"),
        otool: has("otool"),
        lief: py_has("lief"),
        rizin: has("rizin") || has("rz-bin"),
        gdb: has("gdb"),
        lldb: has("lldb"),
        volatility3: has("vol") || has("vol3") || py_has("volatility3"),
        capa: has("capa"),
        floss: has("floss"),
        frida: has("frida") || has("frida-ps") || py_has("frida"),
        strace: has("strace"),
        ltrace: has("ltrace"),
        tshark: has("tshark"),
        tcpdump: has("tcpdump"),
        mitmproxy: has("mitmdump") || has("mitmproxy"),
        rea,
    }
}

fn build_re_directive(tools: &ReTools) -> String {
    let mut disasm = Vec::new();
    if tools.ida { disasm.push("IDA"); }
    if tools.ghidra { disasm.push("Ghidra"); }
    if tools.binja { disasm.push("Binary Ninja"); }
    if tools.r2 { disasm.push("radare2"); }
    if tools.rizin { disasm.push("rizin"); }

    let mut debug = Vec::new();
    if tools.lldb { debug.push("lldb"); }
    if tools.gdb { debug.push("gdb"); }
    if tools.frida { debug.push("Frida"); }
    if tools.strace { debug.push("strace"); }
    if tools.ltrace { debug.push("ltrace"); }

    let mut network = Vec::new();
    if tools.tshark { network.push("tshark"); }
    if tools.tcpdump { network.push("tcpdump"); }
    if tools.mitmproxy { network.push("mitmproxy"); }

    let mut analysis = Vec::new();
    if tools.otool { analysis.push("otool"); }
    if tools.lief { analysis.push("lief"); }
    if tools.capa { analysis.push("capa"); }
    if tools.floss { analysis.push("floss"); }
    if tools.volatility3 { analysis.push("volatility3"); }

    let mut all: Vec<&str> = Vec::new();
    all.extend(&disasm);
    all.extend(&debug);
    all.extend(&network);
    all.extend(&analysis);

    let availability = if all.is_empty() {
        "RE tools detected: none. Install at least one decompiler/disassembler and one runtime tool.".to_string()
    } else {
        format!("RE tools detected: {}.", all.join(", "))
    };

    let mut sections = Vec::new();
    if !disasm.is_empty() {
        sections.push(format!("Disassemblers: {}", disasm.join(", ")));
    }
    if !debug.is_empty() {
        sections.push(format!("Dynamic/debug: {}", debug.join(", ")));
    }
    if !network.is_empty() {
        sections.push(format!("Network: {}", network.join(", ")));
    }
    if !analysis.is_empty() {
        sections.push(format!("Analysis: {}", analysis.join(", ")));
    }
    if tools.rea {
        sections.push("REA MCP: active".into());
    }
    let breakdown = if sections.is_empty() { String::new() } else { format!(" [{}]", sections.join("; ")) };

    let rea_note = if tools.rea {
        " REA MCP server is available — use REA tools for disassembly, decompilation, function listing, string extraction, xref analysis, Frida hooking, .NET decompilation, and Android APK analysis. REA orchestrates Ghidra/IDA/r2/Frida automatically; prefer REA's unified interface over calling individual tools directly when both are available."
    } else {
        ""
    };

    format!(
        "{availability}{breakdown} Prefer headless interfaces first: idat/idat64, Ghidra analyzeHeadless, re-mcp backends, radare2/rizin CLI, and format-native tooling such as otool/readelf/objdump/strings. Fall back to GUI workflows only when evidence requires visual inspection or manual annotation. Priority order: IDA > Ghidra > Binary Ninja > radare2/rizin > format-native tooling. For dynamic work prefer Frida plus platform-native debuggers. For memory forensics use volatility3. For behavior fingerprinting use capa/floss.{rea_note}"
    )
}

pub fn build_command(cfg: &Config, agent: &str, target: &Target, tax: &Taxonomy) -> Command {
    build_command_ctx(cfg, agent, target, tax, None)
}

pub fn build_command_ctx(
    cfg: &Config,
    agent: &str,
    target: &Target,
    tax: &Taxonomy,
    context: Option<&str>,
) -> Command {
    let base = agent
        .rfind('.')
        .and_then(|dot| agent[dot + 1..].parse::<usize>().ok().map(|_| &agent[..dot]))
        .unwrap_or(agent);
    let agent_file = cfg.root.join("agents").join(format!("{base}.md"));
    let prompt = task_prompt(cfg, agent, target, tax, context);

    match cfg.runtime.as_str() {
        "codex" => {
            let system = std::fs::read_to_string(&agent_file).unwrap_or_default();
            let merged = if system.trim().is_empty() {
                prompt
            } else {
                format!("{system}\n\n{prompt}")
            };
            let mut c = Command::new("codex");
            c.arg("exec")
                .arg("--skip-git-repo-check")
                .arg("--ephemeral")
                .arg(merged)
                .env("MALVEX_MODEL_HINT", &cfg.model)
                .env("MALVEX_FALLBACK_HINTS", cfg.fallbacks.join(","))
                .stdin(std::process::Stdio::null());
            c
        }
        "custom" => {
            let system = std::fs::read_to_string(&agent_file).unwrap_or_default();
            let merged = if system.trim().is_empty() {
                prompt
            } else {
                format!("{system}\n\n{prompt}")
            };
            let mut c = Command::new("sh");
            c.arg("-lc")
                .arg("if [ -z \"$MALVEX_CUSTOM_CMD\" ]; then echo 'MALVEX_CUSTOM_CMD not set' >&2; exit 2; fi; eval \"$MALVEX_CUSTOM_CMD\"")
                .env("MALVEX_PROMPT", merged)
                .env("MALVEX_MODEL", &cfg.model)
                .env("MALVEX_FALLBACKS", cfg.fallbacks.join(","))
                .env("MALVEX_AGENT", base)
                .env("MALVEX_ROOT", &cfg.root)
                .stdin(std::process::Stdio::null());
            c
        }
        "hermes" => {
            let system = std::fs::read_to_string(&agent_file).unwrap_or_default();
            let merged = if system.trim().is_empty() {
                prompt
            } else {
                format!("{system}\n\n{prompt}")
            };
            let provider = std::env::var("MALVEX_HERMES_PROVIDER").unwrap_or_default();
            let model = std::env::var("MALVEX_HERMES_MODEL").unwrap_or_else(|_| cfg.model.clone());
            let mut c = Command::new("hermes");
            c.arg("run")
                .arg("--prompt")
                .arg(merged);
            if !provider.is_empty() {
                c.arg("--provider").arg(&provider);
            }
            if !model.is_empty() {
                c.arg("--model").arg(&model);
            }
            c.env("MALVEX_AGENT", base)
                .env("MALVEX_ROOT", &cfg.root)
                .stdin(std::process::Stdio::null());
            c
        }
        "ollama" => {
            let system = std::fs::read_to_string(&agent_file).unwrap_or_default();
            let merged = if system.trim().is_empty() {
                prompt
            } else {
                format!("{system}\n\n{prompt}")
            };
            let model = std::env::var("MALVEX_OLLAMA_MODEL").unwrap_or_else(|_| cfg.model.clone());
            let mut c = Command::new("sh");
            c.arg("-c")
                .arg(format!(
                    "printf '%s' \"$MALVEX_PROMPT\" | ollama run {}",
                    shell_escape(&model)
                ))
                .env("MALVEX_PROMPT", merged)
                .env("MALVEX_AGENT", base)
                .env("MALVEX_ROOT", &cfg.root)
                .stdin(std::process::Stdio::null());
            c
        }
        _ => {
            let mut c = Command::new("claude");
            c.arg("-p")
                .arg(prompt)
                .arg("--model")
                .arg(&cfg.model)
                .arg("--fallback-model")
                .arg(cfg.fallbacks.join(","))
                .arg("--dangerously-skip-permissions")
                .arg("--append-system-prompt-file")
                .arg(agent_file)
                .arg("--add-dir")
                .arg(&cfg.root)
                .arg("--output-format")
                .arg(&cfg.output_format)
                .env("IS_SANDBOX", "1")
                .stdin(std::process::Stdio::null());
            c
        }
    }
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

pub fn render_command(c: &Command) -> String {
    let prog = c.get_program().to_string_lossy();
    let args: Vec<String> = c
        .get_args()
        .map(|a| {
            let s = a.to_string_lossy();
            if s.contains(' ') {
                format!("{s:?}")
            } else {
                s.into_owned()
            }
        })
        .collect();
    format!("{prog} {}", args.join(" "))
}

#[derive(Debug)]
pub struct AgentRun {
    pub agent: String,
    pub ok: bool,
    pub output_tail: String,
    pub findings: Vec<Finding>,
    pub raw_path: Option<String>,
}

pub fn run(cfg: &Config, target: &Target) -> anyhow::Result<Vec<AgentRun>> {
    let tax = Taxonomy::load(&cfg.root.join("vulns").join("taxonomy.yaml"))?;
    let mut stages = plan_with_parallel(target, cfg.parallel);
    if let Some(filter) = &cfg.stage_filter {
        stages.retain(|s| filter.iter().any(|n| n == s.name));
    }

    println!(
        "Malvex pipeline — target {} ({}/{}), platform {}",
        target.path,
        target.format,
        target.arch,
        platform_of(target)
    );
    println!(
        "runtime {} | model {} | fallbacks {}{}",
        cfg.runtime,
        cfg.model,
        cfg.fallbacks.join(","),
        if cfg.parallel > 1 {
            format!(" | parallel={}", cfg.parallel)
        } else {
            String::new()
        }
    );

    if !cfg.dry_run {
        let report = exec::run_real(cfg, target, &stages, &tax)?;
        return Ok(report.runs);
    }

    let mut runs = Vec::new();
    for (i, stage) in stages.iter().enumerate() {
        println!(
            "[stage {}/{}] {}{}",
            i + 1,
            stages.len(),
            stage.name,
            stage.gate.map(|g| format!("  ({g})")).unwrap_or_default()
        );
        for agent in &stage.agents {
            let cmd = build_command(cfg, agent, target, &tax);
            println!("    $ {}", render_command(&cmd));
            runs.push(AgentRun {
                agent: agent.clone(),
                ok: true,
                output_tail: "dry-run".into(),
                findings: Vec::new(),
                raw_path: None,
            });
        }
    }
    Ok(runs)
}

pub struct Coverage {
    pub total_vectors: usize,
    pub skills_present: Vec<String>,
    pub skills_missing: Vec<String>,
    pub agents_present: Vec<String>,
    pub agents_missing: Vec<String>,
}

pub fn coverage(cfg: &Config) -> anyhow::Result<Coverage> {
    let tax = Taxonomy::load(&cfg.root.join("vulns").join("taxonomy.yaml"))?;
    let (mut sp, mut sm) = (Vec::new(), Vec::new());
    for v in &tax.vectors {
        let f = cfg.root.join("skills").join(&v.id).join("SKILL.md");
        if f.is_file() {
            sp.push(v.id.clone());
        } else {
            sm.push(v.id.clone());
        }
    }

    let mut agent_names = tax.agents();
    for role in ["validator", "interactive-repl"] {
        if !agent_names.iter().any(|a| a == role) {
            agent_names.push(role.into());
        }
    }
    let (mut ap, mut am) = (Vec::new(), Vec::new());
    for a in &agent_names {
        let f = cfg.root.join("agents").join(format!("{a}.md"));
        if f.is_file() {
            ap.push(a.clone());
        } else {
            am.push(a.clone());
        }
    }

    Ok(Coverage {
        total_vectors: tax.vectors.len(),
        skills_present: sp,
        skills_missing: sm,
        agents_present: ap,
        agents_missing: am,
    })
}
