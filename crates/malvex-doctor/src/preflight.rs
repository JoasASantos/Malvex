//! Preflight — readiness check BEFORE spending time/cost on an analysis.
//!
//! `doctor` answers "which tools exist on this machine". Preflight answers the question
//! that actually matters: **"if I run `malvex run` now, will it work?"** — and when it
//! won't, says exactly what's missing, whether root is needed, and the exact command to fix it.

use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Blocker,
    Degraded,
    Ok,
}

impl Level {
    pub fn tag(self) -> &'static str {
        match self {
            Level::Blocker => "BLOCKS",
            Level::Degraded => "DEGRADES",
            Level::Ok => "OK",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    pub fix: String,
}

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn check_claude(quick: bool) -> Check {
    if !have("claude") {
        return Check {
            name: "claude CLI",
            level: Level::Blocker,
            detail: format!(
                "not found in PATH (PATH={})",
                std::env::var("PATH").unwrap_or_default()
            ),
            fix: "curl -fsSL https://claude.ai/install.sh | bash   (installs to ~/.local/bin; \
                  if already installed, the process PATH may not see it — services like \
                  launchd/systemd/cron don't inherit shell PATH)"
                .into(),
        };
    }
    if quick {
        return Check {
            name: "claude CLI",
            level: Level::Ok,
            detail: "found in PATH (auth/quota not checked: --quick)".into(),
            fix: String::new(),
        };
    }
    let out = Command::new("claude")
        .arg("-p")
        .arg("respond only: ok")
        .arg("--output-format")
        .arg("json")
        .env("IS_SANDBOX", "1")
        .stdin(std::process::Stdio::null())
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if crate::preflight_account_exhausted(&stdout) {
                return Check {
                    name: "claude CLI",
                    level: Level::Blocker,
                    detail: "installed, but account quota exhausted".into(),
                    fix: "wait for quota reset, or use an alternative runtime: \
                          malvex run <target> --runtime hermes   or   --runtime ollama"
                        .into(),
                };
            }
            if !o.status.success() || stdout.trim().is_empty() {
                let err = String::from_utf8_lossy(&o.stderr);
                return Check {
                    name: "claude CLI",
                    level: Level::Blocker,
                    detail: format!(
                        "installed, but test call failed: {}",
                        err.lines().next().unwrap_or("no output").trim()
                    ),
                    fix: "authenticate once interactively: claude".into(),
                };
            }
            Check {
                name: "claude CLI",
                level: Level::Ok,
                detail: "installed, authenticated, quota available".into(),
                fix: String::new(),
            }
        }
        Err(e) => Check {
            name: "claude CLI",
            level: Level::Blocker,
            detail: format!("failed to execute: {e}"),
            fix: "check installation: claude --version".into(),
        },
    }
}

pub fn run(root: &std::path::Path, quick: bool) -> Vec<Check> {
    let mut checks = vec![check_claude(quick)];

    // Rust toolchain
    let cargo = have("cargo");
    checks.push(Check {
        name: "rust toolchain",
        level: if cargo { Level::Ok } else { Level::Degraded },
        detail: if cargo {
            "cargo available".into()
        } else {
            "cargo not found".into()
        },
        fix: if cargo {
            String::new()
        } else {
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y".into()
        },
    });

    // At least one disassembler
    let ida = have("idat64") || have("idat");
    let ghidra = have("analyzeHeadless") || have("ghidraRun") || have("ghidra");
    let r2 = have("r2") || have("radare2");
    let binja = have("binaryninja");
    let has_disasm = ida || ghidra || r2 || binja;
    checks.push(Check {
        name: "disassembler",
        level: if has_disasm {
            Level::Ok
        } else {
            Level::Blocker
        },
        detail: if has_disasm {
            let mut names = Vec::new();
            if ida { names.push("IDA"); }
            if ghidra { names.push("Ghidra"); }
            if r2 { names.push("radare2"); }
            if binja { names.push("Binary Ninja"); }
            format!("available: {}", names.join(", "))
        } else {
            "no disassembler found (IDA, Ghidra, radare2, Binary Ninja)".into()
        },
        fix: if has_disasm {
            String::new()
        } else {
            "macOS: brew install radare2 ghidra | Linux: sudo apt-get install -y radare2 | \
             or install IDA/Ghidra/Binary Ninja manually"
                .into()
        },
    });

    // C/C++ compiler
    let cc = have("clang") || have("cc") || have("gcc");
    checks.push(Check {
        name: "C/C++ compiler",
        level: if cc { Level::Ok } else { Level::Degraded },
        detail: if cc {
            "available".into()
        } else {
            "none of clang/cc/gcc found".into()
        },
        fix: if cc {
            String::new()
        } else {
            "macOS: xcode-select --install | Linux: sudo apt-get install -y build-essential".into()
        },
    });

    // Python
    let py = have("python3") || have("python");
    checks.push(Check {
        name: "python3",
        level: if py { Level::Ok } else { Level::Degraded },
        detail: if py {
            "available".into()
        } else {
            "not found".into()
        },
        fix: if py {
            String::new()
        } else {
            "macOS: brew install python3 | Linux: sudo apt-get install -y python3 python3-pip"
                .into()
        },
    });

    // agents/ directory
    let agents_dir = root.join("agents");
    let has_agents = agents_dir.is_dir()
        && std::fs::read_dir(&agents_dir)
            .ok()
            .map(|rd| rd.flatten().any(|e| {
                e.path().extension().map(|x| x == "md").unwrap_or(false)
            }))
            .unwrap_or(false);
    checks.push(Check {
        name: "agents/ directory",
        level: if has_agents {
            Level::Ok
        } else {
            Level::Blocker
        },
        detail: if has_agents {
            format!("found at {}", agents_dir.display())
        } else {
            format!("missing or empty at {}", agents_dir.display())
        },
        fix: if has_agents {
            String::new()
        } else {
            "run from the malvex repo root, or pass --root <path-to-repo>".into()
        },
    });

    // skills/ directory
    let skills_dir = root.join("skills");
    let has_skills = skills_dir.is_dir();
    checks.push(Check {
        name: "skills/ directory",
        level: if has_skills {
            Level::Ok
        } else {
            Level::Degraded
        },
        detail: if has_skills {
            format!("found at {}", skills_dir.display())
        } else {
            format!("missing at {}", skills_dir.display())
        },
        fix: if has_skills {
            String::new()
        } else {
            "skills/ directory should exist at repo root with SKILL.md files".into()
        },
    });

    // vulns/taxonomy.yaml
    let taxonomy = root.join("vulns").join("taxonomy.yaml");
    let has_taxonomy = taxonomy.is_file();
    checks.push(Check {
        name: "vulns/taxonomy.yaml",
        level: if has_taxonomy {
            Level::Ok
        } else {
            Level::Blocker
        },
        detail: if has_taxonomy {
            "found".into()
        } else {
            format!("missing at {}", taxonomy.display())
        },
        fix: if has_taxonomy {
            String::new()
        } else {
            "run from the malvex repo root, or pass --root <path-to-repo>".into()
        },
    });

    // Write permission
    let probe = root.join(".malvex-preflight-write-test");
    let writable = std::fs::write(&probe, b"x").is_ok();
    std::fs::remove_file(&probe).ok();
    checks.push(Check {
        name: "write permission",
        level: if writable {
            Level::Ok
        } else {
            Level::Blocker
        },
        detail: format!(
            "{} ({})",
            if writable { "writable" } else { "NO write permission" },
            root.display()
        ),
        fix: if writable {
            String::new()
        } else {
            "fix directory ownership instead of running as root: \
             sudo chown -R \"$USER\" <project-root>"
                .into()
        },
    });

    // Root check
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false);
    checks.push(Check {
        name: "process privilege",
        level: if is_root {
            Level::Degraded
        } else {
            Level::Ok
        },
        detail: if is_root {
            "running as ROOT — not required for static analysis or the web panel".into()
        } else {
            "normal user (recommended)".into()
        },
        fix: if is_root {
            "run as a normal user. Root is only needed for specific dynamic instrumentation \
             (attaching to third-party processes) and system package managers."
                .into()
        } else {
            String::new()
        },
    });

    checks
}

pub fn summarize(checks: &[Check]) -> (String, i32) {
    let blockers = checks.iter().filter(|c| c.level == Level::Blocker).count();
    let degraded = checks
        .iter()
        .filter(|c| c.level == Level::Degraded)
        .count();
    if blockers > 0 {
        (
            format!(
                "{blockers} blocker(s) and {degraded} warning(s) — `malvex run` will NOT produce useful analysis."
            ),
            1,
        )
    } else if degraded > 0 {
        (
            format!("ready to run, with {degraded} warning(s) — see above for details."),
            0,
        )
    } else {
        ("all clear — ready to analyze.".to_string(), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_flags_blockers_with_nonzero_exit() {
        let checks = vec![Check {
            name: "x",
            level: Level::Blocker,
            detail: String::new(),
            fix: String::new(),
        }];
        let (msg, code) = summarize(&checks);
        assert_eq!(code, 1);
        assert!(msg.contains("will NOT"));
    }

    #[test]
    fn summarize_is_ok_when_only_degraded() {
        let checks = vec![Check {
            name: "x",
            level: Level::Degraded,
            detail: String::new(),
            fix: String::new(),
        }];
        let (_, code) = summarize(&checks);
        assert_eq!(code, 0);
    }
}
