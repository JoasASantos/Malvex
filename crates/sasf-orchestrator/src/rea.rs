//! REA integration — bridge between Malvex and the REA MCP server.
//!
//! REA (Reverse Engineer Anything) provides base RE capabilities:
//! Ghidra, IDA, radare2, Frida, .NET, Android, browser/electron.
//! Malvex installs REA automatically and adds malware-specific layers on top:
//! YARA/Sigma detection, memory forensics, sandboxing, threat intelligence,
//! OSINT, evidence-driven pipeline with specialized agents.

use std::process::Command;

pub struct ReaBridge {
    available: bool,
}

impl ReaBridge {
    pub fn new() -> Self {
        let available = Command::new("npx")
            .args(["rea", "--version"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Self { available }
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    pub fn ensure_installed() -> bool {
        if Self::new().available {
            return true;
        }
        let has_npm = Command::new("sh")
            .arg("-c")
            .arg("command -v npm")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !has_npm {
            return false;
        }
        Command::new("npm")
            .args(["install", "-g", "rea-agents"])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn setup_agents() -> bool {
        Command::new("npx")
            .args(["rea-agents", "setup"])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn capabilities(&self) -> Vec<&'static str> {
        if !self.available {
            return vec![];
        }
        vec![
            "binary-disassembly",
            "binary-decompilation",
            "function-listing",
            "string-extraction",
            "import-export-analysis",
            "xref-analysis",
            "frida-hooking",
            "dotnet-decompilation",
            "android-apk-analysis",
            "electron-inspection",
            "browser-analysis",
        ]
    }
}
