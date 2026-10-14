//! Tool registry types used by the doctor.

use crate::Platform;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolKind {
    Disassembler,
    Debugger,
    DynamicInstrument,
    Carver,
    Parser,
    Mitm,
    Helper,
    Mcp,
    MemoryForensics,
    NetworkForensics,
    Sandbox,
    ThreatIntel,
    DocumentAnalysis,
    MobileAnalysis,
    FirmwareAnalysis,
    Emulator,
    Unpacker,
    Container,
    Enrichment,
    Honeypot,
    ThreatPlatform,
    SandboxCli,
    Deobfuscator,
    SymbolicExec,
    Visualization,
    YaraEcosystem,
    SigmaEcosystem,
    LinuxForensics,
    MacForensics,
    Classification,
    FileCarver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum License {
    Open,
    Commercial,
}

/// A registry entry: how to detect a tool and how to install it per platform.
/// Serialize-only: it holds `&'static str` literals that cannot be deserialized.
#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub kind: ToolKind,
    pub license: License,
    /// Executable names probed on PATH (first match wins). Empty for MCP-only tools.
    pub probes: &'static [&'static str],
    /// Argument used to print a version line (e.g. "--version").
    pub version_arg: Option<&'static str>,
    /// Install command per platform, or None if not installable there.
    pub install_macos: Option<&'static str>,
    pub install_windows: Option<&'static str>,
    pub install_linux: Option<&'static str>,
    /// MCP server id this tool is reached through, if any (e.g. "ida-pro/idalib").
    pub mcp: Option<&'static str>,
    pub note: &'static str,
}

impl Tool {
    pub fn install_cmd(&self, p: Platform) -> Option<&'static str> {
        match p {
            Platform::Macos => self.install_macos,
            Platform::Windows => self.install_windows,
            Platform::Linux => self.install_linux,
        }
    }
}

/// Result of probing a tool on this host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolStatus {
    pub name: String,
    pub kind: ToolKind,
    pub license: License,
    pub present: bool,
    pub path: Option<String>,
    pub version: Option<String>,
    /// True when the capability is available via a configured MCP server instead of PATH.
    pub via_mcp: Option<String>,
    pub installable: bool,
    pub install_cmd: Option<String>,
    pub note: String,
}
