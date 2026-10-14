//! sasf-core — shared domain types for the Malvex malware-analysis platform.
//!
//! Every stage of the harness (doctor, orchestrator, agents, report) speaks these types.

use serde::{Deserialize, Serialize};

pub mod tool;
pub mod finding;

pub use finding::{Evidence, Finding, Severity, VulnClass, Verdict};
pub use tool::{License, Tool, ToolKind, ToolStatus};

/// Host platform the harness is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Macos,
    Windows,
    Linux,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::Macos
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Macos => "macos",
            Platform::Windows => "windows",
            Platform::Linux => "linux",
        }
    }
}

/// A binary under analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub path: String,
    /// mach-o | pe | elf | fat | unknown
    pub format: String,
    /// x86 | x86_64 | arm64 | ...
    pub arch: String,
    /// Detected packers/protectors: upx | vmprotect | themida | custom | none
    pub shielding: Vec<String>,
    /// Malware family or sample cluster, if identified.
    pub app: String,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    /// When the target lives inside a .app bundle, every Mach-O binary in it
    /// (main, XPC services, Updater, CEF helpers) so agents analyze the whole app.
    #[serde(default)]
    pub bundle_binaries: Vec<String>,
    /// SHA-256 hash per bundle binary: { "sample.exe": "a516...", "loader.exe": "5a12..." }
    #[serde(default)]
    pub bundle_hashes: std::collections::HashMap<String, String>,
}
