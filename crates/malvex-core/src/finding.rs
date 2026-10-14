//! Finding + validation types. Every result the framework emits is a Finding that
//! must pass through a Verdict gate before it reaches a report.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// One of the 50+ attack vectors the framework audits. `id` matches a skill folder
/// under `skills/<id>/` and an entry in `vulns/taxonomy.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnClass {
    pub id: String,
    pub title: String,
    pub cwe: Option<String>,
    /// Platforms this vector applies to.
    pub platforms: Vec<String>,
    /// The agent that owns this vector.
    pub agent: String,
}

/// Validation outcome. A finding never reaches the report as `Confirmed`
/// unless a validator agent reproduced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Reproduced with concrete evidence.
    Confirmed,
    /// Plausible from static signal, not yet reproduced.
    Plausible,
    /// Validator refuted it (mitigated, false positive, unreachable).
    Refuted,
    /// Not yet judged.
    Pending,
}

/// Concrete proof attached to a finding: address, bytes, log line, screenshot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// disasm | decompile | strings | frida-log | poc-run | screenshot | patch
    pub kind: String,
    /// Address / offset if applicable (e.g. "0xacd570").
    pub locus: Option<String>,
    pub detail: String,
    /// Path to an artifact file (poc script, screenshot, patched binary).
    pub artifact: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub vuln_class: String,
    pub title: String,
    pub severity: Severity,
    pub cvss: Option<f32>,
    pub cwe: Option<String>,
    pub verdict: Verdict,
    /// Which binary/app.
    pub target: String,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    /// Path to generated PoC/exploit, if any.
    pub poc: Option<String>,
    pub mitigations: Vec<String>,
    /// Prior analysis/session reference, when this finding re-tests known behavior.
    pub prior_ref: Option<String>,
    /// Attack chains this finding participates in — each a sequence like
    /// "dylib-inject -> XPC connect -> pinning oracle". Nothing is isolated: chains
    /// are what turn medium findings into critical end-to-end exploitation paths.
    #[serde(default)]
    pub chain: Vec<String>,
    /// PoC execution status set by the poc-test stage:
    /// confirmed | fixed | failed | fp-suspect | timeout | skipped | not-run
    #[serde(default)]
    pub poc_status: Option<String>,
}
