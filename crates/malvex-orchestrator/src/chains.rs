//! Loader for vulns/attack-chains.yaml — the curated attack-chain library. Agents get the
//! platform-relevant chains as context; the graph builder seeds any chain whose steps are
//! present in the findings.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct AttackChain {
    pub id: String,
    pub title: String,
    pub platform: String,
    pub steps: Vec<String>,
    #[serde(default)]
    pub precondition: Option<String>,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub composite_cvss: Option<f32>,
    #[serde(default)]
    pub prior_ref: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainLib {
    pub version: u32,
    pub chains: Vec<AttackChain>,
}

impl ChainLib {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Ok(serde_yaml::from_str(&std::fs::read_to_string(path)?)?)
    }

    /// Best-effort load from a repo root; empty on any error so callers can ignore it.
    pub fn load_or_empty(root: &Path) -> Self {
        Self::load(&root.join("vulns").join("attack-chains.yaml"))
            .unwrap_or(ChainLib { version: 0, chains: Vec::new() })
    }

    /// Chains for a platform (matches the platform token or "any").
    pub fn for_platform(&self, platform: &str) -> Vec<&AttackChain> {
        self.chains
            .iter()
            .filter(|c| c.platform == platform || c.platform == "any")
            .collect()
    }
}
