//! Loader for vulns/taxonomy.yaml.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Vector {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub sev: Option<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    pub agent: String,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub prior_ref: Option<String>,
    #[serde(default)]
    pub detect: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Taxonomy {
    pub version: u32,
    pub vectors: Vec<Vector>,
}

impl Taxonomy {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&text)?)
    }

    /// Vectors owned by an agent.
    pub fn for_agent<'a>(&'a self, agent: &str) -> Vec<&'a Vector> {
        self.vectors.iter().filter(|v| v.agent == agent).collect()
    }

    /// Vectors applicable to a platform (empty platforms => all).
    pub fn for_platform<'a>(&'a self, platform: &str) -> Vec<&'a Vector> {
        self.vectors
            .iter()
            .filter(|v| v.platforms.is_empty() || v.platforms.iter().any(|p| p == platform))
            .collect()
    }

    /// Distinct agent names that own at least one vector.
    pub fn agents(&self) -> Vec<String> {
        let mut a: Vec<String> = self.vectors.iter().map(|v| v.agent.clone()).collect();
        a.sort();
        a.dedup();
        a
    }
}
