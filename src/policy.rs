use crate::event::EventKind;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Clone, Debug, Deserialize)]
pub struct PolicySet {
    pub version: u32,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default)]
    pub score: u32,
    pub r#match: Match,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

fn default_severity() -> Severity {
    Severity::Medium
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Match {
    pub event: Option<EventKind>,
    pub executable_prefix: Option<String>,
    pub executable_suffix: Option<String>,
    pub comm: Option<String>,
    pub parent_comm: Option<String>,
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub target_uid: Option<u32>,
    pub container: Option<bool>,
    pub path_prefix: Option<String>,
    pub path_exact: Option<String>,
    pub parent_executable_suffix: Option<String>,
}

impl PolicySet {
    pub fn load(path: &Path) -> Result<Self> {
        let input = fs::read_to_string(path).context("unable to read policy YAML")?;
        let rules: Self = serde_yaml::from_str(&input).context("invalid policy YAML")?;
        anyhow::ensure!(
            rules.version == 1,
            "unsupported policy version {}",
            rules.version
        );
        Ok(rules)
    }
}
