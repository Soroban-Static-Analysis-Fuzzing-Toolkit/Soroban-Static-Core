//! Versioned, community-contributable detector configuration.
//!
//! Detector rules are configured per-id in a `soroban-analyzer.toml` file:
//!
//! ```toml
//! [rules.SOR-101]
//! enabled = true
//! severity = "error"
//! ```
//!
//! One detector per PR: add a `RuleMeta` entry in `detectors.rs` and bump
//! the minor version of this file's schema below.

use serde::{Deserialize, Serialize};
use soroban_common::Severity;
use std::collections::BTreeMap;

/// Schema version of the rules configuration format.
pub const RULES_SCHEMA_VERSION: &str = "1";

/// Default configuration shipped with the tool.
pub const DEFAULT_CONFIG_TOML: &str = r#"# soroban-analyzer rule configuration
schema_version = "1"

# Disable or re-severity individual detectors here.
# Example:
# [rules.SOR-105]
# enabled = false
"#;

/// Per-rule override.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleOverride {
    /// Force-enable or force-disable the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Override the rule's default severity ("note" | "warning" | "error").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
}

/// Full rules configuration file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Schema version; must match `RULES_SCHEMA_VERSION`.
    #[serde(default)]
    pub schema_version: Option<String>,
    /// Overrides keyed by rule id, e.g. `SOR-101`.
    #[serde(default)]
    pub rules: BTreeMap<String, RuleOverride>,
}

impl RulesConfig {
    /// Parse config from TOML text.
    pub fn from_toml_str(s: &str) -> anyhow::Result<Self> {
        let cfg: RulesConfig = toml::from_str(s)?;
        if let Some(v) = &cfg.schema_version {
            if v != RULES_SCHEMA_VERSION {
                anyhow::bail!(
                    "unsupported rules schema_version {v} (expected {RULES_SCHEMA_VERSION})"
                );
            }
        }
        Ok(cfg)
    }

    /// Whether the rule is enabled (default true unless overridden).
    pub fn is_enabled(&self, rule_id: &str) -> bool {
        self.rules.get(rule_id).and_then(|o| o.enabled).unwrap_or(true)
    }

    /// Effective severity for a rule after overrides.
    pub fn severity(&self, rule_id: &str, default: Severity) -> Severity {
        self.rules.get(rule_id).and_then(|o| o.severity).unwrap_or(default)
    }

    /// Write the default config template to a string.
    pub fn template() -> &'static str {
        DEFAULT_CONFIG_TOML
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_overrides() {
        let cfg = RulesConfig::from_toml_str(
            r#"
            schema_version = "1"
            [rules.SOR-105]
            enabled = false
            [rules.SOR-106]
            severity = "note"
            "#,
        )
        .unwrap();
        assert!(!cfg.is_enabled("SOR-105"));
        assert!(cfg.is_enabled("SOR-101"));
        assert_eq!(cfg.severity("SOR-106", Severity::Warning), Severity::Note);
    }
}
