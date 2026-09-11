//! Versioned, community-contributable detector configuration.
//!
//! Detector rules are configured per-id in a `soroban-analyzer.toml` file:
//!
//! ```toml
//! # Both wasm and source modes are supported.
//! [rules.SOR-101]
//! enabled = true
//! severity = "error"
//! ```
//!
//! One detector per PR: add a `RuleMeta` entry in `detectors.rs` and bump
//! the minor version of this file's schema below.

use crate::detectors::{all_rules, RuleKind};
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
///
/// Unknown fields are rejected so a typo (`enable` for `enabled`) fails loudly
/// instead of silently doing nothing.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
        // Reject unknown rule ids: a mis-spelled id would otherwise be a
        // silent no-op, which undermines `--fail-on` gating in CI.
        let known: Vec<&str> = all_rules().iter().map(|r| r.id).collect();
        let unknown: Vec<&str> = cfg
            .rules
            .keys()
            .map(String::as_str)
            .filter(|id| !known.contains(id))
            .collect();
        if !unknown.is_empty() {
            anyhow::bail!(
                "unknown rule id(s) in config: {} (known rules: {})",
                unknown.join(", "),
                known.join(", ")
            );
        }
        Ok(cfg)
    }

    /// Whether the rule is enabled (default true unless overridden).
    pub fn is_enabled(&self, rule_id: &str) -> bool {
        self.rules
            .get(rule_id)
            .and_then(|o| o.enabled)
            .unwrap_or(true)
    }

    /// Effective severity for a rule after overrides.
    pub fn severity(&self, rule_id: &str, default: Severity) -> Severity {
        self.rules
            .get(rule_id)
            .and_then(|o| o.severity)
            .unwrap_or(default)
    }

    /// The severity the user configured for a rule, if any.
    ///
    /// Used by the detector engine so an explicit override wins while
    /// detector-chosen severities (for example SOR-105 escalating to error
    /// above the read ceiling) are otherwise preserved.
    pub fn explicit_severity(&self, rule_id: &str) -> Option<Severity> {
        self.rules.get(rule_id).and_then(|o| o.severity)
    }

    /// Write the default config template to a string.
    pub fn template() -> &'static str {
        DEFAULT_CONFIG_TOML
    }
}

/// Render a documented config file covering every registered rule.
///
/// Each rule appears with its default severity and the input mode it runs in,
/// with the override entry commented out so the file is valid as emitted.
/// Kept in sync with `all_rules()` automatically.
pub fn render_config_template() -> String {
    let mut s = String::new();
    s.push_str("# soroban-analyzer rule configuration\n");
    s.push_str(&format!("schema_version = \"{RULES_SCHEMA_VERSION}\"\n\n"));
    s.push_str("# Uncomment an entry below to override a rule's default.\n");
    s.push_str("# `both` rules run on compiled wasm and on Rust source.\n\n");
    for rule in all_rules() {
        let kind = match rule.kind {
            RuleKind::Wasm => "wasm",
            RuleKind::Source => "source",
            RuleKind::Both => "both",
        };
        s.push_str(&format!(
            "# {:<8} {:<7} {:<6} {}\n",
            rule.id, rule.default_severity, kind, rule.description
        ));
        s.push_str(&format!(
            "# [rules.{}]\n# enabled = true\n# severity = \"{}\"\n\n",
            rule.id, rule.default_severity
        ));
    }
    s
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

    #[test]
    fn rejects_unknown_rule_ids() {
        let err = RulesConfig::from_toml_str(
            r#"
            schema_version = "1"
            [rules.SOR-999]
            enabled = false
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("SOR-999"), "{err}");
    }

    #[test]
    fn rejects_misspelled_fields() {
        let err = RulesConfig::from_toml_str(
            r#"
            schema_version = "1"
            [rules.SOR-105]
            enable = false
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("enable"), "{err}");
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let err = RulesConfig::from_toml_str("schema_version = \"2\"")
            .unwrap_err()
            .to_string();
        assert!(err.contains("schema_version"), "{err}");
    }

    #[test]
    fn explicit_severity_only_reports_configured_rules() {
        let cfg = RulesConfig::from_toml_str(
            r#"
            schema_version = "1"
            [rules.SOR-106]
            severity = "note"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.explicit_severity("SOR-106"), Some(Severity::Note));
        assert_eq!(cfg.explicit_severity("SOR-101"), None);
    }

    #[test]
    fn template_documents_every_rule_and_round_trips() {
        let template = render_config_template();
        for rule in all_rules() {
            assert!(
                template.contains(rule.id),
                "template is missing {}",
                rule.id
            );
        }
        // Every override entry is commented out, so the emitted file parses.
        RulesConfig::from_toml_str(&template).expect("template must be valid TOML");
    }
}
