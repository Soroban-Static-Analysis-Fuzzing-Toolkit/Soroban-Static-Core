//! Minimal SARIF 2.1.0 output so results land in the GitHub PR review UI.

use crate::{Finding, Severity};
use serde::Serialize;

/// The top-level SARIF log object.
#[derive(Debug, Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: &'static str,
    runs: Vec<Run>,
}

/// Repository the tool's rules are documented in, used for SARIF
/// `informationUri` so consumers link to a real page.
const REPOSITORY_URL: &str =
    "https://github.com/Soroban-Static-Analysis-Fuzzing-Toolkit/Soroban-Static-Core";

/// A single analysis run within the log.
#[derive(Debug, Serialize)]
struct Run {
    tool: Tool,
    results: Vec<ResultSarif>,
}

/// The tool that produced the run.
#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

/// Tool metadata (name, version, rule index).
#[derive(Debug, Serialize)]
struct Driver {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<Rule>,
}

/// A rule referenced by results.
#[derive(Debug, Serialize)]
struct Rule {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<RuleProperties>,
}

/// Extra metadata attached to a rule.
#[derive(Debug, Serialize)]
struct RuleProperties {
    #[serde(rename = "security-severity", skip_serializing_if = "Option::is_none")]
    security_severity: Option<String>,
    tags: Vec<String>,
}

/// One analysis result.
#[derive(Debug, Serialize)]
struct ResultSarif {
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(rename = "ruleIndex")]
    rule_index: usize,
    level: &'static str,
    message: Message,
    locations: Vec<LocationSarif>,
}

/// A result message.
#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

/// A physical location for a result.
#[derive(Debug, Serialize)]
struct LocationSarif {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

/// A physical location: artifact + region.
#[derive(Debug, Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

/// A referenced artifact (file).
#[derive(Debug, Serialize)]
struct ArtifactLocation {
    uri: String,
}

/// A region within an artifact.
#[derive(Debug, Serialize)]
struct Region {
    #[serde(rename = "byteOffset", skip_serializing_if = "Option::is_none")]
    byte_offset: Option<u64>,
    #[serde(rename = "startLine", skip_serializing_if = "Option::is_none")]
    start_line: Option<u64>,
}

impl SarifLog {
    /// Build a SARIF log from analyzer findings.
    pub fn from_findings(driver_name: &str, driver_version: &str, findings: &[Finding]) -> Self {
        // Deterministic, de-duplicated rule list.
        let mut rule_ids: Vec<String> = Vec::new();
        for f in findings {
            if !rule_ids.contains(&f.rule_id) {
                rule_ids.push(f.rule_id.clone());
            }
        }
        rule_ids.sort();
        let rules: Vec<Rule> = rule_ids
            .iter()
            .map(|id| Rule {
                id: id.clone(),
                properties: Some(RuleProperties {
                    security_severity: Some(security_severity_for(id)),
                    tags: vec!["security".into(), "soroban".into()],
                }),
            })
            .collect();

        let results = findings
            .iter()
            .map(|f| ResultSarif {
                rule_id: f.rule_id.clone(),
                rule_index: rule_ids.iter().position(|id| id == &f.rule_id).unwrap_or(0),
                level: level_for(f.severity),
                message: Message {
                    text: message_text(f),
                },
                locations: vec![LocationSarif {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation {
                            uri: f.location.file.replace('\\', "/"),
                        },
                        region: Some(Region {
                            byte_offset: f.location.offset,
                            start_line: f.location.line,
                        }),
                    },
                }],
            })
            .collect();

        Self {
            schema: "https://json.schemastore.org/sarif-2.1.0.json".into(),
            version: "2.1.0",
            runs: vec![Run {
                tool: Tool {
                    driver: Driver {
                        name: driver_name.into(),
                        version: Some(driver_version.into()),
                        information_uri: REPOSITORY_URL.into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

fn level_for(sev: Severity) -> &'static str {
    match sev {
        Severity::Note => "note",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn message_text(f: &Finding) -> String {
    match &f.location.function {
        Some(func) => format!("[{func}] {}", f.message),
        None => f.message.clone(),
    }
}

/// Map rule ids onto GitHub `security-severity` (code-scanning severity).
fn security_severity_for(rule_id: &str) -> String {
    match rule_id {
        "SOR-101" | "SOR-102" | "SOR-103" | "SOR-104" => "9.0".into(),
        "SOR-105" | "SOR-106" => "7.0".into(),
        _ => "5.0".into(),
    }
}
