//! Shared types for the Soroban analyzer: findings, network limits and SARIF output.

pub mod limits;
pub mod sarif;

pub use limits::{CostCoefficients, NetworkLimits};

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity of a reported finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Style / informational.
    Note,
    /// Potential issue, may be intentional.
    Warning,
    /// Likely a real bug or security issue.
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Note => "note",
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        f.write_str(s)
    }
}

/// A rule that fired while analyzing a target.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    /// Stable rule id, e.g. `SOR-101`.
    pub rule_id: String,
    /// Short human-readable title.
    pub message: String,
    /// Optional longer explanation with remediation advice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Severity of the finding.
    pub severity: Severity,
    /// Location of the finding.
    pub location: Location,
}

/// Where a finding occurred.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Location {
    /// File the finding relates to (wasm path, or source file for src mode).
    pub file: String,
    /// Function the finding relates to (wasm function index/name, or rust fn).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Byte offset in the wasm module (wasm mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// 1-based line number (source mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
}

impl Location {
    /// Location pointing at a whole file.
    pub fn file(file: impl Into<String>) -> Self {
        Self { file: file.into(), function: None, offset: None, line: None }
    }
}
