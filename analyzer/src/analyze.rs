//! Orchestration: load target, run detectors + budgeting, produce output.

use crate::{budget, detectors, rules::RulesConfig, source, wasm};
use anyhow::{Context, Result};
use serde::Serialize;
use soroban_common::{Finding, NetworkLimits};
use std::path::Path;

/// Mode used for analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InputMode {
    /// Analyze a compiled `.wasm` contract.
    Wasm,
    /// Analyze Rust source (file or directory).
    Source,
}

/// Which input was analyzed and how.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSummary {
    /// Resolved target path.
    pub target: String,
    /// Input mode used.
    pub mode: InputMode,
    /// Number of findings.
    pub findings: usize,
    /// Number of entrypoints budgeted (wasm mode only).
    pub entrypoints: usize,
}

/// Full output of one analysis run.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisOutput {
    /// Summary of the run.
    pub summary: AnalysisSummary,
    /// Findings from detectors.
    pub findings: Vec<Finding>,
    /// Budget report (wasm mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<budget::BudgetReport>,
}

/// Analyze a wasm file (or WAT, for tests) on disk.
pub fn analyze_module(
    path: &Path,
    cfg: &RulesConfig,
    limits: NetworkLimits,
) -> Result<AnalysisOutput> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read {}", path.display()))?;
    // Accept WAT for convenience (tests, tiny examples).
    let wasm: Vec<u8> = if path.extension().map(|e| e == "wat").unwrap_or(false) {
        wat::parse_bytes(&bytes)
            .context("parse WAT source")?
            .into_owned()
    } else {
        bytes
    };
    let ir = wasm::parse_module(&wasm)?;
    let file_str = path.display().to_string();

    let mut findings = detectors::run_wasm_detectors(&ir, cfg, &file_str);
    detectors::apply_severity_overrides(&mut findings, cfg);
    findings.sort_by(|a, b| (&a.rule_id, &a.location.function).cmp(&(&b.rule_id, &b.location.function)));

    let coeffs = soroban_common::CostCoefficients::default_coeffs();
    let report = budget::budget_module(&ir, &file_str, limits, coeffs);

    Ok(AnalysisOutput {
        summary: AnalysisSummary {
            target: file_str.clone(),
            mode: InputMode::Wasm,
            findings: findings.len(),
            entrypoints: report.entrypoints.len(),
        },
        findings,
        budget: Some(report),
    })
}

/// Analyze a Rust source file or directory tree.
pub fn analyze_source(
    path: &Path,
    cfg: &RulesConfig,
) -> Result<AnalysisOutput> {
    let facts = source::scan_source_tree(path)?;
    let mut findings = detectors::run_source_detectors(&facts, cfg);
    detectors::apply_severity_overrides(&mut findings, cfg);
    findings.sort_by(|a, b| (&a.rule_id, a.location.line).cmp(&(&b.rule_id, b.location.line)));

    Ok(AnalysisOutput {
        summary: AnalysisSummary {
            target: path.display().to_string(),
            mode: InputMode::Source,
            findings: findings.len(),
            entrypoints: 0,
        },
        findings,
        budget: None,
    })
}
