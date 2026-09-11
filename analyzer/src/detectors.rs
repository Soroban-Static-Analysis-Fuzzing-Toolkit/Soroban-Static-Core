//! Detector engine: Soroban-specific vulnerability patterns.
//!
//! One detector per PR: add a `RuleMeta` entry to `RULES`, a check function,
//! and wire it from `check_wasm`/`check_source`. Keep checks conservative —
//! a detector that cries wolf gets disabled by users.

use crate::source::SourceFacts;
use crate::wasm::ModuleIr;
use soroban_common::{Finding, Location, Severity};

/// Static metadata for one detector.
#[derive(Debug, Clone)]
pub struct RuleMeta {
    /// Stable id used in SARIF output and config, e.g. `SOR-101`.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// One-line description.
    pub description: &'static str,
    /// Default severity before user overrides.
    pub default_severity: Severity,
    /// Kind of input the detector consumes.
    pub kind: RuleKind,
}

/// Which input a detector runs against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// Needs the compiled wasm module.
    Wasm,
    /// Needs Rust source (src mode).
    Source,
    /// Runs on both.
    Both,
}

/// All registered detectors, in id order.
pub fn all_rules() -> Vec<RuleMeta> {
    vec![
        RuleMeta {
            id: "SOR-101",
            name: "missing-require-auth",
            description: "Exported contract entrypoint performs state-changing host calls without requiring auth",
            default_severity: Severity::Error,
            kind: RuleKind::Wasm,
        },
        RuleMeta {
            id: "SOR-102",
            name: "storage-type-confusion",
            description: "Persistent or instance storage used where temporary was expected (storage-type misuse)",
            default_severity: Severity::Error,
            kind: RuleKind::Both,
        },
        RuleMeta {
            id: "SOR-103",
            name: "unchecked-token-arithmetic",
            description: "Token amounts flow into arithmetic without overflow checks",
            default_severity: Severity::Error,
            kind: RuleKind::Both,
        },
        RuleMeta {
            id: "SOR-104",
            name: "unbounded-loop-over-storage",
            description: "Loop iterates over storage-derived data without a static bound",
            default_severity: Severity::Error,
            kind: RuleKind::Both,
        },
        RuleMeta {
            id: "SOR-105",
            name: "read-count-estimate",
            description: "Estimated ledger reads for an entrypoint approach or exceed the 200-read ceiling",
            default_severity: Severity::Warning,
            kind: RuleKind::Wasm,
        },
        RuleMeta {
            id: "SOR-106",
            name: "unbounded-memory-growth",
            description: "memory.grow in a loop can exceed the contract memory cap",
            default_severity: Severity::Warning,
            kind: RuleKind::Wasm,
        },
    ]
}

/// Run all wasm detectors against a module.
pub fn run_wasm_detectors(ir: &ModuleIr, cfg: &crate::rules::RulesConfig, file: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in all_rules() {
        if !cfg.is_enabled(rule.id) {
            continue;
        }
        let findings = match rule.kind {
            RuleKind::Wasm | RuleKind::Both => match rule.id {
                "SOR-101" => sor_101_missing_require_auth(ir, &rule, file),
                "SOR-105" => sor_105_read_count_estimate(ir, &rule, file),
                "SOR-106" => sor_106_unbounded_memory(ir, &rule, file),
                _ => vec![],
            },
            RuleKind::Source => vec![],
        };
        out.extend(findings);
    }
    out
}

/// Run all source detectors against collected source facts.
pub fn run_source_detectors(
    facts: &SourceFacts,
    cfg: &crate::rules::RulesConfig,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in all_rules() {
        if !cfg.is_enabled(rule.id) {
            continue;
        }
        let findings = match rule.kind {
            RuleKind::Source | RuleKind::Both => match rule.id {
                "SOR-102" => sor_102_storage_confusion(facts, &rule),
                "SOR-103" => sor_103_unchecked_arith(facts, &rule),
                "SOR-104" => sor_104_unbounded_loop(facts, &rule),
                _ => vec![],
            },
            RuleKind::Wasm => vec![],
        };
        out.extend(findings);
    }
    out
}

/// Apply severity overrides from config.
pub fn apply_severity_overrides(findings: &mut [Finding], cfg: &crate::rules::RulesConfig) {
    for f in findings.iter_mut() {
        if let Some(rule) = all_rules().iter().find(|r| r.id == f.rule_id) {
            f.severity = cfg.severity(f.rule_id.as_str(), rule.default_severity);
        }
    }
}

// ---------------------------------------------------------------------------
// SOR-101: missing require_auth
// ---------------------------------------------------------------------------

/// Host imports that mutate contract state and therefore require authorization.
const STATE_CHANGING_HOST_FNS: &[&str] = &[
    "put_contract_data",
    "del_contract_data",
    "extend_contract_data_ttl",
    "bump_contract_data_ttl",
    "create_contract",
    "upload_wasm",
];

fn sor_101_missing_require_auth(
    ir: &ModuleIr,
    rule: &RuleMeta,
    file: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    // For each defined function: which host fns does it (transitively) reach?
    let n = ir.funcs.len();
    let reach_host: Vec<bool> = (0..n)
        .map(|i| reaches_host_state_change(ir, i))
        .collect();

    for (idx, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() || f.exports.is_empty() {
            continue;
        }
        let calls_require_auth = f.calls.iter().any(|&c| {
            ir.funcs
                .get(c as usize)
                .and_then(|t| t.import.as_ref())
                .map(|(_, n)| n.ends_with("require_auth"))
                .unwrap_or(false)
        });
        if reach_host[idx] && !calls_require_auth {
            out.push(Finding {
                rule_id: rule.id.to_string(),
                message: format!(
                    "entrypoint `{}` mutates storage/state but never calls require_auth",
                    f.display_name(idx)
                ),
                help: Some(
                    "add env.require_auth() for each account/contract authorized to perform this action".into(),
                ),
                severity: rule.default_severity,
                location: Location {
                    file: file.to_string(),
                    function: Some(f.display_name(idx)),
                    offset: f.body_offset,
                    line: None,
                },
            });
        }
    }
    out
}

/// Does function `idx` transitively reach a state-changing host import?
fn reaches_host_state_change(ir: &ModuleIr, idx: usize) -> bool {
    let n = ir.funcs.len();
    let mut seen = vec![false; n];
    let mut stack = vec![idx as u32];
    while let Some(cur) = stack.pop() {
        let cu = cur as usize;
        if seen[cu] {
            continue;
        }
        seen[cu] = true;
        if let Some((_, name)) = &ir.funcs[cu].import {
            if STATE_CHANGING_HOST_FNS.iter().any(|s| name.contains(s)) {
                return true;
            }
            continue;
        }
        for &c in &ir.funcs[cu].calls {
            if (c as usize) < n && !seen[c as usize] {
                stack.push(c);
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// SOR-105: read-count estimate vs the 200-read ceiling
// ---------------------------------------------------------------------------

/// Host imports that perform ledger reads.
const READ_HOST_FNS: &[&str] = &["get_contract_data", "has_contract_data"];

/// Estimated reads per call of a read-performing host fn (conservative).
const EST_READS_PER_CALL: u64 = 1;

fn sor_105_read_count_estimate(
    ir: &ModuleIr,
    rule: &RuleMeta,
    file: &str,
) -> Vec<Finding> {
    let limits = soroban_common::NetworkLimits::mainnet();
    let mut out = Vec::new();

    for (idx, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() || f.exports.is_empty() {
            continue;
        }
        let base = count_direct_reads(ir, idx);
        if base == 0 {
            continue;
        }
        // Loops multiply: without knowing trip counts, assume 2x for
        // functions with backedges (documented heuristic).
        let estimate = if f.loop_backedges > 0 { base * 2 } else { base };
        let pct = estimate * 100 / limits.max_reads.max(1);
        if estimate >= limits.max_reads {
            out.push(Finding {
                rule_id: rule.id.to_string(),
                message: format!(
                    "entrypoint `{}` estimated at ~{estimate} ledger reads (ceiling {})",
                    f.display_name(idx),
                    limits.max_reads
                ),
                help: Some("batch reads, cache in a single Map entry, or restructure storage keys".into()),
                severity: Severity::Error,
                location: Location {
                    file: file.to_string(),
                    function: Some(f.display_name(idx)),
                    offset: f.body_offset,
                    line: None,
                },
            });
        } else if pct >= 70 {
            out.push(Finding {
                rule_id: rule.id.to_string(),
                message: format!(
                    "entrypoint `{}` estimated at ~{estimate} ledger reads (~{pct}% of the {} ceiling)",
                    f.display_name(idx),
                    limits.max_reads
                ),
                help: None,
                severity: Severity::Warning,
                location: Location {
                    file: file.to_string(),
                    function: Some(f.display_name(idx)),
                    offset: f.body_offset,
                    line: None,
                },
            });
        }
    }
    out
}

/// Read-count estimate for budgeting: same heuristic the read-count detector
/// uses, exposed for the budget module.
pub fn count_reads_for_budget(ir: &ModuleIr, idx: usize) -> u64 {
    count_direct_reads(ir, idx)
}

/// Sum direct read-host call sites reachable within the function's own body
/// plus one call level into helpers (kept shallow intentionally).
fn count_direct_reads(ir: &ModuleIr, idx: usize) -> u64 {
    let f = &ir.funcs[idx];
    let mut total = 0u64;
    for &c in &f.calls {
        if let Some(t) = ir.funcs.get(c as usize) {
            match &t.import {
                Some((_, name)) => {
                    if READ_HOST_FNS.iter().any(|s| name.contains(s)) {
                        total += EST_READS_PER_CALL;
                    }
                }
                None => {
                    // One level of helper inlining.
                    for &c2 in &t.calls {
                        if let Some(t2) = ir.funcs.get(c2 as usize) {
                            if let Some((_, n2)) = &t2.import {
                                if READ_HOST_FNS.iter().any(|s| n2.contains(s)) {
                                    total += EST_READS_PER_CALL;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    total
}

// ---------------------------------------------------------------------------
// SOR-106: unbounded memory growth
// ---------------------------------------------------------------------------

fn sor_106_unbounded_memory(
    ir: &ModuleIr,
    rule: &RuleMeta,
    file: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (idx, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() {
            continue;
        }
        if f.memory_grow_sites > 0 && f.loop_backedges > 0 {
            out.push(Finding {
                rule_id: rule.id.to_string(),
                message: format!(
                    "function `{}` calls memory.grow inside (or near) a loop; memory can exceed the cap",
                    f.display_name(idx)
                ),
                help: Some("bound allocations before the loop; Soroban contracts have a fixed memory ceiling".into()),
                severity: rule.default_severity,
                location: Location {
                    file: file.to_string(),
                    function: Some(f.display_name(idx)),
                    offset: f.body_offset,
                    line: None,
                },
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Source-mode detectors
// ---------------------------------------------------------------------------

/// Check SOR-102: storage-type confusion heuristics on source.
fn sor_102_storage_confusion(facts: &SourceFacts, rule: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in &facts.functions {
        for (i, lit) in f.storage_literals.iter().enumerate() {
            // Heuristic 1: user data stored as Instance where later ops suggest
            // per-item data (instance storage is meant for small config data).
            if lit.spec == "Instance" && f.instance_keys.len() > 8 {
                out.push(Finding {
                    rule_id: rule.id.to_string(),
                    message: format!(
                        "`{}` stores many distinct keys ({}) in Instance storage; instance storage is for small bounded data",
                        f.name, f.instance_keys.len()
                    ),
                    help: Some("consider Persistent for per-item entries".into()),
                    severity: rule.default_severity,
                    location: Location {
                        file: f.file.clone(),
                        function: Some(f.name.clone()),
                        offset: None,
                        line: Some(lit.line as u64),
                    },
                });
            }
            // Heuristic 2: TTL extension mismatch — bumping TTL on Temporary.
            if f.ttl_bump_lines.contains(&(lit.line as u64)) && lit.spec == "Temporary" {
                out.push(Finding {
                    rule_id: rule.id.to_string(),
                    message: format!(
                        "`{}` extends TTL of Temporary storage; consider Persistent for data meant to outlive short windows",
                        f.name
                    ),
                    help: None,
                    severity: Severity::Warning,
                    location: Location {
                        file: f.file.clone(),
                        function: Some(f.name.clone()),
                        offset: None,
                        line: Some(lit.line as u64),
                    },
                });
            }
            let _ = i;
        }
    }
    out
}

/// Check SOR-103: unchecked arithmetic on token amounts.
fn sor_103_unchecked_arith(facts: &SourceFacts, rule: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in &facts.functions {
        // A function that transfers tokens and does raw arithmetic on amounts.
        let does_transfer = f.calls.iter().any(|c| {
            let c = c.as_str();
            c == "transfer" || c.ends_with("::transfer") || c.ends_with("transfer(")
        });
        if !does_transfer {
            continue;
        }
        for (line, op) in &f.raw_arith_on_amounts {
            out.push(Finding {
                rule_id: rule.id.to_string(),
                message: format!(
                    "`{}` performs unchecked `{}` on a token amount; use checked_* or overflowing_*",
                    f.name, op
                ),
                help: Some("checked_add/checked_sub on i128 amounts, or rely on soroban-sdk's checked ops".into()),
                severity: rule.default_severity,
                location: Location {
                    file: f.file.clone(),
                    function: Some(f.name.clone()),
                    offset: None,
                    line: Some(*line as u64),
                },
            });
        }
    }
    out
}

/// Check SOR-104: unbounded loops over storage.
fn sor_104_unbounded_loop(facts: &SourceFacts, rule: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in &facts.functions {
        for l in &f.loops {
            // Loop bound is "static" if the loop range end is a literal or
            // the loop iterates over a locally-constructed Vec.
            let bound_is_static = l
                .range_end_hint
                .as_deref()
                .map(is_static_bound)
                .unwrap_or(false);
            let iterates_local_vec = l
                .range_end_hint
                .as_deref()
                .map(|h| h.starts_with('&'))
                .unwrap_or(false);
            if bound_is_static || iterates_local_vec {
                continue;
            }
            // Otherwise the range end comes from a variable/expr we can't
            // resolve — flag it if the function also touches storage.
            if f.storage_literals.is_empty() {
                continue;
            }
            out.push(Finding {
                rule_id: rule.id.to_string(),
                message: format!(
                    "`{}` loops over an unbounded range while touching storage; worst-case cost grows with stored data",
                    f.name
                ),
                help: Some("paginate, or bound the iteration with a constant chunk size".into()),
                severity: rule.default_severity,
                location: Location {
                    file: f.file.clone(),
                    function: Some(f.name.clone()),
                    offset: None,
                    line: Some(l.line as u64),
                },
            });
        }
    }
    out
}

/// Whether a range-end hint looks statically bounded.
fn is_static_bound(hint: &str) -> bool {
    let h = hint.trim();
    h.parse::<u64>().is_ok()
        || h == "CHUNK"
        || h == "MAX"
        || h.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
}

