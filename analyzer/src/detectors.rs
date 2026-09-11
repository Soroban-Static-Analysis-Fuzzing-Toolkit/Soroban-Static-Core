//! Detector engine: Soroban-specific vulnerability patterns.
//!
//! One detector per PR: add a `RuleMeta` entry to `all_rules()`, write a check
//! function, and register it in `wasm_check`/`source_check`. The
//! `every_registered_rule_is_wired` test fails when those get out of sync, so a
//! rule can no longer be registered-but-never-run. Keep checks conservative —
//! a detector that cries wolf gets disabled by users.

use crate::rules::RulesConfig;
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

impl RuleKind {
    /// Whether this kind runs against a compiled wasm module.
    pub fn runs_on_wasm(self) -> bool {
        matches!(self, RuleKind::Wasm | RuleKind::Both)
    }

    /// Whether this kind runs against Rust source.
    pub fn runs_on_source(self) -> bool {
        matches!(self, RuleKind::Source | RuleKind::Both)
    }
}

/// All registered detectors, in id order.
pub fn all_rules() -> Vec<RuleMeta> {
    vec![
        RuleMeta {
            id: "SOR-101",
            name: "missing-require-auth",
            description: "Contract entrypoint performs state-changing operations without requiring auth",
            default_severity: Severity::Error,
            kind: RuleKind::Both,
        },
        RuleMeta {
            id: "SOR-102",
            name: "storage-type-confusion",
            description: "Persistent or instance storage used where temporary was expected (storage-type misuse)",
            default_severity: Severity::Error,
            // Source-only: the wasm front-end has no storage-type model yet.
            kind: RuleKind::Source,
        },
        RuleMeta {
            id: "SOR-103",
            name: "unchecked-token-arithmetic",
            description: "Token amounts flow into arithmetic without overflow checks",
            default_severity: Severity::Error,
            // Source-only: needs amount-aware type information from Rust code.
            kind: RuleKind::Source,
        },
        RuleMeta {
            id: "SOR-104",
            name: "unbounded-loop-over-storage",
            description: "Loop iterates over storage-derived data without a static bound",
            default_severity: Severity::Error,
            // Source-only: bound heuristics need source-level range expressions.
            kind: RuleKind::Source,
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

/// Signature of a wasm-mode detector.
type WasmCheck = fn(&ModuleIr, &RuleMeta, &str) -> Vec<Finding>;

/// Signature of a source-mode detector.
type SourceCheck = fn(&SourceFacts, &RuleMeta) -> Vec<Finding>;

/// The wasm-mode check for a rule id, if the rule has one.
///
/// Registration (`all_rules`) and dispatch live side by side so that adding a
/// detector means adding one `RuleMeta` and one arm to each applicable table.
/// The `every_registered_rule_is_wired` test fails if a rule is registered
/// without a matching check, which used to be a silent no-op.
fn wasm_check(rule_id: &str) -> Option<WasmCheck> {
    Some(match rule_id {
        "SOR-101" => sor_101_missing_require_auth,
        "SOR-105" => sor_105_read_count_estimate,
        "SOR-106" => sor_106_unbounded_memory,
        _ => return None,
    })
}

/// The source-mode check for a rule id, if the rule has one.
fn source_check(rule_id: &str) -> Option<SourceCheck> {
    Some(match rule_id {
        "SOR-101" => sor_101_missing_require_auth_source,
        "SOR-102" => sor_102_storage_confusion,
        "SOR-103" => sor_103_unchecked_arith,
        "SOR-104" => sor_104_unbounded_loop,
        _ => return None,
    })
}

/// Run all wasm detectors against a module.
pub fn run_wasm_detectors(ir: &ModuleIr, cfg: &RulesConfig, file: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in all_rules() {
        if !cfg.is_enabled(rule.id) || !rule.kind.runs_on_wasm() {
            continue;
        }
        if let Some(check) = wasm_check(rule.id) {
            out.extend(check(ir, &rule, file));
        }
    }
    out
}

/// Run all source detectors against collected source facts.
///
/// Findings allowed by an inline `soroban-analyzer: allow(...)` directive are
/// dropped here, after the checks have run.
pub fn run_source_detectors(facts: &SourceFacts, cfg: &RulesConfig) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in all_rules() {
        if !cfg.is_enabled(rule.id) || !rule.kind.runs_on_source() {
            continue;
        }
        if let Some(check) = source_check(rule.id) {
            out.extend(check(facts, &rule));
        }
    }
    apply_inline_suppressions(&mut out, facts);
    out
}

/// Drop findings whose `(file, function, rule_id)` is allowed by an inline
/// directive written in the owning function.
fn apply_inline_suppressions(findings: &mut Vec<Finding>, facts: &SourceFacts) {
    findings.retain(|f| {
        let Some(function) = f.location.function.as_deref() else {
            return true;
        };
        !facts.functions.iter().any(|src| {
            src.file == f.location.file
                && src.name == function
                && src.allowed_rules.iter().any(|r| r == &f.rule_id)
        })
    });
}

/// Apply explicit severity overrides from config.
///
/// Detectors pick their own severity — the rule default, or an intentional
/// per-finding escalation such as SOR-105's error above the read ceiling. The
/// config rewrites it only when the user configured that rule explicitly;
/// unconditionally writing the default here would clobber that escalation.
pub fn apply_severity_overrides(findings: &mut [Finding], cfg: &RulesConfig) {
    for f in findings.iter_mut() {
        if let Some(severity) = cfg.explicit_severity(&f.rule_id) {
            f.severity = severity;
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

/// Host imports that establish authorization.
///
/// `require_auth_for_args` also contains this substring, so both host fns that
/// can satisfy the check are covered.
const REQUIRE_AUTH_HOST_FNS: &[&str] = &["require_auth"];

fn sor_101_missing_require_auth(ir: &ModuleIr, rule: &RuleMeta, file: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    // Both sides of the rule use transitive reachability so that authorization
    // delegated to a helper is recognised (the previous direct-call check
    // produced false positives on the common delegation pattern).
    let reach_host = reachable_imports(ir, STATE_CHANGING_HOST_FNS);
    let reach_auth = reachable_imports(ir, REQUIRE_AUTH_HOST_FNS);

    for (idx, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() || f.exports.is_empty() {
            continue;
        }
        if reach_host[idx] && !reach_auth[idx] {
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

/// For every function, whether it transitively reaches an import whose name
/// contains any of `needles`.
///
/// Computed with one reverse-reachability sweep instead of a fresh DFS per
/// function, so a module with `n` functions and `e` call edges costs O(n + e)
/// rather than O(n²).
/// For every function, whether it transitively reaches an import whose name
/// contains any of `needles`.
///
/// Computed with one reverse-reachability sweep instead of a fresh DFS per
/// function, so a module with `n` functions and `e` call edges costs O(n + e)
/// rather than O(n²).
///
/// Semantics: a function "reaches" a host import if it calls it directly or
/// transitively through non-import helper functions. Imported functions are
/// excluded from the caller graph because they have no body and cannot delegate
/// further. Call targets outside the function table are ignored rather than
/// treated as a reachability hit.
fn reachable_imports(ir: &ModuleIr, needles: &[&str]) -> Vec<bool> {
    let n = ir.funcs.len();
    // Reverse call edges: callers[t] lists the functions that call t.
    let mut callers: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut reaches = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();

    for (i, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() {
            continue;
        }
        for &c in &f.calls {
            let ci = c as usize;
            if ci >= n {
                continue;
            }
            callers[ci].push(i as u32);
            let matches = ir.funcs[ci]
                .import
                .as_ref()
                .is_some_and(|(_, name)| needles.iter().any(|needle| name.contains(needle)));
            if matches {
                stack.push(i as u32);
            }
        }
    }

    // Propagate "reaches" backwards along call edges.
    while let Some(cur) = stack.pop() {
        let cu = cur as usize;
        if reaches[cu] {
            continue;
        }
        reaches[cu] = true;
        for &caller in &callers[cu] {
            if !reaches[caller as usize] {
                stack.push(caller);
            }
        }
    }
    reaches
}

// ---------------------------------------------------------------------------
// SOR-101 (source mode): missing require_auth in Rust source

/// Source-mode counterpart of SOR-101. Flags contract functions that perform
/// state-changing operations (storage writes, TTL bumps, token transfers)
/// without calling require_auth.
fn sor_101_missing_require_auth_source(facts: &SourceFacts, rule: &RuleMeta) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in &facts.functions {
        // Skip functions that already call require_auth.
        if f.has_require_auth {
            continue;
        }
        // Determine if this function performs state-changing operations.
        let mut state_changing = false;
        let mut change_description = String::new();

        // Storage writes: .set() calls on Persistent, Temporary, or Instance.
        for lit in &f.storage_literals {
            if lit.spec == "Persistent" || lit.spec == "Temporary" || lit.spec == "Instance" {
                state_changing = true;
                if !change_description.is_empty() {
                    change_description.push(';');
                }
                change_description.push_str(&format!(" {} storage write", lit.spec.to_lowercase()));
            }
        }

        // TTL bumps extend contract data lifetime (state-changing).
        if !f.ttl_bump_lines.is_empty() {
            state_changing = true;
            if !change_description.is_empty() {
                change_description.push(';');
            }
            change_description.push_str(" TTL extension");
        }

        // Token transfers change account balances.
        let does_transfer = f.calls.iter().any(|c| {
            let c = c.as_str();
            c == "transfer" || c.ends_with("::transfer") || c.ends_with("transfer(")
        });
        if does_transfer {
            state_changing = true;
            if !change_description.is_empty() {
                change_description.push(';');
            }
            change_description.push_str(" token transfer");
        }

        if state_changing {
            out.push(Finding {
                rule_id: rule.id.to_string(),
                message: format!(
                    "function `{}` performs{change_description} but never calls require_auth",
                    f.name
                ),
                help: Some(
                    "add env.require_auth() for each account/contract authorized to perform this action".into(),
                ),
                severity: rule.default_severity,
                location: Location {
                    file: f.file.clone(),
                    function: Some(f.name.clone()),
                    offset: None,
                    line: None,
                },
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SOR-105: read-count estimate vs the 200-read ceiling
// ---------------------------------------------------------------------------

/// Host imports that perform ledger reads.
const READ_HOST_FNS: &[&str] = &["get_contract_data", "has_contract_data"];

/// Host imports that perform ledger writes.
const WRITE_HOST_FNS: &[&str] = &["put_contract_data", "del_contract_data"];

/// How many helper-call layers the host-call counters inline.
///
/// Counters use call-site counting, not call-graph reachability: a helper
/// invoked from an unbounded loop does **not** multiply a count we cannot bound
/// statically. Inlining more than one layer would still multiply counts we
/// cannot bound (transitively), so the default is intentionally shallow.
///
/// If you change this, re-run the budget and SOR-105 tests, because both the
/// estimator and the read-count detector rely on the same counter.
const HOST_INLINE_LEVELS: u32 = 1;

fn sor_105_read_count_estimate(ir: &ModuleIr, rule: &RuleMeta, file: &str) -> Vec<Finding> {
    let limits = soroban_common::NetworkLimits::mainnet();
    let mut out = Vec::new();

    for (idx, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() || f.exports.is_empty() {
            continue;
        }
        let base = count_host_calls(ir, idx, READ_HOST_FNS, HOST_INLINE_LEVELS);
        if base == 0 {
            continue;
        }
        // Loops multiply: without knowing trip counts, assume 2x for
        // functions with loop backedges (documented heuristic).
        //
        // This is a conservative guard for the read-count detector, not a
        // measurement. It is intentionally simple so that the behavior is easy
        // to reason about and to test; if you change it, update the
        // `sor_101_accepts_auth_delegated_to_a_helper`-style regression coverage
        // conceptually and re-run the detector tests.
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
                help: Some(
                    "batch reads, cache in a single Map entry, or restructure storage keys".into(),
                ),
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
                // Approaching, not exceeding, the ceiling: stays at the rule
                // default unless the user re-severities it.
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

/// Read-count estimate for budgeting: the same heuristic the read-count
/// detector uses, exposed for the budget module.
pub fn count_reads_for_budget(ir: &ModuleIr, idx: usize) -> u64 {
    count_host_calls(ir, idx, READ_HOST_FNS, HOST_INLINE_LEVELS)
}

/// Write-count estimate for budgeting.
///
/// Mirrors read counting (including one helper level) so writes delegated to a
/// helper are not silently dropped from the budget.
pub fn count_writes_for_budget(ir: &ModuleIr, idx: usize) -> u64 {
    count_host_calls(ir, idx, WRITE_HOST_FNS, HOST_INLINE_LEVELS)
}

/// Count call sites in `idx` that reach a host import matching `needles`,
/// inlining up to `levels` layers of helper calls.
///
/// This is call-site counting, not call-graph reachability: a helper invoked
/// from an unbounded loop should not multiply a count we cannot bound
/// statically.
/// Count call sites in `idx` that reach a host import matching `needles`,
/// inlining up to `levels` layers of helper calls.
///
/// This is call-site counting, not call-graph reachability: each direct call
/// site in `idx` that (transitively) reaches a matching host import is counted
/// once per site. A helper invoked from an unbounded loop therefore does **not**
/// multiply a count we cannot bound statically.
///
/// Imported functions are leaf nodes: they either match (and are counted) or
/// they do not. Defined helpers are recursed into only while `levels > 0`.
/// Call targets outside the function table are ignored.
fn count_host_calls(ir: &ModuleIr, idx: usize, needles: &[&str], levels: u32) -> u64 {
    let Some(f) = ir.funcs.get(idx) else {
        return 0;
    };
    let mut total = 0u64;
    for &c in &f.calls {
        let Some(target) = ir.funcs.get(c as usize) else {
            continue;
        };
        match &target.import {
            Some((_, name)) => {
                if needles.iter().any(|needle| name.contains(needle)) {
                    total += 1;
                }
            }
            None if levels > 0 => {
                total += count_host_calls(ir, c as usize, needles, levels - 1);
            }
            None => {}
        }
    }
    total
}

// ---------------------------------------------------------------------------
// SOR-106: unbounded memory growth
// ---------------------------------------------------------------------------

fn sor_106_unbounded_memory(ir: &ModuleIr, rule: &RuleMeta, file: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (idx, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() {
            continue;
        }
        // Both conditions are required: the issue is unbounded growth, not a
        // single grow site, and not every loop contains a grow. This is a
        // heuristic pattern match on the static IR, not a data-flow proof.
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
///
/// Heuristic: flag a loop if the scanner could not resolve a static range end
/// **and** the enclosing function touches storage. If the range end is a
/// literal, or if it looks like a reference to a locally-constructed iterator,
/// the loop is treated as bounded for now. Everything else is unresolved.
///
/// This is intentionally coarse. It exists to catch the common
/// "iterate over a caller-supplied collection while touching storage" pattern
/// without requiring type information.
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
///
/// This is a heuristic, not a proof: uppercase constants and numeric literals
/// are treated as bounded, and everything else is unresolved.
fn is_static_bound(hint: &str) -> bool {
    let h = hint.trim();
    h.parse::<u64>().is_ok()
        || h == "CHUNK"
        || h == "MAX"
        || h.chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::parse_module;

    fn module(wat_src: &str) -> ModuleIr {
        let bytes = wat::parse_str(wat_src).expect("wat parses");
        parse_module(&bytes).expect("module parses")
    }

    fn wasm_findings(wat_src: &str) -> Vec<Finding> {
        let ir = module(wat_src);
        run_wasm_detectors(&ir, &RulesConfig::default(), "test.wasm")
    }

    #[test]
    fn every_registered_rule_is_wired() {
        let mut seen: Vec<&str> = Vec::new();
        for rule in all_rules() {
            assert!(!seen.contains(&rule.id), "duplicate rule id {}", rule.id);
            seen.push(rule.id);
            if rule.kind.runs_on_wasm() {
                assert!(
                    wasm_check(rule.id).is_some(),
                    "{} is registered for wasm but has no wasm check",
                    rule.id
                );
            }
            if rule.kind.runs_on_source() {
                assert!(
                    source_check(rule.id).is_some(),
                    "{} is registered for source but has no source check",
                    rule.id
                );
            }
        }
    }

    #[test]
    fn rule_ids_are_in_order() {
        let ids: Vec<&str> = all_rules().iter().map(|r| r.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "all_rules() should list ids in order");
    }

    #[test]
    fn sor_101_flags_entrypoint_without_auth() {
        let findings = wasm_findings(
            r#"
            (module
              (import "l" "put_contract_data" (func $put (param i32) (result i32)))
              (func (export "entry") (param i32) (result i32)
                local.get 0
                call $put))
            "#,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "SOR-101"),
            "{findings:?}"
        );
    }

    #[test]
    fn sor_101_accepts_auth_delegated_to_a_helper() {
        // Regression: the entrypoint never calls require_auth directly, but a
        // helper it calls does. The old direct-call check flagged this.
        let findings = wasm_findings(
            r#"
            (module
              (import "l" "put_contract_data" (func $put (param i32) (result i32)))
              (import "l" "require_auth" (func $auth (param i32)))
              (func $check (param i32)
                local.get 0
                call $auth)
              (func $write (param i32) (result i32)
                local.get 0
                call $put)
              (func (export "entry") (param i32) (result i32)
                local.get 0
                call $check
                local.get 0
                call $write))
            "#,
        );
        assert!(
            !findings.iter().any(|f| f.rule_id == "SOR-101"),
            "delegated auth must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn budget_counters_include_delegated_host_calls() {
        let ir = module(
            r#"
            (module
              (import "l" "put_contract_data" (func $put (param i32) (result i32)))
              (import "l" "get_contract_data" (func $get (param i32) (result i32)))
              (func $write (param i32) (result i32)
                local.get 0
                call $put)
              (func (export "entry") (param i32) (result i32)
                local.get 0
                call $write
                drop
                local.get 0
                call $get))
            "#,
        );
        let entry = ir
            .funcs
            .iter()
            .position(|f| f.exports.iter().any(|e| e == "entry"))
            .expect("entry exported");
        assert_eq!(count_writes_for_budget(&ir, entry), 1);
        assert_eq!(count_reads_for_budget(&ir, entry), 1);
        assert_eq!(ir.funcs[entry].exports, vec!["entry"]);
    }
}
