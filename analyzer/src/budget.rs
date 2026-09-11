//! Resource-budget estimator: static per-entrypoint instruction/memory/IO
//! budgeting against Soroban network limits.
//!
//! The instruction model is intentionally simple and *documented as an
//! estimate*: static op counts × cost coefficients, summed over the call
//! graph, with loop trip counts unknown → per-iteration cost reported
//! separately. This answers "will a typical call fit?" without executing.

use crate::wasm::ModuleIr;
use serde::Serialize;
use soroban_common::{CostCoefficients, NetworkLimits};

/// Estimated budget for one entrypoint.
#[derive(Debug, Clone, Serialize)]
pub struct EntrypointBudget {
    /// Entrypoint display name (export name or `func#N`).
    pub name: String,
    /// Wasm function index.
    pub func_index: usize,
    /// Estimated instructions per non-looping call.
    pub est_instructions: u64,
    /// Estimated instructions per single loop iteration (worst innermost loop).
    pub est_instructions_per_loop_iter: u64,
    /// Static loop count (headers + backedges) in the entrypoint's body.
    pub loop_backedges: u32,
    /// Estimated ledger reads (direct + one helper level).
    pub est_reads: u64,
    /// Estimated ledger writes (direct host write calls).
    pub est_writes: u64,
    /// Whether the call graph contains recursion.
    pub recursive: bool,
    /// Estimated linear memory pages: the module's declared minimum plus one
    /// page per `memory.grow` site in the entrypoint's body (a lower bound).
    pub memory_pages: Option<u32>,
    /// Verdict vs the configured limits.
    pub verdict: Verdict,
}

/// Verdict for a budget estimate.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Verdict {
    /// Comfortably within limits.
    Ok,
    /// Close to a limit (≥70% of any cap).
    Warn,
    /// Likely exceeds a cap.
    Over,
}

impl Verdict {
    /// Label used in text output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Warn => "warn",
            Verdict::Over => "OVER BUDGET",
        }
    }
}

/// Budget report for a whole module.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetReport {
    /// Module file analyzed.
    pub file: String,
    /// Module size in bytes.
    pub code_size: u64,
    /// Verdict on binary size vs `max_code_size`.
    pub code_size_verdict: Verdict,
    /// Per-entrypoint budgets.
    pub entrypoints: Vec<EntrypointBudget>,
    /// Limits used for the assessment.
    pub limits: NetworkLimits,
}

/// Compute a budget report for a parsed module.
pub fn budget_module(
    ir: &ModuleIr,
    file: &str,
    limits: NetworkLimits,
    coeffs: CostCoefficients,
) -> BudgetReport {
    // Memo keyed by (function, call depth) and reset per entrypoint. A table
    // shared across entrypoints let one entrypoint's depth-truncated estimate
    // leak into another's, so results depended on iteration order.
    let mut memo: Vec<Vec<Option<u64>>> = vec![vec![None; MAX_CALL_DEPTH + 1]; ir.funcs.len()];

    let mut entrypoints = Vec::new();
    for (idx, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() || f.exports.is_empty() {
            continue;
        }
        for row in memo.iter_mut() {
            row.fill(None);
        }
        let est = estimate_ins(ir, idx, &mut memo, coeffs, 0);
        let reads = crate::detectors::count_reads_for_budget(ir, idx);
        let writes = crate::detectors::count_writes_for_budget(ir, idx);
        let memory_pages = memory_pages_with_growth(ir, f);

        let verdict = if instruction_over(est, &limits)
            || at_or_over(reads, limits.max_reads)
            || at_or_over(writes, limits.max_writes)
            || memory_over(memory_pages, &limits)
            || recursive_over_budget(f)
        {
            Verdict::Over
        } else if near_cap(est, limits.max_instructions)
            || near_cap(reads, limits.max_reads)
            || near_cap(writes, limits.max_writes)
            || memory_near(memory_pages, &limits)
        {
            Verdict::Warn
        } else {
            Verdict::Ok
        };

        entrypoints.push(EntrypointBudget {
            name: f.display_name(idx),
            func_index: idx,
            est_instructions: est,
            est_instructions_per_loop_iter: f.ops_per_loop,
            loop_backedges: f.loop_backedges,
            est_reads: reads,
            est_writes: writes,
            recursive: f.recursive,
            memory_pages,
            verdict,
        });
    }

    let code_size_verdict = if ir.code_size > limits.max_code_size {
        Verdict::Over
    } else if ir.code_size * 10 >= limits.max_code_size * 7 {
        Verdict::Warn
    } else {
        Verdict::Ok
    };

    BudgetReport {
        file: file.to_string(),
        code_size: ir.code_size,
        code_size_verdict,
        entrypoints,
        limits,
    }
}

/// Call-graph depth at which the cycle guard truncates to body cost.
///
/// Recursion and mutual recursion make exact totals impossible statically; the
/// guard bounds the estimate instead of diverging.
const MAX_CALL_DEPTH: usize = 16;

/// Per-function instruction estimate with cycle-safe, depth-keyed memoization.
fn estimate_ins(
    ir: &ModuleIr,
    idx: usize,
    memo: &mut [Vec<Option<u64>>],
    c: CostCoefficients,
    depth: usize,
) -> u64 {
    if depth > MAX_CALL_DEPTH {
        return body_cost(ir, idx, c);
    }
    if let Some(v) = memo[idx][depth] {
        return v;
    }
    let f = &ir.funcs[idx];
    let mut total = body_cost(ir, idx, c);
    for &call in &f.calls {
        if let Some(t) = ir.funcs.get(call as usize) {
            let cost = match &t.import {
                Some(_) => c.host_call_ins,
                None => estimate_ins(ir, call as usize, memo, c, depth + 1),
            };
            total = total.saturating_add(cost);
        }
    }
    memo[idx][depth] = Some(total);
    total
}

/// Static cost of one function's own operators (no callees).
fn body_cost(ir: &ModuleIr, idx: usize, c: CostCoefficients) -> u64 {
    let f = &ir.funcs[idx];
    let mut cost = f.n_ops.saturating_mul(c.default_ins);
    // Loops: charge one extra iteration's worth per backedge (unknown trip
    // counts; the per-iteration cost is reported separately).
    cost = cost.saturating_add(f.ops_per_loop.saturating_mul(c.default_ins));
    cost
}

/// Declared memory pages plus one page per growth site in the entrypoint's
/// own body, as a lower bound on peak memory.
fn memory_pages_with_growth(ir: &ModuleIr, f: &crate::wasm::FuncInfo) -> Option<u32> {
    ir.memory_min_pages
        .map(|declared| declared.saturating_add(f.memory_grow_sites))
}

/// Recursion alone does not imply over-budget; flag only unbounded growth via memory.
fn recursive_over_budget(f: &crate::wasm::FuncInfo) -> bool {
    f.recursive && f.memory_grow_sites > 0
}

/// Whether the instruction estimate is at or beyond the transaction cap.
fn instruction_over(est: u64, limits: &NetworkLimits) -> bool {
    at_or_over(est, limits.max_instructions)
}

/// Whether the memory estimate exceeds the memory cap.
fn memory_over(pages: Option<u32>, limits: &NetworkLimits) -> bool {
    pages.is_some_and(|p| p > limits.max_memory_pages)
}

/// Whether the memory estimate is within the 70% warning band.
fn memory_near(pages: Option<u32>, limits: &NetworkLimits) -> bool {
    pages.is_some_and(|p| near_cap(u64::from(p), u64::from(limits.max_memory_pages)))
}

/// Whether `value` is at or beyond `cap` (caps are inclusive ceilings).
fn at_or_over(value: u64, cap: u64) -> bool {
    cap > 0 && value >= cap
}

/// Whether `value` is at or beyond 70% of `cap`.
fn near_cap(value: u64, cap: u64) -> bool {
    cap > 0 && value.saturating_mul(10) >= cap.saturating_mul(7)
}

/// Format a one-line text summary of a budget report.
pub fn format_budget_report(report: &BudgetReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "budget: {} ({} bytes, size verdict: {})\n",
        report.file,
        report.code_size,
        report.code_size_verdict.as_str()
    ));
    s.push_str(&format!(
        "  limits: reads<={} writes<={} memory_pages<={} code_size<={} instructions<={}\n",
        report.limits.max_reads,
        report.limits.max_writes,
        report.limits.max_memory_pages,
        report.limits.max_code_size,
        report.limits.max_instructions
    ));
    if report.entrypoints.is_empty() {
        s.push_str("  (no exported entrypoints found)\n");
    }
    for e in &report.entrypoints {
        s.push_str(&format!(
            "  {:<24} ins~{:>9}  loop_iter~{:>5}  reads~{:>3}  writes~{:>3}  {}{}\n",
            e.name,
            e.est_instructions,
            e.est_instructions_per_loop_iter,
            e.est_reads,
            e.est_writes,
            e.verdict.as_str(),
            if e.recursive { " (recursive)" } else { "" }
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::parse_module;

    fn budget(wat_src: &str) -> BudgetReport {
        let bytes = wat::parse_str(wat_src).expect("wat parses");
        let ir = parse_module(&bytes).expect("module parses");
        budget_module(
            &ir,
            "test.wasm",
            NetworkLimits::mainnet(),
            CostCoefficients::default_coeffs(),
        )
    }

    fn estimate_of(report: &BudgetReport, name: &str) -> u64 {
        report
            .entrypoints
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("entrypoint {name} not found"))
            .est_instructions
    }

    /// A 21-link call chain in which every link calls a host import. `b` calls
    /// the middle of the chain directly, so if one entrypoint's memo leaked
    /// into another's, `b`'s estimate would change depending on whether `a`
    /// was exported too.
    fn chain_wat(export_a: bool) -> String {
        let mut s = String::from(
            "(module\n  (import \"l\" \"get_contract_data\" (func $host (param i32) (result i32)))\n",
        );
        s.push_str("  (func $f0 (param i32) (result i32)\n    local.get 0\n    call $host)\n");
        for i in 1..=20 {
            s.push_str(&format!(
                "  (func $f{i} (param i32) (result i32)\n    local.get 0\n    call $f{}\n    i32.const 0\n    call $host\n    drop)\n",
                i - 1
            ));
        }
        if export_a {
            s.push_str(
                "  (func (export \"a\") (param i32) (result i32)\n    local.get 0\n    call $f20)\n",
            );
        }
        s.push_str(
            "  (func (export \"b\") (param i32) (result i32)\n    local.get 0\n    call $f10)\n)\n",
        );
        s
    }

    #[test]
    fn entrypoint_estimates_do_not_depend_on_each_other() {
        let with_a = budget(&chain_wat(true));
        let without_a = budget(&chain_wat(false));
        assert_eq!(
            estimate_of(&with_a, "b"),
            estimate_of(&without_a, "b"),
            "b's estimate must not be poisoned by a's deeper traversal"
        );
    }

    #[test]
    fn budgets_are_repeatable() {
        let first = budget(&chain_wat(true));
        let second = budget(&chain_wat(true));
        assert_eq!(first.entrypoints.len(), second.entrypoints.len());
        for (a, b) in first.entrypoints.iter().zip(&second.entrypoints) {
            assert_eq!(a.est_instructions, b.est_instructions);
            assert_eq!(a.verdict, b.verdict);
        }
    }

    #[test]
    fn declared_memory_beyond_cap_is_over_budget() {
        let report = budget(
            r#"
            (module
              (memory 300)
              (func (export "entry") (result i32)
                i32.const 0))
            "#,
        );
        assert_eq!(report.entrypoints[0].memory_pages, Some(300));
        assert_eq!(report.entrypoints[0].verdict, Verdict::Over);
    }

    #[test]
    fn thresholds_are_relative_to_the_configured_cap() {
        assert!(at_or_over(100, 100));
        assert!(!at_or_over(99, 100));
        assert!(near_cap(70, 100));
        assert!(!near_cap(69, 100));
        // A zero cap disables the check instead of flagging everything.
        assert!(!at_or_over(1, 0));
        assert!(!near_cap(1, 0));
    }
}
