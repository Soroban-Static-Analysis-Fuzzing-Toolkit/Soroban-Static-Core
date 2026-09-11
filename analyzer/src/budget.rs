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
    /// Estimated linear memory pages from the module memory section.
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
    // Memo table for per-function instruction estimates.
    let mut memo: Vec<Option<u64>> = vec![None; ir.funcs.len()];

    let mut entrypoints = Vec::new();
    for (idx, f) in ir.funcs.iter().enumerate() {
        if f.import.is_some() || f.exports.is_empty() {
            continue;
        }
        let est = estimate_ins(ir, idx, &mut memo, coeffs, 0);
        let reads = crate::detectors::count_reads_for_budget(ir, idx);
        let writes = count_writes(ir, idx);

        // Memory: declared pages plus growth sites give a lower bound.
        let memory_pages = ir.memory_min_pages;

        let verdict = if est >= u64::MAX / 2 || recursive_over_budget(f) {
            Verdict::Over
        } else if est_warn(est, reads, writes, &limits) {
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

    BudgetReport { file: file.to_string(), code_size: ir.code_size, code_size_verdict, entrypoints, limits }
}

/// Per-function instruction estimate with cycle-safe memoization.
fn estimate_ins(
    ir: &ModuleIr,
    idx: usize,
    memo: &mut Vec<Option<u64>>,
    c: CostCoefficients,
    depth: u32,
) -> u64 {
    if depth > 16 {
        // Cycle guard: recursion makes exact totals impossible statically;
        // return the function's own body cost to bound the estimate.
        return body_cost(ir, idx, c);
    }
    if let Some(v) = memo[idx] {
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
    memo[idx] = Some(total);
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

/// Number of direct write-host call sites in a function.
fn count_writes(ir: &ModuleIr, idx: usize) -> u64 {
    const WRITE_HOST_FNS: &[&str] =
        &["put_contract_data", "del_contract_data"];
    let f = &ir.funcs[idx];
    let mut total = 0u64;
    for &c in &f.calls {
        if let Some(t) = ir.funcs.get(c as usize) {
            if let Some((_, name)) = &t.import {
                if WRITE_HOST_FNS.iter().any(|s| name.contains(s)) {
                    total += 1;
                }
            }
        }
    }
    total
}

/// Recursion alone does not imply over-budget; flag only unbounded growth via memory.
fn recursive_over_budget(f: &crate::wasm::FuncInfo) -> bool {
    f.recursive && f.memory_grow_sites > 0
}

/// ≥70% of any cap → warn.
fn est_warn(est: u64, reads: u64, writes: u64, limits: &NetworkLimits) -> bool {
    est >= 7_000_000
        || reads * 10 >= limits.max_reads * 7
        || writes * 10 >= limits.max_writes * 7
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
        "  limits: reads<={} writes<={} memory_pages<={} code_size<={}\n",
        report.limits.max_reads,
        report.limits.max_writes,
        report.limits.max_memory_pages,
        report.limits.max_code_size
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
