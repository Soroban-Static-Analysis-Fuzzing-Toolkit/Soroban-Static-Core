//! Wasm front-end: streaming parse into a small module IR used by detectors.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use wasmparser::{
    ExternalKind, Imports, Operator, Parser, Payload, TypeRef, Validator, WasmFeatures,
};

/// A wasm function (imported or defined).
#[derive(Debug, Clone)]
pub struct FuncInfo {
    /// Import `("module", "name")` if this is an imported function.
    pub import: Option<(String, String)>,
    /// Export names pointing at this function.
    pub exports: Vec<String>,
    /// Byte offset of the function body start in the module (defined fns only).
    pub body_offset: Option<u64>,
    /// Number of declared locals (defined fns only).
    pub n_locals: u32,
    /// Number of operators executed (defined fns only).
    pub n_ops: u64,
    /// Static operators executed per loop iteration (defined fns only).
    pub ops_per_loop: u64,
    /// Number of `loop` headers (defined fns only).
    pub loops: u32,
    /// Number of `br` targeting loop headers (defined fns only).
    pub loop_backedges: u32,
    /// Number of `memory.grow` sites (defined fns only).
    pub memory_grow_sites: u32,
    /// Direct call targets (defined fns only).
    pub calls: Vec<u32>,
    /// True if the function is recursive (calls itself transitively).
    pub recursive: bool,
}

impl FuncInfo {
    /// Name used in reports: export name if any, else `func#N`.
    pub fn display_name(&self, idx: usize) -> String {
        if let Some((m, n)) = &self.import {
            format!("{m}.{n}")
        } else {
            match self.exports.first() {
                Some(e) => (*e).clone(),
                None => format!("func#{idx}"),
            }
        }
    }
}

/// A parsed module: function table + per-function operator data.
#[derive(Debug, Default)]
pub struct ModuleIr {
    /// Functions indexed by wasm function index space.
    pub funcs: Vec<FuncInfo>,
    /// Count of imported functions (index space offset for defined fns).
    pub num_imported_funcs: u32,
    /// Number of defined function bodies.
    pub num_defined_funcs: u32,
    /// Host imports observed, with the number of call sites referencing them.
    pub host_call_counts: BTreeMap<String, u32>,
    /// Memory declaration (min pages) if any.
    pub memory_min_pages: Option<u32>,
    /// Raw module size in bytes.
    pub code_size: u64,
}

/// Parse and validate a wasm module, collecting the IR used by detectors.
pub fn parse_module(wasm: &[u8]) -> Result<ModuleIr> {
    let mut ir = ModuleIr { code_size: wasm.len() as u64, ..Default::default() };

    // Full-module validation first; a hard error for malformed modules.
    let mut validator = Validator::new_with_features(WasmFeatures::all());
    validator
        .validate_all(wasm)
        .context("wasm validation failed (is this a Soroban contract build?)")?;

    let mut exports_by_index: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let mut n_imported = 0u32;
    let mut n_defined = 0u32;
    let mut func_bodies_seen = 0u32;

    for payload in Parser::new(0).parse_all(wasm) {
        match payload? {
            Payload::ImportSection(s) => {
                for group in s {
                    match group? {
                        Imports::Single(_, imp) => {
                            record_func_import(&mut ir, &mut n_imported, imp.module, imp.name, imp.ty);
                        }
                        Imports::Compact1 { module, items } => {
                            for item in items {
                                let item = item?;
                                record_func_import(
                                    &mut ir,
                                    &mut n_imported,
                                    module,
                                    item.name,
                                    item.ty,
                                );
                            }
                        }
                        Imports::Compact2 { module, ty, names } => {
                            for name in names {
                                record_func_import(&mut ir, &mut n_imported, module, name?, ty);
                            }
                        }
                    }
                }
            }
            Payload::FunctionSection(_) => {
                // Body count established via CodeSectionEntry below.
            }
            Payload::MemorySection(s) => {
                for mem in s {
                    let mem = mem?;
                    ir.memory_min_pages = Some(mem.initial.min(u32::MAX as u64) as u32);
                }
            }
            Payload::ExportSection(s) => {
                for exp in s {
                    let exp = exp?;
                    if matches!(exp.kind, ExternalKind::Func | ExternalKind::FuncExact) {
                        exports_by_index.entry(exp.index).or_default().push(exp.name.to_string());
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let abs_idx = n_imported as usize + (n_defined as usize);
                n_defined += 1;
                func_bodies_seen += 1;
                let body_offset = body.range().start as u64;

                let mut locals = 0u32;
                let mut locals_reader = body.get_locals_reader()?;
                for _ in 0..locals_reader.get_count() {
                    let (count, _ty) = locals_reader.read()?;
                    locals = locals.saturating_add(count);
                }

                let mut info = FuncInfo {
                    import: None,
                    exports: exports_by_index.get(&(abs_idx as u32)).cloned().unwrap_or_default(),
                    body_offset: Some(body_offset),
                    n_locals: locals,
                    n_ops: 0,
                    ops_per_loop: 0,
                    loops: 0,
                    loop_backedges: 0,
                    memory_grow_sites: 0,
                    calls: vec![],
                    recursive: false,
                };

                // The module already passed `validate_all`, so bodies are known
                // valid; this pass only collects operator statistics. The
                // iterator stops cleanly after the body's terminating `end`
                // (reading past it is an error in wasmparser >= 0.245).
                for op in body.get_operators_reader()? {
                    let op = op.context("operator read failed")?;
                    match &op {
                        Operator::Call { function_index } => {
                            info.calls.push(*function_index);
                        }
                        Operator::Loop { .. } => info.loops += 1,
                        Operator::MemoryGrow { .. } => info.memory_grow_sites += 1,
                        _ => {}
                    }
                    info.n_ops += 1;
                }
                ir.funcs.push(info);
            }
            _ => {}
        }
    }

    if func_bodies_seen != n_defined {
        bail!("code section mismatch: {n_defined} declared, {func_bodies_seen} seen");
    }
    ir.num_imported_funcs = n_imported;
    ir.num_defined_funcs = n_defined;

    // Count host-call sites by resolving defined functions' direct calls.
    for f in &ir.funcs {
        if f.import.is_some() {
            continue;
        }
        for &c in &f.calls {
            if let Some(target) = ir.funcs.get(c as usize) {
                if let Some((m, n)) = &target.import {
                    *ir.host_call_counts.entry(format!("{m}.{n}")).or_insert(0) += 1;
                }
            }
        }
    }

    // Mark recursion (direct self-call or cycles in the call graph).
    mark_recursion(&mut ir);

    // Refine per-loop operator counts with a control-depth pass.
    compute_loop_costs(wasm, &mut ir)?;
    Ok(ir)
}

/// Record one imported function into the IR, ignoring non-function imports.
fn record_func_import(
    ir: &mut ModuleIr,
    n_imported: &mut u32,
    module: &str,
    name: &str,
    ty: TypeRef,
) {
    if !matches!(ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
        return;
    }
    *n_imported += 1;
    ir.host_call_counts.entry(format!("{module}.{name}")).or_insert(0);
    ir.funcs.push(FuncInfo {
        import: Some((module.to_string(), name.to_string())),
        exports: vec![],
        body_offset: None,
        n_locals: 0,
        n_ops: 0,
        ops_per_loop: 0,
        loops: 0,
        loop_backedges: 0,
        memory_grow_sites: 0,
        calls: vec![],
        recursive: false,
    });
}

/// Transitive-closure reachability to mark recursive functions.
fn mark_recursion(ir: &mut ModuleIr) {
    let n = ir.funcs.len();
    let calls: Vec<Vec<u32>> = ir.funcs.iter().map(|f| f.calls.clone()).collect();
    for i in 0..n {
        let mut seen = vec![false; n];
        let mut stack = vec![i as u32];
        let mut reaches_self = false;
        while let Some(cur) = stack.pop() {
            let cu = cur as usize;
            if seen[cu] {
                continue;
            }
            seen[cu] = true;
            for &c in &calls[cu] {
                let cc = c as usize;
                if cc == i {
                    reaches_self = true;
                }
                if !seen[cc] {
                    stack.push(c);
                }
            }
        }
        ir.funcs[i].recursive = reaches_self;
    }
}

/// Second streaming pass: attribute operator counts to innermost loop nesting
/// so `ops_per_loop` reflects work done per iteration, not per call.
fn compute_loop_costs(wasm: &[u8], ir: &mut ModuleIr) -> Result<()> {
    let mut per_fn_loop_ops: Vec<Vec<u64>> = Vec::new();
    let mut per_fn_loops: Vec<Vec<(u32, u32)>> = Vec::new(); // (header depth, backedges)

    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::CodeSectionEntry(body) = payload? {
            let mut loop_ops: Vec<u64> = Vec::new();
            let mut loop_meta: Vec<(u32, u32)> = Vec::new();
            let mut depth = 0u32;
            for op in body.get_operators_reader()? {
                let op = op.context("operator read failed")?;
                match &op {
                    Operator::Block { .. } | Operator::If { .. } => depth += 1,
                    Operator::Loop { .. } => {
                        loop_ops.push(0);
                        loop_meta.push((depth, 0));
                        depth += 1;
                    }
                    Operator::End => {
                        depth = depth.saturating_sub(1);
                    }
                    // Both unconditional and conditional branches back to a
                    // loop header are backedges; compiled Rust loops almost
                    // always use `br_if`.
                    Operator::Br { relative_depth }
                    | Operator::BrIf { relative_depth } => {
                        let target = depth.saturating_sub(*relative_depth + 1);
                        for (hdr_depth, backedges) in loop_meta.iter_mut().rev() {
                            if *hdr_depth == target {
                                *backedges += 1;
                                break;
                            }
                        }
                    }
                    other => {
                        if let Some(last) = loop_ops.last_mut() {
                            if is_counted(other) {
                                *last += 1;
                            }
                        }
                    }
                }
            }
            per_fn_loop_ops.push(loop_ops);
            per_fn_loops.push(loop_meta);
        }
    }

    // `per_fn_*` vectors are indexed by defined-function ordinal, while
    // `ir.funcs` is the full function index space (imports come first).
    let imported = ir.num_imported_funcs as usize;
    for (i, f) in ir.funcs.iter_mut().enumerate() {
        if f.import.is_some() {
            continue;
        }
        let defined_idx = i.saturating_sub(imported);
        if let Some(ops) = per_fn_loop_ops.get(defined_idx) {
            f.ops_per_loop = ops.iter().copied().max().unwrap_or(0);
        }
        if let Some(meta) = per_fn_loops.get(defined_idx) {
            f.loop_backedges = meta.iter().map(|(_, b)| *b).sum();
        }
    }
    Ok(())
}

/// Whether an operator counts toward the static instruction estimate.
fn is_counted(op: &Operator) -> bool {
    !matches!(op, Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wat::parse_str;

    #[test]
    fn parses_simple_module() {
        let wasm = parse_str(
            r#"
            (module
              (import "x" "f" (func $f (param i32)))
              (func (export "run") (param i64) (result i64)
                local.get 0
                i64.const 1
                i64.add
                drop
                i32.const 0
                call $f
                local.get 0)
            )"#,
        )
        .unwrap();
        let ir = parse_module(&wasm).unwrap();
        assert_eq!(ir.num_imported_funcs, 1);
        assert_eq!(ir.num_defined_funcs, 1);
        assert_eq!(ir.funcs[1].calls, vec![0]);
        assert_eq!(ir.host_call_counts["x.f"], 1);
        // 7 explicit operators plus the body's terminating `end`.
        assert_eq!(ir.funcs[1].n_ops, 8);
    }

    #[test]
    fn detects_loop_cost() {
        let wasm = parse_str(
            r#"
            (module
              (func (export "spin") (param i32) (result i32)
                (local i32)
                loop $l
                  local.get 1
                  i32.const 1
                  i32.add
                  local.tee 1
                  local.get 0
                  i32.lt_s
                  br_if $l
                end
                local.get 1)
            )"#,
        )
        .unwrap();
        let ir = parse_module(&wasm).unwrap();
        assert_eq!(ir.funcs[0].loops, 1);
        assert_eq!(ir.funcs[0].loop_backedges, 1);
        assert!(ir.funcs[0].ops_per_loop >= 5);
    }
}
