//! Probe: verify the wasmparser 0.245 API surface used by `soroban-analyzer`.
//!
//! This is a build-and-run smoke test for the parsing strategy the analyzer
//! relies on: full-module validation, streaming payloads, grouped imports, and
//! per-function operator iteration via `Operator` matching (the analyzer does
//! not use the `VisitOperator` trait, whose methods dispatch individually).

use wasmparser::{
    BinaryReaderError, ExternalKind, Imports, Operator, Parser, Payload, TypeRef, Validator,
    WasmFeatures,
};

#[derive(Default)]
struct Counts {
    total: u64,
    local_gets: u64,
    calls: Vec<String>,
    blocks: u32,
    loops: u32,
    bins: u64,
}

fn main() -> Result<(), BinaryReaderError> {
    let wat = r#"
        (module
          (type $t (func (param i64 i64) (result i64)))
          (import "x" "require_auth" (func $req_auth (param i32)))
          (func $add (export "add") (type $t) (local i32)
            local.get 0
            local.get 1
            i64.add
            i32.const 0
            call $req_auth
            drop
            loop $l
              local.get 2
              i32.const 1
              i32.add
              local.tee 2
              i32.const 10
              i32.lt_s
              br_if $l
            end
            local.get 0)
        )
    "#;
    let wasm = wat::parse_str(wat).expect("wat parse");

    // 1. Full-module validation (requires the `validate` feature).
    let mut validator = Validator::new_with_features(WasmFeatures::all());
    validator.validate_all(&wasm)?;
    println!("validate_all: OK");

    // 2. Streaming pass over payloads.
    let mut counts = Counts::default();
    let mut rec_groups = 0usize;
    let mut func_bodies = 0usize;
    for payload in Parser::new(0).parse_all(&wasm) {
        match payload? {
            Payload::ImportSection(s) => {
                for group in s {
                    match group? {
                        Imports::Single(_, imp) => {
                            if matches!(imp.ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
                                println!("import func: {} #{}", imp.module, imp.name);
                            }
                        }
                        Imports::Compact1 { module, items } => {
                            for item in items {
                                println!("import func: {module} #{}", item?.name);
                            }
                        }
                        Imports::Compact2 { module, names, .. } => {
                            for name in names {
                                println!("import func: {module} #{}", name?);
                            }
                        }
                    }
                }
            }
            Payload::TypeSection(s) => {
                for ty in s {
                    let _ = ty?;
                    rec_groups += 1;
                }
            }
            Payload::ExportSection(s) => {
                for exp in s {
                    let exp = exp?;
                    if matches!(exp.kind, ExternalKind::Func | ExternalKind::FuncExact) {
                        println!("export func: {}", exp.name);
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                func_bodies += 1;
                // `get_operators_reader` yields every operator including the
                // body's terminating `end`, then stops.
                for op in body.get_operators_reader()? {
                    let op = op?;
                    counts.total += 1;
                    match op {
                        Operator::LocalGet { .. } => counts.local_gets += 1,
                        Operator::Call { function_index } => {
                            counts.calls.push(format!("func#{function_index}"));
                        }
                        Operator::Block { .. } => counts.blocks += 1,
                        Operator::Loop { .. } => counts.loops += 1,
                        Operator::I64Add
                        | Operator::I64Sub
                        | Operator::I64Mul
                        | Operator::I64DivU => {
                            counts.bins += 1;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    println!(
        "bodies={} total={} locals={} blocks={} loops={} bins={} calls={:?} types={}",
        func_bodies,
        counts.total,
        counts.local_gets,
        counts.blocks,
        counts.loops,
        counts.bins,
        counts.calls,
        rec_groups
    );
    Ok(())
}
