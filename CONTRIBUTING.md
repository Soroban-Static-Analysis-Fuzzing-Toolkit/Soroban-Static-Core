# Contributing

Thanks for helping improve Soroban-Static-Core. This document covers local
setup, the detector-authoring workflow, and the conventions CI enforces.

## Local setup

```bash
cargo build --workspace
cargo test --workspace          # unit tests + end-to-end CLI tests
cargo run -p soroban-probe      # pins the wasmparser API surface we rely on
```

Before opening a pull request, run the same checks CI runs:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p soroban-probe
```

## Adding a detector

Adding a rule touches exactly four things, and the test suite will tell you if
you miss one:

1. **Register it.** Add a `RuleMeta` entry to `all_rules()` in
   `analyzer/src/detectors.rs`, in id order, with the correct `RuleKind`.
   SOR ids are allocated sequentially; take the next free one.
2. **Write the check.** Add a function with the matching signature:
   - wasm: `fn(&ModuleIr, &RuleMeta, &str) -> Vec<Finding>`
   - source: `fn(&SourceFacts, &RuleMeta) -> Vec<Finding>`
3. **Wire it.** Add an arm to `wasm_check` and/or `source_check`. If a rule's
   `RuleKind` says it runs in a mode but it is missing from that table,
   `every_registered_rule_is_wired` fails — this used to be a silent no-op.
4. **Test it.** Add a positive and a negative case. Prefer a minimal WAT fixture
   (see `analyzer/tests/fixtures/`) or a small source snippet.

## Severity guidance

- `error` — a likely bug or security issue. These drive the default exit code,
  so a false positive here breaks users' CI.
- `warning` — a plausible problem that may be intentional.
- `note` — style or informational.

Keep detectors **conservative**: a detector that cries wolf gets disabled, which
helps nobody. When a heuristic cannot be sure, prefer a lower severity or a
narrower trigger. Detectors choose their own severity (including intentional
per-finding escalation, as SOR-105 does above the read ceiling); a
`soroban-analyzer.toml` override only applies when the user sets it explicitly.

## Configuration changes

`analyzer/src/rules.rs` owns the config schema. If you add or rename a field or
change the meaning of the file, bump `RULES_SCHEMA_VERSION`. Unknown fields and
unknown rule ids are rejected so typos fail loudly rather than silently doing
nothing.

## Verifying SARIF output

Findings are surfaced in GitHub code scanning, so treat the SARIF shape as an
API:

```bash
cargo run -p soroban-analyzer -- --format sarif target/contract.wasm > results.sarif
python3 -m json.tool results.sarif > /dev/null   # must be valid JSON
```

`analyzer/tests/cli.rs` asserts the SARIF version, driver name and the
`informationUri`; extend those tests if you change the output.

## Reporting bugs

Include the analyzer version, the input (a reduced WAT/source snippet if it is
not sensitive), and the exact command. A minimal reproduction is worth more than
a long description.
