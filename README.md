# Soroban-Static-Core

Static analysis and resource budgeting for [Soroban](https://soroban.stellar.org/)
smart contracts. It analyzes either a compiled wasm contract or Rust source,
reports findings as text, JSON or SARIF, and estimates per-entrypoint resource
budgets against mainnet limits — no execution required.

## Workspace

| Crate | Purpose |
| --- | --- |
| `common` | Shared types (findings, severities), network limits, cost coefficients and the SARIF 2.1.0 writer. |
| `analyzer` | Wasm/source front-ends, the detector engine, the budget estimator and the `soroban-analyzer` CLI. |
| `probe` | Build-and-run smoke test that pins the exact `wasmparser` 0.245 API surface the analyzer relies on. |

## Build

```bash
cargo build --release
cargo test --workspace
cargo run -p soroban-probe      # verifies the wasmparser integration
```

## Usage

```bash
# Compiled contract (or WAT, for quick tests); mode inferred from the extension
soroban-analyzer target/soroban/token.wasm

# Rust source file or directory
soroban-analyzer --mode source contracts/token/src

# Machine-readable output for CI
soroban-analyzer --format sarif target/contract.wasm > results.sarif
soroban-analyzer --format json target/contract.wasm

# Inspect or scaffold rule configuration
soroban-analyzer --list-rules
soroban-analyzer --init-config > soroban-analyzer.toml
```

Multiple targets are analyzed in parallel. A wasm directory is expanded to
every `.wasm`/`.wat` file it contains.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above `--fail-on` (default `error`). |
| `1` | At least one finding at or above `--fail-on`. |
| `2` | Usage or I/O error. |

## Rules

| Id | Severity | Kind | Detects |
| --- | --- | --- | --- |
| `SOR-101` | error | both | Entrypoint that performs state-changing operations without `require_auth`. |
| `SOR-102` | error | source | Storage-type confusion (e.g. per-item data in instance storage). |
| `SOR-103` | error | source | Token amounts flowing into unchecked arithmetic. |
| `SOR-104` | error | source | Loops over storage-derived data without a static bound. |
| `SOR-105` | warning | wasm | Estimated ledger reads approaching the 200-read ceiling. |
| `SOR-106` | warning | wasm | `memory.grow` inside a loop risking the memory cap. |

Detectors are conservative by design; each rule can be disabled or
re-severitied per project.

### Suppressing a finding

In source mode a function can opt out of specific rules with an inline
directive. This is preferred over disabling a rule project-wide:

```rust
pub fn pay(env: Env, amount: i128) {
    // soroban-analyzer: allow(SOR-103)
    let balance = amount + 10;
}
```

## Configuration

`soroban-analyzer.toml` (also emitted by `--init-config`):

```toml
schema_version = "1"

[rules.SOR-106]
enabled = false

[rules.SOR-101]
severity = "warning"
```

Pass it with `--config soroban-analyzer.toml`.

## GitHub code scanning

The SARIF output is compatible with GitHub's `codeql-action` upload step, so
findings appear in the pull-request "Security" tab:

```yaml
- run: soroban-analyzer --format sarif target/contract.wasm > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Scope and precision

### Wasm mode

Wasm analysis parses and validates the binary with `wasmparser`, then runs a
small static IR through the detector and budget engines. Instruction and I/O
counts are **static estimates** (`n_ops × coefficients`, plus one level of
helper inlining for host calls), summed over the call graph. Loop trip counts
are unknowable statically, so the per-iteration cost is reported separately
rather than folded into the total. Budget numbers answer "will a typical call
fit?" — they are not consensus values. Verdicts are computed against the caps
in [`common/src/limits.rs`](common/src/limits.rs) (reads, writes, memory
pages, code size and CPU instructions), warning from 70% of any cap upward.

Wasm mode does **not** model storage types, value types, or amount semantics.
Rules that depend on that information ("SOR-102", "SOR-103", "SOR-104") are
source-only for now.

### Source mode

Source analysis is a **lightweight heuristic scanner**, not a full `rustc`
HIR/MIR pipeline. It recognizes common Soroban SDK idioms (storage literals,
`require_auth`, token transfers, loops, TTL bumps) well enough to feed the
source-mode detectors, and it is deliberately conservative: when a heuristic
cannot be sure, it prefers a lower severity or no finding.

Because it works line-by-line over cleaned source text, it can miss patterns
that depend on type information, macros, or non-trivial control flow, and it
can occasionally match idioms inside comments or string literals if the
cleaning pass is surprised. The scanner includes fuzz-style adversarial-line
smoke tests to keep the lexer from panicking, but it is not a substitute for
proper semantic analysis.

### Shared caveats

- Host-call counting inlines only one helper layer by default. Deeper inlining
  would multiply counts the analyzer cannot bound statically.
- Recursion and mutual recursion make exact instruction totals impossible
  statically, so the budget estimator truncates deep call chains and reports
  the recursion flag separately.
- Loop cost uses a documented heuristic: functions with loop backedges are
  assumed to multiply their host-read estimate by 2 for the read-count
  detector. This is a conservative guard, not a measurement.
- Rule metadata says "both" only when a check exists for that mode. The
  `every_registered_rule_is_wired` test fails when the registration and the
  dispatch tables get out of sync, so a rule can no longer be registered but
  never run.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). CI runs `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
and the `probe` smoke test on every pull request, plus weekly to catch upstream
`wasmparser` API drift.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.
