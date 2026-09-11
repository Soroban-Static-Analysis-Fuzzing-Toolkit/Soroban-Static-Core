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
| `SOR-102` | error | both | Storage-type confusion (e.g. per-item data in instance storage). |
| `SOR-103` | error | both | Token amounts flowing into unchecked arithmetic. |
| `SOR-104` | error | both | Loops over storage-derived data without a static bound. |
| `SOR-105` | warning | wasm | Estimated ledger reads approaching the 200-read ceiling. |
| `SOR-106` | warning | wasm | `memory.grow` inside a loop risking the memory cap. |

Detectors are conservative by design; each rule can be disabled or
re-severitied per project.

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

## Notes on precision

Wasm instruction counts are static estimates (`n_ops × coefficients`), summed
over the call graph. Loop trip counts are unknowable statically, so the
per-iteration cost is reported separately rather than folded into the total.
Budget numbers answer "will a typical call fit?" — they are not consensus
values.
