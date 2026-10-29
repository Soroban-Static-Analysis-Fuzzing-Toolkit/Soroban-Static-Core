# Validation against `stellar/soroban-examples`

The source-mode detectors are checked against the official Soroban example
contracts. These contracts are written by the Stellar team and are mostly
correct, so most findings on them should be either intended design choices or
false positives to fix.

- Corpus: [`stellar/soroban-examples`](https://github.com/stellar/soroban-examples)
  at `03d42aa6b973dcf3a453a99d0c6a6e8d25a196e2` (2026-10-06), 29 contracts.
- Command, per contract: `soroban-analyzer --mode source --fail-on never <contract>/src`

## Results

| | Findings | `token` contract |
| --- | --- | --- |
| Before (`7a1da38`) | 120 | 11, all false positives |
| After | 26 | 0 |

The drop came from three scanner fixes:

1. **Reads counted as writes.** Any line that mentioned `persistent()`,
   `instance()` or `temporary()` was treated as a storage write, so getters
   such as `balance()` were reported by SOR-101. Each storage call is now
   classified as read, write or TTL extension, including chains split over
   several lines (`e.storage()` / `.persistent()` / `.set(..)`).
2. **Test code was scanned.** `test.rs`, `tests/`, `#[cfg(test)]` modules and
   `#[test]` functions are now skipped.
3. **Private helpers were treated as entrypoints.** SOR-101 now checks only
   `pub fn`s inside `#[contractimpl]`, and follows local helper calls in both
   directions: auth done in a helper counts, and a write done in a helper is
   still caught (reported as "via `helper`"). `__constructor` is skipped.

## Remaining findings

| Rule | Count | Assessment |
| --- | --- | --- |
| SOR-101 | 9 | Correct by the rule's definition: unauthenticated entrypoints that write state (`increment` counters, `pause::set`, `merkle_distribution::claim`, `ttl::setup`). The examples are intentionally permissionless; real contracts would suppress with `allow(SOR-101)`. |
| SOR-103 | 9 | Noisy. Every example builds with `overflow-checks = true`, so overflow panics instead of wrapping. The rule should read the release profile. |
| SOR-104 | 8 | Noisy. Fires on loops over function arguments (e.g. signer lists in `__check_auth`) because the function also touches storage; the rule should require the loop source to come from storage. |

The SOR-103 and SOR-104 issues are tracked in the issue tracker.

## Reproducing

```bash
git clone --depth 1 https://github.com/stellar/soroban-examples
cargo build --release
for d in soroban-examples/*/src; do
  ./target/release/soroban-analyzer --mode source --fail-on never "$d"
done
```
