//! Soroban network resource limits and static cost estimation coefficients.

use serde::Serialize;

/// Protocol-level resource caps per transaction / invocation.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct NetworkLimits {
    /// Maximum ledger read entries per invocation.
    pub max_reads: u64,
    /// Maximum ledger write (footprint rw) entries per invocation.
    pub max_writes: u64,
    /// Maximum contract memory pages (64 KiB each) for the guest.
    pub max_memory_pages: u32,
    /// Maximum wasm binary size in bytes for a deployed contract.
    pub max_code_size: u64,
}

impl NetworkLimits {
    /// Limits matching a currently realistic mainnet configuration.
    pub const fn mainnet() -> Self {
        Self { max_reads: 200, max_writes: 50, max_memory_pages: 256, max_code_size: 64 * 1024 }
    }
}

/// Static cost coefficients used to estimate per-call instruction budgets.
///
/// These are calibrated order-of-magnitude estimates mirroring the relative
/// costs enforced by the Soroban host's metering model. They are meant for
/// budgeting decisions ("will this call fit?"), not for consensus values.
#[derive(Debug, Clone, Copy)]
pub struct CostCoefficients {
    /// Cost of a plain (non-const) numeric or control instruction.
    pub default_ins: u64,
    /// Cost of a `call` into a local function (callee cost is added separately).
    pub call_ins: u64,
    /// Cost of a `call_indirect`.
    pub call_indirect_ins: u64,
    /// Cost of a host-function import call (e.g. a `Vec` or `Map` primitive).
    pub host_call_ins: u64,
    /// Cost per 64 bytes copied by a `memory.copy`.
    pub mem_copy_per_64b: u64,
    /// Extra cost charged per byte of linear memory grown by `memory.grow`.
    pub mem_grow_per_page: u64,
}

impl CostCoefficients {
    /// Conservative default coefficients.
    pub const fn default_coeffs() -> Self {
        Self { default_ins: 1, call_ins: 8, call_indirect_ins: 40, host_call_ins: 200, mem_copy_per_64b: 4, mem_grow_per_page: 30_000 }
    }
}
