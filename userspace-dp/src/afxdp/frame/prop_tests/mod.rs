//! #1824 — in-tree proptest harness for the frame layer.
//!
//! Surfaces (plan: docs/research/1824-fuzz-harness/plan.md §5.3):
//!   - `inspect.rs`  — S1: parse no-panic (P-I1), bounds (P-I2), offset
//!     consistency (P-I3), valid-packet round-trip (P-I4), meta
//!     independence (P-I5).
//!   - `rewrite.rs`  — S2: NAT round-trip identity (P-N1) with the
//!     P-N2 validity oracle, descriptor-vs-generic differential
//!     (P-N3), decline/divergence pins as deterministic examples
//!     (P-N3b — including the #1838/#1839/#1840 defect pins), payload
//!     immutability (P-N4).
//!   - `segment.rs`  — S4: TSO splitter no-panic (P-T1), reassembly
//!     identity (P-T2), per-segment wellformedness (P-T3), NAT
//!     composition (P-T4).
//!   - `strategies.rs` — shared generators (garbage frames, arbitrary
//!     metadata, valid packet builders, structured IPv6 ext-header
//!     chains, NAT decisions).
//!   - `oracle.rs` — test-local full-recompute checksum validity
//!     oracle + masked byte-equality helper. Deliberately NOT
//!     `verify_built_frame_checksums` (v4-TCP-only, frame/mod.rs:1129
//!     early-returns `(true, true)` for everything else).
//!
//! Determinism contract (plan §5.4): passing runs use a fresh random
//! seed each run — continuous exploration is the point. What is
//! deterministic: (a) the committed `proptest-regressions/**` corpus,
//! replayed FIRST on every run (the actual regression-pinning
//! mechanism — never hand-edit or delete those files), and (b) the
//! explicit case counts below.
//!
//! Soak knob: `PROPTEST_CASES=100000 cargo test --release prop_` for
//! operator-driven deep runs; never wired into any gate.
//!
//! The #1838/#1839/#1840 defect trio is FIXED; the domain gates that
//! encoded the defects are lifted:
//!   - #1838: NAT-applying and segmentation generators emit IPv6 WITH
//!     extension-header chains (the ext-aware offset is threaded
//!     through both rewrite paths via `v6_rel_l4_offset`).
//!   - #1839: the P-N3 descriptor-vs-generic differential asserts FULL
//!     byte equality (empty mask). P-N1's apply+undo round trip still
//!     masks checksum bytes — it restores the value class, not the
//!     one's-complement zero representation.
//!   - #1840: valid-packet generators still never emit v6 UDP checksum
//!     0x0000 — that encoding is malformed per RFC 8200 §8.1 (outside
//!     the VALID domain); the deterministic pins in `rewrite.rs` cover
//!     the malformed encoding on both paths.

use super::*;
use proptest::prelude::*;

mod inspect;
mod oracle;
mod nat_l4_rule_parity_17250;
mod rewrite;
mod segment;
mod strategies;

/// Explicit per-property config (plan §5.4): fixed case counts, fresh
/// run seed, bounded shrink effort. `PROPTEST_CASES` (read by proptest
/// itself before our overrides? it is not — we set cases explicitly,
/// so the env soak knob goes through `with_cases_env`).
fn cfg(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases: cases_env_override(cases),
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    }
}

/// Honor `PROPTEST_CASES` as a soak override even though every
/// property sets an explicit count (an explicit `cases` field would
/// otherwise shadow the env var).
fn cases_env_override(default_cases: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default_cases)
}
