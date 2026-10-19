// Three-color policer *application* helpers extracted from engine.rs by
// #1546. Distinct from `filter/policer.rs`, which holds the standalone
// `ThreeColorPolicerState`/`ThreeColorPolicerRuntime` types. These helpers
// invoke `runtime.meter()` once per matching term and merge the returned
// `ThreeColorDecision` into the caller-visible `ThreeColorPolicerAction`.
//
// Concurrency contract (#5390 — LOCK-FREE; the pre-#5390
// `Mutex<ThreeColorPolicerState>` wrapper this header used to describe is
// RETIRED):
//   - `ThreeColorPolicerState::meter` is `&self` (not `&mut self`): the
//     token-bucket state is shared across all workers behind an `Arc` and
//     metered concurrently — refills through per-rate timestamp CAS, then
//     consumes tokens through a bounded `compare_exchange_weak` loop over
//     the packed `credits` word (`filter/policer.rs`). NO `Mutex` anywhere:
//     the RSS-spread flow aggregate no longer serializes on a per-packet
//     futex, and the poison failure mode is gone with the lock. The #5390
//     fail-on-revert test in `filter/policer.rs` guards this shape — do not
//     "restore" a mutex here.
//   - `ThreeColorPolicerRuntime::meter(&self, ...)` (filter/mod.rs) meters
//     lock-free through the state CAS and then records counters via relaxed
//     atomic adds.
//   - The `meter()` call -> counter-record order is preserved: each call
//     site invokes `runtime.meter()` and propagates its `dscp_rewrite`/
//     `drop` decision without intervening allocations.

use super::super::*;

#[inline]
pub(super) fn apply_term_three_color_policer(
    term: &FilterTerm,
    now_ns: Option<u64>,
    packet_bytes: u64,
) -> ThreeColorPolicerAction {
    let Some(runtime) = term.three_color_policer.as_ref() else {
        return ThreeColorPolicerAction::default();
    };
    let Some(now_ns) = now_ns else {
        return ThreeColorPolicerAction::default();
    };
    let decision = runtime.meter(now_ns, packet_bytes, PacketColor::Green);
    ThreeColorPolicerAction {
        dscp_rewrite: decision.dscp_rewrite,
        drop: decision.drop,
    }
}

pub(crate) fn apply_cached_three_color_policers(
    policers: &CachedThreeColorPolicers,
    now_ns: u64,
    packet_bytes: u64,
) -> ThreeColorPolicerAction {
    let mut action = ThreeColorPolicerAction::default();
    policers.for_each(|policer| {
        let decision = policer.meter(now_ns, packet_bytes, PacketColor::Green);
        // #15793: latest matched term wins, mirroring the fresh/inline walks
        // (`merge_matched_tx_modifiers` / `merge_matched_modifiers` assign
        // per matched term). The previous `.or` kept the FIRST rewrite, so
        // cached/deferred replay emitted a different DSCP than the first
        // packet for multi-term policer filters.
        if decision.dscp_rewrite.is_some() {
            action.dscp_rewrite = decision.dscp_rewrite;
        }
        action.drop |= decision.drop;
    });
    action
}

pub(crate) fn filter_state_has_input_three_color_policer(state: &FilterState, is_v6: bool) -> bool {
    if is_v6 {
        state.has_input_three_color_policer_v6
    } else {
        state.has_input_three_color_policer_v4
    }
}
