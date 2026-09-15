// BindingLiveState::snapshot() field propagation + owner-profile
// cacheline-isolation tests. Split from umem/tests.rs (#4667).

use super::*;

#[test]
fn binding_live_snapshot_propagates_709_owner_profile_counters() {
    // #709: pin that the snapshot() path copies all owner-profile
    // atomics into the BindingLiveSnapshot. A future edit that
    // misses one field would silently under-surface telemetry to
    // the operator CLI / Prometheus — this test fails fast on the
    // missing field.
    let live = BindingLiveState::new();
    live.owner_profile_owner.drain_latency_hist[3].store(7, Ordering::Relaxed);
    live.owner_profile_owner.drain_latency_hist[15].store(2, Ordering::Relaxed);
    live.owner_profile_owner
        .drain_invocations
        .store(100, Ordering::Relaxed);
    live.owner_profile_owner
        .drain_noop_invocations
        .store(50, Ordering::Relaxed);
    live.owner_profile_peer.redirect_acquire_hist[1].store(11, Ordering::Relaxed);
    live.owner_profile_owner
        .owner_pps
        .store(1234, Ordering::Relaxed);
    live.owner_profile_peer
        .peer_pps
        .store(567, Ordering::Relaxed);

    // #812: exercise the new TX submit-latency atomics on the
    // same snapshot path so a future `snapshot()` refactor that
    // drops one of the three new loads fails here (same shape
    // as the #709 pin above). Non-coprime values per field so
    // a cross-field mis-attribution is caught.
    live.owner_profile_owner.tx_submit_latency_hist[2].store(19, Ordering::Relaxed);
    live.owner_profile_owner.tx_submit_latency_hist[14].store(23, Ordering::Relaxed);
    live.owner_profile_owner
        .tx_submit_latency_count
        .store(42, Ordering::Relaxed);
    live.owner_profile_owner
        .tx_submit_latency_sum_ns
        .store(999_999, Ordering::Relaxed);

    let snap = live.snapshot();
    assert_eq!(snap.drain_latency_hist[3], 7);
    assert_eq!(snap.drain_latency_hist[15], 2);
    assert_eq!(snap.drain_invocations, 100);
    assert_eq!(snap.drain_noop_invocations, 50);
    assert_eq!(snap.redirect_acquire_hist[1], 11);
    assert_eq!(snap.owner_pps, 1234);
    assert_eq!(snap.peer_pps, 567);
    // #812 new assertions.
    assert_eq!(snap.tx_submit_latency_hist[2], 19);
    assert_eq!(snap.tx_submit_latency_hist[14], 23);
    assert_eq!(snap.tx_submit_latency_count, 42);
    assert_eq!(snap.tx_submit_latency_sum_ns, 999_999);
}

#[test]
fn owner_profile_telemetry_is_cacheline_isolated_from_binding_live_state() {
    // #746: pin the alignment invariant this PR is buying. If a
    // future refactor silently drops the `#[repr(align(64))]`
    // attribute on either of the owner-profile structs — or
    // reshuffles `BindingLiveState` fields so the two groups
    // land on the same cacheline as their neighbor — this test
    // fails loudly.
    //
    // The two assertions are complementary: alignment on the
    // struct types alone is not enough if the containing
    // `BindingLiveState` somehow mis-places them, and field-offset
    // alignment alone is not enough if the struct itself lost its
    // `#[repr(align(64))]`.
    use core::mem::{align_of, offset_of, size_of};

    assert_eq!(align_of::<OwnerProfileOwnerWrites>(), 64);
    assert_eq!(align_of::<OwnerProfilePeerWrites>(), 64);

    let owner_off = offset_of!(BindingLiveState, owner_profile_owner);
    let peer_off = offset_of!(BindingLiveState, owner_profile_peer);
    assert_eq!(
        owner_off % 64,
        0,
        "owner_profile_owner must sit on a 64-byte cacheline boundary",
    );
    assert_eq!(
        peer_off % 64,
        0,
        "owner_profile_peer must sit on a 64-byte cacheline boundary",
    );

    // The two profile structs must NOT share a cacheline: their
    // offset difference must be at least the larger struct size
    // (both are padded to 64-B alignment, so this also implies
    // rounded-up cacheline distance).
    let gap = peer_off.abs_diff(owner_off);
    assert!(
        gap >= size_of::<OwnerProfileOwnerWrites>().max(size_of::<OwnerProfilePeerWrites>()),
        "owner and peer profile structs must not share a cacheline (gap={gap}, \
         owner_size={}, peer_size={})",
        size_of::<OwnerProfileOwnerWrites>(),
        size_of::<OwnerProfilePeerWrites>(),
    );
}

#[test]
fn tx_status_drop_error_outranks_retry_hint_until_rebind_6145() {
    // #6145: pin the `last_error` snapshot precedence introduced by
    // #4971's lock-free TX-retry status. The snapshot renders the
    // `last_error` mutex string when non-empty, and ONLY falls back to
    // the `last_tx_retry_status` atomic when that string is empty.
    //
    // The property under test: an exceptional `TxError::Drop` error
    // (written to `last_error` via `set_error`) OUTRANKS the live
    // expected-retry hint and keeps masking it until the binding
    // rebinds (`clear_error`). This is deliberate — a Drop flags a real
    // capacity / slice-bounds fault and is rarer + more severe than
    // routine backpressure, so it must not be masked by a flood of
    // retry hints.
    //
    // FAIL-ON-REVERT (assertion, NOT a build break — every symbol used
    // here exists regardless of the precedence branch): inverting the
    // precedence so the retry atomic wins over a non-empty `last_error`
    // makes the Phase-3 assertion RED (it would surface the retry
    // reason instead of the latched Drop message). Removing the
    // empty-`last_error` fallback entirely makes Phase 2 / Phase 5 RED.
    use crate::afxdp::tx::{TxDropReason, TxRetryReason};

    let live = BindingLiveState::new();

    // Phase 1 — clean slate: no error, no retry hint → empty.
    assert!(
        live.snapshot().last_error.is_empty(),
        "phase 1: a fresh binding has no last_error and no retry hint"
    );

    // Phase 2 — an expected retry with an EMPTY last_error renders the
    // retry reason (the #4971 fallback works).
    live.set_tx_retry_status(TxRetryReason::NoFreeTxFrame);
    assert_eq!(
        live.snapshot().last_error,
        TxRetryReason::NoFreeTxFrame.as_str(),
        "phase 2: with last_error empty, the retry hint is the fallback"
    );

    // Phase 3 — an exceptional Drop latches last_error. Even with the
    // retry hint still set, the Drop message OUTRANKS the retry reason.
    let drop_msg =
        TxDropReason::PreparedSliceOutOfRange { offset: 4096, len: 128 }.message();
    live.set_error(drop_msg.clone());
    // Sustained retries keep firing AFTER the Drop latched — they only
    // touch the lock-free atomic, never clearing last_error.
    live.set_tx_retry_status(TxRetryReason::TxRingInsertFailed);
    let snap = live.snapshot();
    assert_eq!(
        snap.last_error, drop_msg,
        "phase 3: a latched Drop error must outrank the live retry hint"
    );
    assert_ne!(
        snap.last_error,
        TxRetryReason::TxRingInsertFailed.as_str(),
        "phase 3: the current retry reason must NOT surface while a Drop is latched"
    );

    // Phase 4 — rebind: clear_error wipes BOTH the mutex string and the
    // retry atomic (#4971). Snapshot returns to empty.
    live.clear_error();
    assert!(
        live.snapshot().last_error.is_empty(),
        "phase 4: clear_error (rebind) resets both last_error and the retry hint"
    );

    // Phase 5 — post-rebind: a fresh retry recorded after the clear now
    // renders again (last_error empty → fallback live).
    live.set_tx_retry_status(TxRetryReason::NoPreparedTxFrame);
    assert_eq!(
        live.snapshot().last_error,
        TxRetryReason::NoPreparedTxFrame.as_str(),
        "phase 5: after rebind, a fresh retry reason surfaces normally"
    );
}

#[test]
fn binding_live_snapshot_propagates_710_drop_counters() {
    // #710: `refresh_bindings` in the coordinator copies
    // `snap.redirect_inbox_overflow_drops`, `pending_tx_local_overflow_drops`,
    // and `tx_submit_error_drops` onto the per-binding `BindingStatus`.
    // This test pins the contract that BindingLiveState::snapshot() actually
    // reads those atomics and writes them into the BindingLiveSnapshot
    // struct — the middle layer between the counter increments and
    // the operator-facing BindingStatus. `no_owner_binding_drops` is
    // intentionally NOT in the snapshot (see the rustdoc on
    // `BindingLiveSnapshot` for why), so it is not asserted here.
    let live = BindingLiveState::new();
    live.redirect_inbox_overflow_drops
        .store(3, Ordering::Relaxed);
    live.pending_tx_local_overflow_drops
        .store(5, Ordering::Relaxed);
    live.tx_submit_error_drops.store(7, Ordering::Relaxed);
    live.tx_shared_recycle_unknown_slot_drops
        .store(13, Ordering::Relaxed);
    live.tx_shared_recycle_unknown_slot_rescued
        .store(47, Ordering::Relaxed);
    live.syn_cookie_challenges.store(17, Ordering::Relaxed);
    live.syn_cookie_secret_unavailable
        .store(19, Ordering::Relaxed);
    live.syn_cookie_syn_ack_sent.store(23, Ordering::Relaxed);
    live.syn_cookie_ack_rst_sent.store(29, Ordering::Relaxed);
    live.syn_cookie_reply_budget_drops
        .store(31, Ordering::Relaxed);
    live.syn_cookie_ack_valid.store(37, Ordering::Relaxed);
    live.syn_cookie_ack_invalid.store(41, Ordering::Relaxed);
    live.syn_cookie_bypass.store(43, Ordering::Relaxed);
    live.no_owner_binding_drops.store(11, Ordering::Relaxed);

    let snap = live.snapshot();
    assert_eq!(snap.redirect_inbox_overflow_drops, 3);
    assert_eq!(snap.pending_tx_local_overflow_drops, 5);
    assert_eq!(snap.tx_submit_error_drops, 7);
    assert_eq!(snap.tx_shared_recycle_unknown_slot_drops, 13);
    assert_eq!(snap.tx_shared_recycle_unknown_slot_rescued, 47);
    assert_eq!(snap.syn_cookie_challenges, 17);
    assert_eq!(snap.syn_cookie_secret_unavailable, 19);
    assert_eq!(snap.syn_cookie_syn_ack_sent, 23);
    assert_eq!(snap.syn_cookie_ack_rst_sent, 29);
    assert_eq!(snap.syn_cookie_reply_budget_drops, 31);
    assert_eq!(snap.syn_cookie_ack_valid, 37);
    assert_eq!(snap.syn_cookie_ack_invalid, 41);
    assert_eq!(snap.syn_cookie_bypass, 43);
    // `no_owner_binding_drops` has no per-binding protocol surface;
    // it is read directly from the atomic by
    // `Coordinator::cos_no_owner_binding_drops_total()`.
    assert_eq!(
        live.no_owner_binding_drops.load(Ordering::Relaxed),
        11,
        "atomic remains readable for the coordinator-level aggregation"
    );
}
