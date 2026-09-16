// BindingLiveState redirect-inbox admission + overflow-counter
// tests. Split from umem/tests.rs (#4667).

use super::*;

#[test]
fn enqueue_tx_owned_increments_redirect_inbox_overflow_counter_when_soft_cap_drops_newcomer() {
    // #710 / #706: pin that a redirect-inbox overflow in
    // `enqueue_tx_owned` increments both `redirect_inbox_overflow_drops`
    // (dedicated view) and `tx_errors` (generic), regardless of
    // which request gets dropped. Post-#706 the policy is drop-
    // newest (the incoming push is discarded); pre-#706 it was
    // drop-oldest (the head of the queue was evicted). Either way,
    // every push must return `Ok(())` and both counters advance in
    // lockstep.
    let live = BindingLiveState::new();
    live.max_pending_tx.store(2, Ordering::Relaxed);

    // Fill to cap — no overflow yet.
    live.enqueue_tx_owned(test_tx_request_for_inbox(1))
        .expect("push 1");
    live.enqueue_tx_owned(test_tx_request_for_inbox(2))
        .expect("push 2");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        0
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 0);

    // Third push hits the soft cap — drop-newest, counters advance.
    live.enqueue_tx_owned(test_tx_request_for_inbox(3))
        .expect("push 3 drops newest");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        live.tx_errors.load(Ordering::Relaxed),
        1,
        "generic tx_errors stays in lockstep with the dedicated drop \
         counter on this path — the dedicated counter is a subset view"
    );

    // Fourth push, another overflow — both counters advance again.
    live.enqueue_tx_owned(test_tx_request_for_inbox(4))
        .expect("push 4 drops newest");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        2
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 2);
}

#[test]
fn take_pending_tx_into_appends_without_resetting_caller_buffer() {
    // #706: pin that `take_pending_tx_into` preserves the caller's
    // existing `VecDeque` contents. The owner-worker drain feeds its
    // `pending_tx_local` buffer through the call; if the new API ever
    // regressed to `*out = drained` or `out.clear()`, items already
    // queued locally would be dropped on every poll.
    let live = BindingLiveState::new();
    live.max_pending_tx.store(8, Ordering::Relaxed);
    live.enqueue_tx_owned(test_tx_request_for_inbox(10))
        .expect("push inbox");
    live.enqueue_tx_owned(test_tx_request_for_inbox(11))
        .expect("push inbox");

    let mut out = VecDeque::from([test_tx_request_for_inbox(1), test_tx_request_for_inbox(2)]);
    live.take_pending_tx_into(&mut out);

    let payloads: Vec<u8> = out.iter().map(|req| req.bytes[0]).collect();
    assert_eq!(
        payloads,
        vec![1, 2, 10, 11],
        "caller-provided items must come first; inbox items appended in FIFO order"
    );
    assert!(live.pending_tx_empty(), "inbox fully drained");
}

#[test]
fn enqueue_tx_owned_below_cap_does_not_touch_overflow_counter() {
    let live = BindingLiveState::new();
    live.max_pending_tx.store(8, Ordering::Relaxed);

    for payload in 0..4 {
        live.enqueue_tx_owned(test_tx_request_for_inbox(payload))
            .expect("push below cap");
    }
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        0
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 0);
}

/// #6304: the admission-attempt instrument moves none of FOUR PINNED
/// `BindingLiveState` layout values. Stated that narrowly on purpose — it is
/// what was measured, and it is weaker than "does not perturb the struct",
/// which the last paragraph here explains this cell cannot show.
///
/// `try_acquire_pending_tx_admission` carries a `#[cfg(test)]` bump into a
/// THREAD-LOCAL counter so
/// `live_flow_cache_callsite_nonsampled_makes_no_shared_admission_attempt_6304`
/// can distinguish sample-first from reserve-first at the live call site. This
/// struct is the one whose cross-core cacheline behaviour #6114 exists to fix,
/// so the standing objection to instrumenting it is real: a test-only member
/// puts a layout under test that production never has.
///
/// A thread-local answers that objection by construction — it lives in its own
/// storage — and this cell is the measurement rather than the argument. It reads
/// the TEST configuration; the `const _: [(); N]` asserts beside the struct in
/// `binding_state/mod.rs` are what make the statement a CROSS-configuration one,
/// since they are not `cfg`-gated and must hold in the production build too.
/// Both numbers here and there are the same literals on purpose.
///
/// Why the two offsets and not just the size — measured, not assumed. A
/// `#[cfg(test)]` `AtomicU64` field declared ahead of `pending_tx_admitted`
/// leaves size and align UNCHANGED (it fits in existing tail slack) and moves
/// `pending_tx_admitted` 2152 -> 2160; declared last, after
/// #6664 moved the two OFFSET literals here (2152 -> 2160, 2280 -> 2288) in
/// lockstep with the `const _` asserts beside the struct, when the production
/// field `next_table_unsupported_drops` was added to the cold-counter run.
/// Size and align are unchanged — the 8 bytes came out of tail padding. This
/// cell is the readable mirror, so it moves WITH those asserts or it is not a
/// mirror; it is not independent evidence and must never be re-measured alone.
///
/// `delta_loss_pending`, it leaves size, align and `pending_tx_admitted`
/// unchanged and moves `delta_loss_pending` 2280 -> 2288. A size-only guard
/// calls both of those layout-neutral, and both would be exactly the
/// perturbation #6114 cares about.
///
/// WHAT THIS CELL CAN AND CANNOT DO. It cannot FAIL. The four `const _`
/// asserts beside the struct are not `cfg`-gated, so a wrong value in the test
/// configuration is a compile error and this binary never gets built — the
/// assertions below execute, always pass, and exist as a readable mirror of the
/// numbers plus their reasoning, not as an independent check. Nor are four
/// pinned values a whole-struct fingerprint: a perturbation that moves only
/// unpinned fields satisfies all four. See the comment beside the struct for the
/// full scope, including why `repr(Rust)` plus an unpinned toolchain makes these
/// literals a build tripwire rather than a portable invariant.
#[test]
// #7054 re-measured the two OFFSET literals here (2160 -> 2168, 2288 -> 2296)
// in lockstep with the compile-time asserts in `binding_state/mod.rs`, when the
// unconditional `nat64_frag_assoc_evicted` counter joined the cold-counter run.
// Both must move together: this runtime cell and those `const _` asserts are
// the pair that makes a `#[cfg(test)]` field detectable, because for such a
// field production and test builds disagree and at most one can be green at any
// one set of literals. An unconditional field shifts both by the same 8 bytes,
// so re-measuring both is the guard being ANSWERED. `size_of` stays 2304 — the
// bytes came out of tail padding, again.
//
// #8108 re-measured the two OFFSETS again (2176 -> 2184, 2304 -> 2312) when the
// unconditional `session_delta_high_water` counter joined the cold run. Same
// lockstep, verified the way the paragraph above requires: both build
// configurations green on one set of literals. `size_of` did NOT move this time
// — still 2368 — so the 64-byte unit #7156's field opened had room for this one.
// That is the second time the "tail padding is now full" prediction has not
// held, which is why this guard pins the OFFSETS separately from the size.
//
// #7156 re-measured all three moving literals (size 2304 -> 2368, offsets
// 2168 -> 2176 and 2296 -> 2304) when the unconditional `pending_neigh_visits`
// counter joined that run. Same lockstep, and verified the way the paragraph
// above says it must be: BOTH build configurations green on one set of
// literals, which a `#[cfg(test)]` field could not achieve. Unlike #6664 and
// #7054, `size_of` DID move this time — the tail padding is now full, so the
// struct grew a whole 64-byte alignment unit.
//
// #8670 re-measured the two OFFSETS again (2184 -> 2192, 2312 -> 2320) when the
// unconditional `nat64_ineligible_protocol` counter joined the cold run. Same
// lockstep, verified the way the paragraph above requires: both build
// configurations green on one set of literals. `size_of` did NOT move — still
// 2368 — which is now the THIRD time the "tail padding is full" prediction has
// not held. An unchanged 2368 is therefore not evidence a field failed to
// land; the offsets are what carried the proof, which is the whole reason this
// guard pins them separately from the size.
//
// #8890 re-measured the two OFFSETS again (2192 -> 2200, 2320 -> 2328) when the
// unconditional `nat64_tunnel_encap_unsupported` counter joined the cold run.
// Same lockstep, verified the way the paragraph above requires: BOTH build
// configurations were built and both reported the same two shifts, by the same
// 8 bytes, so one set of literals makes both green — which a `#[cfg(test)]`
// field could not achieve, and which is the entire discriminator between
// answering this guard and defeating it. `size_of` did NOT move — still 2368 —
// the FOURTH time the "tail padding is full" prediction has not held.
fn admission_attempt_instrument_leaves_four_pinned_layout_values_unchanged_6304() {
    assert_eq!(
        std::mem::size_of::<BindingLiveState>(),
        2368,
        "#6304: the `cfg(test)` admission-attempt instrument must not change \
         `BindingLiveState`'s SIZE — the same literal is asserted at compile \
         time in `binding_state/mod.rs`, which is where the production build \
         checks it"
    );
    assert_eq!(
        std::mem::align_of::<BindingLiveState>(),
        64,
        "#6304: ...nor its ALIGNMENT"
    );
    // F-149 (#9904): `tx_shared_recycle_unknown_slot_rescued` moves both
    // offsets +8 in BOTH builds (unconditional field), matching the updated
    // compile-time literals in `binding_state/mod.rs`. #9956 F-051:
    // `flowless_forward_packets/bytes` move both +16 more (2224/2352).
    assert_eq!(
        std::mem::offset_of!(BindingLiveState, pending_tx_admitted),
        2224,
        "#6304/#6114: ...nor the OFFSET of the admission counter whose \
         cacheline this is all about. A `cfg(test)` field ahead of it moves \
         this to 2160 while leaving the size assert above satisfied"
    );
    assert_eq!(
        std::mem::offset_of!(BindingLiveState, delta_loss_pending),
        2352,
        "#6304: ...nor the offset of the last-declared field, which is the \
         sentinel for a `cfg(test)` member appended at the END of the struct — \
         that shape moves this to 2288 and trips nothing else"
    );
}
