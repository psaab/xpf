//! #8108: the RPC-fallback delta buffer's occupancy is measurable.
//!
//! The issue's acceptance is "a measured ring-occupancy figure from a
//! revocation burst large enough to matter — not a computed bound", and it
//! explicitly allows the issue to be CLOSED if the measurement shows the ring
//! is not reached. Neither outcome was available: `pending_session_deltas.len()`
//! was read only for the cap check and nothing retained it, and
//! `delta_loss_pending` is a BOOLEAN — "we overflowed at least once", never
//! "we reached 90%".
//!
//! So a buffer running comfortably and a buffer surviving on luck were the same
//! observation. This makes them different.

use super::*;
use std::sync::atomic::Ordering;

fn delta_8108(_id: u64) -> SessionDeltaInfo {
    // The contents are irrelevant to occupancy — this measures DEPTH, and a
    // depth counts entries regardless of what they carry.
    SessionDeltaInfo::default()
}

/// The defining property: it records the MAXIMUM, not the current depth.
///
/// This is the whole reason it is a high-water mark. The buffer drains, so a
/// depth gauge sampled at 1 Hz sees a revocation burst only if the sample lands
/// inside it — and reports a comfortable small number otherwise, for exactly
/// the event being measured. A cell that only pushed and read would pass
/// against a plain depth gauge; this one drains first.
#[test]
fn the_high_water_survives_a_drain_8108() {
    let b = BindingLiveState::new();
    for i in 0..7 {
        b.push_session_delta(delta_8108(i));
    }
    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        7,
        "high water must equal the depth reached"
    );

    let drained = b.drain_session_deltas(usize::MAX);
    assert_eq!(drained.len(), 7, "precondition: the buffer drained");

    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        7,
        "after a full drain the CURRENT depth is 0 but the high water must still \
         read 7. A gauge that fell back to 0 here would report a healthy buffer \
         for the burst it just absorbed, which is the measurement this exists to \
         make possible."
    );
}

/// It rises to the new maximum and never falls back to a lower peak.
#[test]
fn the_high_water_only_rises_8108() {
    let b = BindingLiveState::new();
    for i in 0..5 {
        b.push_session_delta(delta_8108(i));
    }
    let _ = b.drain_session_deltas(usize::MAX);
    for i in 0..2 {
        b.push_session_delta(delta_8108(100 + i));
    }
    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        5,
        "a smaller later burst must not lower the recorded peak"
    );

    for i in 0..9 {
        b.push_session_delta(delta_8108(200 + i));
    }
    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        11,
        "a larger burst must raise it (2 retained + 9 = 11)"
    );
}

/// A fresh binding reads zero, so "never pushed" and "pushed nothing" are the
/// same observation — which they are — and the metric cannot be mistaken for
/// having measured something it did not.
#[test]
fn a_fresh_binding_reports_zero_high_water_8108() {
    let b = BindingLiveState::new();
    assert_eq!(b.session_delta_high_water.load(Ordering::Relaxed), 0);
}

/// The three states the issue needs separated, asserted together.
///
/// Before #8108 only the third was observable, and only as a boolean. The point
/// of the pair is that "near the cap but never dropped" — surviving on luck —
/// is now distinguishable from "comfortable", and that distinction is what
/// decides whether the fallback in the issue's item 2 is worth building.
#[test]
fn high_water_and_dropped_separate_comfortable_from_lucky_8108() {
    // Comfortable: well under the cap, nothing dropped.
    let comfortable = BindingLiveState::new();
    for i in 0..4 {
        comfortable.push_session_delta(delta_8108(i));
    }
    assert!(comfortable.session_delta_high_water.load(Ordering::Relaxed) < MAX_PENDING_SESSION_DELTAS as u64);
    assert_eq!(comfortable.session_delta_dropped.load(Ordering::Relaxed), 0);

    // Lossy: filled past the cap. dropped > 0 AND the high water pins at the cap.
    let lossy = BindingLiveState::new();
    for i in 0..(MAX_PENDING_SESSION_DELTAS + 5) {
        lossy.push_session_delta(delta_8108(i as u64));
    }
    assert_eq!(
        lossy.session_delta_high_water.load(Ordering::Relaxed),
        MAX_PENDING_SESSION_DELTAS as u64,
        "the high water tops out AT the cap — it never records a depth the buffer \
         cannot hold, so a reader cannot mistake the overflow for a deeper queue"
    );
    assert_eq!(
        lossy.session_delta_dropped.load(Ordering::Relaxed),
        5,
        "and the drops are counted separately, so 'reached the cap' and 'lost \
         deltas' stay distinguishable"
    );
    assert!(lossy.delta_loss_pending.load(Ordering::Relaxed));
}

// ---------------------------------------------------------------------------
// #8593: the loss-of-sync latch must not be armed by the resync's own export.
// ---------------------------------------------------------------------------

/// Fill the RPC-fallback buffer to `MAX_PENDING_SESSION_DELTAS` and clear the
/// latch the filling armed, so the assertions below measure exactly the ONE
/// push that follows.
fn full_buffer_with_latch_cleared_8593() -> BindingLiveState {
    let b = BindingLiveState::new();
    for i in 0..MAX_PENDING_SESSION_DELTAS {
        b.push_session_delta(delta_8108(i as u64));
    }
    assert_eq!(
        b.session_delta_dropped.load(Ordering::Relaxed),
        0,
        "fixture: filling exactly to the cap must not have dropped yet, or the \
         single push below is not the one being measured"
    );
    // Filling to the cap does not overflow, so nothing armed. Take it anyway so
    // a future change to the fill loop cannot leave a stale true here.
    let _ = b.take_delta_loss();
    b
}

/// THE DISCRIMINATOR (#8593). "The trigger fired and the resync CLEARED it" and
/// "the trigger fired and the resync RE-ARMED it" produce the same observation
/// in every pre-existing cell — they all assert that the export ran, or that
/// the SessionTable latch is clear, and neither can see the per-binding latch
/// the export re-arms. This asserts the difference directly, on the same
/// buffer, one push apart.
///
/// Both pushes DROP — that is asserted, because a cell in which the bulk push
/// simply fit would show "not armed" for a reason that has nothing to do with
/// the fix.
///
/// Fail-on-revert: route `push_session_delta_bulk_export` back to the arming
/// path and the first assertion reds. That reproduces the measured #8593 loop:
/// the export's overflow arms the latch, the worker loop folds it into
/// `sessions.set_delta_loss()`, and the next pass exports again.
#[test]
fn a_bulk_export_overflow_does_not_re_arm_the_resync_8593() {
    // (a) A BULK-EXPORT delta that does not fit: counted, NOT armed.
    let b = full_buffer_with_latch_cleared_8593();
    b.push_session_delta_bulk_export(delta_8108(9_001));
    assert_eq!(
        b.session_delta_dropped.load(Ordering::Relaxed),
        1,
        "fixture: the bulk push must actually have been REFUSED — if it fit, \
         'not armed' says nothing"
    );
    assert!(
        !b.take_delta_loss(),
        "a resync EXPORT delta that overflows must not arm the latch that \
         triggers the resync. Arming it is the #8593 feedback loop: measured at \
         92% of 25.26M deltas dropped, still running ~149k/s with zero traffic"
    );

    // (b) THE CONTROL, same buffer state, one push different: an INCREMENTAL
    // delta that does not fit MUST arm. Without this the fix is satisfied by
    // "never arm", which deletes the #5290 recovery entirely.
    let c = full_buffer_with_latch_cleared_8593();
    c.push_session_delta(delta_8108(9_002));
    assert_eq!(
        c.session_delta_dropped.load(Ordering::Relaxed),
        1,
        "fixture: the incremental push must also have been refused"
    );
    assert!(
        c.take_delta_loss(),
        "an INCREMENTAL drop is a HA-relevant open/close the standby will never \
         see; it must still arm the owner-RG resync (#5290)"
    );
}

/// The latch is the only thing that differs. A bulk-export push that FITS must
/// behave exactly like an incremental one — same buffer, same counters, same
/// high water — or the fix has quietly changed what the fallback carries.
///
/// Fires on: making `push_session_delta_bulk_export` skip the buffer instead of
/// skipping the arm. That would stop the daemon's polling fallback from
/// carrying any of the snapshot, which is a different change from the one
/// #8593 argues for.
#[test]
fn a_bulk_export_delta_that_fits_is_stored_like_any_other_8593() {
    let b = BindingLiveState::new();
    b.push_session_delta_bulk_export(delta_8108(1));
    b.push_session_delta_bulk_export(delta_8108(2));
    assert_eq!(
        b.session_delta_generated.load(Ordering::Relaxed),
        2,
        "a bulk delta is still generated"
    );
    assert_eq!(b.session_delta_dropped.load(Ordering::Relaxed), 0);
    assert_eq!(
        b.session_delta_high_water.load(Ordering::Relaxed),
        2,
        "and still counts toward the #8108 occupancy measurement"
    );
    assert_eq!(
        b.drain_session_deltas(usize::MAX).len(),
        2,
        "and is still DELIVERED to the RPC-fallback consumer — the fix skips the \
         ARM, not the buffer"
    );
}

/// #9856 STEP-0 (M2): the owner-RG export's control response keeps at most 4096
/// deltas per binding buffer — sessions past the cap are dropped at the push
/// and the `more` bit cannot see them, so a FullResync can ACK a partial
/// export. RED on base. Post-fix the export rides a dedicated export buffer
/// drained incrementally while workers produce (this cell migrates to that API;
/// the "every session reaches the response" assertion is kept).
#[test]
fn bulk_export_response_keeps_only_4096_deltas_9856() {
    // Post-M2b driver: the export rides the dedicated per-worker buffer,
    // drained incrementally while workers produce (drain-then-retry models
    // the worker's pause-without-advance on Full). Assertion kept: every
    // session reaches the response; +100-past-cap shape kept vs the new cap.
    let b = ExportBufferState::new();
    const N: usize = EXPORT_BUFFER_CAP_ENTRIES + 100;
    let mut delivered = 0usize;
    for i in 0..N {
        loop {
            match b.push_export_open(9, delta_8108(i as u64)) {
                Ok(()) => break,
                Err(_) => delivered += b.drain_export(usize::MAX).len(),
            }
        }
    }
    delivered += b.drain_export(usize::MAX).len();
    assert_eq!(
        delivered, N,
        "#9856: dedicated export buffer must deliver every session; kept {delivered} of {N}"
    );
    assert_eq!(
        b.export_dropped(),
        0,
        "opens never drop — Full pauses, never drops"
    );
}
