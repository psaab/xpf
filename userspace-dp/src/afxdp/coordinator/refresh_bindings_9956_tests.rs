//! #9956 F-051: the flowless counter round trip.
//!
//! Every stop between the poll chokepoint and the operator status is a manual
//! mirror — batch → flush → live → snapshot → copy → `BindingStatus` →
//! `zero_unbound_slot` — and a stop that drops a field is silent: no census
//! covers flush or `copy_live_snapshot` (#5190 covers copy/zero consistency
//! only, through the dispatcher). The reconcile zero-pass half
//! (`reset_binding_counters`) has no census either and is pinned by the
//! companion cell in `reconcile/reset.rs`. This cell drives the real functions
//! end to end so an omitted field fails here with the stop named.

use super::*;

#[test]
fn flowless_counters_round_trip_batch_to_status_to_reset_9956() {
    let mut batch = crate::afxdp::BatchCounters::default();
    batch.touched = true;
    batch.flowless_forward_packets = 3;
    batch.flowless_forward_bytes = 300;
    let live = crate::afxdp::binding_state::BindingLiveState::new();
    batch.flush(&live);
    assert_eq!(
        live.flowless_forward_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        3,
        "flush must carry flowless packets batch → live"
    );
    assert_eq!(
        live.flowless_forward_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        300,
        "flush must carry flowless bytes batch → live"
    );

    // live → snapshot → copy → BindingStatus.
    let snap = live.snapshot();
    assert_eq!(
        (snap.flowless_forward_packets, snap.flowless_forward_bytes),
        (3, 300),
        "snapshot must carry the flowless family live → snapshot"
    );
    let mut status = crate::protocol::BindingStatus::default();
    copy_live_snapshot(&mut status, snap);
    assert_eq!(
        (
            status.flowless_forward_packets,
            status.flowless_forward_bytes
        ),
        (3, 300),
        "copy must carry the flowless family snapshot → status"
    );

    // The unbound-slot reset half must clear the family (`reset_binding_counters`,
    // the reconcile zero-pass, is covered by its companion cell in
    // `reconcile/reset.rs` — it is `pub(super)`-scoped to `reconcile` and not
    // nameable from here).
    zero_unbound_slot(&mut status);
    assert_eq!(
        (
            status.flowless_forward_packets,
            status.flowless_forward_bytes
        ),
        (0, 0),
        "zero_unbound_slot must clear the flowless family"
    );
}
