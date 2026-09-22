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

#[test]
fn named_pre_l3_counters_round_trip_and_reset_10498() {
    let mut batch = crate::afxdp::BatchCounters::default();
    batch.touched = true;
    batch.umem_slice_dropped = 7;
    batch.unknown_vlan_dropped = 11;
    batch.dst_mac_dropped = 13;
    let live = crate::afxdp::binding_state::BindingLiveState::new();
    batch.flush(&live);
    assert_eq!(
        (
            live.umem_slice_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
            live.unknown_vlan_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
            live.dst_mac_dropped
                .load(std::sync::atomic::Ordering::Relaxed),
        ),
        (7, 11, 13),
        "flush must carry named pre-L3 drops batch → live"
    );

    let snap = live.snapshot();
    assert_eq!(
        (
            snap.umem_slice_dropped,
            snap.unknown_vlan_dropped,
            snap.dst_mac_dropped,
        ),
        (7, 11, 13),
        "snapshot must carry named pre-L3 drops live → snapshot"
    );
    let mut status = crate::protocol::BindingStatus::default();
    copy_live_snapshot(&mut status, snap);
    assert_eq!(
        (
            status.umem_slice_dropped,
            status.unknown_vlan_dropped,
            status.dst_mac_dropped,
        ),
        (7, 11, 13),
        "copy must carry named pre-L3 drops snapshot → status"
    );
    zero_unbound_slot(&mut status);
    assert_eq!(
        (
            status.umem_slice_dropped,
            status.unknown_vlan_dropped,
            status.dst_mac_dropped,
        ),
        (0, 0, 0),
        "zero_unbound_slot must clear named pre-L3 drops"
    );
}

#[test]
fn named_pre_l3_wire_keys_are_exact_10498() {
    let status = crate::protocol::BindingStatus {
        umem_slice_dropped: 1,
        unknown_vlan_dropped: 2,
        dst_mac_dropped: 3,
        ..Default::default()
    };
    let value = serde_json::to_value(status).expect("serialize BindingStatus");
    assert_eq!(value["umem_slice_dropped"], 1);
    assert_eq!(value["unknown_vlan_dropped"], 2);
    assert_eq!(value["dst_mac_dropped"], 3);
}
