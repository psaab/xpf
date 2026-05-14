// Tests for afxdp/tx/dispatch.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep dispatch.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "dispatch_tests.rs"]` from dispatch.rs.

use super::*;
use crate::test_zone_ids::*;

fn test_forwarding_with_egress_mtu(mtu: usize) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        80,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu,
            src_mac: [0; 6],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        },
    );
    forwarding
}
fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 80,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    }
}

fn test_cos_fast_interfaces(
    egress_ifindex: i32,
    default_queue: u8,
    shared_exact_queues: &[(u8, bool)],
) -> FastMap<i32, WorkerCoSInterfaceFastPath> {
    let mut queue_index_by_id = [COS_FAST_QUEUE_INDEX_MISS; 256];
    let mut queue_fast_path = Vec::new();
    for (idx, (queue_id, shared_exact)) in shared_exact_queues.iter().copied().enumerate() {
        queue_index_by_id[usize::from(queue_id)] = idx as u16;
        queue_fast_path.push(WorkerCoSQueueFastPath {
            shared_exact,
            owner_worker_id: 0,
            owner_live: None,
            shared_queue_lease: shared_exact
                .then(|| Arc::new(SharedCoSQueueLease::new(1_250_000_000, 256 * 1024, 2))),
            vtime_floor: None,
        });
    }
    let mut interfaces = FastMap::default();
    interfaces.insert(
        egress_ifindex,
        WorkerCoSInterfaceFastPath {
            tx_ifindex: 11,
            default_queue_index: queue_index_by_id[usize::from(default_queue)] as usize,
            queue_index_by_id,
            tx_owner_live: None,
            shared_root_lease: None,
            queue_fast_path,
        },
    );
    interfaces
}

#[test]
fn forwarded_tcp_may_need_segmentation_skips_mtu_sized_frame() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let frame = vec![0u8; 14 + 1500];
    assert!(!forwarded_tcp_may_need_segmentation(
        &frame,
        meta,
        &test_decision(),
        &forwarding,
    ));
}

#[test]
fn forwarded_tcp_may_need_segmentation_uses_frame_vlan_offset_over_stale_meta() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        // Stale metadata shape observed in #1282: the live frame is VLAN
        // tagged, but metadata still points at a 14-byte Ethernet header.
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let mut frame = vec![0u8; 18 + 1500];
    frame[12] = 0x81;
    frame[13] = 0x00;
    frame[16] = 0x08;
    frame[17] = 0x00;

    assert!(!forwarded_tcp_may_need_segmentation(
        &frame,
        meta,
        &test_decision(),
        &forwarding,
    ));
}

#[test]
fn segmentation_miss_counter_skips_mtu_sized_vlan_frame_with_stale_meta() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let mut frame = vec![0u8; 18 + 1500];
    frame[12] = 0x81;
    frame[13] = 0x00;
    frame[16] = 0x08;
    frame[17] = 0x00;
    let tcp_segmentation_needed =
        forwarded_tcp_may_need_segmentation(&frame, meta, &test_decision(), &forwarding);
    let mut dbg = DebugPollCounters::default();

    assert!(!count_forwarded_tcp_segmentation_miss_if_needed(
        &mut dbg,
        false,
        tcp_segmentation_needed,
    ));
    assert_eq!(dbg.seg_needed_but_none, 0);
}

#[test]
fn segmentation_miss_counter_truth_table() {
    let cases = [
        (false, true, true, 1),
        (true, true, false, 0),
        (true, false, false, 0),
        (false, false, false, 0),
    ];

    for (copied_source_frame, tcp_segmentation_needed, expected_counted, expected_counter) in cases
    {
        let mut dbg = DebugPollCounters::default();

        assert_eq!(
            count_forwarded_tcp_segmentation_miss_if_needed(
                &mut dbg,
                copied_source_frame,
                tcp_segmentation_needed,
            ),
            expected_counted,
        );
        assert_eq!(dbg.seg_needed_but_none, expected_counter);
    }
}

#[test]
fn forwarded_tcp_may_need_segmentation_flags_oversized_frame() {
    let forwarding = test_forwarding_with_egress_mtu(1500);
    let meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        l3_offset: 14,
        ..UserspaceDpMeta::default()
    };
    let frame = vec![0u8; 14 + 1600];
    assert!(forwarded_tcp_may_need_segmentation(
        &frame,
        meta,
        &test_decision(),
        &forwarding,
    ));
}

#[test]
fn shared_recycle_target_uses_lookup_when_slot_matches() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let slots = [10, 20, 30];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        Some(1)
    );
}

#[test]
fn shared_recycle_target_scans_when_lookup_is_stale_or_wrong_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let slots = [10, 99, 20];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        Some(2)
    );
}

#[test]
fn shared_recycle_target_drops_unknown_or_out_of_range_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 99);
    let slots = [10, 30];

    assert_eq!(
        shared_recycle_target_index(slots.len(), &lookup, 20, |idx| slots.get(idx).copied()),
        None
    );
}

fn test_split_slot_at(
    left: &[u32],
    current_index: usize,
    current_slot: u32,
    right: &[u32],
    target_index: usize,
) -> Option<u32> {
    if target_index == current_index {
        return Some(current_slot);
    }
    if target_index < current_index {
        return left.get(target_index).copied();
    }
    right
        .get(target_index.saturating_sub(current_index + 1))
        .copied()
}

#[test]
fn shared_recycle_split_target_scans_when_lookup_is_stale() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 1);
    let left = [10, 99];
    let current_index = 2;
    let current_slot = 30;
    let right = [20, 40];

    assert_eq!(
        shared_recycle_target_index_for_split(left.len(), right.len(), &lookup, 20, |idx| {
            test_split_slot_at(&left, current_index, current_slot, &right, idx)
        }),
        Some(3)
    );
}

#[test]
fn shared_recycle_split_target_drops_unknown_slot() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(20, 9);
    let left = [10, 30];
    let current_index = 2;
    let current_slot = 40;
    let right = [50, 60];

    assert_eq!(
        shared_recycle_target_index_for_split(left.len(), right.len(), &lookup, 20, |idx| {
            test_split_slot_at(&left, current_index, current_slot, &right, idx)
        }),
        None
    );
}

#[test]
fn shared_recycle_unknown_slot_drop_increments_tx_errors() {
    let live = BindingLiveState::new();

    record_shared_recycle_unknown_slot_drops(Some(&live), 2);
    record_shared_recycle_unknown_slot_drops(Some(&live), 0);
    record_shared_recycle_unknown_slot_drops(None, 5);

    assert_eq!(live.tx_errors.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn shared_exact_queue_lease_uses_requested_queue_id() {
    let cos_fast_interfaces = test_cos_fast_interfaces(80, 5, &[(5, true)]);

    assert!(request_uses_shared_exact_queue_lease(
        &cos_fast_interfaces,
        80,
        Some(5),
    ));
    assert!(!request_uses_shared_exact_queue_lease(
        &cos_fast_interfaces,
        80,
        Some(4),
    ));
}

#[test]
fn shared_exact_queue_lease_uses_interface_default_queue() {
    let cos_fast_interfaces = test_cos_fast_interfaces(80, 5, &[(5, true)]);

    assert!(request_uses_shared_exact_queue_lease(
        &cos_fast_interfaces,
        80,
        None,
    ));
}
