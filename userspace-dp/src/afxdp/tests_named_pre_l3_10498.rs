// #10498: named pre-L3 drops must be exercised through the poll-head harness.

use super::test_fixtures::agreed_zone_trunk_snapshot_10313;
use super::tests_support::*;
use super::*;

fn frame_and_meta() -> (Vec<u8>, UserspaceDpMeta) {
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        40_000,
        443,
        TCP_FLAG_SYN,
        TEST_VLAN50_MAC,
    );
    let meta = txn_meta_v4(11, TCP_FLAG_SYN, frame.len() as u16);
    (frame, meta)
}

fn assert_pre_l3_drop_stops_downstream_10498(
    batch: &BatchCounters,
    dbg: &DebugPollCounters,
    binding: &BindingWorker,
    sessions: &SessionTable,
) {
    assert_eq!(batch.forward_candidate_packets, 0);
    assert_eq!(batch.flowless_forward_packets, 0);
    assert_eq!(batch.local_delivery_packets, 0);
    assert_eq!(batch.route_miss_packets, 0);
    assert_eq!(dbg.forward, 0);
    assert_eq!(dbg.local, 0);
    assert_eq!(dbg.session_create, 0);
    assert_eq!(dbg.no_route, 0);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 0);
}

#[test]
fn poll_head_counts_umem_slice_drop_and_recycles_10498() {
    let forwarding = ForwardingState::default();
    let ha_state = BTreeMap::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    let mut sessions = SessionTable::new();
    let (frame, meta) = frame_and_meta();

    // Keep the descriptor address valid for metadata parsing, but make its
    // frame range exceed the UMEM area. This reaches the named UMEM arm rather
    // than the metadata-error path.
    let (batch, dbg) = txn_run_descriptor_with_desc_len(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        u32::MAX,
    );

    assert_eq!(batch.umem_slice_dropped, 1);
    assert_eq!(batch.unknown_vlan_dropped, 0);
    assert_eq!(batch.dst_mac_dropped, 0);
    assert_pre_l3_drop_stops_downstream_10498(&batch, &dbg, &binding, &sessions);
    assert_eq!(binding.scratch.scratch_recycle, vec![128]);
}

#[test]
fn poll_head_counts_unknown_vlan_drop_and_recycles_10498() {
    let forwarding = build_forwarding_state(&agreed_zone_trunk_snapshot_10313());
    let ha_state = BTreeMap::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    let mut sessions = SessionTable::new();
    let (frame, mut meta) = frame_and_meta();
    meta.ingress_vlan_present = 1;
    meta.ingress_vlan_id = 99;

    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(batch.umem_slice_dropped, 0);
    assert_eq!(batch.unknown_vlan_dropped, 1);
    assert_eq!(batch.dst_mac_dropped, 0);
    assert_pre_l3_drop_stops_downstream_10498(&batch, &dbg, &binding, &sessions);
    assert_eq!(binding.scratch.scratch_recycle, vec![128]);
}

#[test]
fn poll_head_counts_destination_mac_drop_and_recycles_10498() {
    let forwarding = ForwardingState::default();
    let ha_state = BTreeMap::new();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    let mut sessions = SessionTable::new();
    let (frame, meta) = frame_and_meta();

    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(batch.umem_slice_dropped, 0);
    assert_eq!(batch.unknown_vlan_dropped, 0);
    assert_eq!(batch.dst_mac_dropped, 1);
    assert_pre_l3_drop_stops_downstream_10498(&batch, &dbg, &binding, &sessions);
    assert_eq!(binding.scratch.scratch_recycle, vec![128]);
}

#[test]
fn poll_head_accepts_group_and_local_destination_macs_10498() {
    let forwarding = build_forwarding_state(&agreed_zone_trunk_snapshot_10313());
    let ha_state = BTreeMap::new();

    for (label, dst_mac) in [
        ("broadcast", [0xff; 6]),
        ("multicast", [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]),
        // `reth0.50` is the configured logical ingress unit in the fixture.
        ("configured-local", [0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
    ] {
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
        let mut sessions = SessionTable::new();
        let (mut frame, mut meta) = frame_and_meta();
        frame[..6].copy_from_slice(&dst_mac);
        meta.ingress_vlan_present = 1;
        meta.ingress_vlan_id = 50;

        let (batch, _dbg) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame,
            meta,
        );

        assert_eq!(batch.umem_slice_dropped, 0, "{label}");
        assert_eq!(batch.unknown_vlan_dropped, 0, "{label}");
        assert_eq!(batch.dst_mac_dropped, 0, "{label}");
    }
}
