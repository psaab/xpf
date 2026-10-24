// #16483: on the flow-backed (TCP/UDP, session-miss) path, a packet
// dropped by a poisoned DNAT rule (#14947 `lenient_match_dropped`) must
// advance that rule's NatRuleCounter by exactly 1 per dropped packet,
// mirroring the #15534 flowless contract ("no session is ever installed
// for a dropped packet"). Before the fix the flow-backed `Poisoned` arm
// discarded the counter handle returned by
// `lookup_result_with_counter_scoped`, so every flow to a poisoned rule
// was blackholed invisibly in `show security nat destination rule`.
//
// RED on master: poisoned subject stays 0 after a TCP SYN through
// `txn_run_descriptor_checked`. Healthy control: exactly 1 per
// installed flow (charged at the committed install, not here).
use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state_with_counters;
use crate::afxdp::tests_support::*;
use std::net::Ipv4Addr;

fn dnat_snapshot_16483(poisoned: bool) -> crate::ConfigSnapshot {
    let mut snap = crate::afxdp::test_fixtures::nat_snapshot();
    // WAN neighbor for the healthy pool target so the translated flow
    // can resolve and install.
    snap.neighbors.push(crate::NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.200".to_string(),
        mac: "02:aa:bb:cc:dd:60".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
        ..Default::default()
    });
    // Ingress is LAN (reth1.0, ifindex 24); the DNAT VIP is external.
    // The healthy pool target (10.0.61.200) is on the connected LAN
    // subnet, so the post-translation policy pair is lan->lan.
    snap.policies.push(crate::PolicyRuleSnapshot {
        name: "allow-lan-lan-16483".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    });
    snap.destination_nat_rules
        .push(crate::DestinationNATRuleSnapshot {
            name: "dnat-16483".to_string(),
            destination_address: "8.8.8.8".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "10.0.61.200".to_string(),
            pool_port: 8443,
            counter_id: 16483,
            lenient_match_dropped: poisoned,
            ..Default::default()
        });
    snap
}

fn run_one_16483(poisoned: bool) -> (crate::nat::NatCounterStore, usize, usize) {
    let snap = dnat_snapshot_16483(poisoned);
    let policy_counters = crate::policy::PolicyCounterStore::default();
    let nat_counters = crate::nat::NatCounterStore::default();
    let forwarding =
        build_forwarding_state_with_counters(&snap, &policy_counters, &nat_counters);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = std::sync::Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
        TEST_LAN_MAC,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    assert_eq!(dbg.rx, 1, "#16483: descriptor must reach the poll body");
    (nat_counters, sessions.len(), binding.scratch.scratch_forwards.len())
}

#[test]
fn flow_backed_poisoned_dnat_counts_drop_16483() {
    let (nat_counters, sessions_len, forwards_len) = run_one_16483(true);
    assert_eq!(sessions_len, 0, "#16483: poisoned DNAT must not install a session");
    assert_eq!(forwards_len, 0, "#16483: poisoned DNAT must not forward");
    let snaps = nat_counters.snapshots();
    assert_eq!(snaps.len(), 1, "#16483: exactly one NAT rule counter");
    assert_eq!(snaps[0].counter_id, 16483);
    assert_eq!(
        snaps[0].packets, 1,
        "#16483: poisoned flow-backed drop must advance the rule counter by exactly 1 per dropped packet"
    );
    assert_eq!(
        snaps[0].bytes, 54,
        "#16483: bytes are the dropped packet length (meta.pkt_len, the 54-byte TCP SYN frame)"
    );
}

#[test]
fn flow_backed_healthy_dnat_counts_once_per_install_16483() {
    let (nat_counters, sessions_len, _forwards_len) = run_one_16483(false);
    assert!(
        sessions_len >= 1,
        "#16483 healthy control: translated flow must install a session (sessions={sessions_len})"
    );
    let snaps = nat_counters.snapshots();
    assert_eq!(snaps.len(), 1, "#16483 healthy: exactly one NAT rule counter");
    assert_eq!(snaps[0].counter_id, 16483);
    assert_eq!(
        snaps[0].packets, 1,
        "#16483 healthy control: exactly 1 per installed flow (not double-counted by the poisoned arm)"
    );
}
