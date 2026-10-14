// #12865 regression: zone counters credit the adjudicated (admission) pair.
// Slow-path FabricRedirect and VLAN-trunk cells (hostile-review probes,
// promoted to permanent regressions).
//   P1: does the SLOW-path (first-packet) FabricRedirect punt credit the
//       INTENDED egress zone (wan) rather than the redirect transport?
//   P2 (control): does the same punt credit the logical ingress zone?
#![allow(unused_imports)]
use crate::NeighborSnapshot;

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;

fn active_rg_probe(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

/// Local copy of tests_fabric_zone_stamp.rs's fixture (private there):
/// nat_snapshot_with_fabric + the reachable LAN neighbor on reth1.0 (24).
fn fabric_snapshot_with_lan_neighbor_probe() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.102".to_string(),
        mac: "de:ad:be:ef:00:01".to_string(),
        state: "reachable".to_string(),
        ..Default::default()
    });
    snapshot
}

#[test]
fn zone_counter_12865_slow_path_fabric_redirect_credits_intended_egress_zone() {
    let forwarding = build_forwarding_state(&fabric_snapshot_with_lan_neighbor_probe());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let lan_host = Ipv4Addr::new(10, 0, 61, 102);
    let wan_peer = Ipv4Addr::new(8, 8, 8, 8);
    // #7770 split: LAN RG 2 local, WAN RG 1 the peer's -> the punt leg.
    let ha_state = BTreeMap::from([(2, active_rg_probe(now_secs))]);
    let mut sessions = SessionTable::new();
    let mut lan_binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    lan_binding.interface = Arc::<str>::from("ge-0-0-1");
    let out_frame = build_txn_tcp_syn_frame_v4(
        lan_host,
        wan_peer,
        12345,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let out_meta = txn_meta_v4(24, TCP_FLAG_SYN, out_frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut lan_binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &out_frame,
        out_meta,
        true,
    );
    // Fixture preconditions: this really is the #7770 FabricRedirect punt.
    assert_eq!(dbg.policy_deny, 0, "probe: the punt must not be denied");
    assert_eq!(
        lan_binding.scratch.scratch_forwards.len(),
        1,
        "probe: the punt must queue exactly one fabric forward"
    );
    let mut shapes = Vec::new();
    sessions.iter_with_origin(|_key, decision, metadata, origin| {
        shapes.push((
            origin,
            decision.resolution.disposition,
            metadata.ingress_zone,
            metadata.egress_zone,
            metadata.is_reverse,
        ));
    });
    assert_eq!(shapes.len(), 1, "probe: exactly one seed session");
    assert_eq!(
        shapes[0].1,
        ForwardingDisposition::FabricRedirect,
        "probe: the punted flow's session must be a FabricRedirect"
    );
    assert_eq!(
        shapes[0].3,
        TEST_WAN_ZONE_ID,
        "probe: the seed's egress zone must be the INTENDED wan zone (pre-redirect)"
    );

    crate::afxdp::zone_counters::flush_recorded_zone_counters(
        &forwarding.zone_counter_store,
        &forwarding.zone_counter_slot_map,
    );
    let rows = forwarding.zone_counter_store.snapshot();
    eprintln!("probe rows: {:?}", rows);
    let lan = rows
        .iter()
        .find(|r| r.zone_id == TEST_LAN_ZONE_ID)
        .expect("probe: the logical ingress (lan) must be credited");
    assert_eq!(
        (lan.ingress_packets, lan.ingress_bytes),
        (1, out_frame.len() as u64),
        "probe P2: slow-path ingress must credit the admission (logical) zone"
    );
    let wan = rows.iter().find(|r| r.zone_id == TEST_WAN_ZONE_ID).expect(
        "probe P1 #12865: the FabricRedirect punt's egress side must credit the \
         INTENDED wan zone (the admission pair's egress), not the fabric \
         transport (whose unzoned parent yields no row at all)",
    );
    assert_eq!(
        (wan.egress_packets, wan.egress_bytes),
        (1, out_frame.len() as u64),
        "probe P1 #12865: intended-egress credit for the redirected first packet"
    );
}

/// Probe P3 (residual evidence): with a POPULATED raw shim ingress zone (as
/// the production XDP shim stamps), how many ingress credits does ONE
/// slow-path forwarded packet produce? Prints the rows; asserts nothing
/// beyond arrival so the printed numbers are the evidence.
#[test]
fn zone_counter_12865_slow_path_double_count_with_populated_shim_zone() {
    let forwarding = build_forwarding_state(&fabric_snapshot_with_lan_neighbor_probe());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(2, active_rg_probe(now_secs))]);
    let mut sessions = SessionTable::new();
    let mut lan_binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    lan_binding.interface = Arc::<str>::from("ge-0-0-1");
    let out_frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let mut out_meta = txn_meta_v4(24, TCP_FLAG_SYN, out_frame.len() as u16);
    out_meta.ingress_zone = TEST_LAN_ZONE_ID;
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut lan_binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &out_frame,
        out_meta,
        true,
    );
    assert_eq!(dbg.policy_deny, 0);
    assert_eq!(lan_binding.scratch.scratch_forwards.len(), 1);
    crate::afxdp::zone_counters::flush_recorded_zone_counters(
        &forwarding.zone_counter_store,
        &forwarding.zone_counter_slot_map,
    );
    let rows = forwarding.zone_counter_store.snapshot();
    eprintln!("P3 rows (one packet, shim ingress_zone=lan): {:?}", rows);
    let lan = rows.iter().find(|r| r.zone_id == TEST_LAN_ZONE_ID);
    assert!(
        lan.is_some_and(|r| r.ingress_packets >= 1),
        "P3: the packet must be counted at least once"
    );
}

/// Probe P4: the SECOND packet of the same punted flow (session/cache hit,
/// fast path) — does the FAST path credit the intended wan egress zone via
/// the cached session metadata? This is the half the PR's fix does deliver.
#[test]
fn zone_counter_12865_fast_path_second_packet_credits_intended_egress() {
    let forwarding = build_forwarding_state(&fabric_snapshot_with_lan_neighbor_probe());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(2, active_rg_probe(now_secs))]);
    let mut sessions = SessionTable::new();
    let mut lan_binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    lan_binding.interface = Arc::<str>::from("ge-0-0-1");
    let out_frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(8, 8, 8, 8),
        12345,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let out_meta = txn_meta_v4(24, TCP_FLAG_SYN, out_frame.len() as u16);
    // First packet: the slow-path punt (misattributed egress per P1).
    let (_b1, d1) = txn_run_descriptor_checked(
        &mut lan_binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &out_frame,
        out_meta,
        true,
    );
    assert_eq!(d1.policy_deny, 0);
    // Second packet: same tuple, same ingress — must be served as a hit.
    let (_b2, d2) = txn_run_descriptor_checked(
        &mut lan_binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &out_frame,
        out_meta,
        true,
    );
    assert_eq!(d2.policy_deny, 0, "P4: second packet denied?");
    crate::afxdp::zone_counters::flush_recorded_zone_counters(
        &forwarding.zone_counter_store,
        &forwarding.zone_counter_slot_map,
    );
    let rows = forwarding.zone_counter_store.snapshot();
    eprintln!("P4 rows (punt + session-hit packet): {:?}", rows);
    let wan = rows
        .iter()
        .find(|r| r.zone_id == TEST_WAN_ZONE_ID)
        .expect("P4: the intended wan egress must be credited by SOME packet");
    assert!(
        wan.egress_packets >= 1,
        "P4: wan egress credit must exist by the second packet"
    );
}
