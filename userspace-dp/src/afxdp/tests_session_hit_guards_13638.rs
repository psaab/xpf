//! #13638 (deep-review D3-06): the slow-path session-HIT arm must enforce the
//! same three transit guards the flow-cache hit (`stage_flow_cache_hit`) and
//! the common post-decision tail enforce, BEFORE any hit side effect:
//! session promotion/materialization, deferred owner close, policy/filter
//! revalidation, ICMP Time Exceeded, fragment-association install, session
//! accounting, or TX.
//!
//! Pre-fix, a packet that hits an established session but is not served from
//! the flow cache (RST/FIN close packets, TTL=1, first ACK before the cache
//! warms) ran those side effects and only met the guards at the common tail —
//! after `apply_deferred_owner_close` had already stamped closing state and
//! after the Time-Exceeded builder had already queued a reply.
//!
//! FAIL-ON-REVERT: removing the early hit-arm gate lets the broadcast RST
//! close the session / lets the martian / fenced / group copies transmit.

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::NeighborSnapshot;
use crate::protocol::IpsecBindlessSelectorSnapshot;
use crate::session::{SessionMetadata, SessionOrigin};
use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
const TCP_FLAG_ACK: u8 = crate::tcp_flags::TCP_ACK;

const HIT_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const HIT_SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const FENCE_DST: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 200);

fn hit_meta(src: Ipv4Addr, dst: Ipv4Addr, flags: u8, frame_len: usize) -> UserspaceDpMeta {
    let mut meta = txn_meta_v4(24, flags, frame_len as u16);
    meta.flow_src_addr[..4].copy_from_slice(&src.octets());
    meta.flow_dst_addr[..4].copy_from_slice(&dst.octets());
    meta.flow_src_port = 40_000;
    meta.flow_dst_port = 443;
    meta
}
fn hit_session_key(src: Ipv4Addr, dst: Ipv4Addr) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        src_port: 40_000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}
fn seed_session(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    key: SessionKey,
    tcp_flags: u8,
) {
    let resolution = lookup_forwarding_resolution(forwarding, key.dst_ip).resolution;
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert!(sessions.install_with_protocol_with_origin(
        key,
        SessionDecision {
            resolution,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 24,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        tcp_flags,
    ));
}
fn hit_ha_state() -> BTreeMap<i32, HAGroupRuntime> {
    txn_ha_state()
}

/// Establish the CLIENT->SERVER session via a PACKET_HOST SYN, then prove the
/// follow-up copy hits the session (not the flow cache) and is dropped.
#[test]
fn session_hit_l2_group_rst_does_not_close_or_forward_13638() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = hit_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");

    let mut sessions = SessionTable::new();
    seed_session(
        &mut sessions,
        &forwarding,
        hit_session_key(HIT_CLIENT, HIT_SERVER),
        TCP_FLAG_ACK,
    );

    // L2-broadcast copy of the same tuple with RST: an established-hit close
    // packet. It must neither transmit nor stamp closing state.
    let rst = build_txn_tcp_syn_frame_v4(
        HIT_CLIENT,
        HIT_SERVER,
        40_000,
        443,
        TCP_FLAG_RST | TCP_FLAG_ACK,
        [0xff; 6],
    );
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &rst,
        hit_meta(
            HIT_CLIENT,
            HIT_SERVER,
            TCP_FLAG_RST | TCP_FLAG_ACK,
            rst.len(),
        ),
    );
    assert_eq!(batch.validated_packets, 1);
    assert_eq!(
        dbg.session_hit, 0,
        "pre-session guard runs before hit accounting"
    );
    assert_eq!(dbg.tx, 0, "L2-group session hit must not transmit");
    assert_eq!(dbg.forward, 0);
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "no forward may be queued"
    );
    assert_eq!(sessions.len(), 1, "dropped copy must not remove session");
    assert_eq!(
        sessions.close_class_wire_for(&hit_session_key(HIT_CLIENT, HIT_SERVER)),
        0,
        "guarded RST must not stamp the live session closed"
    );

    // Positive control: the same tuple as a normal PACKET_HOST ACK still
    // forwards and keeps the pair alive, proving the drop above was the
    // L2-group guard and not a broken fixture.
    let ack = build_txn_tcp_syn_frame_v4(
        HIT_CLIENT,
        HIT_SERVER,
        40_000,
        443,
        TCP_FLAG_ACK,
        TEST_LAN_MAC,
    );
    let (_, ack_dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &ack,
        hit_meta(HIT_CLIENT, HIT_SERVER, TCP_FLAG_ACK, ack.len()),
    );
    assert_eq!(ack_dbg.tx, 1, "conforming ACK control must still forward");
    assert_eq!(sessions.len(), 1);
}

#[test]
fn session_hit_l2_group_ttl1_generates_no_time_exceeded_13638() {
    let forwarding = build_forwarding_state(&nat_snapshot());
    let ha_state = hit_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let key = hit_session_key(HIT_CLIENT, HIT_SERVER);
    let resolution = lookup_forwarding_resolution(&forwarding, IpAddr::V4(HIT_SERVER)).resolution;
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        SessionDecision {
            resolution,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 24,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    assert_eq!(sessions.len(), 1);

    // Seed the session directly so this TTL=1 packet cannot be served from a
    // flow-cache entry; it must enter the slow-path session-HIT arm.
    // TTL=1 L2-broadcast ACK copy: pre-fix the hit arm built an ICMP Time
    // Exceeded (queued forward) before the tail L2 gate could drop it.
    let mut ttl1 =
        build_txn_tcp_syn_frame_v4(HIT_CLIENT, HIT_SERVER, 40_000, 443, TCP_FLAG_ACK, [0xff; 6]);
    ttl1[22] = 1; // IPv4 TTL byte
    let ip_sum = checksum16(&ttl1[14..34]);
    ttl1[24] = (ip_sum >> 8) as u8;
    ttl1[25] = ip_sum as u8;
    let (batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &ttl1,
        hit_meta(HIT_CLIENT, HIT_SERVER, TCP_FLAG_ACK, ttl1.len()),
    );
    assert_eq!(batch.validated_packets, 1);
    assert_eq!(
        dbg.session_hit, 0,
        "pre-session guard runs before hit accounting"
    );
    assert_eq!(dbg.tx, 0, "TTL=1 group hit must not transmit");
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "no ICMP Time Exceeded (or forward) may be queued for a group hit"
    );
    assert_eq!(sessions.len(), 1);
}

#[test]
fn session_hit_martian_source_drops_before_side_effects_13638() {
    // Reuse the #10689 fixture: pre-seeded loopback-source session.
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules.clear();
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: FENCE_DST.to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
        ..Default::default()
    });
    let forwarding = build_forwarding_state(&snapshot);
    let source = Ipv4Addr::LOCALHOST;
    let resolution = lookup_forwarding_resolution(&forwarding, IpAddr::V4(FENCE_DST)).resolution;
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(source),
        dst_ip: IpAddr::V4(FENCE_DST),
        src_port: 40_000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        forward_key,
        SessionDecision {
            resolution,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 24,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    assert_eq!(sessions.len(), 1);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    // RST/ACK hit: pre-fix this stamped deferred owner close before the tail
    // martian gate dropped it.
    let rst = build_txn_tcp_syn_frame_v4(
        source,
        FENCE_DST,
        40_000,
        443,
        TCP_FLAG_RST | TCP_FLAG_ACK,
        TEST_LAN_MAC,
    );
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &hit_ha_state(),
        &rst,
        hit_meta(source, FENCE_DST, TCP_FLAG_RST | TCP_FLAG_ACK, rst.len()),
        true,
    );
    assert_eq!(batch.validated_packets, 1);
    assert_eq!(
        dbg.session_hit, 0,
        "pre-session guard runs before hit accounting"
    );
    assert_eq!(dbg.tx, 0, "martian session hit must not transmit");
    assert_eq!(dbg.forward, 0);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 1, "drop must not remove the session");
    assert_eq!(
        sessions.close_class_wire_for(&hit_session_key(source, FENCE_DST)),
        0,
        "martian gate must run before deferred RST close"
    );
}

#[test]
fn session_hit_bindless_selector_fence_drops_before_side_effects_13638() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.bindless_selector_fence_enabled = true;
    snapshot.bindless_selector_rows = vec![IpsecBindlessSelectorSnapshot {
        local_ts: "10.0.61.0/24".to_string(),
        remote_ts: "172.16.80.0/24".to_string(),
    }];
    snapshot
        .interfaces
        .iter_mut()
        .find(|interface| interface.name == "reth0.80")
        .expect("WAN egress fixture interface")
        .redundancy_group = 1;
    let forwarding = build_forwarding_state(&snapshot);
    let src = HIT_CLIENT; // inside 10.0.61.0/24; dst inside 172.16.80.0/24
    let resolution = lookup_forwarding_resolution(&forwarding, IpAddr::V4(FENCE_DST)).resolution;
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(FENCE_DST),
        src_port: 40_000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        forward_key,
        SessionDecision {
            resolution,
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_zone_check: 0,
            egress_zone_check: 0,
            ingress_ifindex: 24,
            ingress_vlan_id: 0,
            forward_ingress_vlan_id: None,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    assert_eq!(sessions.len(), 1);

    assert!(
        forwarding
            .bindless_ipsec_selector_fence
            .matches(IpAddr::V4(src), IpAddr::V4(FENCE_DST),),
        "fixture must carry a matching bindless selector"
    );
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let rst = build_txn_tcp_syn_frame_v4(
        src,
        FENCE_DST,
        40_000,
        443,
        TCP_FLAG_RST | TCP_FLAG_ACK,
        TEST_LAN_MAC,
    );
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &hit_ha_state(),
        &rst,
        hit_meta(src, FENCE_DST, TCP_FLAG_RST | TCP_FLAG_ACK, rst.len()),
        true,
    );
    assert_eq!(batch.validated_packets, 1);
    assert_eq!(
        dbg.session_hit, 0,
        "selector gate must run before hit accounting"
    );
    assert_eq!(
        dbg.policy_deny, 1,
        "selector-fence drop must be charged as policy deny"
    );
    assert_eq!(dbg.tx, 0, "fenced session hit must not transmit");
    assert_eq!(dbg.forward, 0);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 1, "fence drop must not remove the session");
    assert_eq!(
        sessions.close_class_wire_for(&hit_session_key(src, FENCE_DST)),
        0,
        "selector gate must run before deferred RST close"
    );
}
