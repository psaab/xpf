//! #10685: a NAT64 destination embedding a firewall-owned IPv4 address must
//! not resolve to helper LocalDelivery. The kernel owns no synthetic NAT64
//! address, so reinjecting the original IPv6 frame would bypass the v4-keyed
//! host policy and leave the packet untranslated; LocalMiss would also mint
//! state for a packet that was not translated.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::PolicyRuleSnapshot;
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv6Addr};

const INGRESS_IFINDEX: u32 = 24;
const CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0xef00, 0, 0, 0, 0x102);
const PREF64_LOCAL_V4: Ipv6Addr = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x3d01);
const PREF64_PUBLIC_V4: Ipv6Addr = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808);

fn nat64_snapshot_10685() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }];
    snapshot
}

fn run_nat64_miss_10685(
    forwarding: &ForwardingState,
    dst: Ipv6Addr,
) -> (usize, DebugPollCounters, BatchCounters) {
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_IFINDEX as i32, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    let frame = build_txn_tcp_syn_frame_v6(
        CLIENT,
        dst,
        54321,
        443,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let meta = txn_meta_v6(INGRESS_IFINDEX, frame.len());
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    (sessions.len(), debug, batch)
}

#[test]
fn nat64_localdelivery_with_v4_junos_host_deny_does_not_reinject_or_mint_10685() {
    let mut snapshot = nat64_snapshot_10685();
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "deny-nat64-firewall-v4".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["10.0.61.1/32".to_string()],
        applications: vec!["any".to_string()],
        action: "deny".to_string(),
        ..Default::default()
    });
    let forwarding = build_forwarding_state(&snapshot);
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V4("10.0.61.1".parse().unwrap()))
            .disposition,
        ForwardingDisposition::LocalDelivery,
        "fixture must resolve the embedded IPv4 destination to the firewall"
    );

    let (sessions, debug, batch) = run_nat64_miss_10685(&forwarding, PREF64_LOCAL_V4);
    assert_eq!(
        sessions, 0,
        "#10685: NAT64-to-LocalDelivery must not mint a LocalMiss session, even when the \
         configuration has a v4-keyed junos-host deny"
    );
    assert_eq!(
        batch.session_creates, 0,
        "no local or reverse session may be installed"
    );
    assert_eq!(
        debug.local, 0,
        "#10685: untranslated NAT64 must not reach LocalDelivery reinjection \
         (local={}, policy_deny={}, host_inbound_deny={}, session_create={})",
        debug.local, debug.policy_deny, debug.host_inbound_deny, debug.session_create,
    );
}

#[test]
fn nat64_localdelivery_without_policy_does_not_mint_or_reinject_10685() {
    let forwarding = build_forwarding_state(&nat64_snapshot_10685());
    let (sessions, debug, batch) = run_nat64_miss_10685(&forwarding, PREF64_LOCAL_V4);
    assert_eq!(
        sessions, 0,
        "NAT64-to-LocalDelivery must not mint a LocalMiss session"
    );
    assert_eq!(
        batch.session_creates, 0,
        "no helper session may be installed"
    );
    assert_eq!(
        debug.local, 0,
        "NAT64-to-LocalDelivery must not reinject when no policy denies the packet"
    );
}

#[test]
fn nat64_nonlocal_ipv4_destination_still_translates_and_forwards_10685() {
    let forwarding = build_forwarding_state(&nat64_snapshot_10685());
    let (sessions, debug, batch) = run_nat64_miss_10685(&forwarding, PREF64_PUBLIC_V4);
    assert_eq!(debug.tx, 1, "ordinary NAT64 transit must still forward");
    assert_eq!(
        batch.nat64_translations, 1,
        "ordinary NAT64 transit must translate"
    );
    assert_eq!(
        sessions, 2,
        "ordinary NAT64 transit retains its forward/reverse pair"
    );
}

#[test]
fn nat64_flowbacked_no_route_reinjects_after_translation_11066() {
    let mut established_snapshot = nat64_snapshot_10685();
    established_snapshot.default_policy = "permit".to_string();
    let established_forwarding = build_forwarding_state(&established_snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_IFINDEX as i32, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut established_sessions = SessionTable::new();
    established_sessions.set_max_sessions_for_test(16);
    let frame = build_txn_tcp_syn_frame_v6(
        CLIENT,
        PREF64_PUBLIC_V4,
        54321,
        443,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let meta = txn_meta_v6(INGRESS_IFINDEX, frame.len());
    let (established_batch, established_debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut established_sessions,
        &established_forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    assert_eq!(established_debug.tx, 1);
    assert_eq!(established_batch.nat64_translations, 1);

    let flow = crate::afxdp::frame::parse_session_flow_from_frame(&frame, meta)
        .expect("the NAT64 SYN must parse as a flow");
    let (established, _) = established_sessions
        .probe_with_origin(&flow.forward_key)
        .expect("the translated NAT64 flow must be installed");
    assert!(established.decision.nat.nat64);
    let nat64_reverse = established.metadata.nat64_reverse;
    let translated = crate::afxdp::frame::build_nat64_l3_packet_for_slow_path(
        &frame,
        meta,
        &established.decision,
        nat64_reverse.as_ref(),
        established_forwarding.nat64.no_v6_frag_header,
    )
    .expect("the slow-path builder must translate the recorded NAT64 decision");
    assert_eq!(translated[0] >> 4, 4, "the delegated packet must be IPv4");
    let Some(IpAddr::V4(translated_src)) = established.decision.nat.rewrite_src else {
        panic!("the forward NAT64 decision must carry its pool source");
    };
    let Some(IpAddr::V4(translated_dst)) = established.decision.nat.rewrite_dst else {
        panic!("the forward NAT64 decision must carry its extracted destination");
    };
    assert_eq!(&translated[12..16], &translated_src.octets());
    assert_eq!(&translated[16..20], &translated_dst.octets());
    assert_eq!(
        u16::from_be_bytes([translated[20], translated[21]]),
        established
            .decision
            .nat
            .rewrite_src_port
            .expect("NAT64 must carry the allocated source port")
    );
    assert_eq!(u16::from_be_bytes([translated[22], translated[23]]), 443);
    assert_eq!(
        translated[8], 64,
        "the NoRoute builder must preserve Hop Limit"
    );

    // Install the committed NAT64 decision with a NoRoute disposition to
    // exercise the slow-path handoff itself (session hits retain their
    // installed resolution across forwarding-state replacement).
    let mut no_route_decision = established.decision;
    no_route_decision.resolution.disposition = ForwardingDisposition::NoRoute;
    no_route_decision.resolution.local_ifindex = 0;
    no_route_decision.resolution.egress_ifindex = 0;
    no_route_decision.resolution.tx_ifindex = 0;
    no_route_decision.resolution.tunnel_endpoint_id = 0;
    no_route_decision.resolution.next_hop = None;
    no_route_decision.resolution.neighbor_mac = None;
    no_route_decision.resolution.src_mac = None;
    no_route_decision.resolution.tx_vlan_id = 0;
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    assert!(sessions.install_with_protocol(
        flow.forward_key,
        no_route_decision,
        established.metadata,
        123_000_000_000,
        crate::ip_proto::PROTO_TCP,
        TCP_FLAG_SYN,
    ));

    let mut no_route_snapshot = nat64_snapshot_10685();
    no_route_snapshot.routes.clear();
    no_route_snapshot.default_policy = "permit".to_string();
    let no_route_forwarding = build_forwarding_state(&no_route_snapshot);
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let reinjector = Arc::new(crate::slowpath::SlowPathReinjector::new_without_worker(
        1500,
    ));
    reinjector.enable_test_packet_capture();
    let (_, debug) = txn_run_descriptor_inner_with_slow_path(
        &mut binding,
        &mut sessions,
        &no_route_forwarding,
        &ha_state,
        &frame,
        meta,
        &local_tunnel_deliveries,
        &shared_sessions,
        None,
        Some(&reinjector),
    );
    assert_eq!(debug.rx, 1);
    assert_eq!(debug.session_hit, 1);
    assert_eq!(debug.no_route, 1);
    assert_eq!(
        reinjector.test_enqueued_delegated(),
        vec![true],
        "the translated IPv4 packet must reach the kernel slow path"
    );

    let direct_live = crate::afxdp::binding_state::BindingLiveState::new();
    let direct_binding = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: INGRESS_IFINDEX as i32,
    };
    let direct_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));

    // TTL/Hop Limit 1 belongs to the delegated kernel FIB. NAT64 must neither
    // expire it locally nor decrement it a second time before enqueue.
    let mut ttl_one_frame = frame.clone();
    ttl_one_frame[14 + 7] = 1;
    assert!(
        crate::afxdp::tx::dispatch::maybe_reinject_slow_path_from_frame_with_outlet(
            &direct_binding,
            &direct_live,
            Some(&reinjector),
            &local_tunnel_deliveries,
            &ttl_one_frame,
            meta,
            no_route_decision,
            crate::afxdp::tx::dispatch::SlowPathOutlet::Delegated,
            nat64_reverse.as_ref(),
            &direct_exceptions,
            "nat64_no_route_ttl_one",
            &no_route_forwarding,
        )
    );

    // The reverse NAT64 direction must likewise enqueue IPv6 with the ingress
    // TTL intact and restore the original client address and port.
    let translated_port = no_route_decision
        .nat
        .rewrite_src_port
        .expect("forward NAT64 decision carries its translated source port");
    let reply_frame = build_txn_tcp_syn_frame_v4(
        translated_dst,
        translated_src,
        443,
        translated_port,
        TCP_FLAG_SYN | 0x10,
        crate::afxdp::tests_support::TEST_WAN_MAC,
    );
    let reply_meta = txn_meta_v4(12, TCP_FLAG_SYN | 0x10, reply_frame.len() as u16);
    let reverse_decision = SessionDecision {
        nat: no_route_decision.nat.reverse(
            IpAddr::V6(CLIENT),
            IpAddr::V6(PREF64_PUBLIC_V4),
            54321,
            443,
        ),
        ..no_route_decision
    };
    assert!(
        crate::afxdp::tx::dispatch::maybe_reinject_slow_path_from_frame_with_outlet(
            &direct_binding,
            &direct_live,
            Some(&reinjector),
            &local_tunnel_deliveries,
            &reply_frame,
            reply_meta,
            reverse_decision,
            crate::afxdp::tx::dispatch::SlowPathOutlet::Delegated,
            nat64_reverse.as_ref(),
            &direct_exceptions,
            "nat64_no_route_reverse",
            &no_route_forwarding,
        )
    );

    let mut reverse_ttl_one_frame = reply_frame.clone();
    reverse_ttl_one_frame[14 + 8] = 1;
    reverse_ttl_one_frame[24..26].fill(0);
    let ipv4_header_checksum =
        crate::afxdp::frame::checksum::checksum16(&reverse_ttl_one_frame[14..34]);
    reverse_ttl_one_frame[24..26].copy_from_slice(&ipv4_header_checksum.to_be_bytes());
    assert!(
        crate::afxdp::tx::dispatch::maybe_reinject_slow_path_from_frame_with_outlet(
            &direct_binding,
            &direct_live,
            Some(&reinjector),
            &local_tunnel_deliveries,
            &reverse_ttl_one_frame,
            reply_meta,
            reverse_decision,
            crate::afxdp::tx::dispatch::SlowPathOutlet::Delegated,
            nat64_reverse.as_ref(),
            &direct_exceptions,
            "nat64_no_route_reverse_ttl_one",
            &no_route_forwarding,
        )
    );

    let queued_packets = reinjector.test_enqueued_packets();
    assert_eq!(queued_packets.len(), 4);
    assert!(queued_packets.iter().all(|(delegated, _)| *delegated));
    let forward_queued = &queued_packets[0].1;
    assert_eq!(forward_queued[0] >> 4, 4);
    assert_eq!(forward_queued[8], 64);
    assert_eq!(&forward_queued[12..16], &translated_src.octets());
    assert_eq!(&forward_queued[16..20], &translated_dst.octets());
    assert_eq!(
        u16::from_be_bytes([forward_queued[20], forward_queued[21]]),
        translated_port
    );
    assert_eq!(
        u16::from_be_bytes([forward_queued[22], forward_queued[23]]),
        443
    );
    assert_eq!(queued_packets[1].1[0] >> 4, 4);
    assert_eq!(queued_packets[1].1[8], 1);
    let forward_ttl_one = &queued_packets[1].1;
    assert_eq!(&forward_ttl_one[12..16], &translated_src.octets());
    assert_eq!(&forward_ttl_one[16..20], &translated_dst.octets());
    assert_eq!(
        u16::from_be_bytes([forward_ttl_one[22], forward_ttl_one[23]]),
        443
    );
    assert_eq!(
        u16::from_be_bytes([queued_packets[1].1[20], queued_packets[1].1[21]]),
        translated_port
    );
    let reverse_queued = &queued_packets[2].1;
    assert_eq!(reverse_queued[0] >> 4, 6);
    assert_eq!(reverse_queued[7], 64);
    assert_eq!(&reverse_queued[8..24], &PREF64_PUBLIC_V4.octets());
    assert_eq!(&reverse_queued[24..40], &CLIENT.octets());
    assert_eq!(
        u16::from_be_bytes([reverse_queued[40], reverse_queued[41]]),
        443
    );
    assert_eq!(
        u16::from_be_bytes([reverse_queued[42], reverse_queued[43]]),
        54321
    );
    assert_eq!(queued_packets[3].1[0] >> 4, 6);
    assert_eq!(queued_packets[3].1[7], 1);

    // Missing reverse metadata is a NAT64-specific prepare failure, never a
    // fallback to queueing the untranslated IPv4 reply.
    assert!(
        !crate::afxdp::tx::dispatch::maybe_reinject_slow_path_from_frame_with_outlet(
            &direct_binding,
            &direct_live,
            Some(&reinjector),
            &local_tunnel_deliveries,
            &reply_frame,
            reply_meta,
            reverse_decision,
            crate::afxdp::tx::dispatch::SlowPathOutlet::Delegated,
            None,
            &direct_exceptions,
            "nat64_no_route_missing_metadata",
            &no_route_forwarding,
        )
    );
    assert_eq!(
        direct_live.slow_path_drops.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        direct_exceptions
            .lock()
            .expect("exception ring")
            .back()
            .expect("NAT64 prepare failure event")
            .reason,
        "nat64_slow_path_prepare_failed"
    );
    assert_eq!(
        reinjector.test_enqueued_packets().len(),
        4,
        "missing NAT64 reverse metadata must not enqueue untranslated bytes"
    );
}
