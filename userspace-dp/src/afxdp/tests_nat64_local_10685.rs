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
            .resolution
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

// #14114: a NAT64 non-first fragment whose first fragment committed with a
// ForwardCandidate association, but whose tail is adjudicated NoRoute (the
// route was withdrawn between fragments), must still be L3-translated by
// the slow-path builder and delegated to the kernel FIB — in both
// directions, with Hop Limit / TTL preserved and payload bytes verbatim.
// Before the fix the whole-packet preserve-TTL translators returned None
// for every non-first fragment, so the tail dropped as
// nat64_slow_path_prepare_failed even though its NAT64 decision was
// recorded. A miss (no recorded reverse metadata / no NAT64 decision)
// must still fail closed: nothing untranslated is queued.
#[test]
fn nat64_nonfirst_no_route_reinjects_after_l3_translation_14114() {
    let mut established_snapshot = nat64_snapshot_10685();
    established_snapshot.default_policy = "permit".to_string();
    let established_forwarding = build_forwarding_state(&established_snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_IFINDEX as i32, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut established_sessions = SessionTable::new();
    established_sessions.set_max_sessions_for_test(16);
    let first_frame = build_txn_tcp_syn_frame_v6(
        CLIENT,
        PREF64_PUBLIC_V4,
        54321,
        443,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let first_meta = txn_meta_v6(INGRESS_IFINDEX, first_frame.len());
    let (established_batch, established_debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut established_sessions,
        &established_forwarding,
        &ha_state,
        &first_frame,
        first_meta,
        true,
    );
    assert_eq!(established_debug.tx, 1);
    assert_eq!(established_batch.nat64_translations, 1);
    let flow = crate::afxdp::frame::parse_session_flow_from_frame(&first_frame, first_meta)
        .expect("the NAT64 SYN must parse as a flow");
    let (established, _) = established_sessions
        .probe_with_origin(&flow.forward_key)
        .expect("the translated NAT64 flow must be installed");
    assert!(established.decision.nat.nat64);
    let nat64_reverse = established.metadata.nat64_reverse;
    let Some(IpAddr::V4(translated_src)) = established.decision.nat.rewrite_src else {
        panic!("forward NAT64 decision must carry its pool source");
    };
    let Some(IpAddr::V4(translated_dst)) = established.decision.nat.rewrite_dst else {
        panic!("forward NAT64 decision must carry its extracted destination");
    };
    let translated_port = established
        .decision
        .nat
        .rewrite_src_port
        .expect("forward NAT64 decision must carry its translated source port");

    // The recorded NAT64 decision, re-dispositioned NoRoute exactly as the
    // #11066 sibling does (session hits retain their installed resolution
    // across forwarding-state replacement; a withdrawn route re-resolves
    // to NoRoute while the NAT64 translation stays recorded).
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

    let mut no_route_snapshot = nat64_snapshot_10685();
    no_route_snapshot.routes.clear();
    no_route_snapshot.default_policy = "permit".to_string();
    let no_route_forwarding = build_forwarding_state(&no_route_snapshot);
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let reinjector = Arc::new(crate::slowpath::SlowPathReinjector::new_without_worker(
        1500,
    ));
    reinjector.enable_test_packet_capture();
    let direct_live = crate::afxdp::binding_state::BindingLiveState::new();
    let direct_binding = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("reth1.0"),
        ifindex: INGRESS_IFINDEX as i32,
    };
    let direct_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));

    // Forward non-first fragment: eth + IPv6 + Fragment(offset 1, MF=0,
    // ident 0x14114) + opaque payload whose first bytes deliberately
    // resemble a TCP header (ports 1111/2222) so any L4 port rewrite of
    // the payload is observable.
    let payload: [u8; 16] = [
        0x04, 0x57, 0x08, 0xae, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08,
    ];
    let mut fwd_tail = Vec::new();
    fwd_tail.extend_from_slice(&crate::afxdp::tests_support::TEST_LAN_MAC);
    fwd_tail.extend_from_slice(&[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x86, 0xdd]);
    let mut v6 = vec![0u8; 40];
    v6[0] = 0x60;
    v6[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v6[6] = 44;
    v6[7] = 64;
    v6[8..24].copy_from_slice(&CLIENT.octets());
    v6[24..40].copy_from_slice(&PREF64_PUBLIC_V4.octets());
    fwd_tail.extend_from_slice(&v6);
    let mut frag = [0u8; 8];
    frag[0] = PROTO_TCP;
    frag[2..4].copy_from_slice(&0x0008u16.to_be_bytes());
    frag[4..8].copy_from_slice(&0x14114u32.to_be_bytes());
    fwd_tail.extend_from_slice(&frag);
    fwd_tail.extend_from_slice(&payload);
    let mut fwd_meta = txn_meta_v6(INGRESS_IFINDEX, fwd_tail.len());
    fwd_meta.protocol = crate::session::SHIM_PROTO_FRAGMENT_NO_L4;
    fwd_meta.flow_src_addr = CLIENT.octets();
    fwd_meta.flow_dst_addr = PREF64_PUBLIC_V4.octets();

    assert!(
        crate::afxdp::tx::dispatch::maybe_reinject_slow_path_from_frame_with_outlet(
            &direct_binding,
            &direct_live,
            Some(&reinjector),
            &local_tunnel_deliveries,
            &fwd_tail,
            fwd_meta,
            no_route_decision,
            crate::afxdp::tx::dispatch::SlowPathOutlet::Delegated,
            nat64_reverse.as_ref(),
            &direct_exceptions,
            "nat64_nonfirst_no_route_forward",
            &no_route_forwarding,
        ),
        "#14114: an associated NAT64 non-first fragment must be translated and delegated, not dropped"
    );

    // Reverse non-first fragment: eth + IPv4(offset 1 = byte offset 8,
    // MF=0, ident 0x4321) + the same opaque payload.
    let mut rev_tail = build_txn_tcp_syn_frame_v4(
        translated_dst,
        translated_src,
        443,
        translated_port,
        TCP_FLAG_SYN | 0x10,
        crate::afxdp::tests_support::TEST_WAN_MAC,
    );
    rev_tail.truncate(14 + 20);
    rev_tail.extend_from_slice(&payload);
    let rev_total = (rev_tail.len() - 14) as u16;
    rev_tail[16..18].copy_from_slice(&rev_total.to_be_bytes());
    rev_tail[18..20].copy_from_slice(&0x4321u16.to_be_bytes());
    rev_tail[20..22].copy_from_slice(&0x0001u16.to_be_bytes());
    rev_tail[24..26].fill(0);
    let rev_csum = crate::afxdp::frame::checksum16(&rev_tail[14..34]);
    rev_tail[24..26].copy_from_slice(&rev_csum.to_be_bytes());
    let mut rev_meta = txn_meta_v4(12, 0, rev_tail.len() as u16);
    rev_meta.protocol = crate::session::SHIM_PROTO_FRAGMENT_NO_L4;
    rev_meta.flow_src_addr[..4].copy_from_slice(&translated_dst.octets());
    rev_meta.flow_dst_addr[..4].copy_from_slice(&translated_src.octets());
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
            &rev_tail,
            rev_meta,
            reverse_decision,
            crate::afxdp::tx::dispatch::SlowPathOutlet::Delegated,
            nat64_reverse.as_ref(),
            &direct_exceptions,
            "nat64_nonfirst_no_route_reverse",
            &no_route_forwarding,
        ),
        "#14114: an associated reverse NAT64 non-first fragment must be translated and delegated"
    );

    let queued = reinjector.test_enqueued_packets();
    assert_eq!(queued.len(), 2);
    assert!(queued.iter().all(|(delegated, _)| *delegated));
    let fwd_out = &queued[0].1;
    assert_eq!(fwd_out[0] >> 4, 4, "forward tail must become IPv4");
    assert_eq!(
        fwd_out[8], 64,
        "forward tail Hop Limit must be preserved for the kernel FIB"
    );
    assert_eq!(&fwd_out[12..16], &translated_src.octets());
    assert_eq!(&fwd_out[16..20], &translated_dst.octets());
    assert_eq!(
        u16::from_be_bytes([fwd_out[4], fwd_out[5]]),
        0x4114,
        "IPv4 Identification is the low 16 bits of the IPv6 fragment ident"
    );
    assert_eq!(
        u16::from_be_bytes([fwd_out[6], fwd_out[7]]) & 0x1fff,
        1,
        "fragment offset must survive translation"
    );
    assert_eq!(
        &fwd_out[20..],
        &payload,
        "non-first payload must be copied verbatim — no port rewrite of payload bytes"
    );
    let rev_out = &queued[1].1;
    assert_eq!(rev_out[0] >> 4, 6, "reverse tail must become IPv6");
    assert_eq!(
        rev_out[7], 64,
        "reverse tail TTL must be preserved for the kernel FIB"
    );
    assert_eq!(
        rev_out[6], 44,
        "reverse tail must carry an IPv6 Fragment header"
    );
    assert_eq!(&rev_out[8..24], &PREF64_PUBLIC_V4.octets());
    assert_eq!(&rev_out[24..40], &CLIENT.octets());
    assert_eq!(
        u32::from_be_bytes([rev_out[44], rev_out[45], rev_out[46], rev_out[47]]),
        0x4321,
        "IPv6 Identification is the zero-extended IPv4 ident"
    );
    assert_eq!(
        &rev_out[48..],
        &payload,
        "reverse non-first payload must be copied verbatim"
    );

    // Fail-closed controls: the same tails without their recorded NAT64
    // translation context must not be queued untranslated.
    assert!(
        !crate::afxdp::tx::dispatch::maybe_reinject_slow_path_from_frame_with_outlet(
            &direct_binding,
            &direct_live,
            Some(&reinjector),
            &local_tunnel_deliveries,
            &rev_tail,
            rev_meta,
            reverse_decision,
            crate::afxdp::tx::dispatch::SlowPathOutlet::Delegated,
            None,
            &direct_exceptions,
            "nat64_nonfirst_no_route_missing_reverse",
            &no_route_forwarding,
        ),
        "a reverse tail without Nat64ReverseInfo must fail closed"
    );
    assert_eq!(reinjector.test_enqueued_packets().len(), 2);
}
