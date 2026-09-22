// IPv4/IPv6 fragment handling, output-filter fragment semantics, and fabric queue-hash.
//
// Split out of afxdp/tests.rs (#4840) as a sibling `#[path]` test module
// loaded from afxdp/mod.rs. Pure code motion: every #[test] fn is moved
// verbatim; shared test-support helpers live in afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::worker::WorkerTxPipeline;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};
use super::tests_support::*;

#[test]
fn non_first_fragment_v4_not_dropped_by_port_matching_output_filter() {
    // payload at the post-IP offset spells src=33333 dst=443 — exactly what
    // the buggy meta fallback would parse as the discarded web port.
    let payload = [0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0];
    let frame = eth_ipv4_frag_frame(0x0001, &payload, crate::afxdp::tests_support::TEST_LAN_MAC); // non-first (offset != 0)
    let forwarding = wan_drop_443_forwarding();
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let meta = frag_test_meta(14);
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None, // flowless — the #2344 fragment case
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );

    let req = req.expect(
        "a non-first fragment must NOT be dropped by a port-matching output filter \
         (gate routes it to the None flow_key default-queue path)",
    );
    assert_eq!(
        req.flow_key, None,
        "fragment TX selection must use no flow_key (no payload-derived ports)"
    );
    assert_eq!(
        req.expected_ports, None,
        "fragment must not carry payload-derived expected ports"
    );
}


#[test]
fn control_icmp_v4_installs_no_synthesized_tx_flow_key() {
    // #3290 (TX/CoS side): a permitted ICMPv4 control packet (Time-Exceeded)
    // whose shim metadata carries a hostile pseudo-port (0xBEEF) must NOT
    // propagate a synthesized flow key into TX selection / CoS output-filter
    // evaluation. The forward_request meta-fallback gate mirrors the
    // conntrack-side parse_session_flow_from_bytes verdict (the primary flow is
    // None for these packets). Reverting the gate makes the fallback synthesize
    // a meta-keyed flow with src_port=0xBEEF -> req.flow_key becomes Some -> RED.
    let frame = eth_ipv4_icmp_frame(11); // Time-Exceeded
    let forwarding = wan_drop_443_forwarding();
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        pkt_len: frame.len() as u16,
        l3_offset: 14,
        l4_offset: 34,
        flow_src_port: 0xBEEF,
        flow_dst_port: 0,
        flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..UserspaceDpMeta::default()
    };
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None, // primary flow is None (conntrack-side #3290 gate)
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    )
    .expect("control ICMP must still forward (TCP-only output filter does not match)");

    assert_eq!(
        req.flow_key, None,
        "#3290: a control ICMP packet must not synthesize a metadata-derived TX flow key"
    );
}

#[test]
fn slack_tcp_v4_installs_no_synthesized_tx_flow_key_9894() {
    // #9894 (GPT-3, immediate path): short total_len=20 + 4 slack bytes
    // spelling (33333, 443), with a complete shim-style stamped tuple at a
    // realistic l4_offset=34. Conntrack yields None (fast-path gate); the TX
    // meta-fallback must mirror that verdict — not resurrect the phantom
    // tuple into flow_key / expected_ports / CoS output-filter evaluation.
    // The wan_drop_443 egress filter DISCARDS TCP dst 443, so any
    // phantom-port evaluation drops the request (req None). Reverting the
    // forward_request arm synthesizes Some((33333, 443)) -> the filter drops
    // -> expect RED; reverting only the authoritative_forward_ports gate
    // leaves expected_ports Some -> assert RED.
    let mut frame = eth_ipv4_frag_frame(0x0000, &[0x82, 0x35, 0x01, 0xbb], crate::afxdp::tests_support::TEST_LAN_MAC);
    frame[16] = 0x00;
    frame[17] = 20; // total_len=20: the 4 port bytes are slack, not datagram
    assert_eq!(&frame[34..38], &[0x82, 0x35, 0x01, 0xbb]);
    let forwarding = wan_drop_443_forwarding();
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let mut meta = frag_test_meta(14);
    meta.l4_offset = 34; // realistic shim stamp: L4 points at the slack bytes
    meta.pkt_len = frame.len() as u16;
    // Conntrack side first: the production parse must refuse (chain link —
    // the TX arm mirrors this verdict rather than re-deciding it).
    assert_eq!(
        parse_session_flow_from_bytes(&frame, meta),
        None,
        "precondition: the slack tuple must be flowless on the parse side"
    );
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None, // primary flow is None (conntrack-side #9894 gate, pinned above)
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    )
    .expect("slack TCP must still forward (phantom 443 must not match the output filter)");

    assert_eq!(
        req.flow_key, None,
        "#9894: a slack-ports packet must not synthesize a metadata-derived TX flow key"
    );
    assert_eq!(
        req.expected_ports, None,
        "#9894: a slack-ports packet must not carry phantom expected ports"
    );
}


#[test]
fn flowless_non_fragmented_tcp_still_hits_port_matching_output_filter() {
    // Same meta (dst port 443) but a FIRST/atomic fragment (offset 0) — a
    // real L4 header, so the gate must NOT fire and the meta fallback's
    // ports must drive the discard. Proves we did not over-gate every None
    // flow to the default queue. (#9894: l4_offset is set to the realistic
    // 34 — total 28 covers [34,38), so the declared-end gate genuinely
    // passes here rather than passing vacuously on l4=0.)
    let payload = [0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0];
    let frame = eth_ipv4_frag_frame(0x0000, &payload, crate::afxdp::tests_support::TEST_LAN_MAC); // atomic (offset 0)
    let forwarding = wan_drop_443_forwarding();
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let mut meta = frag_test_meta(14);
    meta.l4_offset = 34;
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None, // flowless, but a real L4 header (not a fragment)
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );

    assert!(
        req.is_none(),
        "a flowless NON-fragmented TCP packet to dst 443 must still be dropped \
         by the port-matching terminal output filter (gate must not over-suppress)"
    );
}


#[test]
fn fabric_queue_hash_non_first_fragment_is_port_independent_3tuple() {
    // Two non-first fragments of one datagram differ only in payload bytes
    // (the fictitious "ports"); the fabric hash must be identical so they
    // bind the same fabric target (no cross-chassis reordering).
    let mut meta_a = frag_test_meta(14);
    meta_a.flow_src_port = 1111;
    meta_a.flow_dst_port = 2222;
    let mut meta_b = meta_a;
    meta_b.flow_src_port = 40000; // different payload bytes
    meta_b.flow_dst_port = 50000;

    let h_a = fabric_queue_hash(None, Some((1111, 2222)), meta_a, true);
    let h_b = fabric_queue_hash(None, Some((40000, 50000)), meta_b, true);
    assert_eq!(
        h_a, h_b,
        "fragment fabric hash must be port-independent (3-tuple: src/dst/proto)"
    );

    // The 3-tuple still distinguishes different src/dst/proto.
    let mut meta_c = meta_a;
    meta_c.flow_dst_addr[3] = 201; // different dst IP
    let h_c = fabric_queue_hash(None, Some((1111, 2222)), meta_c, true);
    assert_ne!(h_a, h_c, "fragment fabric hash must depend on dst address");

    let mut meta_d = meta_a;
    meta_d.protocol = PROTO_UDP;
    let h_d = fabric_queue_hash(None, Some((1111, 2222)), meta_d, true);
    assert_ne!(h_a, h_d, "fragment fabric hash must depend on protocol");

    // And the non-fragment (ported) path is still port-sensitive — proves
    // the gate flag, not a blanket change, drives the new behavior.
    let h_ported_a = fabric_queue_hash(None, Some((1111, 2222)), meta_a, false);
    let h_ported_b = fabric_queue_hash(None, Some((40000, 50000)), meta_b, false);
    assert_ne!(
        h_ported_a, h_ported_b,
        "non-fragment fabric hash must remain port-sensitive"
    );
}

// ---- #3291: flowless / non-first-fragment transit ENFORCEMENT ------------
//
// A non-first IPv4 fragment is flowless (#2344: its post-IP bytes are payload,
// never L4 ports). Before #3291 the flowless transit arm ran only
// resolve_forwarding (+ HA + fabric) and forwarded the fragment whenever a route
// existed — so a `deny-all` zone pair, an interface input filter, and PBR
// (`then routing-instance`) all silently no-op'd on fragments (fail-open). These
// tests push a real non-first fragment through poll_binding_process_descriptor
// and pin the gate that now applies zone policy + input filter + PBR. Reverting
// the gate flips the deny / input-filter / PBR cases from drop back to forward,
// turning the asserts RED.


#[test]
fn flowless_non_first_fragment_transit_dropped_by_deny_all_3291() {
    // lan->wan is denied (default-deny; only dmz->wan permitted). A non-first
    // fragment from lan toward a routed wan dst must be DROPPED by zone policy.
    // RED-on-revert: the flowless arm used to forward it (dbg.forward == 1,
    // dbg.policy_deny == 0).
    let mut snapshot = policy_deny_snapshot();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
        true,
    );

    assert_eq!(
        dbg.policy_deny, 1,
        "#3291: a deny-all zone pair must DROP a flowless non-first fragment"
    );
    assert_eq!(
        dbg.forward, 0,
        "#3291: the fragment must NOT forward under deny-all (RED on revert)"
    );
}


#[test]
fn flowless_non_first_fragment_transit_permitted_by_any_policy_3291() {
    // An address/`application any` permit for lan->wan must still FORWARD a
    // non-first fragment — the gate must not over-block legitimate flowless
    // forwarding.
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies = vec![PolicyRuleSnapshot {
        name: "permit-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
        true,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "#3291: an `application any` permit must not deny the fragment"
    );
    assert_eq!(
        dbg.forward, 1,
        "#3291: a permitted non-first fragment must still forward (no over-gating)"
    );
}


/// eth(14) + IPv4(20, proto=UDP) + UDP(8). `frag_off` carries the IPv4
/// flags+offset word (0x2000 => MF, offset 0 == first fragment; 0x0001 =>
/// offset 1 == non-first). `id` is the 16-bit IPv4 Identification shared by
/// every fragment of one datagram. src 10.0.61.100 (lan) -> dst 172.16.80.200
/// (wan), matching `frag_transit_wan_neighbor`.
fn udp_frag_frame_5689(frag_off: u16, id: u16) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x08, 0x00,
    ];
    f[..6].copy_from_slice(&crate::afxdp::tests_support::TEST_LAN_MAC);
    // For a first fragment the 8 bytes at l4 are a real UDP header (sport
    // 33333, dport 443); for a non-first fragment they are payload (never read
    // as ports — the fragment is flowless per #2344).
    let udp = [0x82, 0x35, 0x01, 0xbb, 0x00, 0x08, 0x00, 0x00];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = (20 + udp.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[6..8].copy_from_slice(&frag_off.to_be_bytes());
    ip[8] = 64; // ttl
    ip[9] = PROTO_UDP;
    ip[12..16].copy_from_slice(&[10, 0, 61, 100]); // src (lan)
    ip[16..20].copy_from_slice(&[172, 16, 80, 200]); // dst (wan)
    f.extend_from_slice(&ip);
    f.extend_from_slice(&udp);
    f
}

fn udp_frag_meta_5689() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24, // reth1.0 (lan)
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        pkt_len: 42,
        l3_offset: 14,
        l4_offset: 34,
        flow_src_port: 33333,
        flow_dst_port: 443,
        flow_src_addr: [10, 0, 61, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

/// #10130: reply-side interface-SNAT fragment with no L4 header. The
/// destination is the public address assigned to the WAN interface, so the
/// flowless resolver selects LocalDelivery rather than ForwardCandidate.
fn udp_reply_frag_frame_10130(frag_off: u16, id: u16) -> Vec<u8> {
    let mut f = vec![
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x08, 0x00,
    ];
    let udp_or_payload = [0x01, 0xbb, 0x82, 0x35, 0x00, 0x08, 0x00, 0x00];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = (20 + udp_or_payload.len()) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[6..8].copy_from_slice(&frag_off.to_be_bytes());
    ip[8] = 64;
    ip[9] = PROTO_UDP;
    ip[12..16].copy_from_slice(&[172, 16, 80, 200]);
    ip[16..20].copy_from_slice(&[172, 16, 80, 8]);
    f.extend_from_slice(&ip);
    f.extend_from_slice(&udp_or_payload);
    f
}


#[test]
fn flowless_non_first_fragment_inherits_ordinary_snat_translation_5689() {
    // #5689: a non-first fragment of an ORDINARY-NAT (interface SNAT lan->wan)
    // flow must inherit the first fragment's translation on the flowless arm
    // (address-only L3 rewrite) instead of being forwarded UNTRANSLATED. Before
    // this fix only NAT64 had a fragment association; an ordinary-NAT/NPT
    // non-first fragment resolved `NatDecision::default()` and leaked out with
    // the untranslated internal source.
    //
    // The FIRST fragment (offset 0, MF=1) runs the full cold path: it is
    // permitted, interface-SNAT'd to the wan interface IP (172.16.80.8), a
    // session is installed, AND the ordinary-NAT fragment association is
    // installed. The NON-first fragment (offset 1, same IPv4 id) is flowless;
    // the flowless arm consults the association and inherits the SNAT decision.
    //
    // RED-on-revert: reverting the install (cold-path) OR the flowless consult
    // makes the non-first fragment resolve `NatDecision::default()` ->
    // `nat_applied_none == 1`, `nat_applied_snat == 0` (forwarded untranslated).
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();

    // (1) FIRST fragment: MF=1, offset 0, id 0xbeef. Seeds the session, applies
    //     interface SNAT, and installs the ordinary-NAT fragment association.
    let first = udp_frag_frame_5689(0x2000, 0xbeef);
    let (_b1, dbg1) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        udp_frag_meta_5689(),
        true,
    );
    assert_eq!(
        dbg1.nat_applied_snat, 1,
        "#5689: the SNAT'd first fragment must translate (source -> wan IP)"
    );
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        1,
        "#5689: the first fragment must install exactly one ordinary-NAT association"
    );

    // (2) NON-first fragment: offset 1, SAME id 0xbeef -> flowless -> consult
    //     the association installed above and inherit the SNAT translation.
    let non_first = udp_frag_frame_5689(0x0001, 0xbeef);
    let (_b2, dbg2) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        udp_frag_meta_5689(),
        true,
    );
    assert_eq!(
        dbg2.forward, 1,
        "#5689: the non-first fragment must forward"
    );
    assert_eq!(
        dbg2.nat_applied_snat, 1,
        "#5689: the non-first fragment must INHERIT the SNAT translation (RED on revert)"
    );
    assert_eq!(
        dbg2.nat_applied_none, 0,
        "#5689: the non-first fragment must NOT be forwarded untranslated"
    );
}

/// #10130: a reordered interface-SNAT reply tail must be rejected even when
/// its destination resolves to LocalDelivery. Without the session-gated L3
/// reverse discriminator this packet reaches host-inbound handling as a plain
/// fragment and can escape untranslated.
#[test]
fn flowless_interface_snat_reply_tail_is_session_gated_10130() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding_lan = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding_lan.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();

    // Establish the live forward interface-SNAT session.
    let first = udp_frag_frame_5689(0x2000, 0xbeef);
    let (_batch_first, dbg_first) = txn_run_descriptor_checked(
        &mut binding_lan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        udp_frag_meta_5689(),
        true,
    );
    assert_eq!(dbg_first.nat_applied_snat, 1);

    // The reply tail uses a fresh identification, so no reverse fragment
    // association exists. Its destination is the local public interface IP.
    let mut binding_wan = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding_wan.interface = Arc::<str>::from("reth0.80");
    let reply_tail = udp_reply_frag_frame_10130(0x0001, 0xcafe);
    let reply_meta = UserspaceDpMeta {
        ingress_ifindex: 12,
        flow_src_port: 443,
        flow_dst_port: 33333,
        flow_src_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..udp_frag_meta_5689()
    };
    let (batch_reply, dbg_reply) = txn_run_descriptor_checked(
        &mut binding_wan,
        &mut sessions,
        &forwarding,
        &ha_state,
        &reply_tail,
        reply_meta,
        true,
    );
    assert_eq!(
        dbg_reply.forward, 0,
        "#10130: reordered interface-SNAT reply tail must not forward"
    );
    assert_eq!(
        batch_reply.nat_frag_untranslated_dropped, 1,
        "#10130: LocalDelivery reply-tail rejection is observable"
    );
}

/// #8367: on the FLOWLESS TX path under plain SNAT, the egress interface
/// `filter output` must be MATCHED — and its `then log` event ATTRIBUTED —
/// against the POST-NAT (on-wire) tuple, not the pre-translation one.
///
/// #7656 established that contract, but only for NAT64, where the staleness is
/// a FAMILY change and therefore loud: the wrong-family filter was selected
/// outright. This is the non-NAT64 half. The family is unchanged and only the
/// addresses move, so nothing about the packet looks wrong — a
/// `from source-address <pool>` term simply does not match a packet whose
/// on-wire source IS the pool address, and a `then log` records a source the
/// packet never carried on the wire.
///
/// # The fixture, and why it is shaped this way
///
/// Interface SNAT lan -> wan rewrites 10.0.61.100 to the wan interface address
/// 172.16.80.8. Two fragments of ONE datagram go through:
///
/// * the FIRST fragment has a flow, so it takes the flow-bearing path, which
///   has used the post-NAT wire key since #3642. It is the POSITIVE CONTROL —
///   its `1` proves the term is well-formed, TX-eligible, attached to the
///   interface the packet actually leaves by, and reachable on this fixture, so
///   the flowless value beside it is about the flowless packet and not about a
///   dead fixture.
/// * the NON-FIRST fragment is FLOWLESS (#2344) and inherits the first's SNAT
///   decision through the ordinary-NAT fragment association (#5689/#6095). It
///   is the packet under test.
///
/// The term is ADDRESS-BEARING and its expected value DIFFERS between the two
/// tuples. That is the #7656 fixture warning carried over verbatim: an
/// address-less term fires on whichever tuple the evaluator was handed and
/// cannot distinguish "matched the post-NAT tuple" from "matched the pre-NAT
/// one". On #7656 a family-only half-fix passed the address-less cell and was
/// caught only by an address-bearing one — and here there is no family signal
/// at all, since both tuples are IPv4.
///
/// # Two sites, and the assertions are split across both
///
/// `forward_request.rs` feeds the post-NAT flowless key to TWO consumers:
/// `resolve_cos_tx_selection_at_prenat` (which decides whether the term MATCHES)
/// and `apply_cos_drop_side_effects` (which decides which tuple the event
/// CARRIES). The event COUNT binds the first; the event's `src_ip` binds the
/// second. Asserting only that a log exists would pass on a record attributed
/// to the wrong tuple, which is the #7656 defect one layer down on this code.
#[test]
fn flowless_snat_egress_output_filter_matches_the_postnat_tuple_8367() {
    // (label, the term's `from source-address`, want_first, want_flowless)
    for (label, term_source, want_first, want_flowless) in [
        // The PRE-NAT source. The packet arrived with it and no longer carries
        // it on the wire, so neither packet may match.
        (
            "pre-NAT source term: the ingress tuple must no longer match",
            "10.0.61.100/32",
            0u64,
            0u64,
        ),
        // The POST-NAT source — the wan interface address interface-SNAT
        // rewrote to. Both packets leave with it, so both must match.
        (
            "post-NAT source term: the on-wire tuple must match",
            "172.16.80.8/32",
            1u64,
            1u64,
        ),
    ] {
        let mut snapshot = policy_deny_snapshot();
        snapshot.default_policy = "permit".to_string();
        snapshot.policies.clear();
        snapshot.neighbors = vec![frag_transit_wan_neighbor()];
        snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
            name: "snat-lan-wan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }];
        // `then accept` + `then log` on the WAN egress: both packets MUST still
        // forward, so a drop can never be mistaken for the property under test.
        snapshot.interfaces[1].filter_output_v4 = "postnat-src".to_string();
        snapshot.filters = vec![FirewallFilterSnapshot {
            name: "postnat-src".to_string(),
            family: "inet".to_string(),
            terms: vec![FirewallTermSnapshot {
                name: "by-source".to_string(),
                source_addresses: vec![term_source.to_string()],
                source_constrained: true,
                action: "accept".to_string(),
                log: true,
                ..Default::default()
            }],
        }];
        let forwarding = build_forwarding_state(&snapshot);

        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        let ha_state = BTreeMap::new();

        // (1) FIRST fragment (MF=1, offset 0): seeds the session, applies
        //     interface SNAT, installs the ordinary-NAT fragment association.
        //     Both packets use the CAPTURING runner so they share one clock —
        //     mixing runners hands them clocks billions of nanoseconds apart and
        //     the association the first installs is not valid for the second.
        let first = udp_frag_frame_5689(0x2000, 0xbeef);
        let (_b1, dbg1, first_handle, _rx1) = txn_run_descriptor_capturing_events(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &first,
            udp_frag_meta_5689(),
        );
        assert_eq!(dbg1.forward, 1, "{label}: the first fragment must forward");
        assert_eq!(
            dbg1.nat_applied_snat, 1,
            "{label} PREMISE: the first fragment must be SNAT'd, or the post-NAT \
             source term below is being matched against a packet that was never \
             translated"
        );
        assert_eq!(
            first_handle.dataplane_event_stats().filter_log.sent,
            want_first,
            "{label}: flow-bearing first fragment (the positive control)"
        );

        // (2) NON-FIRST fragment (offset 1, same IPv4 id): FLOWLESS. Consults
        //     the association and inherits the SNAT decision, so it leaves with
        //     the same on-wire source as the first fragment.
        let non_first = udp_frag_frame_5689(0x0001, 0xbeef);
        let (_b2, dbg2, second_handle, rx2) = txn_run_descriptor_capturing_events(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &non_first,
            udp_frag_meta_5689(),
        );
        assert_eq!(
            dbg2.forward, 1,
            "{label}: the non-first fragment must forward — the defect under test \
             is a mis-matched filter on a correctly forwarded packet"
        );
        assert_eq!(
            dbg2.nat_applied_snat, 1,
            "{label} PREMISE: the non-first fragment must INHERIT the SNAT \
             translation (#5689). Without this it leaves untranslated and the \
             pre-NAT source would legitimately match"
        );
        assert_eq!(
            second_handle.dataplane_event_stats().filter_log.sent,
            want_flowless,
            "{label}: FLOWLESS non-first fragment. A 0 on the post-NAT arm means \
             the egress output filter is still being MATCHED against the ingress \
             (pre-NAT) tuple — family, addresses and protocol must all come from \
             the synthesized post-NAT wire key (l3_wire_session_flow_from_meta), \
             not from `meta`"
        );

        if want_flowless == 0 {
            continue;
        }
        // The record must carry the POST-NAT addresses. The count above binds
        // the MATCH site; this binds the ATTRIBUTION site, which is a different
        // read of the same key — reverting it alone keeps the count at 1 and
        // logs 10.0.61.100 for a packet that left as 172.16.80.8.
        let event = rx2
            .try_recv()
            .expect("a filter-log event frame must have been queued")
            .decode_dataplane_event()
            .expect("filter-log payload must decode");
        assert_eq!(
            event.kind,
            crate::event_stream::codec::DataplaneEventKind::FilterLog
        );
        assert_eq!(
            event.src_ip,
            "172.16.80.8".parse::<std::net::IpAddr>().expect("src"),
            "{label}: the filter-log record must carry the POST-NAT source the \
             packet actually left with. 10.0.61.100 here is the pre-translation \
             source — a WRONG record rather than a missing one, which is worse \
             for anyone reading logs to reconstruct a flow"
        );
        assert_eq!(
            event.dst_ip,
            "172.16.80.200".parse::<std::net::IpAddr>().expect("dst"),
            "{label}: and the destination, which this SNAT does not translate"
        );
    }
}


#[test]
fn nat_nonfirst_fragment_assoc_miss_fails_closed_6122() {
    // #6122: a NON-first fragment of an ORDINARY-NAT (interface SNAT lan->wan)
    // flow that MISSES the fragment-association cache must be DROPPED
    // fail-closed, NOT forwarded UNTRANSLATED. The miss is exercised the way it
    // happens in production on the reorder / eviction / TTL-straddle /
    // config-generation-bump / never-forwarded-first edges: the non-first
    // fragment reaches the flowless arm with an EMPTY association cache (no
    // first fragment installed one). Before #6122 the flowless default forwarded
    // it with `NatDecision::default()`, leaking the internal source
    // (10.0.61.100) onto the wan wire. #6122 fails closed: the discriminator
    // sees the SNAT rule WOULD translate this flow's L3 identity, so the
    // permitted-but-untranslatable fragment is dropped (the sender retransmits).
    //
    // RED-on-revert: reverting the fail-closed drop makes the fragment forward
    // untranslated -> `dbg.forward == 1`, `dbg.nat_applied_none == 1`,
    // `batch.nat_frag_untranslated_dropped == 0`, tripping all three asserts.
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "snat-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();

    // Precondition: the association cache is EMPTY (no first fragment seen), so
    // the flowless consult below is a genuine MISS.
    assert_eq!(
        forwarding.nat64.frag_assoc.len(),
        0,
        "#6122 precondition: no fragment association installed (a pure miss)"
    );

    // NON-first fragment (offset 1, id 0xbeef) arriving WITHOUT its first
    // fragment -> flowless -> association MISS -> #6122 fail-closed drop.
    let non_first = udp_frag_frame_5689(0x0001, 0xbeef);
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        udp_frag_meta_5689(),
        true,
    );
    assert_eq!(
        dbg.forward, 0,
        "#6122: a NAT'd non-first fragment that misses the association must NOT forward"
    );
    assert_eq!(
        dbg.nat_applied_none, 0,
        "#6122: the fragment must NOT be forwarded untranslated (no internal-source leak)"
    );
    assert_eq!(
        batch.nat_frag_untranslated_dropped, 1,
        "#6122: the fail-closed drop must be counted (RED on revert)"
    );
}


#[test]
fn nonnat_nonfirst_fragment_assoc_miss_still_forwards_6122() {
    // #6122 no-regression: a NON-NAT'd (plain-forwarded) non-first fragment that
    // misses the association must STILL forward normally. The #6122 fail-closed
    // drop is scoped to fragments whose flow WOULD be NAT-translated; a plain
    // fragmented flow needs no translation, so dropping it would break ordinary
    // fragmented forwarding. Same topology as the SNAT test above but with NO
    // NAT rule of any kind, so the discriminator finds no matching rule and the
    // fragment forwards untranslated (the correct disposition for a no-NAT flow).
    //
    // Guards against an over-broad fix: reverting the discriminator's NAT-scope
    // gate (dropping EVERY same-family fragment miss) makes `dbg.forward == 0`
    // and `batch.nat_frag_untranslated_dropped == 1`, tripping these asserts.
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    // No source_nat_rules / DNAT / static-NAT / NPTv6 -> a plain (no-NAT) flow.
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();

    let non_first = udp_frag_frame_5689(0x0001, 0xbeef);
    let (batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        udp_frag_meta_5689(),
        true,
    );
    assert_eq!(
        dbg.forward, 1,
        "#6122: a plain (no-NAT) non-first fragment must still forward"
    );
    assert_eq!(
        dbg.nat_applied_none, 1,
        "#6122: a plain fragment forwards untranslated (correct — no NAT applies)"
    );
    assert_eq!(
        batch.nat_frag_untranslated_dropped, 0,
        "#6122: a plain fragment must NOT be counted as a NAT'd-fragment drop"
    );
}


#[test]
fn flowless_non_first_fragment_dropped_by_is_fragment_input_filter_3291() {
    // Interface input filter `from is-fragment then discard` on the ingress
    // interface must DROP a non-first fragment. Default-permit policy ensures
    // the drop is the filter's doing, not zone policy. RED-on-revert: the
    // flowless arm never ran the input filter (dbg.forward == 1).
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.interfaces[0].filter_input_v4 = "drop-frags".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "drop-frags".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "frag".to_string(),
            is_fragment: true,
            action: "discard".to_string(),
            ..Default::default()
        }],
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
        true,
    );

    assert_eq!(
        dbg.forward, 0,
        "#3291: `from is-fragment then discard` must drop a non-first fragment (RED on revert)"
    );
}


#[test]
fn flowless_non_first_fragment_steered_by_pbr_routing_instance_3291() {
    // Firewall-filter PBR `from is-fragment then routing-instance scrub` must
    // steer the fragment's route lookup to the (empty) `scrub` table -> NoRoute.
    // Default-permit policy + a base connected route to 172.16.80.0/24 mean
    // that WITHOUT the gate the fragment forwards via the base table.
    // RED-on-revert: the flowless arm ignored PBR -> base route -> forward.
    //
    // #10467: the userspace route lookup reaches NoRoute in the explicit
    // `scrub` table. That result is terminal at the poll chokepoint; handing
    // the original frame to the kernel would lose the ingress/table identity
    // and allow MAIN to forward it. Ordinary MAIN-table NoRoute keeps its
    // existing slow-path behavior, but a non-default install identity does not.
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.interfaces[0].filter_input_v4 = "frag-to-scrub".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "frag-to-scrub".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "frag".to_string(),
            is_fragment: true,
            action: "accept".to_string(),
            routing_instance: "scrub".to_string(),
            ..Default::default()
        }],
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
        true,
    );

    assert_eq!(
        dbg.forward, 0,
        "#3291: PBR `then routing-instance scrub` must steer the fragment to the \
         empty scrub table -> NoRoute -> drop (RED on revert: base-table forward)"
    );
    assert_eq!(
        dbg.no_route, 1,
        "#3291: the PBR-steered fragment resolves NoRoute in the empty scrub table"
    );
    // #10467: an explicit-table NoRoute is terminal before generic reinjection.
    // This harness installs no reinjector (`slow_path: None`), so a regression
    // that reaches the enqueue site would bump `slow_path_drops` to 1. The
    // fixed scoped gate must leave it at zero.
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        0,
        "#10467: the PBR-steered NoRoute fragment must not reach the slow path"
    );
}

// ---- #9894 (GPT-2): flowless L3 contexts must not spuriously match
// port-constrained input-filter/PBR terms on their 0-substituted ports ----

/// Slack-TCP transit frame: atomic (offset 0, NOT a non-first fragment),
/// total_len=20 with 4 trailing slack bytes spelling (1111, 443).
/// Addrs match the frag-transit fixtures (10.0.61.100 -> 172.16.80.200) so
/// the base table forwards it.
fn slack_tcp_transit_frame_9894() -> Vec<u8> {
    let mut frame = eth_ipv4_frag_frame(0x0000, &[0x04, 0x57, 0x01, 0xbb], crate::afxdp::tests_support::TEST_LAN_MAC);
    frame[16] = 0x00;
    frame[17] = 20; // total_len=20: the L4 bytes are slack, not datagram
    frame
}

/// Matching shim-style meta: complete stamped tuple (1111, 443) at a
/// realistic l4_offset=34 (pointing at the slack bytes), lan ingress.
fn slack_tcp_transit_meta_9894() -> UserspaceDpMeta {
    let mut meta = frag_v4_transit_meta();
    meta.l4_offset = 34;
    meta.flow_src_port = 1111;
    meta.flow_dst_port = 443;
    meta.pkt_len = 24; // L3 backing length, mirroring the fixture convention
    meta
}

/// Well-formed TCP transit frame with the given ports (20-byte header, SYN,
/// total covers L4) for the real-flow controls.
fn wellformed_tcp_transit_frame_9894(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[12] = 0x50; // dataofs 5
    tcp[13] = 0x02; // SYN
    eth_ipv4_frag_frame(0x0000, &tcp, crate::afxdp::tests_support::TEST_LAN_MAC)
}

fn wellformed_tcp_transit_meta_9894(src_port: u16, dst_port: u16) -> UserspaceDpMeta {
    let mut meta = frag_v4_transit_meta();
    meta.l4_offset = 34;
    meta.flow_src_port = src_port;
    meta.flow_dst_port = dst_port;
    meta.pkt_len = 40;
    meta
}

fn permit_all_with_input_filter_9894(filter_name: &str, terms: Vec<FirewallTermSnapshot>) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.interfaces[0].filter_input_v4 = filter_name.to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: filter_name.to_string(),
        family: "inet".to_string(),
        terms,
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    build_forwarding_state(&snapshot)
}

fn run_one_packet_9894(
    forwarding: &ForwardingState,
    frame: &[u8],
    meta: UserspaceDpMeta,
) -> (u64, u64) {
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        forwarding,
        &ha_state,
        frame,
        meta,
        true,
    );
    (dbg.forward, dbg.no_route)
}

#[test]
fn flowless_slack_tcp_not_steered_by_port_except_pbr_9894() {
    // GPT-2 loop pin: input filter `from { tcp; destination-port-except 22; }
    // then routing-instance scrub`. The flowless slack-TCP packet evaluates
    // PBR on an L3-only context (ports 0/0): without suppression the except
    // term invert-matches the synthetic zero (0 != 22) and steers to the
    // empty scrub table (NoRoute). Post-fix it base-forwards. Reverting the
    // pbr.rs marking flips forward 1 -> 0 / no_route 0 -> 1 -> RED.
    let forwarding = permit_all_with_input_filter_9894(
        "except-to-scrub",
        vec![FirewallTermSnapshot {
            name: "except".to_string(),
            protocols: vec!["tcp".to_string()],
            destination_ports_except: vec!["22".to_string()],
            routing_instance: "scrub".to_string(),
            action: "accept".to_string(),
            ..Default::default()
        }],
    );
    // The flowless shape: base-forwarded, NOT steered.
    let (forward, no_route) = run_one_packet_9894(
        &forwarding,
        &slack_tcp_transit_frame_9894(),
        slack_tcp_transit_meta_9894(),
    );
    assert_eq!(
        forward, 1,
        "flowless slack TCP must base-forward, not steer"
    );
    assert_eq!(no_route, 0);
    // Control 1: a real flow with dst 80 DOES steer (80 != 22 matches) —
    // proves the term steers and suppression is flowless-only.
    let (forward, no_route) = run_one_packet_9894(
        &forwarding,
        &wellformed_tcp_transit_frame_9894(40000, 80),
        wellformed_tcp_transit_meta_9894(40000, 80),
    );
    assert_eq!(forward, 0, "real dst-80 flow must steer to scrub");
    assert_eq!(no_route, 1);
    // Control 2: except semantics intact — dst 22 is excluded, forwards.
    let (forward, no_route) = run_one_packet_9894(
        &forwarding,
        &wellformed_tcp_transit_frame_9894(40000, 22),
        wellformed_tcp_transit_meta_9894(40000, 22),
    );
    assert_eq!(forward, 1, "dst-22 flow is excluded from the steer");
    assert_eq!(no_route, 0);
}

#[test]
fn flowless_slack_tcp_not_dropped_by_port_except_input_filter_9894() {
    // GPT-2 loop pin, input-filter half: `from { tcp;
    // destination-port-except 22; } then discard`. The flowless slack-TCP
    // packet must FORWARD (suppressed); without suppression the except term
    // invert-matches (0,0) and discards. Reverting the poll_descriptor
    // marking flips forward 1 -> 0 -> RED.
    let forwarding = permit_all_with_input_filter_9894(
        "drop-except",
        vec![FirewallTermSnapshot {
            name: "except".to_string(),
            protocols: vec!["tcp".to_string()],
            destination_ports_except: vec!["22".to_string()],
            action: "discard".to_string(),
            ..Default::default()
        }],
    );
    let (forward, _) = run_one_packet_9894(
        &forwarding,
        &slack_tcp_transit_frame_9894(),
        slack_tcp_transit_meta_9894(),
    );
    assert_eq!(
        forward, 1,
        "flowless slack TCP must not match the except term"
    );
    // Control: a real dst-80 flow DOES match and is discarded.
    let (forward, _) = run_one_packet_9894(
        &forwarding,
        &wellformed_tcp_transit_frame_9894(40000, 80),
        wellformed_tcp_transit_meta_9894(40000, 80),
    );
    assert_eq!(forward, 0, "real dst-80 flow must hit the discard term");
}

// ---- #4024: flowless / non-first-fragment MISSING-NEIGHBOR ENFORCEMENT ----
//
// #3291 enforced zone policy on the flowless ForwardCandidate arm but deferred
// MissingNeighbor to "its own cold-path arm" — whose #1913 policy gate is
// `if let Some(flow)` and so never fired for a flowless (flow == None) packet.
// So a flowless fragment whose next-hop neighbor was unresolved fell through to
// the FIB reinject, and a `deny-all` zone pair FAILED OPEN for it (kernel
// forwarded the transit). #4024 adds the flowless (flow == None) policy gate to
// the MissingNeighbor arm. Reverting the gate flips the deny case from a
// policy-deny drop back to a buffered-and-reinjected forward, turning the
// asserts RED.


#[test]
fn flowless_non_first_fragment_missing_neighbor_dropped_by_deny_all_4024() {
    // lan->wan is default-deny (policy_deny_snapshot only permits dmz->wan).
    // With NO neighbor for 172.16.80.200 the connected WAN route resolves but
    // ARP is unresolved -> MissingNeighbor. A flowless (non-first fragment) that
    // hits that cold path MUST be DROPPED by zone policy, not FIB-reinjected.
    // RED-on-revert: the flowless MissingNeighbor arm used to skip the policy
    // gate (dbg.policy_deny == 0) and buffer the frame for retry
    // (pending_neigh not empty) while the trailing chokepoint reinjected it.
    let mut snapshot = policy_deny_snapshot();
    // Empty neighbors => the WAN connected route resolves egress but no MAC =>
    // MissingNeighbor (the cold path under test), not ForwardCandidate.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
        true,
    );

    assert_eq!(
        dbg.missing_neigh, 1,
        "#4024: no neighbor for the connected WAN dst must resolve MissingNeighbor \
         (the flowless cold path under test)"
    );
    assert_eq!(
        dbg.policy_deny, 1,
        "#4024: a deny-all zone pair must DROP a flowless MissingNeighbor fragment \
         via the policy gate (RED on revert: 0 — flowless skipped the gate)"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "#4024: a denied flowless MissingNeighbor fragment must NOT be buffered \
         for neighbor retry (RED on revert: buffered before the reinject leak)"
    );
}


#[test]
fn flowless_non_first_fragment_missing_neighbor_permitted_forwards_4024() {
    // An `application any` permit for lan->wan must NOT deny a flowless
    // MissingNeighbor fragment — the gate must not over-block legitimate
    // flowless forwarding. The permitted fragment stays on the cold path
    // (buffered for in-place retry once the neighbor resolves).
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies = vec![PolicyRuleSnapshot {
        name: "permit-lan-wan".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }];
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta(),
        true,
    );

    assert_eq!(
        dbg.missing_neigh, 1,
        "#4024: the permitted fragment still resolves MissingNeighbor"
    );
    assert_eq!(
        dbg.policy_deny, 0,
        "#4024: an `application any` permit must not deny the flowless fragment"
    );
    assert!(
        !binding.pending_neigh.is_empty(),
        "#4024: a PERMITTED flowless MissingNeighbor fragment must still take the \
         forward/retry path (buffered for neighbor resolution) — no over-gating"
    );
}

// ---- #2364: seeded fabric queue hash ------------------------------------


#[test]
fn fabric_queue_hash_is_stable_within_one_seed() {
    // Intra-process invariant: every fragment/packet of one datagram must
    // pick the same fabric binding, so the hash must be stable for a fixed
    // seed. Pin a seed and demand identical output across repeats.
    let metas = fabric_adversarial_metas(32);
    let seed = 0x0123_4567_89AB_CDEFu64;
    let first: Vec<u64> = metas
        .iter()
        .map(|(m, ports)| fabric_queue_hash_seeded(seed, None, Some(*ports), *m, false))
        .collect();
    for _ in 0..128 {
        let again: Vec<u64> = metas
            .iter()
            .map(|(m, ports)| fabric_queue_hash_seeded(seed, None, Some(*ports), *m, false))
            .collect();
        assert_eq!(
            first, again,
            "fabric_queue_hash must be stable for a fixed seed (no fragment reorder)"
        );
    }
}


#[test]
fn fabric_queue_hash_distribution_depends_on_seed() {
    // Hardening invariant: the fabric queue selection is not an externally
    // probeable pure function of the tuple. Two seeds must produce a
    // different hash distribution for the SAME attacker tuple set, so a
    // flow generator cannot precompute a single-worker pin. With the prior
    // unseeded `seed = meta.protocol` the distribution is seed-independent
    // and this fails — fail-on-revert.
    let metas = fabric_adversarial_metas(64);
    let ref_seed = 0xA5A5_0000_C3C3_FFFFu64;
    let reference: Vec<u64> = metas
        .iter()
        .map(|(m, ports)| fabric_queue_hash_seeded(ref_seed, None, Some(*ports), *m, false))
        .collect();
    let mut diverged = false;
    for seed in 1u64..4096u64 {
        if seed == ref_seed {
            continue;
        }
        let dist: Vec<u64> = metas
            .iter()
            .map(|(m, ports)| fabric_queue_hash_seeded(seed, None, Some(*ports), *m, false))
            .collect();
        if dist != reference {
            diverged = true;
            break;
        }
    }
    assert!(
        diverged,
        "fabric_queue_hash distribution did not change across seeds — \
         hash is seed-independent (unseeded regression, #2364)"
    );
}


#[test]
fn fabric_queue_hash_seed_reshuffles_modular_target_buckets() {
    // The production consumer is `flow_hash % local_fabric_binding_count`.
    // Model that with a small modulus and show the per-flow target bucket
    // assignment changes across seeds — i.e. an attacker who biased all
    // flows onto one fabric worker under a known mapping loses that pin on
    // the next boot's reseed.
    const FABRIC_QUEUES: u64 = 6; // mlx5 VF: 6 combined RX queues → 6 workers
    let metas = fabric_adversarial_metas(96);
    let buckets = |seed: u64| -> Vec<u64> {
        metas
            .iter()
            .map(|(m, ports)| {
                fabric_queue_hash_seeded(seed, None, Some(*ports), *m, false) % FABRIC_QUEUES
            })
            .collect()
    };
    let a = buckets(0xDEAD_BEEF_CAFE_BABE);
    let b = buckets(0xDEAD_BEEF_CAFE_BABE ^ 0xFFFF_FFFF_FFFF_FFFF);
    assert_ne!(
        a, b,
        "modular fabric target assignment is identical across seeds — \
         reseed does not break a precomputed single-worker pin (#2364)"
    );
}


#[test]
fn non_first_fragment_v6_not_dropped_by_port_matching_output_filter() {
    let payload = [0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0];
    let frame = eth_ipv6_frag_frame(0x0008, &payload); // non-first (offset != 0)
    let forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v6: "wan-drop6".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop6".into(),
            family: "inet6".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                log: true,
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    let ingress_ident = frag_test_ingress_ident();
    let decision = frag_test_decision();
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        pkt_len: 80,
        l3_offset: 14,
        flow_src_port: 33333,
        flow_dst_port: 443,
        flow_src_addr: [
            0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x00,
        ],
        flow_dst_addr: [
            0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00,
        ],
        ..UserspaceDpMeta::default()
    };
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        None,
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );

    let req = req.expect("a non-first IPv6 fragment must NOT be dropped by a port filter");
    assert_eq!(req.flow_key, None, "v6 fragment TX selection must use no flow_key");
    assert_eq!(req.expected_ports, None, "v6 fragment must not carry payload ports");
}


#[test]
fn pending_neigh_fragment_buffers_no_flow_key() {
    // Mirrors the poll_descriptor pending-neigh buffer-admission expression
    // (#2357): a buffered packet's stored flow_key later drives
    // resolve_cos_tx_selection_at on flush, so a non-first fragment must
    // store `None` rather than a payload-derived ported tuple. A legitimate
    // flowless TCP packet (real L4 header) keeps its meta-derived flow_key.
    let flow: Option<&SessionFlow> = None;

    // Non-first fragment frame; meta claims a ported tuple (the shim stamps
    // payload bytes). The gate must suppress the meta fallback.
    let frag_frame = eth_ipv4_frag_frame(0x0001, &[0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0], crate::afxdp::tests_support::TEST_LAN_MAC);
    let frag_meta = frag_test_meta(14);
    let frag_key = flow
        .as_ref()
        .map(|flow| flow.forward_key.clone())
        .or_else(|| {
            if frame_is_non_first_fragment(&frag_frame, frag_meta) {
                None
            } else {
                parse_session_flow_from_meta(frag_meta).map(|flow| flow.forward_key)
            }
        });
    assert_eq!(
        frag_key, None,
        "a buffered non-first fragment must store no flow_key"
    );

    // First/atomic fragment (real L4 header) — same meta — keeps its ports.
    let ok_frame = eth_ipv4_frag_frame(0x0000, &[0x82, 0x35, 0x01, 0xbb, 0, 0, 0, 0], crate::afxdp::tests_support::TEST_LAN_MAC);
    let ok_meta = frag_test_meta(14);
    let ok_key = flow
        .as_ref()
        .map(|flow| flow.forward_key.clone())
        .or_else(|| {
            if frame_is_non_first_fragment(&ok_frame, ok_meta) {
                None
            } else {
                parse_session_flow_from_meta(ok_meta).map(|flow| flow.forward_key)
            }
        });
    let ok_key = ok_key.expect("a flowless non-fragmented TCP packet keeps its meta flow_key");
    assert_eq!(ok_key.dst_port, 443, "legit flowless packet keeps its dst port");
}


// #3534 fail-on-revert: build_forwarding_state must thread the snapshot's
// implicit-default-policy RT_FLOW log selection
// (ConfigSnapshot.default_log_session_init/close) onto PolicyState so the
// default-verdict result can stamp a default-PERMIT session. Reverting the
// forwarding_build/mod.rs assignment leaves the PolicyState flags false and the
// "true" assertions go RED. Additive: an omitted field decodes to false.
#[test]
fn build_forwarding_state_threads_default_policy_log_flags() {
    let state = build_forwarding_state(&ConfigSnapshot {
        default_policy: "permit".into(),
        default_log_session_init: true,
        default_log_session_close: true,
        ..Default::default()
    });
    assert!(
        state.policy.default_log_session_init,
        "default_log_session_init must reach PolicyState from the snapshot"
    );
    assert!(
        state.policy.default_log_session_close,
        "default_log_session_close must reach PolicyState from the snapshot"
    );

    // Omitting the selection leaves both false (the default behaviour).
    let quiet = build_forwarding_state(&ConfigSnapshot {
        default_policy: "permit".into(),
        ..Default::default()
    });
    assert!(!quiet.policy.default_log_session_init);
    assert!(!quiet.policy.default_log_session_close);
}

// #5798 FAIL-ON-REVERT, NON-NAT64 arm: an ORDINARY same-family NAT association
// HIT must also be subject to the per-packet interface INPUT FILTER.
//
// The hit-arm filter block lives on the shared `{ hit }` arm, which serves BOTH
// consults — the NAT64 (cross-family) one and the #5689 same-family SNAT / DNAT
// / static-NAT / NPTv6 one. `nat64_association_hit_still_runs_interface_input_filter_5798`
// (tests_nat64_tunnel.rs) exercises only the NAT64 consult, so it would stay
// green if the filter were gated to NAT64 associations, leaving every ordinary
// NAT association hit unfiltered. This test closes that: an interface-SNAT
// lan->wan datagram, whose non-first fragment inherits via
// `nat_consult_forward_fragment_assoc`.
//
// Why the filter can install AND still catch the non-first fragment (no cache
// seeding needed here): term 1 matches `destination-port 443`, which only the
// FIRST fragment carries — a non-first fragment is flowless, so the hit arm
// evaluates it with `l3_session_flow_from_meta`'s zero ports and `l4_present`
// false. So the first fragment terminates on the accept term and installs the
// association; the non-first fragment falls through to term 2's
// `from is-fragment then discard`.
//
// The `nat_frag_untranslated_dropped == 0` assertion is what stops this passing
// for the wrong reason: it proves the fragment was dropped by the FILTER on the
// hit path, not by the #6122 fail-closed drop that a consult MISS would take.
//
// RED on revert: delete the input-filter block from the `{ hit }` arm in
// poll_descriptor (or gate it on `decision.nat.nat64`) and the discarded case
// forwards + SNATs.
#[test]
fn nat_ordinary_association_hit_still_runs_interface_input_filter_5798() {
    // Returns (forward, nat_applied_snat, nat_frag_untranslated_dropped) for the
    // NON-first fragment.
    let run = |second_term_action: &str| -> (u64, u64, u64) {
        let mut snapshot = policy_deny_snapshot();
        snapshot.default_policy = "permit".to_string();
        snapshot.policies.clear();
        snapshot.neighbors = vec![frag_transit_wan_neighbor()];
        snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
            name: "snat-lan-wan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }];
        snapshot.interfaces[0].filter_input_v4 = "frag-gate".to_string();
        snapshot.filters = vec![FirewallFilterSnapshot {
            name: "frag-gate".to_string(),
            family: "inet".to_string(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-first".to_string(),
                    destination_ports: vec!["443".to_string()],
                    action: "accept".to_string(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "fragments".to_string(),
                    is_fragment: true,
                    action: second_term_action.to_string(),
                    ..Default::default()
                },
            ],
        }];
        let forwarding = build_forwarding_state(&snapshot);

        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        let ha_state = BTreeMap::new();

        // FIRST fragment: terminates on the `destination-port 443` accept term,
        // is interface-SNAT'd, and installs the ordinary-NAT association.
        let first = udp_frag_frame_5689(0x2000, 0xf00d);
        let (_b1, dbg1) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &first,
            udp_frag_meta_5689(),
            true,
        );
        assert_eq!(
            dbg1.nat_applied_snat, 1,
            "the SNAT'd first fragment must translate and install the association"
        );
        assert_eq!(
            forwarding.nat64.frag_assoc.len(),
            1,
            "the first fragment must install exactly one ordinary-NAT association"
        );

        // NON-first fragment: association HIT, then the per-packet filter.
        let non_first = udp_frag_frame_5689(0x0001, 0xf00d);
        let (batch, dbg2) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &non_first,
            udp_frag_meta_5689(),
            true,
        );
        (
            dbg2.forward,
            dbg2.nat_applied_snat,
            batch.nat_frag_untranslated_dropped,
        )
    };

    // Control: with the fragment term set to `accept`, the ordinary-NAT
    // association hit forwards and inherits the SNAT translation. This proves
    // the seeded hit is real, so the discard case below cannot pass for an
    // unrelated reason.
    let (fwd_open, snat_open, miss_drop_open) = run("accept");
    assert_eq!(
        fwd_open, 1,
        "#5798 control: with an accepting fragment term the ordinary-NAT hit must forward"
    );
    assert_eq!(
        snat_open, 1,
        "#5798 control: the inherited fragment must be SNAT-translated"
    );
    assert_eq!(
        miss_drop_open, 0,
        "#5798 control: it was an association HIT, not a #6122 fail-closed miss"
    );

    // The guard.
    let (fwd_filtered, snat_filtered, miss_drop_filtered) = run("discard");
    assert_eq!(
        fwd_filtered, 0,
        "#5798: a NON-NAT64 (ordinary SNAT) association HIT must still be subject to the \
         per-packet interface input filter — `from is-fragment then discard` must drop it"
    );
    assert_eq!(
        snat_filtered, 0,
        "#5798: the filtered fragment must not be SNAT-translated and forwarded"
    );
    assert_eq!(
        miss_drop_filtered, 0,
        "#5798: the drop must come from the INPUT FILTER on the hit path, not from the #6122 \
         fail-closed association-miss drop (which would mean the association never hit and \
         this test proved nothing about the hit arm)"
    );
}
// ---- #7890: per-arm cells. An unspecified source must not skip enforcement ----
//
// Each cell is built from ITS OWN arm's derived class, not from the issue's
// stated shape. That shape — "non-first fragment hitting an existing
// association" — is `:3422`'s and only `:3422`'s; a fixture built from it lands
// in that arm and passes without ever executing the site it names. The shapes
// were derived by instrumenting the four arms and reading the fixtures of the
// tests that reach them (#7890).
//
// Every cell asserts the WITNESS moved before asserting what enforcement did.
// Without that, a fixture that misses a conjunct never enters the arm and passes
// proving nothing — which is the failure the enumeration existed to prevent.

/// The unspecified-source witness, read as a delta the way the #7055 cells do.
fn unspecified_witness_7890() -> u64 {
    crate::afxdp::frame::L3_CTX_NONE_UNSPECIFIED_ADDR.load(std::sync::atomic::Ordering::Relaxed)
}

/// `frag_v4_transit_meta` with the source zeroed — the reachable shape.
///
/// The shim stamps `flow_src_addr` faithfully from the IP header and has no
/// unspecified filter, so a header carrying `0.0.0.0` produces exactly this: a
/// FULLY PARSED meta whose source is unspecified (#7055 leg 2).
fn frag_v4_transit_meta_unspecified_src_7890() -> UserspaceDpMeta {
    UserspaceDpMeta {
        flow_src_addr: [0u8; 16],
        ..frag_v4_transit_meta()
    }
}

/// ARM `:3593` — the flowless input-filter arm.
///
/// `from is-fragment then discard` must drop a non-first fragment whose source
/// is unspecified, exactly as it does one with a valid source. Before #7890 the
/// arm's `if let Some(l3_flow)` refused and the packet forwarded UNFILTERED.
///
/// This is the operator-verdict property, not a disposition: the fixture
/// configures `discard` and the packet is dropped BY THE FILTER. The companion
/// cell below configures a filter that does NOT discard and asserts the packet
/// forwards — together they show the verdict is being honoured rather than a
/// blanket drop substituted for it.
#[test]
fn unspecified_source_still_runs_the_is_fragment_input_filter_7890() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.interfaces[0].filter_input_v4 = "drop-frags".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "drop-frags".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "frag".to_string(),
            is_fragment: true,
            action: "discard".to_string(),
            ..Default::default()
        }],
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC);

    let before = unspecified_witness_7890();
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta_unspecified_src_7890(),
        true,
    );

    // WITNESS FIRST: prove the arm was entered with an unspecified source. If
    // this does not move, the fixture missed a conjunct and everything below is
    // vacuous.
    assert!(
        unspecified_witness_7890() > before,
        "the unspecified-source arm was never entered — the fixture does not \
         reach the site it names, so the enforcement assertion below would pass \
         proving nothing (#7890)"
    );
    assert_eq!(
        dbg.forward, 0,
        "`from is-fragment then discard` must drop a fragment whose source is \
         unspecified too. Before #7890 the session-identity resolver refused, \
         the whole enforcement block was skipped, and the packet forwarded \
         UNFILTERED — an operator-configured control silently evaded"
    );
}

/// The other half of the operator-verdict property, and the reason a
/// `then discard` fixture alone is not enough.
///
/// A cell that only configures `discard` **cannot distinguish "the filter ran
/// and discarded" from "the code now drops on `None`"** — the correct fix and
/// the wrong one produce identical output on that input. Here the configured
/// verdict is `accept`, so a drop-on-`None` repair reds this while the correct
/// one passes.
#[test]
fn unspecified_source_honours_a_non_discard_filter_verdict_7890() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.interfaces[0].filter_input_v4 = "count-frags".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "count-frags".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "frag".to_string(),
            is_fragment: true,
            action: "accept".to_string(),
            ..Default::default()
        }],
    }];
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC);

    let before = unspecified_witness_7890();
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta_unspecified_src_7890(),
        true,
    );

    assert!(
        unspecified_witness_7890() > before,
        "the arm must be entered, or this proves nothing"
    );
    assert_eq!(
        dbg.forward, 1,
        "the operator configured `then accept`, so the packet must FORWARD. A \
         repair that drops on `None` reaches the right answer only when the \
         configured verdict happens to be discard, and silently contradicts the \
         operator otherwise — this is the input that tells the two apart"
    );
}

/// Zero the IPv4 source in the FRAME as well as the meta.
///
/// The meta is what the enforcement resolvers read, but `:3422`'s association
/// lookup is keyed on `packet_frame[l3_offset..]` — the raw header — so a cell
/// for that arm has to move both or the fixture is incoherent.
fn zero_v4_src_7890(mut frame: Vec<u8>) -> Vec<u8> {
    frame[26..30].copy_from_slice(&[0, 0, 0, 0]); // l3_offset 14 + 12
    frame
}

fn set_v4_dst_7890(mut frame: Vec<u8>, dst: [u8; 4]) -> Vec<u8> {
    frame[30..34].copy_from_slice(&dst); // l3_offset 14 + 16
    frame
}

/// ARM `:3422` — the fragment-association HIT arm.
///
/// Derived class: a non-first fragment that HITS an association installed by
/// its own first fragment. #5798 established that such a hit inherits the
/// stateful permit but must still run the per-packet interface input filter.
/// #7890 asks whether that still holds when the datagram's source is
/// unspecified.
///
/// Note the fixture moves the FRAME source too: the association is keyed on the
/// raw header, so a meta-only edit would install under one key and consult
/// another, and the cell would measure a consult MISS while claiming to measure
/// a hit.
#[test]
fn unspecified_source_association_hit_still_runs_the_input_filter_7890() {
    // Returns (forward, batch.nat_frag_untranslated_dropped, witness_moved) for
    // the NON-first fragment, parameterised on the fragment term's action so the
    // cell carries #5798's own accept-control. Without that control a `discard`
    // fixture alone cannot tell "the filter ran" from "the code drops on `None`".
    let run = |frag_term_action: &str| -> (u64, u64, bool) {
        let mut snapshot = policy_deny_snapshot();
        snapshot.default_policy = "permit".to_string();
        snapshot.policies.clear();
        snapshot.neighbors = vec![frag_transit_wan_neighbor()];
        snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
            name: "snat-lan-wan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }];
        snapshot.interfaces[0].filter_input_v4 = "frag-gate".to_string();
        snapshot.filters = vec![FirewallFilterSnapshot {
            name: "frag-gate".to_string(),
            family: "inet".to_string(),
            terms: vec![
                FirewallTermSnapshot {
                    name: "allow-first".to_string(),
                    destination_ports: vec!["443".to_string()],
                    action: "accept".to_string(),
                    ..Default::default()
                },
                FirewallTermSnapshot {
                    name: "fragments".to_string(),
                    is_fragment: true,
                    action: frag_term_action.to_string(),
                    ..Default::default()
                },
            ],
        }];
        let forwarding = build_forwarding_state(&snapshot);

        let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
        binding.interface = Arc::<str>::from("reth1.0");
        let mut sessions = SessionTable::new();
        let ha_state = BTreeMap::new();
        let unspec_meta = UserspaceDpMeta {
            flow_src_addr: [0u8; 16],
            ..udp_frag_meta_5689()
        };

        // FIRST fragment: carries dport 443, terminates on the accept term, is
        // SNAT'd, and installs the association.
        let first = zero_v4_src_7890(udp_frag_frame_5689(0x2000, 0xf00d));
        let (_b1, _dbg1) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &first,
            unspec_meta,
            true,
        );
        assert_eq!(
            forwarding.nat64.frag_assoc.len(),
            1,
            "the unspecified-source first fragment must still install exactly one \
             association — without it the non-first fragment below takes the MISS \
             arm and this cell measures `:3593`, not `:3422`"
        );

        // NON-first fragment: association HIT, then the per-packet filter.
        let non_first = zero_v4_src_7890(udp_frag_frame_5689(0x0001, 0xf00d));
        let before = unspecified_witness_7890();
        let (batch, dbg2) = txn_run_descriptor_checked(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &non_first,
            unspec_meta,
            true,
        );
        (
            dbg2.forward,
            batch.nat_frag_untranslated_dropped,
            unspecified_witness_7890() > before,
        )
    };

    // Control: an accepting fragment term must still FORWARD. This is what tells
    // a real filter evaluation apart from a drop-on-`None` repair.
    let (fwd_open, miss_drop_open, seen_open) = run("accept");
    assert!(
        seen_open,
        "an unspecified address must have been SEEN on this packet's path — if \
         not, the fixture is not exercising the condition under test"
    );
    assert_eq!(
        miss_drop_open, 0,
        "control: it was an association HIT, not a #6122 fail-closed miss"
    );
    assert_eq!(
        fwd_open, 1,
        "an accepting fragment term must forward an unspecified-source \
         association hit — a repair that drops on `None` reds here"
    );

    // The guard.
    let (fwd_filtered, miss_drop_filtered, seen_filtered) = run("discard");
    assert!(
        seen_filtered,
        "an unspecified address must have been SEEN on this packet's path"
    );
    assert_eq!(
        miss_drop_filtered, 0,
        "the drop must come from the INPUT FILTER on the hit path, not the #6122 \
         fail-closed association-miss drop — otherwise the association never hit \
         and this proved nothing about `:3422`"
    );
    assert_eq!(
        fwd_filtered, 0,
        "`from is-fragment then discard` must catch an association-hit fragment \
         whose source is unspecified. Before #7890 the resolver refused, the \
         filter block was skipped, and the fragment forwarded — inheriting the \
         stateful permit while evading the per-packet control, which is exactly \
         the split #5798 was opened to close"
    );
}

/// ARM `:5052` — the flowless MissingNeighbor cold-path policy gate.
///
/// Derived class: a flowless packet whose next-hop neighbor is unresolved.
/// #4024 added the policy gate here so a `deny-all` zone pair does not fail
/// OPEN for a flowless fragment. That gate is `if let Some(l3_flow)`, so before
/// #7890 an unspecified source re-opened precisely the hole #4024 closed.
#[test]
fn unspecified_source_missing_neighbor_fragment_still_policy_denied_7890() {
    let mut snapshot = policy_deny_snapshot();
    // No neighbor for the connected WAN dst => route resolves, ARP does not =>
    // MissingNeighbor, the cold path this arm owns.
    snapshot.neighbors.clear();
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = zero_v4_src_7890(frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC));

    let before = unspecified_witness_7890();
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta_unspecified_src_7890(),
        true,
    );

    assert!(
        unspecified_witness_7890() > before,
        "an unspecified address must have been SEEN on this packet's path"
    );
    assert_eq!(
        dbg.missing_neigh, 1,
        "the fixture must actually resolve MissingNeighbor — otherwise it is \
         measuring some other arm"
    );
    assert_eq!(
        dbg.policy_deny, 1,
        "a deny-all zone pair must DROP a flowless MissingNeighbor fragment \
         whose source is unspecified. Before #7890 this was 0: the gate's \
         resolver refused and the frame fell through to the FIB reinject, \
         reopening the #4024 fail-open"
    );
    assert!(
        binding.pending_neigh.is_empty(),
        "a denied fragment must not be buffered for neighbor retry"
    );
}

/// ARM `:4684` — the flowless NoRoute policy-denial arm.
///
/// Derived class: a flowless packet whose destination resolves to NO route.
/// The arm's own comment names the reachable case as a dst-unspecified packet
/// that "dies at NoRoute"; an unspecified SOURCE reaches it by the other door —
/// a routable-looking header for which the FIB has nothing.
#[test]
fn unspecified_source_noroute_fragment_still_policy_denied_7890() {
    let snapshot = policy_deny_snapshot();
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    // 203.0.113.9 is in no route table in the fixture => NoRoute.
    let frame = set_v4_dst_7890(
        zero_v4_src_7890(frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC)),
        [203, 0, 113, 9],
    );
    let meta = UserspaceDpMeta {
        flow_dst_addr: [203, 0, 113, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ..frag_v4_transit_meta_unspecified_src_7890()
    };

    let before = unspecified_witness_7890();
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );

    assert!(
        unspecified_witness_7890() > before,
        "an unspecified address must have been SEEN on this packet's path"
    );
    assert_eq!(
        dbg.policy_deny, 1,
        "the NoRoute adjudication must DENY a flowless unspecified-source packet \
         on a default-deny box. Before #7890 this was 0: the resolver refused, \
         `adjudicated` stayed None, and the packet fell through the arm \
         UNADJUDICATED — the exact word the arm's own comment uses.\n\
         \n\
         Asserting `dbg.forward == 0` here instead does NOT bind this arm: a \
         NoRoute packet does not forward either way, so that assertion passes \
         under the reverted resolver. Measured — the site-local mutation \
         escaped the whole 5133-test suite with `forward` as the observable and \
         is caught with `policy_deny`."
    );
}

/// `forward_request.rs` — the FLOWLESS egress filter-log attribution (#5467).
///
/// This site needs its own assertion shape, and a `dbg`-counter cell cannot
/// supply it. The failure here is a MISSING LOG on a packet that forwards
/// correctly: before #7890 the resolver refused for an unspecified source,
/// `log_flow` stayed `None`, the `if let (Some, Some)` never fired, and the
/// operator's `then log` produced nothing — while the packet went out the wire
/// exactly as configured. From the packet's side an absent log and a correct
/// forward are the SAME observation, so the cell has to read the event stream.
///
/// It asserts the record EXISTS **and carries the right addresses**: existence
/// alone would still pass if the site attributed the log to some other tuple,
/// which is the #7656 defect one layer down on this very code.
///
/// **Mutation note — this cell binds the PAIR of sites, not either one.**
/// `forward_request.rs` resolves the flowless log flow as
/// `ctx.flowless_wire_flow.or_else(|| l3_enforcement_flow_from_meta(..))`, and
/// `flowless_wire_flow` is itself built by `l3_wire_session_flow_from_meta`
/// from the same resolver. Reverting EITHER site alone leaves the whole suite
/// green, including this cell — measured, both directions. Reverting BOTH reds
/// this cell and nothing else in 5135 tests.
///
/// That is not a weak fixture, and the two sites are not redundant in the
/// healthy program: instrumented across the full suite, the `.or_else` fallback
/// fires **zero** times, because `flowless_wire_flow` is always already `Some`.
/// It is the MUTATION that wakes the dormant fallback, which then repairs the
/// mutant. Worth stating plainly because the naive reading of a single-site
/// escape — "no test covers this line" — is the opposite of what is true here.
#[test]
fn unspecified_source_flowless_egress_filter_log_is_still_emitted_7890() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    // Egress `then accept` + `then log` on the WAN side: the packet MUST still
    // forward, so a drop cannot be mistaken for the property under test.
    snapshot.interfaces[1].filter_output_v4 = "log-frags".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "log-frags".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "frag".to_string(),
            is_fragment: true,
            action: "accept".to_string(),
            log: true,
            ..Default::default()
        }],
    }];
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();
    let frame = zero_v4_src_7890(frag_v4_transit_frame(crate::afxdp::tests_support::TEST_LAN_MAC));

    let before = unspecified_witness_7890();
    let (_batch, dbg, handle, rx) = txn_run_descriptor_capturing_events(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        frag_v4_transit_meta_unspecified_src_7890(),
    );

    assert!(
        unspecified_witness_7890() > before,
        "an unspecified address must have been SEEN on this packet's path"
    );
    assert_eq!(
        dbg.forward, 1,
        "the fixture must FORWARD — the defect under test is a missing log on a \
         correctly forwarded packet, so a cell whose packet drops is measuring \
         something else"
    );
    assert_eq!(
        handle.dataplane_event_stats().filter_log.sent,
        1,
        "an egress `then log` term matching a FLOWLESS unspecified-source \
         fragment must still emit its filter-log event. Before #7890 this was 0 \
         and NOTHING else about the packet changed: it forwarded exactly as \
         configured, so no packet-side observable could distinguish the two"
    );

    let event = rx
        .try_recv()
        .expect("a filter-log event frame must have been queued")
        .decode_dataplane_event()
        .expect("filter-log payload must decode");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(
        event.src_ip,
        "0.0.0.0".parse::<std::net::IpAddr>().expect("src"),
        "the record must carry the packet's ACTUAL source. Asserting only that \
         a log exists would pass on a record attributed to the wrong tuple — \
         which is the #7656 defect one layer down on this same code"
    );
    assert_eq!(
        event.dst_ip,
        "172.16.80.200".parse::<std::net::IpAddr>().expect("dst"),
        "and the packet's actual destination"
    );
}


#[test]
fn flowless_fragment_bytes_are_charged_to_no_session_9956() {
    // #9956 F-051: both packet-accounting sites are flow-gated
    // (`poll_descriptor/mod.rs`: `if let Some(flow) = flow.as_ref()` before
    // `sessions.account_packet(..)`, and `flow_cache_hit.rs`), so a
    // flowless-forwarded (non-first fragment) packet is NEVER charged to a
    // session. The SAME chokepoint still counts it globally
    // (`forward_candidate_packets`) and per zone (`record_zone_traffic`), so
    // `SESSION_CLOSE`, flow export and `show security flow session`
    // under-report a fragmented flow by its entire non-first volume while the
    // zone/global totals tell the truth — a silent gap with no counter family
    // of its own.
    //
    // This cell drives TWO fragments of one plain (no-NAT) UDP datagram
    // through the real poll path: the FIRST (flow-backed, installs the
    // session) and the NON-first (flowless, forwards). Both forward and both
    // are counted globally; the session sees only the first.
    //
    // RED on base: the session carried 1 packet / 42 bytes instead of 2 / 84
    // with the gap silent. The shipped direction is the explicit flowless
    // counter family (charging a port-less fragment to a 5-tuple session is
    // ambiguous under port reuse): session + flowless reconciles with the
    // global total here — fixture-exact, not universal (`account_packet`
    // no-ops on not-yet-existing sessions, so production can still
    // under-count the session leg on install races).
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.neighbors = vec![frag_transit_wan_neighbor()];
    // No source_nat_rules / DNAT / static-NAT / NPTv6 -> a plain (no-NAT)
    // flow, so both fragments forward untranslated.
    let forwarding = build_forwarding_state(&snapshot);

    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let ha_state = BTreeMap::new();

    // (1) FIRST fragment: MF=1, offset 0, id 0xbeef. Flow-backed: installs
    //     the session and is charged to it at the shared chokepoint.
    let first = udp_frag_frame_5689(0x2000, 0xbeef);
    let (batch1, dbg1) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &first,
        udp_frag_meta_5689(),
        true,
    );
    assert_eq!(
        dbg1.forward, 1,
        "#9956 F-051 precondition: the first fragment must forward"
    );
    let mut first_request = binding
        .scratch
        .scratch_forwards
        .pop()
        .expect("#10285: first fragment pending TX request");
    first_request
        .overlap_admissions
        .take()
        .expect("#10285: first fragment overlap admission")
        .commit();
    drop(first_request);

    // (2) NON-first fragment: offset 1, SAME id 0xbeef. Flowless (#2344):
    //     forwards with no session to charge (RED-on-revert guard for the
    //     "still forwards" half lives in
    //     `nonnat_nonfirst_fragment_assoc_miss_still_forwards_6122`).
    let non_first = udp_frag_frame_5689(0x0001, 0xbeef);
    let (batch2, dbg2) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &non_first,
        udp_frag_meta_5689(),
        true,
    );
    assert_eq!(
        dbg2.forward, 1,
        "#9956 F-051 precondition: the non-first fragment must forward"
    );

    // Control: the global chokepoint counted BOTH packets.
    assert_eq!(
        batch1.forward_candidate_packets + batch2.forward_candidate_packets,
        2,
        "#9956 F-051 control: both fragments must be counted globally, so a \
         session total below 2 is a session-accounting gap rather than a \
         forwarding gap"
    );

    // THE FIX (#9956 F-051): the session still carries only the first
    // fragment — charging a port-less fragment to a 5-tuple session would be
    // ambiguous under port reuse — but the non-first volume is now VISIBLE in
    // the dedicated flowless family instead of silent. Frame lengths are the
    // byte basis (no forward-bytes counter exists; `rx_bytes` is
    // receive-side); in production session + flowless reconciles against the
    // zone-pair delta.
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        src_ip: "10.0.61.100".parse().expect("src"),
        dst_ip: "172.16.80.200".parse().expect("dst"),
        src_port: 33333,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let c = sessions
        .session_counters(&key)
        .expect("#9956 F-051 precondition: the first fragment must have installed the session");
    assert_eq!(
        (c.fwd_packets, c.fwd_bytes),
        (1, first.len() as u64),
        "#9956 F-051: the session carries exactly the flow-backed first \
         fragment (RED form asserted 2 here: the gap this family closes)"
    );
    let flowless_packets = batch1.flowless_forward_packets + batch2.flowless_forward_packets;
    let flowless_bytes = batch1.flowless_forward_bytes + batch2.flowless_forward_bytes;
    assert_eq!(
        (flowless_packets, flowless_bytes),
        (1, non_first.len() as u64),
        "#9956 F-051: the flowless family must carry exactly the non-first \
         fragment's volume"
    );
    assert_eq!(
        c.fwd_packets + flowless_packets,
        batch1.forward_candidate_packets + batch2.forward_candidate_packets,
        "#9956 F-051: session + flowless must reconcile with the global total"
    );
    assert_eq!(
        c.fwd_bytes + flowless_bytes,
        (first.len() + non_first.len()) as u64,
        "#9956 F-051: session + flowless bytes must match the forwarded volume"
    );
    assert_eq!(
        forwarding.nat64.frag_overlap.len(),
        1,
        "#10285: queued non-first request retains the overlap entry until \
         TX acceptance"
    );
    for mut request in binding.scratch.scratch_forwards.drain(..) {
        if let Some(mut admissions) = request.overlap_admissions.take() {
            admissions.commit();
        }
    }
    assert_eq!(
        forwarding.nat64.frag_overlap.len(),
        0,
        "#10285: queued first+last requests settle their overlap admissions \
         only after explicit TX acceptance"
    );
}
