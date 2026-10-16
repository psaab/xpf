//! #12906: the `NoRoute` policy adjudication cells.
//!
//! The defect (issue #12906): the `NoRoute` arm judged the zone-pair /
//! `junos-global` policy against the PRE-NAT wire destination and the RAW
//! fabric zone stamp, unlike every sibling policy site — the
//! ForwardCandidate session-miss gate and the #5174/#10267 MissingNeighbor
//! arm match the #2345 POST-translation destination tuple, and both apply
//! the #6458 V2 owner-RG gate to a zone-encoded fabric stamp. Consequences
//! on a default-permit box: a deny written for the translated (real)
//! destination missed, so the untranslated frame was delegated to the
//! kernel FIB with no zone policy (#2345 bypass); a deny written for the
//! wire (public/VIP) tuple matched and cached the WRONG rule's denial id.
//!
//! These cells pin `noroute_policy_adjudication`, extracted from the arm.
//! #13769 also adds end-to-end cells below that drive a descriptor through
//! `poll_binding_process_descriptor` itself, so the arm's wiring — notably
//! the #13645 effective-protocol argument — is held behaviourally, not by
//! feeding the selector and adjudicator by hand.

use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::{nat_snapshot, nat_snapshot_with_fabric};
use crate::policy::PolicyAction;
use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
use std::collections::BTreeMap;

/// Wire (pre-translation) tuple: a LAN client hitting the public VIP
/// `203.0.113.9:443`. The VIP DNATs to the real server
/// `198.18.0.50:8443` (`vip_dnat_12906`).
fn wire_flow() -> SessionFlow {
    let src = "10.0.61.100".parse::<IpAddr>().expect("src");
    let dst = "203.0.113.9".parse::<IpAddr>().expect("dst");
    SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: src,
            dst_ip: dst,
            src_port: 40000,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

/// Wire tuple of a NAT64 flow: the same LAN client hitting the synthetic
/// `64:ff9b::198.18.2.9` (Pref64 `64:ff9b::/96` embedding the real IPv4
/// host `198.18.2.9`).
fn nat64_wire_flow() -> SessionFlow {
    let src = "2001:db8:61::100".parse::<IpAddr>().expect("src");
    let dst = "64:ff9b::198.18.2.9".parse::<IpAddr>().expect("dst");
    SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: 6,
            src_ip: src,
            dst_ip: dst,
            src_port: 40000,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

/// The inbound destination translation the session-miss block records on
/// the decision (`nptv6_nat.or(pre_routing_dnat)`): VIP 203.0.113.9:443 →
/// real server 198.18.0.50:8443.
fn vip_dnat_12906() -> crate::nat::NatDecision {
    crate::nat::NatDecision {
        rewrite_dst: Some("198.18.0.50".parse::<IpAddr>().expect("translated dst")),
        rewrite_dst_port: Some(8443),
        ..Default::default()
    }
}

/// A NoRoute resolution that RETAINS its logical egress identity — the
/// tunnel shape (#7480: "a tunnel can retain its logical ifindex when its
/// outer lookup has no route"). Egress 12 is reth0.80: zone `wan`,
/// redundancy group 1.
fn no_route_retaining_wan_egress() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}

/// A base NoRoute resolution: no egress identity at all (`egress_ifindex:
/// 0`), so the to-zone is the #3110 unzoned sentinel and only the default
/// policy decides.
fn base_no_route() -> ForwardingResolution {
    ForwardingResolution {
        egress_ifindex: 0,
        tx_ifindex: 0,
        ..no_route_retaining_wan_egress()
    }
}

fn active_rg1(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        },
    )])
}

/// Default-PERMIT box whose only rule denies the TRANSLATED server tuple
/// `198.18.0.50` lan→wan. Every cell's verdict is therefore attributable
/// to the tuple the gate judged, never to a default deny.
fn translated_deny_snapshot_12906() -> crate::ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.default_policy = "permit".to_string();
    snap.policies = vec![crate::PolicyRuleSnapshot {
        name: "deny-translated-server".to_string(),
        policy_id: 4242,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["198.18.0.50/32".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    }];
    snap
}

/// Default-permit box whose only rule denies the WIRE (public VIP) tuple
/// `203.0.113.9` lan→wan — the shape an operator's PRE-#2345 deny was
/// written against.
fn wire_deny_snapshot_12906() -> crate::ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.default_policy = "permit".to_string();
    snap.policies = vec![crate::PolicyRuleSnapshot {
        name: "deny-public-vip".to_string(),
        policy_id: 5150,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["203.0.113.9/32".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    }];
    snap
}

/// THE SECURITY CELL. A DNAT'd flow whose translated destination has no
/// route must be denied by the deny written for the TRANSLATED tuple, with
/// that rule's id as the cached denial — the same verdict (and the same
/// rule) the ForwardCandidate path renders for the resolved flow.
///
/// FAIL-ON-REVERT: judge `policy_dst_ip` on `adj_flow.dst_ip` (the pre-NAT
/// wire destination, the pre-#12906 arm) and this reds — the wire VIP
/// misses the rule, the default permits, and the untranslated frame is
/// delegated to the kernel FIB (the #2345 bypass).
#[test]
fn translated_dnat_deny_is_judged_post_translation_12906() {
    let state = build_forwarding_state(&translated_deny_snapshot_12906());
    let now_ns = crate::afxdp::monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let flow = wire_flow();

    let adj = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        24, // reth1.0 — logical ingress in `lan`
        None,
        no_route_retaining_wan_egress(),
        vip_dnat_12906(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );

    let result = adj.denial.expect(
        "the deny written for the TRANSLATED server (198.18.0.50) must fire on a \
         DNAT'd NoRoute flow — judging the wire VIP is the #2345 bypass",
    );
    assert_eq!(result.action, PolicyAction::Deny);
    assert_eq!(
        result.policy_id, 4242,
        "the cached denial id must be the translated-dst rule's, so the flow-cache \
         deny seed attributes the drop to the rule the operator wrote (#2345)"
    );
    assert_eq!(
        adj.ports,
        Some((40000, 8443)),
        "the ports view (deny event app-id, port-bearing terms) must carry the \
         TRANSLATED destination port"
    );
    assert_eq!(adj.from_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(adj.to_zone_id, TEST_WAN_ZONE_ID);

    // Refutation half (the cell proves nothing without it): the SAME frame
    // with NO translation applied misses the translated-dst rule and the
    // default permits — the deny above is the translation's, not incidental.
    let untranslated = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        24,
        None,
        no_route_retaining_wan_egress(),
        crate::nat::NatDecision::default(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert!(
        untranslated.denial.is_none(),
        "fixture premise: an untranslated flow to the wire VIP delegates under the \
         default permit, so the security cell's deny is tuple-dependent"
    );
}

/// The mis-attribution cell. A deny written for the WIRE (public VIP)
/// tuple — the pre-#2345 authoring style — must NOT be matched or cached
/// for a DNAT'd flow: #2345 moved the match to the translated tuple, so
/// firing the wire rule here cached a DIFFERENT rule's denial id than the
/// resolved path would ever render.
///
/// FAIL-ON-REVERT: judge `policy_dst_ip` on the wire destination and the
/// first assertion reds (the wire rule fires on the DNAT'd flow).
#[test]
fn wire_tuple_deny_is_not_cached_for_a_translated_flow_12906() {
    let state = build_forwarding_state(&wire_deny_snapshot_12906());
    let now_ns = crate::afxdp::monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let flow = wire_flow();

    let adj = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        24,
        None,
        no_route_retaining_wan_egress(),
        vip_dnat_12906(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert!(
        adj.denial.is_none(),
        "a DNAT'd flow must not match the deny written for its PRE-translation \
         VIP — that cached the wrong rule's denial id and shadowed the \
         translated-tuple policy the operator actually wrote"
    );

    // Sanity: the same rule DOES fire when no translation applies — the
    // untranslated flow IS the wire tuple.
    let untranslated = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        24,
        None,
        no_route_retaining_wan_egress(),
        crate::nat::NatDecision::default(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert_eq!(
        untranslated.denial.expect("wire-tuple rule fires untranslated").policy_id,
        5150
    );
}

/// The owner-RG cell (#6458 V2, the binding the MissingNeighbor arm already
/// applies). A zone-encoded fabric stamp drives the NoRoute from-zone only
/// when the retained egress's owner RG is forwarding-active locally; a base
/// NoRoute has no owner, so its stamp never survives the gate.
///
/// FAIL-ON-REVERT: pass the RAW stamp to the zone-pair computation (the
/// pre-#12906 arm) and the inactive-RG and base-NoRoute assertions red —
/// the stamp drives the zone pair anyway.
#[test]
fn fabric_stamp_is_bound_to_the_owner_rg_12906() {
    let mut snap = nat_snapshot_with_fabric();
    snap.default_policy = "permit".to_string();
    snap.policies = translated_deny_snapshot_12906().policies;
    let state = build_forwarding_state(&snap);
    let now_ns = crate::afxdp::monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let flow = wire_flow();

    // (a) Owner RG 1 (reth0.80) NOT forwarding-active locally: the stamp is
    // ignored and the fabric interface's own zone (none → #3110 sentinel 0)
    // governs, so no zone pair exists. The #6682/#11067 unzoned-ingress
    // gate then denies FAIL-CLOSED (unattributed) instead of reaching the
    // default permit — and crucially NOT via the stamped pair's rule.
    let inactive = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        21, // fabric parent ge-0/0/0 — carries no zone
        Some(TEST_LAN_ZONE_ID),
        no_route_retaining_wan_egress(),
        vip_dnat_12906(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert_eq!(inactive.gated_ingress_zone_override, None);
    assert_eq!(
        inactive.from_zone_id, 0,
        "an ungated stamp must not drive the from-zone when the owner RG is not \
         forwarding-active locally (#6458 V2)"
    );
    let inactive_result = inactive
        .denial
        .expect("an ungated stamp must not buy the flow a zone pair: the \
                 #6682/#11067 unzoned-ingress gate denies fail-closed");
    assert_ne!(
        inactive_result.policy_id, 4242,
        "the deny must not attribute to the stamped lan→wan pair's rule"
    );
    assert_eq!(
        inactive_result.policy_id,
        crate::policy::UNATTRIBUTED_POLICY_ID
    );

    // (b) Owner RG 1 locally active: the legitimate punt keeps its stamp,
    // and the stamped zone pair + translated tuple deny exactly as the
    // session-miss gate renders the same flow.
    let active = noroute_policy_adjudication(
        &state,
        &active_rg1(now_secs),
        now_secs,
        21,
        Some(TEST_LAN_ZONE_ID),
        no_route_retaining_wan_egress(),
        vip_dnat_12906(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert_eq!(active.gated_ingress_zone_override, Some(TEST_LAN_ZONE_ID));
    assert_eq!(active.from_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(
        active.denial.expect("legitimate punt denies on the stamped pair").policy_id,
        4242
    );

    // (c) A BASE NoRoute has no egress identity, so its owner RG is unknown
    // (0) and the stamp never survives the gate — even with RG 1 active.
    // Its unzoned fabric ingress keeps the fail-closed #6682 deny, while a
    // ZONED ingress keeps the #7480 availability contract: the interface's
    // own zone forms the from-zone and the unresolved egress keeps the
    // default-policy decision.
    let base = noroute_policy_adjudication(
        &state,
        &active_rg1(now_secs),
        now_secs,
        21,
        Some(TEST_LAN_ZONE_ID),
        base_no_route(),
        vip_dnat_12906(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert_eq!(base.gated_ingress_zone_override, None);
    assert_eq!(base.to_zone_id, 0);
    assert_eq!(
        base.denial
            .expect("an unzoned fabric ingress denies fail-closed (#6682)")
            .policy_id,
        crate::policy::UNATTRIBUTED_POLICY_ID
    );
    let zoned_base = noroute_policy_adjudication(
        &state,
        &active_rg1(now_secs),
        now_secs,
        24, // reth1.0 — a zoned ingress, the ordinary #7480 shape
        None,
        base_no_route(),
        vip_dnat_12906(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert_eq!(zoned_base.from_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(zoned_base.to_zone_id, 0);
    assert!(
        zoned_base.denial.is_none(),
        "a zero-identity NoRoute on a zoned ingress keeps its default-policy \
         decision (#7480 availability cell)"
    );
}

/// The NAT64 cell (#2358 cross-family parity with the ForwardCandidate and
/// MissingNeighbor paths). A NoRoute NAT64 flow arrives with a DEFAULT
/// `decision.nat` (the NAT64 forward decision is minted only in the
/// ForwardCandidate Permit branch), so the post-translation destination is
/// recovered by the dest-only re-classify and the policy matches the
/// (V6 src, V4 dst) mixed tuple written for the real IPv4 host.
///
/// FAIL-ON-REVERT: drop the re-classify (judge the synthetic IPv6
/// destination, the pre-#12906 arm) and the first assertion reds — an
/// IPv4 destination set cannot match the synthetic v6 address.
#[test]
fn nat64_flow_is_judged_on_the_extracted_ipv4_destination_12906() {
    let mut snap = translated_deny_snapshot_12906();
    snap.policies = vec![crate::PolicyRuleSnapshot {
        name: "deny-nat64-host".to_string(),
        policy_id: 6464,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        // A legacy address set with NO v6 literal is v6-match-any (the
        // legacy `from_prefixes` empty→MatchAny rule), which would let the
        // refutation half below match the SYNTHETIC v6 destination too. Pin
        // an unreachable v6 literal so the v6 side matches nothing and only
        // the extracted IPv4 can hit this rule.
        destination_addresses: vec![
            "198.18.2.9/32".to_string(),
            "2001:db8:dead::/64".to_string(),
        ],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    }];
    snap.nat64_rules = vec![crate::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snap);
    let now_ns = crate::afxdp::monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let flow = nat64_wire_flow();

    let adj = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        24,
        None,
        no_route_retaining_wan_egress(),
        crate::nat::NatDecision::default(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert_eq!(
        adj.denial
            .expect("the (V6 src, V4 dst) mixed tuple must match the deny written \
                    for the real IPv4 host (#2358)")
            .policy_id,
        6464
    );

    // Refutation half: the same synthetic destination on a box with NO
    // NAT64 prefix is ordinary IPv6 — the wire view adjudicates and the
    // default permits.
    let mut no_prefix = translated_deny_snapshot_12906();
    no_prefix.policies = snap.policies.clone();
    let plain = build_forwarding_state(&no_prefix);
    let adj_plain = noroute_policy_adjudication(
        &plain,
        &BTreeMap::new(),
        now_secs,
        24,
        None,
        no_route_retaining_wan_egress(),
        crate::nat::NatDecision::default(),
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert!(
        adj_plain.denial.is_none(),
        "fixture premise: without the Pref64 the synthetic v6 destination is the \
         wire tuple and misses the IPv4 rule"
    );
}

/// The flowless-parity cell (#7480/#3291). A flowless NoRoute packet keeps
/// `ports = None` through the new adjudication so port-bearing terms fail
/// closed, while its L3 identity still adjudicates on the post-translation
/// address view.
#[test]
fn flowless_ports_stay_fail_closed_through_the_adjudication_12906() {
    let state = build_forwarding_state(&wire_deny_snapshot_12906());
    let now_ns = crate::afxdp::monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let flow = wire_flow();

    let adj = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        24,
        None,
        no_route_retaining_wan_egress(),
        crate::nat::NatDecision::default(),
        false,
        &flow,
        6,
        false,
        None,
        64,
        now_ns,
    );
    assert_eq!(
        adj.ports, None,
        "a flowless packet must keep ports None so port-bearing terms fail closed"
    );
    assert_eq!(
        adj.denial.expect("the L3 wire tuple still denies an address-only rule")
            .policy_id,
        5150
    );
}

// #13645 (D4-10): the NoRoute arm passes the frame-derived effective
// protocol, not raw `meta.protocol`. The arm itself needs a live binding,
// so this pins the wiring the same way the #11338 PBR cells pin theirs:
// flowless_effective_protocol(frame, meta) under the AH and fragment
// shapes, then the pure adjudication must deny on an effective-protocol
// term. Pre-fix the arm passed meta.protocol (inner TCP stamped 6, or
// sentinel 255), so an `ah`/`udp`-only deny never fired and the frame
// was delegated to the kernel FIB.
fn ah_deny_snapshot_13645() -> crate::ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.default_policy = "permit".to_string();
    snap.policies = vec![crate::PolicyRuleSnapshot {
        name: "deny-ah".to_string(),
        policy_id: 6464,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["ah".to_string()],
        application_terms: vec![crate::PolicyApplicationSnapshot {
            name: "ah".to_string(),
            protocol: "ah".to_string(),
            ..Default::default()
        }],
        action: "deny".to_string(),
        ..Default::default()
    }];
    snap
}

/// Minimal v6+AH+TCP frame (as v6_ah_tcp_frame_10729): eth(14) +
/// IPv6(40, nexthdr=51) + AH(12: next=6) with real src/dst so the
/// frame-derived identity matches the lan->wan pair.
fn v6_ah_frame_13645() -> Vec<u8> {
    let mut frame = vec![0u8; 14 + 40 + 12 + 20];
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    frame[14] = 0x60;
    frame[14 + 4..14 + 6].copy_from_slice(&((12u16 + 20u16).to_be_bytes()));
    frame[14 + 6] = 51;
    frame[14 + 7] = 64;
    frame[14 + 8..14 + 24].copy_from_slice(
        &"2001:db8:61::100"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame[14 + 24..14 + 40].copy_from_slice(
        &"2001:db8:82::50"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame[14 + 40] = 6;
    frame[14 + 41] = 1;
    frame
}

fn v6_flow_13645(src: &str, dst: &str) -> SessionFlow {
    let src_ip = src.parse::<IpAddr>().expect("src");
    let dst_ip = dst.parse::<IpAddr>().expect("dst");
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: 51,
            src_ip,
            dst_ip,
            src_port: 40000,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

#[test]
fn noroute_uses_flowless_effective_protocol_not_raw_meta_13645() {
    // (a) AH shape: raw stamped protocol is the inner TCP (6); the
    // frame-derived effective protocol is AH (51). The NoRoute arm must
    // adjudicate on 51 so an `ah` deny fires exactly as on the
    // ForwardCandidate / MissingNeighbor flowless twins (mod.rs flowless
    // arms pass flowless_effective_protocol).
    let ah_frame = v6_ah_frame_13645();
    let ah_meta = crate::afxdp::types::UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        l3_offset: 14,
        l4_offset: 14 + 40 + 12,
        ..crate::afxdp::types::UserspaceDpMeta::default()
    };
    let eff_ah = noroute_policy_protocol(&ah_frame, ah_meta, false);
    assert_eq!(
        eff_ah,
        crate::ip_proto::PROTO_AH,
        "v6+AH must evaluate as proto 51, not the stamped inner protocol"
    );
    assert_eq!(
        noroute_policy_protocol(&ah_frame, ah_meta, true),
        ah_meta.protocol,
        "flow-backed adjudication must retain its established protocol identity"
    );

    // (b) Native non-first fragment shape: raw stamped protocol is the
    // no-L4 sentinel (255); the effective protocol is the Fragment
    // header's Next Header (UDP, as pinned by the #11338 cell).
    let mut frag_frame = crate::afxdp::tests_support::eth_ipv6_frag_frame(0x0001, &[0; 8]);
    frag_frame[54] = crate::ip_proto::PROTO_UDP;
    let frag_meta = crate::afxdp::types::UserspaceDpMeta {
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::session::SHIM_PROTO_FRAGMENT_NO_L4,
        l3_offset: 14,
        l4_offset: 62,
        ..crate::afxdp::types::UserspaceDpMeta::default()
    };
    let eff_frag = noroute_policy_protocol(&frag_frame, frag_meta, false);
    assert_eq!(
        eff_frag,
        crate::ip_proto::PROTO_UDP,
        "a non-first fragment must evaluate as its Fragment.Next Header, not the sentinel"
    );

    // The verdict half under the effective identity: an `ah`-only
    // protocol deny on a default-permit box fires when the adjudication
    // is fed the EFFECTIVE protocol. Fed the raw stamp (6) it would miss
    // and delegate — that raw feed is exactly what the #13645 arm fix
    // removes. The pure protocol selector is called by the actual NoRoute
    // arm and pinned above for both shim mismatch classes.
    let state = build_forwarding_state(&ah_deny_snapshot_13645());
    let now_ns = crate::afxdp::monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let flow = v6_flow_13645("2001:db8:61::100", "2001:db8:82::50");
    let adj = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        24,
        None,
        no_route_retaining_wan_egress(),
        crate::nat::NatDecision::default(),
        false,
        &flow,
        eff_ah,
        false,
        None,
        86,
        now_ns,
    );
    assert_eq!(
        adj.denial
            .expect("the AH deny must fire for a v6+AH NoRoute frame under the effective proto")
            .policy_id,
        6464
    );
    // Refutation half: the RAW stamp (6) misses the ah term and the
    // default permits — proving the verdict is protocol-identity
    // dependent, i.e. passing raw meta.protocol is a real bypass.
    let raw = noroute_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        24,
        None,
        no_route_retaining_wan_egress(),
        crate::nat::NatDecision::default(),
        false,
        &flow,
        6,
        false,
        None,
        86,
        now_ns,
    );
    assert!(
        raw.denial.is_none(),
        "fixture premise: the raw inner-TCP stamp misses the ah deny, so the \
         effective-protocol feed is load-bearing"
    );
}

/// #13769: drive the real descriptor through the NoRoute arm. The IPv6
/// inner route selects a GRE logical egress; its deliberately unreachable
/// outer endpoint makes the production resolver retain that egress with a
/// NoRoute disposition. An AH-only deny must fire on the frame-derived
/// protocol 51, not the shim's inner-TCP stamp 6.
#[test]
fn noroute_descriptor_uses_effective_protocol_for_ah_deny_13769() {
    let mut snapshot = crate::afxdp::test_fixtures::native_gre_snapshot(false);
    snapshot.zones.push(crate::ZoneSnapshot {
        name: "lan".to_string(),
        id: TEST_LAN_ZONE_ID,
        ..Default::default()
    });
    let (sfmix_domain, _) = crate::session::install_table_identity("sfmix");
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "reth1.0".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 24,
        routing_domain: sfmix_domain,
        ..Default::default()
    });
    snapshot.policies = ah_deny_snapshot_13645().policies;
    snapshot.policies[0].from_zone = "any".to_string();
    snapshot.policies[0].to_zone = "any".to_string();
    snapshot.routes.push(crate::RouteSnapshot {
        table: "sfmix.inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "::/0".to_string(),
        next_hop_weights: vec![],
        next_hops: vec!["@gr-0/0/0.0".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
        rule_priority: 0,
        mtu: 0,
    });
    snapshot.tunnel_endpoints[0].destination = "2001:db8:dead::7".to_string();
    let forwarding = build_forwarding_state(&snapshot);

    let mut frame = vec![0u8; 14 + 40 + 12 + 20];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    frame[14] = 0x60;
    frame[14 + 4..14 + 6].copy_from_slice(&32u16.to_be_bytes());
    frame[14 + 6] = crate::ip_proto::PROTO_AH;
    frame[14 + 7] = 64;
    frame[14 + 8..14 + 24].copy_from_slice(
        &"2001:db8:61::100"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame[14 + 24..14 + 40].copy_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame[14 + 40] = crate::ip_proto::PROTO_TCP;
    frame[14 + 41] = 1;

    let mut meta = crate::afxdp::tests_support::txn_meta_v6(24, frame.len());
    meta.l4_offset = 14 + 40 + 12;
    meta.flow_src_addr = "2001:db8:61::100".parse::<std::net::Ipv6Addr>().unwrap().octets();
    meta.flow_dst_addr = "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets();
    assert_eq!(
        crate::afxdp::frame::parse_session_flow_from_bytes(&frame, meta),
        None,
        "AH must enter NoRoute adjudication as flowless"
    );
    let route = crate::afxdp::forwarding::lookup_forwarding_resolution_inner(
        &forwarding,
        None,
        "2001:db8::2".parse().expect("destination"),
        Some("sfmix.inet6.0"),
    )
    .resolution;
    assert_eq!(route.disposition, ForwardingDisposition::NoRoute);
    assert_eq!(route.egress_ifindex, 362);
    assert_eq!(
        forwarding.egress_zone_id(route.egress_ifindex),
        crate::test_zone_ids::TEST_SFMIX_ZONE_ID
    );
    let mut binding = crate::afxdp::worker::BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = std::sync::Arc::<str>::from("reth1.0");
    let mut sessions = crate::session::SessionTable::new();
    let (_batch, dbg) = crate::afxdp::tests_support::txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        &forwarding,
        &BTreeMap::new(),
        &frame,
        meta,
        true,
    );

    assert_eq!(dbg.rx, 1, "the descriptor must reach the production poll body");
    assert_eq!(dbg.no_route, 1, "the dead GRE underlay must take the NoRoute arm");
    assert_eq!(
        dbg.policy_deny, 1,
        "the AH-only deny must be applied inside NoRoute adjudication; reverting \
         the callsite to meta.protocol=TCP lets the default permit delegate it"
    );
    assert_eq!(dbg.forward, 0);
    assert_eq!(
        forwarding
            .policy
            .rule_for_policy_id(6464)
            .expect("AH deny rule")
            .hit_counter
            .test_packet_count(),
        1,
        "the configured AH rule itself must adjudicate the descriptor"
    );
}
