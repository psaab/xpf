// policy evaluation against DNAT/NPTv6/NAT64-translated destinations (incl. missing-neighbor).
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

/// DNAT: a policy that permits ONLY the translated internal destination
/// (10.0.61.102) MUST permit + forward the inbound packet whose original
/// destination is the public VIP (172.16.80.8). Proves the policy match
/// ran on the post-DNAT address.
#[test]
fn policy_inbound_dnat_matches_translated_destination_permit() {
    let snapshot = inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.102/32", "permit-internal"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    // Inbound: external client -> public VIP:443 on the wan interface.
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54321,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "policy on the translated internal dst must NOT deny the DNAT'd flow"
    );
    assert_eq!(
        dbg.tx, 1,
        "DNAT'd flow permitted by a policy on the translated dst must forward"
    );
    // forward + reverse install: session reversal is preserved.
    assert_eq!(
        sessions.len(),
        2,
        "forward + reverse session install (return-path reversal preserved)"
    );
}


/// DNAT fail-on-revert: a policy that permits ONLY the original public VIP
/// (172.16.80.8) — and does NOT cover the internal host — MUST deny the
/// inbound packet, because the match runs on the post-DNAT internal dst.
/// If the lookup reverted to the pre-DNAT tuple this would wrongly permit.
#[test]
fn policy_inbound_dnat_denies_when_only_original_dst_permitted() {
    let snapshot = inbound_dnat_snapshot(wan_to_lan_permit("172.16.80.8/32", "permit-public-vip"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54322,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.tx, 0,
        "a policy covering only the public VIP must NOT forward the DNAT'd flow"
    );
    assert!(
        dbg.policy_deny >= 1,
        "match on the post-DNAT internal dst (uncovered) must deny"
    );
    assert_eq!(sessions.len(), 0, "denied flow installs no session");
}


/// DNAT port: a policy that permits the translated dst at the translated
/// PORT (8443) but with the wrong port (443) for the same address would
/// not match. Permitting tcp/8443 to 10.0.61.102 forwards; this pins the
/// translated dst PORT (not just the address) into the policy match.
#[test]
fn policy_inbound_dnat_matches_translated_destination_port() {
    let mut permit = wan_to_lan_permit("10.0.61.102/32", "permit-internal-8443");
    // Restrict the application to tcp/8443 (the translated port). The
    // original packet is tcp/443; only a match on the post-DNAT port 8443
    // can permit it.
    permit.applications = vec!["app-8443".to_string()];
    permit.application_terms = vec![crate::protocol::PolicyApplicationSnapshot {
        name: "app-8443".to_string(),
        protocol: "tcp".to_string(),
        source_port: String::new(),
        destination_port: "8443".to_string(),
        icmp_type: None,
        icmp_code: None,
        inactivity_timeout: None,
    }];
    let snapshot = inbound_dnat_snapshot(permit);
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54323,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "policy on tcp/8443 (translated port) must permit the DNAT'd flow"
    );
    assert_eq!(dbg.tx, 1, "match on the translated dst port must forward");
}


/// NPTv6: a policy permitting ONLY the INTERNAL prefix must permit + forward
/// an inbound packet addressed to the EXTERNAL prefix. Proves the match
/// runs on the post-NPTv6 (internal) destination.
#[test]
fn policy_inbound_nptv6_matches_translated_destination_permit() {
    let snapshot = inbound_nptv6_snapshot(wan_to_lan_permit(
        "fd35:1940:27::/48",
        "permit-internal-prefix",
    ));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:80::200".parse().expect("ext client");
    // External-prefix destination; NPTv6 maps it to fd35:1940:27:100::102.
    let dst: Ipv6Addr = "2602:fd41:70:100::102".parse().expect("ext dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 54321, 443);
    let meta = txn_meta_v6(12, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "policy on the internal prefix must NOT deny the NPTv6-translated flow"
    );
    assert_eq!(
        dbg.tx, 1,
        "NPTv6 flow permitted by a policy on the internal prefix must forward"
    );
    assert_eq!(sessions.len(), 2, "forward + reverse install");
}


/// NPTv6 fail-on-revert: a policy permitting ONLY the EXTERNAL prefix (and
/// NOT the internal one) must DENY the inbound packet, because the match
/// runs on the post-NPTv6 internal destination.
#[test]
fn policy_inbound_nptv6_denies_when_only_external_prefix_permitted() {
    let snapshot = inbound_nptv6_snapshot(wan_to_lan_permit(
        "2602:fd41:70::/48",
        "permit-external-prefix",
    ));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:80::200".parse().expect("ext client");
    let dst: Ipv6Addr = "2602:fd41:70:100::102".parse().expect("ext dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 54322, 443);
    let meta = txn_meta_v6(12, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.tx, 0,
        "a policy covering only the external prefix must NOT forward the NPTv6 flow"
    );
    assert!(
        dbg.policy_deny >= 1,
        "match on the post-NPTv6 internal dst (uncovered) must deny"
    );
    assert_eq!(sessions.len(), 0);
}


/// NAT64 (#2358): the inbound policy is evaluated on the EXTRACTED real IPv4
/// destination (8.8.8.8, decoded from the synthetic `64:ff9b::808:808` dst),
/// NOT the synthetic IPv6 dst. On the ForwardCandidate path `policy_dst_ip`
/// = `effective_resolution_target` = the extracted IPv4, and
/// `policy.rs::try_match_rule` matches it via the cross-family (V6 src, V4
/// dst) arm. This test permits on the whole `64:ff9b::/96` prefix and still
/// forwards the flow — but only because a v6-only destination set (no v4
/// prefix) compiles to IPv4-match-any under the legacy address-set
/// convention, so the rule matches the extracted v4 dst on the match-any
/// path (a whole-prefix NAT64 rule, NOT a synthetic-IPv6 match). The
/// `synthetic_v6` in the test name is a pre-#2358 misnomer.
#[test]
fn policy_inbound_nat64_matches_synthetic_v6_destination_permit() {
    let snapshot = nat64_snapshot(lan_to_wan_permit("64:ff9b::/96", "permit-synthetic-v6"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("v6 client");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = txn_meta_v6(24, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.policy_deny, 0,
        "policy on the synthetic IPv6 prefix must NOT deny the NAT64 flow"
    );
    assert_eq!(
        dbg.tx, 1,
        "NAT64 flow permitted by a policy on the synthetic IPv6 dst must forward"
    );
    assert_eq!(sessions.len(), 2, "NAT64 forward + reverse install");
}


/// NAT64 fail-on-revert (#2358): an explicit DENY whose destination is the
/// whole `64:ff9b::/96` NAT64 prefix must DROP the flow; a trailing
/// permit-any is the only other rule, so the deny is the ONLY thing that can
/// drop it. On the ForwardCandidate path the inbound policy is evaluated on
/// the EXTRACTED IPv4 destination, and the v6-only `64:ff9b::/96` destination
/// set compiles to IPv4-match-any (legacy convention), so the cross-family
/// (V6 src, V4 dst) arm matches the extracted v4 dst and the deny wins over
/// the trailing permit-any. If the post-translation match tuple regressed,
/// the verdict would change and this test would fail.
#[test]
fn policy_inbound_nat64_denies_on_synthetic_v6_deny_rule() {
    let mut deny = lan_to_wan_permit("64:ff9b::/96", "deny-synthetic-v6");
    deny.action = "deny".to_string();
    let mut snapshot = nat64_snapshot(deny);
    // A trailing permit-any so the ONLY thing that can drop this flow is the
    // synthetic-V6 deny rule matching first — not the default policy.
    snapshot
        .policies
        .push(lan_to_wan_permit("any", "permit-rest"));
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("v6 client");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12346, 443);
    let meta = txn_meta_v6(24, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(
        dbg.tx, 0,
        "an explicit deny on the synthetic IPv6 dst must drop the NAT64 flow"
    );
    assert!(
        dbg.policy_deny >= 1,
        "the synthetic-V6 deny rule must match the NAT64 flow"
    );
    assert_eq!(sessions.len(), 0);
}


/// Session reversal is preserved by the #2345 policy-tuple change. The
/// policy-match tuple change touches ONLY the policy lookup, NOT the
/// installed session keys: a DNAT forward still keys the reverse session
/// off the PUBLIC-facing wire tuple (the public VIP as the reply source),
/// so return traffic from the internal host (rewritten back to the VIP on
/// egress) reverses correctly. This pins that the reverse key is built
/// from the public dst, independent of the policy-match address.
#[test]
fn inbound_dnat_reverse_session_key_uses_public_facing_tuple() {
    // Forward: external client 198.51.100.10:54321 -> public VIP
    // 172.16.80.8:443, DNAT'd to internal 10.0.61.102:8443.
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        src_port: 54321,
        dst_port: 443,
    };
    let dnat = NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        rewrite_dst_port: Some(8443),
        ..NatDecision::default()
    };
    let reverse = reverse_session_key(&forward_key, dnat);
    // The reply from the internal host arrives as 10.0.61.102:8443 ->
    // 198.51.100.10:54321; the reverse session key must match exactly that
    // wire 5-tuple so the return packet reverses (dst rewritten back to the
    // public VIP on egress). This is unchanged by the policy-tuple fix.
    assert_eq!(
        reverse.src_ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        "reverse src = internal host (post-DNAT dst), reply wire source"
    );
    assert_eq!(reverse.src_port, 8443, "reverse src port = translated dst port");
    assert_eq!(
        reverse.dst_ip,
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        "reverse dst = original external client"
    );
    assert_eq!(reverse.dst_port, 54321, "reverse dst port = original src port");
}

/// #6473 fail-on-revert: static NAT takes precedence over a destination-NAT
/// pool rule covering the SAME external address (Junos first-packet order:
/// static NAT → destination NAT — "static NAT rules take precedence over
/// destination NAT rules"). The packet below matches BOTH:
///   - static rule `web-static`: 172.16.80.8 ↔ 10.0.61.50 (plain 1:1)
///   - DNAT pool  `web-dnat`:   dst 172.16.80.8:443 → 10.0.61.102:8443
/// The installed session MUST carry the STATIC translation (rewrite_dst =
/// 10.0.61.50, no port rewrite). On the pre-fix DNAT-first evaluation the
/// pool shadows the static mapping (rewrite_dst = 10.0.61.102, port 8443)
/// and this test goes RED.
#[test]
fn static_nat_precedes_overlapping_dnat_pool_6473() {
    let mut snapshot = inbound_dnat_snapshot(wan_to_lan_permit("any", "permit-any"));
    // Static 1:1 on the SAME external IP as the DNAT pool rule, pointing at
    // a DIFFERENT internal host.
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: "web-static".to_string(),
        from_zone: "wan".to_string(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: "172.16.80.8".to_string(),
        internal_ip: "10.0.61.50".to_string(),
        match_destination_port: 0,
        mapped_port: 0,
    }];
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "reth1.0".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: "10.0.61.50".to_string(),
        mac: "02:aa:bb:cc:dd:50".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54333,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert!(
        dbg.tx >= 1,
        "sanity: the overlapped flow is permitted and forwards either way"
    );

    let pool_internal = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let static_internal = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50));
    let mut pool_wins = 0u32;
    let mut static_wins = 0u32;
    let mut pool_port_wins = 0u32;
    sessions.iter_with_origin(|_key, decision, _metadata, _origin| {
        if decision.nat.rewrite_dst == Some(pool_internal) {
            pool_wins += 1;
        }
        if decision.nat.rewrite_dst == Some(static_internal) {
            static_wins += 1;
        }
        if decision.nat.rewrite_dst_port == Some(8443) {
            pool_port_wins += 1;
        }
    });
    assert!(
        static_wins >= 1,
        "Junos order: the static 1:1 mapping must win the overlap"
    );
    assert_eq!(
        pool_wins, 0,
        "the DNAT pool must NOT shadow the static rule (pre-#6473 behavior)"
    );
    assert_eq!(
        pool_port_wins, 0,
        "a plain static 1:1 rewrites no port (the pool's :443→:8443 must NOT apply)"
    );
}

// =====================================================================
// #2345 MissingNeighbor (neighbor-ABSENT) cold-path coverage.
//
// All the tests above install the next-hop neighbor, so they exercise
// ONLY the ForwardCandidate policy-eval site. These tests drop the
// next-hop neighbor so the resolution returns MissingNeighbor and the
// SEPARATE policy gate at the MissingNeighbor site runs instead. That
// site reconstructs the post-translation tuple from the merged
// `decision.nat` (the miss-block `effective_resolution_target` is out of
// scope there), so a revert there would not be caught by the
// ForwardCandidate tests.
//
// MissingNeighbor verdict signals used below:
//   - PERMIT: the cold path seeds a MissingNeighborSeed session (forward
//     + reverse), so `sessions.len() >= 1` and `policy_deny == 0`. The
//     trigger packet is NOT forwarded yet (it buffers / probes), so
//     `dbg.tx == 0` on this path even on permit.
//   - DENY: the deny gate recycles the frame, installs no session, and
//     bumps `policy_deny` (>= 1). `sessions.len() == 0`.
// `missing_neigh >= 1` confirms the MissingNeighbor arm was actually the
// path taken (rather than the flow silently resolving to ForwardCandidate
// because a neighbor leaked in).
// =====================================================================


/// DNAT MissingNeighbor: a policy permitting ONLY the translated internal
/// destination must PERMIT (seed a session) the inbound DNAT'd flow when
/// the internal host's neighbor is unresolved. Proves the MissingNeighbor
/// site matches on the post-DNAT internal dst. Fails if the MissingNeighbor
/// eval reverts to flow.dst_ip (the public VIP, uncovered → deny).
#[test]
fn policy_inbound_dnat_missing_neighbor_permits_on_translated_dst() {
    let mut snapshot =
        inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.102/32", "permit-internal"));
    drop_neighbor(&mut snapshot, "10.0.61.102");
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54331,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.missing_neigh >= 1,
        "the unresolved internal host must drive the MissingNeighbor arm"
    );
    assert_eq!(
        dbg.policy_deny, 0,
        "MissingNeighbor policy on the translated internal dst must NOT deny"
    );
    assert!(
        sessions.len() >= 1,
        "a permitted MissingNeighbor DNAT flow seeds a session"
    );
}


/// DNAT MissingNeighbor fail-on-revert: a policy permitting ONLY the
/// original public VIP must DENY the inbound DNAT'd flow at the
/// MissingNeighbor site (the match runs on the post-DNAT internal dst,
/// which the policy does not cover). Fails if the MissingNeighbor eval
/// reverts to the pre-DNAT tuple (which would wrongly permit + seed).
#[test]
fn policy_inbound_dnat_missing_neighbor_denies_when_only_original_dst_permitted() {
    let mut snapshot =
        inbound_dnat_snapshot(wan_to_lan_permit("172.16.80.8/32", "permit-public-vip"));
    drop_neighbor(&mut snapshot, "10.0.61.102");
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54332,
        443,
        TCP_FLAG_SYN,
    );
    let meta = txn_meta_v4(12, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.policy_deny >= 1,
        "MissingNeighbor match on the post-DNAT internal dst (uncovered) must deny"
    );
    assert_eq!(
        sessions.len(),
        0,
        "a denied MissingNeighbor flow seeds no session"
    );
    assert_eq!(dbg.tx, 0, "denied flow does not forward");
}


/// NPTv6 MissingNeighbor: a policy permitting ONLY the internal prefix
/// must PERMIT (seed) the inbound external-prefix flow when the internal
/// host's neighbor is unresolved — proving the MissingNeighbor site uses
/// the post-NPTv6 internal dst.
#[test]
fn policy_inbound_nptv6_missing_neighbor_permits_on_translated_dst() {
    let mut snapshot = inbound_nptv6_snapshot(wan_to_lan_permit(
        "fd35:1940:27::/48",
        "permit-internal-prefix",
    ));
    drop_neighbor(&mut snapshot, "fd35:1940:27:100::102");
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:80::200".parse().expect("ext client");
    let dst: Ipv6Addr = "2602:fd41:70:100::102".parse().expect("ext dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 54331, 443);
    let meta = txn_meta_v6(12, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.missing_neigh >= 1,
        "the unresolved internal host must drive the MissingNeighbor arm"
    );
    assert_eq!(
        dbg.policy_deny, 0,
        "MissingNeighbor policy on the translated internal prefix must NOT deny"
    );
    assert!(
        sessions.len() >= 1,
        "a permitted MissingNeighbor NPTv6 flow seeds a session"
    );
}


/// NPTv6 MissingNeighbor fail-on-revert: a policy permitting ONLY the
/// external prefix must DENY at the MissingNeighbor site.
#[test]
fn policy_inbound_nptv6_missing_neighbor_denies_when_only_external_prefix_permitted() {
    let mut snapshot = inbound_nptv6_snapshot(wan_to_lan_permit(
        "2602:fd41:70::/48",
        "permit-external-prefix",
    ));
    drop_neighbor(&mut snapshot, "fd35:1940:27:100::102");
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:80::200".parse().expect("ext client");
    let dst: Ipv6Addr = "2602:fd41:70:100::102".parse().expect("ext dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 54332, 443);
    let meta = txn_meta_v6(12, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.policy_deny >= 1,
        "MissingNeighbor match on the post-NPTv6 internal dst (uncovered) must deny"
    );
    assert_eq!(sessions.len(), 0);
}


/// NAT64 MissingNeighbor: directly pins that Copilot's feared "NAT64
/// default-deny at MissingNeighbor" does NOT happen. With the IPv4 server's
/// next-hop neighbor (172.16.80.1) unresolved, the NAT64 flow takes the
/// MissingNeighbor cold-path arm; the policy on the synthetic IPv6 prefix
/// permits it (NOT default-denied). Unlike the #2358 ForwardCandidate path
/// (which matches NAT64 on the EXTRACTED real IPv4 dst), this arm does NOT
/// re-classify NAT64: it populates neither nptv6_nat nor pre_routing_dnat,
/// so `decision.nat.rewrite_dst` is None and `policy_dst_ip` falls back to
/// `flow.dst_ip` — the synthetic IPv6 dst — which the same-family (V6 src,
/// V6 dst) arm matches against the `64:ff9b::/96` rule (see the retained
/// synthetic-v6 fallback comment at the MissingNeighbor policy binding in
/// poll_descriptor). If that fallback were reverted to unconditionally feed
/// the extracted IPv4 dst WITHOUT reconstructing the NAT64 v4 tuple here, the
/// synthetic-V6 policy would no longer match and this flow would
/// default-deny — failing this test.
#[test]
fn policy_inbound_nat64_missing_neighbor_permits_on_synthetic_v6_not_default_deny() {
    let mut snapshot =
        nat64_snapshot(lan_to_wan_permit("64:ff9b::/96", "permit-synthetic-v6"));
    // Unresolve the IPv4 server's next hop so the NAT64 flow hits
    // MissingNeighbor instead of ForwardCandidate.
    drop_neighbor(&mut snapshot, "172.16.80.1");
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let src: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("v6 client");
    let dst: Ipv6Addr = "64:ff9b::808:808".parse().expect("nat64 dst");
    let frame = build_txn_tcp_syn_frame_v6(src, dst, 12345, 443);
    let meta = txn_meta_v6(24, frame.len());
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert!(
        dbg.missing_neigh >= 1,
        "the unresolved IPv4 next hop must drive the NAT64 flow to MissingNeighbor"
    );
    assert_eq!(
        dbg.policy_deny, 0,
        "NAT64 MissingNeighbor must match the synthetic IPv6 policy, NOT default-deny"
    );
}

// ---------------------------------------------------------------------------
// #2357 — forwarded non-first IP fragments must not select a CoS/fabric queue
// (or hit an output-filter term) from payload bytes interpreted as L4 ports.
// The TX-CoS / fabric-hash paths re-derive a flow tuple from metadata when
// the gated `flow` is `None` (the #2344 fragment case). These tests pin the
// gate: a non-first fragment routes to the default-queue / port-less paths,
// while a legitimate flowless TCP packet (real L4 header) keeps its ports.
// ---------------------------------------------------------------------------

