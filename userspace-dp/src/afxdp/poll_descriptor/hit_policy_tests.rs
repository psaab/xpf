//! #17027 parity cells: the four established-hit sites cannot drift
//! because they share `hit_policy_query`. These drive one scenario —
//! an egress interface moved into a denying zone plus a source-NAT
//! forward-wire alias — through the builder as each site calls it and
//! assert the same judged `(from, to, src, dst)`. The #18323 verdict-level
//! cell additionally drives the real owner, foreign, and revalidation
//! judgments through the fabric recorded-zone exception.
//!
//! TCP is used (not ICMP) so the owner-ICMP arm's type gate
//! (`icmp_packet_verdict_may_depend_on_type`, a permit-inclusive ICMP
//! term would decline the revalidation arm box-wide) never interferes;
//! the stale-revalidation arm judges with `icmp: None` regardless.

use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::policy_deny_snapshot;
use crate::ip_proto::PROTO_TCP;
use crate::nat::NatDecision;
use crate::session::SessionKey;
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv4Addr};

/// Egress ifindex in `policy_deny_snapshot` (reth0.80, zone wan).
const WAN_IF: i32 = 12;
/// Ingress ifindex in `policy_deny_snapshot` (reth1.0, zone lan).
const LAN_IF: i32 = 24;

fn tcp_flow(src: &str, dst: &str, src_port: u16) -> SessionFlow {
    let src_ip: IpAddr = src.parse().expect("src");
    let dst_ip: IpAddr = dst.parse().expect("dst");
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip,
            dst_ip,
            src_port,
            dst_port: 443,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        },
    }
}

fn meta_for(ingress: i32) -> UserspaceDpMeta {
    let mut meta = UserspaceDpMeta {
        ingress_ifindex: ingress as u32,
        ..UserspaceDpMeta::default()
    };
    meta.protocol = PROTO_TCP;
    meta
}

fn decision(egress_ifindex: i32, nat: NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex,
            tx_ifindex: egress_ifindex,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            neighbor_mac: Some([0; 6]),
            src_mac: Some([0; 6]),
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn metadata(ingress_zone: u32, egress_zone: u32, is_reverse: bool) -> SessionMetadata {
    SessionMetadata {
        ingress_zone,
        egress_zone,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: LAN_IF as u32,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    }
}

/// Snapshot whose only permit (dmz -> wan) never matches lan -> dmz, so
/// a lan flow judged against the live-moved dmz egress falls to the
/// default deny — while the same flow judged against the recorded wan
/// egress with a dmz from-zone would have permitted. The permit's
/// source selector names ONLY the pre-SNAT original `10.0.0.1`.
fn moved_and_snat_forwarding() -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    // The dmz -> wan permit's source names only the pre-SNAT original.
    snapshot.policies[0].source_addresses = vec!["10.0.0.1/32".into()];
    let mut fw = build_forwarding_state(&snapshot);
    // Move the egress interface into dmz in the LIVE ledger the to-zone
    // resolver reads (`ifindex_unambiguous_zone_id`, as the #12867
    // revalidation fixtures stamp it): the live to-zone becomes dmz
    // even though session rows still record egress wan.
    fw.ifindex_unambiguous_zone_id.insert(WAN_IF, TEST_DMZ_ZONE_ID);
    assert_eq!(
        fw.egress_zone_id(WAN_IF),
        TEST_DMZ_ZONE_ID,
        "fixture: egress interface must have moved into dmz"
    );
    fw
}

/// The judged tuple each site must produce for the SNAT-alias flow:
/// from lan (owner/recorded or revalidation live-ifindex 24), to dmz
/// (live moved egress), src = pre-SNAT original, dst = wire dst.
#[test]
fn hit_policy_parity_moved_egress_and_snat_alias_17027() {
    let fw = moved_and_snat_forwarding();
    let nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().expect("pool")),
        rewrite_src_port: Some(50_000),
        ..NatDecision::default()
    };
    let original = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "10.0.0.1".parse().expect("orig src"),
        dst_ip: "198.51.100.9".parse().expect("dst"),
        src_port: 45_000,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    // The wire flow carries the translated source.
    let flow = tcp_flow("203.0.113.10", "198.51.100.9", 50_000);
    let meta = metadata(TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, false);
    let dec = decision(WAN_IF, nat);
    let now = 1_000_000_000u64;
    let judged = JudgedSource::new(original.src_ip, original.src_port);

    // Arm 1 (revalidation shape): LiveIfindex from-zone, ForwardPostDnat,
    // frame-independent (icmp None).
    let q_reval = hit_policy_query(
        &fw,
        &meta,
        dec,
        FromZoneSource::LiveIfindex {
            ifindex: LAN_IF,
            vlan: 0,
        },
        judged,
        flow.dst_ip,
        flow.forward_key.dst_port,
        PROTO_TCP,
        QueryDirection::ForwardPostDnat,
        None,
        now,
    );
    // Arm 2 (owner-ICMP shape): RecordedZone from-zone (== lan here).
    let q_owner = hit_policy_query(
        &fw,
        &meta,
        dec,
        FromZoneSource::RecordedZone(TEST_LAN_ZONE_ID),
        judged,
        flow.dst_ip,
        flow.forward_key.dst_port,
        PROTO_TCP,
        QueryDirection::ForwardPostDnat,
        None,
        now,
    );
    // Arm 3 (foreign shape): Resolved arrival zone — the same lan id,
    // arrived at by the caller from the live arrival interface.
    let q_foreign = hit_policy_query(
        &fw,
        &meta,
        dec,
        FromZoneSource::Resolved(TEST_LAN_ZONE_ID),
        judged,
        flow.dst_ip,
        flow.forward_key.dst_port,
        PROTO_TCP,
        QueryDirection::ForwardPostDnat,
        None,
        now,
    );
    assert_eq!(q_reval, q_owner, "revalidation and owner arms must judge identically");
    assert_eq!(q_owner, q_foreign, "owner and foreign arms must judge identically");
    assert_eq!(
        (q_reval.from_id, q_reval.to_id),
        (TEST_LAN_ZONE_ID, TEST_DMZ_ZONE_ID),
        "the judged pair must be the LIVE moved egress (dmz), not the recorded wan"
    );
    assert_eq!(q_reval.src_ip, original.src_ip, "judged source must be the pre-SNAT original");
    assert_eq!(q_reval.src_port, original.src_port);
    assert_eq!(q_reval.dst_ip, flow.dst_ip);
    // No lan -> dmz permit exists, so every arm denies — and the wire
    // source (203.0.113.10) would ALSO deny here, which is why the
    // source assertion above (not the verdict) carries the SNAT half.
    assert!(
        permits(&q_reval, &fw.policy).is_err(),
        "lan -> dmz has no permit: the moved-egress flow must deny on every arm"
    );

    // Control: judging the WIRE source instead must produce a different
    // query — proving the source axis is actually exercised above.
    let q_wire = hit_policy_query(
        &fw,
        &meta,
        dec,
        FromZoneSource::RecordedZone(TEST_LAN_ZONE_ID),
        JudgedSource::new(flow.src_ip, flow.forward_key.src_port),
        flow.dst_ip,
        flow.forward_key.dst_port,
        PROTO_TCP,
        QueryDirection::ForwardPostDnat,
        None,
        now,
    );
    assert_ne!(q_wire.src_ip, q_reval.src_ip);
}

/// FabricRedirect keeps the recorded egress zone on every arm, even
/// when the live egress has moved (#7770 exception, single-sourced).
#[test]
fn hit_policy_fabric_redirect_keeps_recorded_zone_17027() {
    let fw = moved_and_snat_forwarding();
    let meta = metadata(TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, false);
    let mut dec = decision(WAN_IF, NatDecision::default());
    dec.resolution.disposition = ForwardingDisposition::FabricRedirect;
    let flow = tcp_flow("10.0.0.1", "198.51.100.9", 45_000);
    let q = hit_policy_query(
        &fw,
        &meta,
        dec,
        FromZoneSource::RecordedZone(TEST_LAN_ZONE_ID),
        JudgedSource::new(flow.src_ip, flow.forward_key.src_port),
        flow.dst_ip,
        flow.forward_key.dst_port,
        PROTO_TCP,
        QueryDirection::ForwardPostDnat,
        None,
        1_000,
    );
    assert_eq!(
        q.to_id, TEST_WAN_ZONE_ID,
        "FabricRedirect must judge the recorded egress zone, not the live (moved) one"
    );
    assert_eq!(
        hit_egress_zone(&fw, &meta, dec),
        TEST_WAN_ZONE_ID,
        "hit_egress_zone must agree with the builder for FabricRedirect"
    );
    // And without FabricRedirect the same fixture judges live dmz.
    let dec_fwd = decision(WAN_IF, NatDecision::default());
    assert_eq!(hit_egress_zone(&fw, &meta, dec_fwd), TEST_DMZ_ZONE_ID);
}

/// ReverseWire judges the wire destination even when a DNAT rewrite
/// exists, while ForwardPostDnat judges the rewritten one (#10637 vs
/// #9382 — the deliberate direction split).
#[test]
fn hit_policy_direction_splits_wire_from_postdnat_17027() {
    let fw = moved_and_snat_forwarding();
    let nat = NatDecision {
        rewrite_dst: Some("10.0.0.9".parse().expect("real server")),
        rewrite_dst_port: Some(8443),
        ..NatDecision::default()
    };
    let meta = metadata(TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, true);
    let dec = decision(WAN_IF, nat);
    let flow = tcp_flow("198.51.100.9", "203.0.113.10", 443);
    let src = JudgedSource::new(flow.src_ip, flow.forward_key.src_port);
    let q_fwd = hit_policy_query(
        &fw,
        &meta,
        dec,
        FromZoneSource::RecordedZone(TEST_LAN_ZONE_ID),
        src,
        flow.dst_ip,
        flow.forward_key.dst_port,
        PROTO_TCP,
        QueryDirection::ForwardPostDnat,
        None,
        1_000,
    );
    let q_rev = hit_policy_query(
        &fw,
        &meta,
        dec,
        FromZoneSource::RecordedZone(TEST_LAN_ZONE_ID),
        src,
        flow.dst_ip,
        flow.forward_key.dst_port,
        PROTO_TCP,
        QueryDirection::ReverseWire,
        None,
        1_000,
    );
    assert_eq!(
        q_fwd.dst_ip,
        "10.0.0.9".parse::<IpAddr>().expect("dnat dst"),
        "ForwardPostDnat must judge the post-translation destination"
    );
    assert_eq!(q_fwd.dst_port, 8443);
    assert_eq!(q_rev.dst_ip, flow.dst_ip, "ReverseWire must judge the wire destination");
    assert_eq!(q_rev.dst_port, flow.forward_key.dst_port);
    // `meta_for` is exercised so the helper cannot silently rot.
    assert_eq!(meta_for(LAN_IF).protocol, PROTO_TCP);
}
/// #18323 fold: drive the fabric-vs-live to-zone split through the actual
/// authority and stale-revalidation verdicts. The live egress ledger moves
/// both tested egress interfaces into dmz; policies permit the recorded
/// forward/reverse pairs and deny their live-moved pairs. The recorded-dmz
/// control uses a separate un-moved ledger, so fabric must deny its recorded
/// pair even though the live WAN pair permits. Reverting the FabricRedirect
/// exception in `hit_egress_zone_for` makes the fabric expectations red.
#[test]
fn fabric_recorded_zone_verdict_level_17027() {
    use crate::afxdp::forwarding_build::build_forwarding_state;
    use crate::afxdp::test_fixtures::policy_deny_snapshot;
    use crate::ip_proto::PROTO_ICMP;
    use crate::test_zone_ids::{
        TEST_DMZ_ZONE_ID, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID,
    };
    use std::net::{IpAddr, Ipv4Addr};

    const LAN_IF: i32 = 24;
    const WAN_IF: i32 = 12;
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies.extend([
        crate::PolicyRuleSnapshot {
            name: "allow-lan-wan".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            action: "permit".into(),
            ..Default::default()
        },
        crate::PolicyRuleSnapshot {
            name: "allow-wan-lan".into(),
            from_zone: "wan".into(),
            to_zone: "lan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            action: "permit".into(),
            ..Default::default()
        },
        // Arm owner ICMP verdicts without permitting either moved pair.
        crate::PolicyRuleSnapshot {
            name: "typed-guard".into(),
            from_zone: "dmz".into(),
            to_zone: "lan".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["junos-icmp-ping".into()],
            application_terms: vec![crate::PolicyApplicationSnapshot {
                name: "junos-icmp-ping".into(),
                protocol: "icmp".into(),
                source_port: String::new(),
                destination_port: String::new(),
                icmp_type: Some(8),
                icmp_code: None,
                inactivity_timeout: None,
            }],
            action: "permit".into(),
            ..Default::default()
        },
    ]);

    let build_moved_forwarding = || {
        let mut forwarding = build_forwarding_state(&snapshot);
        // The established-hit to-zone resolver reads this live ledger.
        forwarding
            .ifindex_unambiguous_zone_id
            .insert(WAN_IF, TEST_DMZ_ZONE_ID);
        forwarding
            .ifindex_unambiguous_zone_id
            .insert(LAN_IF, TEST_DMZ_ZONE_ID);
        assert_eq!(forwarding.egress_zone_id(WAN_IF), TEST_DMZ_ZONE_ID);
        assert_eq!(forwarding.egress_zone_id(LAN_IF), TEST_DMZ_ZONE_ID);
        forwarding
    };
    let forwarding = build_moved_forwarding();
    assert!(
        forwarding
            .policy
            .icmp_packet_verdict_may_depend_on_type(PROTO_ICMP),
        "the typed guard must arm the owner ICMP verdict"
    );

    let metadata = |ingress_zone, egress_zone, is_reverse| SessionMetadata {
        ingress_zone,
        egress_zone,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: LAN_IF as u32,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    };
    let decision = |egress_ifindex, disposition| SessionDecision {
        resolution: ForwardingResolution {
            disposition,
            local_ifindex: 0,
            egress_ifindex,
            tx_ifindex: egress_ifindex,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let fabric_forward = decision(WAN_IF, ForwardingDisposition::FabricRedirect);
    let live_forward = decision(WAN_IF, ForwardingDisposition::ForwardCandidate);
    let forward_meta = metadata(TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID, false);
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let destination = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        src_ip: source,
        dst_ip: destination,
        src_port: 0x1234,
        dst_port: 0,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let forward_flow = SessionFlow {
        src_ip: source,
        dst_ip: destination,
        forward_key: forward_key.clone(),
    };
    let forward_frame = crate::afxdp::tests_support::build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(172, 16, 0, 1),
        64,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let packet_meta = |ingress_ifindex| {
        let mut meta = UserspaceDpMeta {
            ingress_ifindex: ingress_ifindex as u32,
            ..UserspaceDpMeta::default()
        };
        meta.protocol = PROTO_ICMP;
        meta.payload_offset = 42;
        meta
    };
    let now_ns = 1_000_000_000;

    // owner_hit_icmp_verdict, forward: FabricRedirect uses recorded lan->wan
    // and permits; the identical non-fabric hit uses live lan->dmz and drops.
    let owner = super::super::session_hit_authority::owner_hit_icmp_verdict;
    assert_eq!(
        owner(
            &forwarding,
            &forward_meta,
            fabric_forward,
            &forward_flow,
            packet_meta(LAN_IF),
            &forward_frame,
            now_ns,
            None,
        ),
        Some(super::super::session_hit_authority::OwnerHitIcmpVerdict::Forward),
        "fabric owner-forward must keep recorded (lan, wan) and permit"
    );
    match owner(
        &forwarding,
        &forward_meta,
        live_forward,
        &forward_flow,
        packet_meta(LAN_IF),
        &forward_frame,
        now_ns,
        None,
    ) {
        Some(super::super::session_hit_authority::OwnerHitIcmpVerdict::Drop(deny)) => {
            assert_eq!(
                (deny.judged_from_zone, deny.judged_to_zone),
                (TEST_LAN_ZONE_ID, TEST_DMZ_ZONE_ID),
                "non-fabric owner-forward must judge live (lan, dmz)"
            );
        }
        other => panic!("non-fabric owner-forward must Drop, got {other:?}"),
    }

    // The reverse ICMP owner uses its own recorded wan->lan pair. Its live
    // egress interface is also moved to dmz, so the non-fabric twin drops.
    let reverse_meta = metadata(TEST_WAN_ZONE_ID, TEST_LAN_ZONE_ID, true);
    let reverse_decision = |disposition| decision(LAN_IF, disposition);
    let reverse_flow = SessionFlow {
        src_ip: destination,
        dst_ip: source,
        forward_key: forward_key.clone(),
    };
    let reverse_frame = crate::afxdp::tests_support::build_icmp_echo_frame_v4(
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        64,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    assert_eq!(
        owner(
            &forwarding,
            &reverse_meta,
            reverse_decision(ForwardingDisposition::FabricRedirect),
            &reverse_flow,
            packet_meta(WAN_IF),
            &reverse_frame,
            now_ns,
            None,
        ),
        Some(super::super::session_hit_authority::OwnerHitIcmpVerdict::Forward),
        "fabric owner-reverse must keep recorded (wan, lan) and permit"
    );
    match owner(
        &forwarding,
        &reverse_meta,
        reverse_decision(ForwardingDisposition::ForwardCandidate),
        &reverse_flow,
        packet_meta(WAN_IF),
        &reverse_frame,
        now_ns,
        None,
    ) {
        Some(super::super::session_hit_authority::OwnerHitIcmpVerdict::Drop(deny)) => {
            assert_eq!(
                (deny.judged_from_zone, deny.judged_to_zone),
                (TEST_WAN_ZONE_ID, TEST_DMZ_ZONE_ID),
                "non-fabric owner-reverse must judge live (wan, dmz)"
            );
        }
        other => panic!("non-fabric owner-reverse must Drop, got {other:?}"),
    }

    // foreign_hit_verdict: a real dmz arrival is foreign to the lan
    // session. Fabric evaluates recorded dmz->wan (permit); non-fabric
    // evaluates dmz->dmz after the egress move (Drop).
    let sessions = SessionTable::new();
    let foreign = super::super::session_hit_authority::foreign_hit_verdict;
    assert!(
        matches!(
            foreign(
                &forwarding,
                &sessions,
                &forward_key,
                &forward_meta,
                fabric_forward,
                &forward_flow,
                packet_meta(LAN_IF),
                &forward_frame,
                TEST_DMZ_ZONE_ID,
                false,
                now_ns,
                None,
            ),
            super::super::session_hit_authority::ForeignHitVerdict::Forward
        ),
        "fabric foreign hit must keep recorded dmz->wan and permit"
    );
    match foreign(
        &forwarding,
        &sessions,
        &forward_key,
        &forward_meta,
        live_forward,
        &forward_flow,
        packet_meta(LAN_IF),
        &forward_frame,
        TEST_DMZ_ZONE_ID,
        false,
        now_ns,
        None,
    ) {
        super::super::session_hit_authority::ForeignHitVerdict::Drop(deny) => {
            assert_eq!(
                (deny.judged_from_zone, deny.judged_to_zone),
                (TEST_DMZ_ZONE_ID, TEST_DMZ_ZONE_ID),
                "non-fabric foreign hit must judge live (dmz, dmz)"
            );
        }
        _ => panic!("non-fabric foreign hit must Drop"),
    }

    // The test-only bridge invokes the actual
    // `zone_policy_deny_on_session_hit` while keeping private types local.
    let tcp_policy_flow = tcp_flow("10.0.0.1", "172.16.0.1", 45_000);
    let zone_judgment = |fw: &ForwardingState,
                         dec: SessionDecision,
                         meta: &SessionMetadata,
                         from: FromZoneSource| {
        super::super::policy_revalidation::zone_policy_verdict_for_test(
            fw,
            dec,
            meta,
            &tcp_policy_flow,
            from,
            now_ns,
        )
    };
    let live_from = FromZoneSource::LiveIfindex {
        ifindex: LAN_IF,
        vlan: 0,
    };
    let live_query = hit_policy_query(
        &forwarding,
        &forward_meta,
        live_forward,
        live_from,
        JudgedSource::new(tcp_policy_flow.src_ip, tcp_policy_flow.forward_key.src_port),
        tcp_policy_flow.dst_ip,
        tcp_policy_flow.forward_key.dst_port,
        PROTO_TCP,
        QueryDirection::ForwardPostDnat,
        None,
        now_ns,
    );
    assert_eq!(
        (live_query.from_id, live_query.to_id),
        (TEST_LAN_ZONE_ID, TEST_DMZ_ZONE_ID),
        "zone-policy non-fabric verdict must judge live (lan, dmz)"
    );
    assert_eq!(
        zone_judgment(
            &forwarding,
            fabric_forward,
            &forward_meta,
            FromZoneSource::RecordedZone(TEST_LAN_ZONE_ID),
        ),
        super::super::policy_revalidation::ZonePolicyVerdictForTest::Permit,
    );
    assert_eq!(
        zone_judgment(&forwarding, live_forward, &forward_meta, live_from),
        super::super::policy_revalidation::ZonePolicyVerdictForTest::Revoke,
    );

    // Anti-mutant control: recorded dmz denies even though the live ledger
    // says wan and would permit. If FabricRedirect read live here, this
    // expectation would change from Revoke to Permit.
    let unmoved_forwarding = build_forwarding_state(&snapshot);
    let recorded_dmz = metadata(TEST_LAN_ZONE_ID, TEST_DMZ_ZONE_ID, false);
    assert_eq!(unmoved_forwarding.egress_zone_id(WAN_IF), TEST_WAN_ZONE_ID);
    assert_eq!(
        zone_judgment(
            &unmoved_forwarding,
            fabric_forward,
            &recorded_dmz,
            FromZoneSource::RecordedZone(TEST_LAN_ZONE_ID),
        ),
        super::super::policy_revalidation::ZonePolicyVerdictForTest::Revoke,
    );
    assert_eq!(
        zone_judgment(&unmoved_forwarding, live_forward, &recorded_dmz, live_from),
        super::super::policy_revalidation::ZonePolicyVerdictForTest::Permit,
    );
}
