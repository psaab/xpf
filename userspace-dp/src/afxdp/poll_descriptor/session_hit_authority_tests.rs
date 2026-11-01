//! #9519: the ownership decision as a pure function. The descriptor cells in
//! `afxdp/tests_session_hit_authority_9519.rs` bind the WIRING; these pin the
//! discriminator's cases a descriptor fixture cannot reach cheaply.

use super::*;
use crate::InterfaceSnapshot;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::{nat_snapshot_with_fabric, policy_deny_snapshot};
use crate::ip_proto::PROTO_ICMP;
use crate::test_zone_ids::*;

/// `reth1.0`, zone `lan`, in `policy_deny_snapshot`.
const LAN_A: i32 = 24;
/// `reth0.80`, zone `wan`, in `policy_deny_snapshot`.
const WAN: i32 = 12;
const LAN_B: i32 = 25;
const DMZ: i32 = 26;
const TUNNEL_INGRESS: i32 = 586;
/// A physical trunk whose two units sit in DIFFERENT zones.
const TRUNK: i32 = 40;
const TRUNK_LAN_UNIT: i32 = 41;
const TRUNK_DMZ_UNIT: i32 = 42;
const LAN_VLAN: u16 = 100;
const DMZ_VLAN: u16 = 200;
const NOT_CONFIGURED: i32 = 99;

fn forwarding(lan_a_moved_to_dmz: bool) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    if lan_a_moved_to_dmz {
        for iface in snapshot.interfaces.iter_mut() {
            if iface.ifindex == LAN_A {
                iface.zone = "dmz".into();
            }
        }
    }
    snapshot.interfaces.extend([
        InterfaceSnapshot {
            name: "reth3.0".into(),
            zone: "lan".into(),
            linux_name: "ge-0-0-3".into(),
            ifindex: LAN_B,
            ..Default::default()
        },
        InterfaceSnapshot {
            name: "reth2.0".into(),
            zone: "dmz".into(),
            linux_name: "ge-0-0-2".into(),
            ifindex: DMZ,
            ..Default::default()
        },
        InterfaceSnapshot {
            name: "reth4.100".into(),
            zone: "lan".into(),
            linux_name: "ge-0-0-4.100".into(),
            ifindex: TRUNK_LAN_UNIT,
            parent_ifindex: TRUNK,
            vlan_id: LAN_VLAN as i32,
            ..Default::default()
        },
        InterfaceSnapshot {
            name: "reth4.200".into(),
            zone: "dmz".into(),
            linux_name: "ge-0-0-4.200".into(),
            ifindex: TRUNK_DMZ_UNIT,
            parent_ifindex: TRUNK,
            vlan_id: DMZ_VLAN as i32,
            ..Default::default()
        },
    ]);
    build_forwarding_state(&snapshot)
}

fn session(zone: u32, ingress_ifindex: i32, vlan: u16, is_reverse: bool) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: zone,
        egress_zone: if is_reverse {
            TEST_LAN_ZONE_ID
        } else {
            TEST_WAN_ZONE_ID
        },
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: ingress_ifindex as u32,
        ingress_vlan_id: vlan,
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

fn arrival(ifindex: i32, vlan: u16) -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: ifindex as u32,
        ingress_vlan_id: vlan,
        ..UserspaceDpMeta::default()
    }
}

fn foreign(arrival_zone: u32, on_admitting_interface: bool) -> HitAuthority {
    HitAuthority::Foreign {
        arrival_zone,
        on_admitting_interface,
    }
}

#[test]
fn a_packet_from_another_zone_is_foreign_9519() {
    let fw = forwarding(false);
    let lan = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::ForwardFlow,
            arrival(LAN_A, 0),
            false,
            None,
        ),
        HitAuthority::Owner,
        "control: the admitting interface in the admitting zone is the owner"
    );
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::ForwardFlow,
            arrival(DMZ, 0),
            false,
            None,
        ),
        foreign(TEST_DMZ_ZONE_ID, false),
        "the same tuple from a dmz interface did not come from the zone that \
         admitted the session, and must be judged as dmz's (#9519)"
    );
}

#[test]
fn unstamped_fabric_ingress_remains_exempt_9519() {
    let fw = forwarding(false);
    let lan = session(TEST_LAN_ZONE_ID, 0, 0, false);
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::SyncImport,
            arrival(DMZ, 0),
            false,
            None,
        ),
        foreign(TEST_DMZ_ZONE_ID, false),
        "control: without the fabric flag this arrival is foreign, or the \
         exemption below is asserting nothing"
    );
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::SyncImport,
            arrival(DMZ, 0),
            true,
            None,
        ),
        HitAuthority::Owner,
        "unstamped fabric overlay has no arrival identity to judge and keeps \
         the #9519 exemption"
    );
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::SyncImport,
            arrival(DMZ, 0),
            true,
            Some(TEST_LAN_ZONE_ID),
        ),
        HitAuthority::Owner,
        "a peer session hit is adjudicated under the session's zone; its \
         same-zone stamp remains an owner arrival"
    );
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::SyncImport,
            arrival(DMZ, 0),
            true,
            Some(TEST_DMZ_ZONE_ID),
        ),
        foreign(TEST_DMZ_ZONE_ID, false),
        "a peer-side session miss is punted without adjudication; its foreign \
         zone stamp must be judged on the owner rather than trusted as a hit"
    );
}

#[test]
fn a_second_interface_in_the_admitting_zone_is_an_owner_9519() {
    let fw = forwarding(false);
    let lan = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::ForwardFlow,
            arrival(LAN_B, 0),
            false,
            None,
        ),
        HitAuthority::Owner,
        "authority is the ZONE, not the interface: a LAG member, an ECMP path or \
         another unit in the same zone must keep forwarding (#9519)"
    );
}

#[test]
fn a_re_zoned_admitting_interface_is_foreign_but_may_revoke_9519() {
    let fw = forwarding(true);
    let lan = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::ForwardFlow,
            arrival(LAN_A, 0),
            false,
            None,
        ),
        foreign(TEST_DMZ_ZONE_ID, true),
        "the admitting interface was moved to dmz by a commit: its packets are \
         judged as dmz's, and — being the session's OWN interface — may revoke \
         it (#9384 through #9519)"
    );
    for origin in [
        SessionOrigin::SyncImport,
        SessionOrigin::SharedMaterialize,
        SessionOrigin::SharedPromote,
        SessionOrigin::WorkerLocalImport,
        SessionOrigin::ReverseFlow,
    ] {
        assert_eq!(
            session_hit_authority(&fw, &lan, origin, arrival(LAN_A, 0), false, None),
            foreign(TEST_DMZ_ZONE_ID, false),
            "an entry whose ingress_ifindex was not stamped from THIS node's frame \
             ({origin:?}) cannot prove the packet came in on its admitting \
             interface, so it must not be allowed to revoke"
        );
    }
}

#[test]
fn a_peer_ifindex_that_collides_with_a_local_one_confers_nothing_9519() {
    let fw = forwarding(false);
    // A peer's import: admitted in wan on the PEER, whose numbering put that
    // interface at an ifindex this node uses for reth1.0 (lan).
    let import = session(TEST_WAN_ZONE_ID, LAN_A, 0, false);
    assert_eq!(
        session_hit_authority(
            &fw,
            &import,
            SessionOrigin::SyncImport,
            arrival(WAN, 0),
            false,
            None,
        ),
        HitAuthority::Owner,
        "control: the import's packets arriving in wan here are its owner"
    );
    assert_eq!(
        session_hit_authority(
            &fw,
            &import,
            SessionOrigin::SyncImport,
            arrival(LAN_A, 0),
            false,
            None,
        ),
        foreign(TEST_LAN_ZONE_ID, false),
        "a lan packet on the local interface whose ifindex happens to equal the \
         peer's must be foreign and must NOT qualify to revoke (#9519)"
    );
}

#[test]
fn a_vlan_unit_is_judged_by_its_own_zone_9519() {
    let fw = forwarding(false);
    let unit = session(TEST_LAN_ZONE_ID, TRUNK, LAN_VLAN, false);
    assert_eq!(
        session_hit_authority(
            &fw,
            &unit,
            SessionOrigin::ForwardFlow,
            arrival(TRUNK, LAN_VLAN),
            false,
            None,
        ),
        HitAuthority::Owner,
        "control: the lan unit's own VLAN is the owner"
    );
    assert_eq!(
        session_hit_authority(
            &fw,
            &unit,
            SessionOrigin::ForwardFlow,
            arrival(TRUNK, DMZ_VLAN),
            false,
            None,
        ),
        foreign(TEST_DMZ_ZONE_ID, false),
        "the dmz unit on the SAME trunk is a different zone. Resolving the \
         physical port instead of the logical unit would answer the trunk's \
         propagated zone for both (#9383), and VLAN is part of the admitting \
         interface's identity (#9519)"
    );
}

#[test]
fn a_reply_is_an_owner_only_from_the_zone_the_flow_went_to_9519() {
    let fw = forwarding(false);
    let reverse = session(TEST_WAN_ZONE_ID, 0, 0, true);
    assert_eq!(
        session_hit_authority(
            &fw,
            &reverse,
            SessionOrigin::ReverseFlow,
            arrival(WAN, 0),
            false,
            None,
        ),
        HitAuthority::Owner,
        "control: the reply from wan, where the flow went, is the owner"
    );
    assert_eq!(
        session_hit_authority(
            &fw,
            &reverse,
            SessionOrigin::ReverseFlow,
            arrival(DMZ, 0),
            false,
            None,
        ),
        foreign(TEST_DMZ_ZONE_ID, false),
        "a reply must come back from where the flow went — #7169's rule for the \
         reverse fallback, now on the direct reverse hit (#9519)"
    );
}

#[test]
fn reply_after_reroute_is_owner_from_new_egress_zone_14318() {
    // Acceptance scenario: lan -> wan1 session rerouted to wan2; after the
    // forward revalidation rebinds the pair (see session tests), a reply
    // arriving from wan2 must be Owner, not Foreign. This pins the
    // authority half: with reverse ingress_zone == wan2, arrival on wan2
    // is Owner; the stale wan1 value would classify it Foreign.
    let fw = forwarding(false);
    let mut reverse = session(TEST_DMZ_ZONE_ID, 0, 0, true);
    reverse.egress_zone = TEST_LAN_ZONE_ID;
    assert_eq!(
        session_hit_authority(
            &fw,
            &reverse,
            SessionOrigin::ReverseFlow,
            arrival(DMZ, 0),
            false,
            None,
        ),
        HitAuthority::Owner,
        "reply from the rerouted egress zone (dmz as wan2 stand-in) is owner after rebind"
    );
    // Control: stale metadata (still wan) classifies the same arrival Foreign.
    let stale = session(TEST_WAN_ZONE_ID, 0, 0, true);
    assert_eq!(
        session_hit_authority(
            &fw,
            &stale,
            SessionOrigin::ReverseFlow,
            arrival(DMZ, 0),
            false,
            None,
        ),
        foreign(TEST_DMZ_ZONE_ID, false),
        "control: stale reverse ingress_zone makes the rerouted reply foreign"
    );
}

#[test]
fn an_arrival_that_resolves_to_no_zone_is_foreign_9519() {
    let fw = forwarding(false);
    let lan = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    assert_eq!(
        session_hit_authority(
            &fw,
            &lan,
            SessionOrigin::ForwardFlow,
            arrival(NOT_CONFIGURED, 0),
            false,
            None,
        ),
        foreign(0, false),
        "an arrival the box puts in no zone cannot be the lan session's owner; it \
         is judged as a zone-0 arrival, which policy refuses to match (#3110)"
    );
}

// #12868: hit verdicts must evaluate scheduled rules at the descriptor's
// captured `now_ns`, not at a fresh `monotonic_nanos()` read. The fixtures
// below place the scheduler heartbeat receipt at t=1_000 with version 7, so
// the lease is fresh at t=1_000 and expired at
// t=1_000 + SCHEDULER_HEARTBEAT_LEASE_NS + 1. At the expired instant a
// scheduled PERMIT must no longer match (fail-closed to the default deny);
// at the fresh instant it must match. On the pre-fix code the verdict
// helpers read the real clock (boot-relative, far past any 300s-old receipt
// only if the box has been up that long — and, crucially, never equal to the
// supplied descriptor time), so the fresh-instant assertions fail: the
// helpers ignore the caller's timestamp entirely.

use crate::PolicyRuleSnapshot;
use crate::policy::SCHEDULER_HEARTBEAT_LEASE_NS;
use std::net::{IpAddr, Ipv4Addr};

const SCHED_RECEIPT_NS: u64 = 1_000;
const SCHED_EXPIRED_NS: u64 = SCHED_RECEIPT_NS + SCHEDULER_HEARTBEAT_LEASE_NS + 1;

fn scheduled_icmp_forwarding() -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = 7;
    snapshot.fib_generation = 9;
    // Scheduled PERMIT lan -> wan, plus an unrelated typed ICMP rule to arm
    // the packet-scoped owner check.
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "sched-lan-permit".into(),
        from_zone: "lan".into(),
        to_zone: "wan".into(),
        scheduler_name: "workhours".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["any".into()],
        action: "permit".into(),
        ..Default::default()
    });
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "icmp-type-guard".into(),
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
    });
    // Scheduled PERMIT dmz -> wan (any application) replaces the fixture's
    // unscheduled dmz permit so the foreign path is also schedule-gated.
    for rule in snapshot.policies.iter_mut() {
        if rule.name == "allow-other" {
            rule.scheduler_name = "workhours".into();
        }
    }
    let fw = build_forwarding_state(&snapshot);
    assert!(
        fw.policy.icmp_packet_verdict_may_depend_on_type(PROTO_ICMP),
        "fixture must arm the type-dependent owner check"
    );
    assert!(
        fw.policy.scheduler_lease.apply(7, SCHED_RECEIPT_NS),
        "fixture heartbeat must be accepted"
    );
    fw
}

fn icmp_echo_frame() -> Vec<u8> {
    crate::afxdp::tests_support::build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(172, 16, 0, 1),
        64,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    )
}

fn icmp_flow() -> SessionFlow {
    let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip,
            dst_ip,
            src_port: 0x1234,
            dst_port: 0,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        },
    }
}

fn icmp_meta() -> UserspaceDpMeta {
    let mut meta = UserspaceDpMeta {
        ingress_ifindex: LAN_A as u32,
        ..UserspaceDpMeta::default()
    };
    meta.protocol = PROTO_ICMP;
    meta.payload_offset = 42;
    meta
}

fn forward_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: WAN,
            tx_ifindex: WAN,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
            neighbor_mac: Some([0; 6]),
            src_mac: Some([0; 6]),
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: crate::nat::NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn reverse_verdict_decision() -> SessionDecision {
    let mut decision = forward_decision();
    decision.resolution.egress_ifindex = LAN_A;
    decision.resolution.tx_ifindex = LAN_A;
    decision
}

#[test]
fn owner_forward_icmp_verdict_uses_descriptor_time_12868() {
    let fw = scheduled_icmp_forwarding();
    let metadata = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    let flow = icmp_flow();
    let frame = icmp_echo_frame();
    let decision = forward_decision();
    assert_eq!(
        owner_hit_icmp_verdict(
            &fw,
            &metadata,
            decision,
            &flow,
            icmp_meta(),
            &frame,
            SCHED_RECEIPT_NS,
            None,
        ),
        Some(OwnerHitIcmpVerdict::Forward),
        "at the fresh descriptor time the scheduled permit is live"
    );
    assert!(matches!(
        owner_hit_icmp_verdict(
            &fw,
            &metadata,
            decision,
            &flow,
            icmp_meta(),
            &frame,
            SCHED_EXPIRED_NS,
            None,
        ),
        Some(OwnerHitIcmpVerdict::Drop(_))
    ));
}

#[test]
fn owner_reverse_icmp_verdict_uses_descriptor_time_12868() {
    let fw = scheduled_icmp_forwarding();
    let mut metadata = session(TEST_LAN_ZONE_ID, LAN_A, 0, true);
    metadata.egress_zone = TEST_WAN_ZONE_ID;
    let flow = icmp_flow();
    let frame = icmp_echo_frame();
    let decision = forward_decision();
    assert_eq!(
        owner_hit_icmp_verdict(
            &fw,
            &metadata,
            decision,
            &flow,
            icmp_meta(),
            &frame,
            SCHED_RECEIPT_NS,
            None,
        ),
        Some(OwnerHitIcmpVerdict::Forward),
        "reverse non-answer at fresh descriptor time uses the scheduled permit"
    );
    assert!(matches!(
        owner_hit_icmp_verdict(
            &fw,
            &metadata,
            decision,
            &flow,
            icmp_meta(),
            &frame,
            SCHED_EXPIRED_NS,
            None,
        ),
        Some(OwnerHitIcmpVerdict::Drop(_))
    ));
}

#[test]
fn foreign_hit_verdict_uses_descriptor_time_12868() {
    let fw = scheduled_icmp_forwarding();
    let metadata = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    let flow = icmp_flow();
    let frame = icmp_echo_frame();
    let decision = forward_decision();
    let sessions = SessionTable::new();
    let key = flow.forward_key.clone();
    // Foreign arrival from dmz: judged dmz -> wan, covered by the scheduled
    // `allow-other` permit.
    assert!(matches!(
        foreign_hit_verdict(
            &fw,
            &sessions,
            &key,
            &metadata,
            decision,
            &flow,
            icmp_meta(),
            &frame,
            TEST_DMZ_ZONE_ID,
            false,
            SCHED_RECEIPT_NS,
            None,
        ),
        ForeignHitVerdict::Forward
    ));
    assert!(matches!(
        foreign_hit_verdict(
            &fw,
            &sessions,
            &key,
            &metadata,
            decision,
            &flow,
            icmp_meta(),
            &frame,
            TEST_DMZ_ZONE_ID,
            false,
            SCHED_EXPIRED_NS,
            None,
        ),
        ForeignHitVerdict::Drop(_)
    ));
}

// ===== #17027 verdict cells: the judged source drives the verdict =====
//
// One ICMP scenario, three verdicts. Zone-pair permits name only the pre-SNAT
// original (10.0.0.1); the wire source (203.0.113.10) falls to default deny.
// An unrelated typed rule arms the owner forward ICMP check.

fn snat_verdict_forwarding() -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies.retain(|p| p.name != "allow-other");
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "typed-guard".into(),
        from_zone: "lan".into(),
        to_zone: "dmz".into(),
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
    });
    for (name, from_zone, to_zone) in [
        ("allow-lan-orig", "lan", "wan"),
        ("allow-dmz-orig", "dmz", "wan"),
        ("allow-wan-reverse-orig", "wan", "lan"),
        ("allow-dmz-reverse-orig", "dmz", "lan"),
    ] {
        snapshot.policies.push(PolicyRuleSnapshot {
            name: name.into(),
            from_zone: from_zone.into(),
            to_zone: to_zone.into(),
            source_addresses: vec!["10.0.0.1/32".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            action: "permit".into(),
            ..Default::default()
        });
    }
    let fw = build_forwarding_state(&snapshot);
    assert!(
        fw.policy.icmp_packet_verdict_may_depend_on_type(PROTO_ICMP),
        "fixture must arm the type-dependent owner check"
    );
    fw
}

fn snat_verdict_flow() -> SessionFlow {
    let src_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    SessionFlow {
        src_ip,
        dst_ip,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        },
    }
}

fn snat_verdict_alias() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        src_port: 0,
        dst_port: 0,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    }
}

fn snat_verdict_frame(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    crate::afxdp::tests_support::build_icmp_echo_frame_v4(
        src,
        dst,
        64,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    )
}

#[test]
fn hit_policy_owner_forward_icmp_judged_source_17027() {
    let fw = snat_verdict_forwarding();
    let metadata = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    let flow = snat_verdict_flow();
    let alias = snat_verdict_alias();
    let frame = snat_verdict_frame(
        Ipv4Addr::new(203, 0, 113, 10),
        Ipv4Addr::new(172, 16, 0, 1),
    );
    let decision = forward_decision();
    assert_eq!(
        owner_hit_icmp_verdict(
            &fw,
            &metadata,
            decision,
            &flow,
            icmp_meta(),
            &frame,
            SCHED_RECEIPT_NS,
            Some(&alias),
        ),
        Some(OwnerHitIcmpVerdict::Forward),
        "forward ICMP on the pre-SNAT original must permit"
    );
    match owner_hit_icmp_verdict(
        &fw,
        &metadata,
        decision,
        &flow,
        icmp_meta(),
        &frame,
        SCHED_RECEIPT_NS,
        None,
    ) {
        Some(OwnerHitIcmpVerdict::Drop(deny)) => assert_eq!(
            (deny.judged_from_zone, deny.judged_to_zone),
            (TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
            "wire-source deny must carry the judged lan->wan pair"
        ),
        other => panic!("forward ICMP on the wire source must drop, got {other:?}"),
    }
}

#[test]
fn hit_policy_owner_reverse_icmp_judged_source_17027() {
    let fw = snat_verdict_forwarding();
    let metadata = session(TEST_WAN_ZONE_ID, WAN, 0, true);
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        forward_key: snat_verdict_flow().forward_key,
    };
    let alias = snat_verdict_alias();
    let frame = snat_verdict_frame(
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    let decision = reverse_verdict_decision();
    let mut packet_meta = icmp_meta();
    packet_meta.ingress_ifindex = WAN as u32;
    for judged in [Some(&alias), None] {
        match owner_hit_icmp_verdict(
            &fw,
            &metadata,
            decision,
            &flow,
            packet_meta,
            &frame,
            SCHED_RECEIPT_NS,
            judged,
        ) {
            Some(OwnerHitIcmpVerdict::Drop(deny)) => assert_eq!(
                (deny.judged_from_zone, deny.judged_to_zone),
                (TEST_WAN_ZONE_ID, TEST_LAN_ZONE_ID),
                "reverse ICMP must judge the WAN responder, not the forward alias"
            ),
            other => panic!("reverse ICMP with wire responder source must drop, got {other:?}"),
        }
    }
}

#[test]
fn hit_policy_foreign_judged_source_17027() {
    let fw = snat_verdict_forwarding();
    let flow = snat_verdict_flow();
    let alias = snat_verdict_alias();
    let frame = snat_verdict_frame(
        Ipv4Addr::new(203, 0, 113, 10),
        Ipv4Addr::new(172, 16, 0, 1),
    );
    let decision = forward_decision();
    let sessions = SessionTable::new();
    let key = flow.forward_key.clone();
    let forward_meta = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    assert!(
        matches!(
            foreign_hit_verdict(
                &fw,
                &sessions,
                &key,
                &forward_meta,
                decision,
                &flow,
                icmp_meta(),
                &frame,
                TEST_DMZ_ZONE_ID,
                false,
                SCHED_RECEIPT_NS,
                Some(&alias),
            ),
            ForeignHitVerdict::Forward
        ),
        "foreign FORWARD must judge the pre-SNAT original"
    );
    match foreign_hit_verdict(
        &fw,
        &sessions,
        &key,
        &forward_meta,
        decision,
        &flow,
        icmp_meta(),
        &frame,
        TEST_DMZ_ZONE_ID,
        false,
        SCHED_RECEIPT_NS,
        None,
    ) {
        ForeignHitVerdict::Drop(deny) => assert_eq!(
            (deny.judged_from_zone, deny.judged_to_zone),
            (TEST_DMZ_ZONE_ID, TEST_WAN_ZONE_ID),
            "foreign forward wire deny must carry the judged dmz->wan pair"
        ),
        _ => panic!("foreign forward on the wire source must drop"),
    }
    let reverse_meta = session(TEST_WAN_ZONE_ID, WAN, 0, true);
    let reverse_flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        forward_key: flow.forward_key.clone(),
    };
    let reverse_frame = snat_verdict_frame(
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    let reverse_decision = reverse_verdict_decision();
    let mut reverse_packet_meta = icmp_meta();
    reverse_packet_meta.ingress_ifindex = DMZ as u32;
    match foreign_hit_verdict(
        &fw,
        &sessions,
        &key,
        &reverse_meta,
        reverse_decision,
        &reverse_flow,
        reverse_packet_meta,
        &reverse_frame,
        TEST_DMZ_ZONE_ID,
        false,
        SCHED_RECEIPT_NS,
        Some(&alias),
    ) {
        ForeignHitVerdict::Drop(deny) => assert_eq!(
            (deny.judged_from_zone, deny.judged_to_zone),
            (TEST_DMZ_ZONE_ID, TEST_LAN_ZONE_ID),
            "foreign REVERSE must judge the WAN responder, not the alias"
        ),
        _ => panic!("foreign reverse must judge the wire responder and drop"),
    }
}

#[test]
fn drop_foreign_knob_turns_a_permitted_foreign_hit_into_a_drop_16044() {
    // Same fixture as foreign_hit_verdict_uses_descriptor_time_12868: at
    // SCHED_RECEIPT_NS the dmz -> wan `allow-other` permit is live, so the
    // default (knob off) adjudicates in place and forwards.
    let metadata = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    let flow = icmp_flow();
    let frame = icmp_echo_frame();
    let decision = forward_decision();
    let sessions = SessionTable::new();
    let key = flow.forward_key.clone();
    let mut fw = scheduled_icmp_forwarding();
    assert!(
        matches!(
            foreign_hit_verdict(
                &fw,
                &sessions,
                &key,
                &metadata,
                decision,
                &flow,
                icmp_meta(),
                &frame,
                TEST_DMZ_ZONE_ID,
                false,
                SCHED_RECEIPT_NS,
            None,
            ),
            ForeignHitVerdict::Forward
        ),
        "control: knob off keeps adjudicate-in-place forwarding"
    );
    fw.drop_foreign_session_hits = true;
    assert!(
        matches!(
            foreign_hit_verdict(
                &fw,
                &sessions,
                &key,
                &metadata,
                decision,
                &flow,
                icmp_meta(),
                &frame,
                TEST_DMZ_ZONE_ID,
                false,
                SCHED_RECEIPT_NS,
            None,
            ),
            ForeignHitVerdict::DropForeign
        ),
        "knob on: a policy-permitted foreign hit is dropped, not forwarded on the owner's entry"
    );
    // Deny arm unchanged: at the expired instant the permit no longer
    // matches, so the verdict stays the attributed Drop, knob or not.
    assert!(
        matches!(
            foreign_hit_verdict(
                &fw,
                &sessions,
                &key,
                &metadata,
                decision,
                &flow,
                icmp_meta(),
                &frame,
                TEST_DMZ_ZONE_ID,
                false,
                SCHED_EXPIRED_NS,
            None,
            ),
            ForeignHitVerdict::Drop(_)
        ),
        "knob on: a denied foreign hit keeps its attributed Drop shape"
    );
    // Host-bound exemption: a LocalDelivery foreign hit is judged by the
    // arrival zone's host-inbound plane downstream, never here.
    let mut host_decision = forward_decision();
    host_decision.resolution.disposition = ForwardingDisposition::LocalDelivery;
    assert!(
        matches!(
            foreign_hit_verdict(
                &fw,
                &sessions,
                &key,
                &metadata,
                host_decision,
                &flow,
                icmp_meta(),
                &frame,
                TEST_DMZ_ZONE_ID,
                false,
                SCHED_RECEIPT_NS,
                None,
            ),
            ForeignHitVerdict::Forward
        ),
        "knob on: host-bound foreign hits still pass to the host-inbound gate"
    );
}

fn cookie_resolution(disposition: ForwardingDisposition) -> ForwardingResolution {
    ForwardingResolution {
        disposition,
        local_ifindex: 0,
        egress_ifindex: WAN,
        tx_ifindex: WAN,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}

fn cookie_flow() -> SessionFlow {
    SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            src_port: 49152,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

#[test]
fn syn_cookie_final_admission_uses_translated_tuple_15947() {
    // The raw destination is in dmz, whose dmz->wan rule permits any.
    // The translated destination remains in wan at the resolution's
    // egress interface, but lan->wan also permits in this fixture's
    // deny snapshot only via allow-other dmz->wan; use arrival on DMZ
    // (egress WAN) and a translated dst that still resolves dmz->wan.
    // The point of the unit is that the helper evaluates the caller-
    // supplied effective tuple, not flow.dst_ip: deny by choosing a
    // source in lan (no lan->wan permit in this snapshot).
    let fw = forwarding(false);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: LAN_A as u32,
        ingress_vlan_id: 0,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let ha = std::collections::BTreeMap::new();
    // lan -> wan has no permit in policy_deny_snapshot (only dmz->wan),
    // so even a ForwardCandidate resolution must suppress the ACK-RST.
    assert!(!super::syn_cookie_final_admission(
        &fw,
        &ha,
        &flow,
        meta,
        None,
        false,
        false,
        0,
        cookie_resolution(ForwardingDisposition::ForwardCandidate),
        flow.dst_ip,
        443,
        None,
        1_000,
        128,
    ));
    // Same call from the dmz arrival interface: the dmz->wan permit
    // admits the translated tuple.
    let mut meta_dmz = meta;
    meta_dmz.ingress_ifindex = DMZ as u32;
    // DMZ is an interface ifindex (26) whose zone is dmz; the source IP
    // still belongs to the flow, but policy matches zones, not address
    // ownership, for this helper.
    assert!(super::syn_cookie_final_admission(
        &fw,
        &ha,
        &flow,
        meta_dmz,
        None,
        false,
        false,
        0,
        cookie_resolution(ForwardingDisposition::ForwardCandidate),
        flow.dst_ip,
        443,
        None,
        1_000,
        128,
    ));
    // LocalDelivery does not demand a transit permit.
    assert!(super::syn_cookie_final_admission(
        &fw,
        &ha,
        &flow,
        meta,
        None,
        false,
        false,
        0,
        cookie_resolution(ForwardingDisposition::LocalDelivery),
        flow.dst_ip,
        443,
        None,
        1_000,
        128,
    ));
    // HA-inactive / no-route dispositions never earn a reply.
    for disposition in [
        ForwardingDisposition::HAInactive,
        ForwardingDisposition::NoRoute,
        ForwardingDisposition::PolicyDenied,
    ] {
        assert!(!super::syn_cookie_final_admission(
            &fw,
            &ha,
            &flow,
            meta_dmz,
            None,
            false,
            false,
            0,
            cookie_resolution(disposition),
            flow.dst_ip,
            443,
            None,
            1_000,
            128,
        ));
    }
}

#[test]
fn shared_transit_admission_keeps_class_and_policy_tuples_separate_17017() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.policies[0].destination_addresses = vec!["198.51.100.77".into()];
    let fw = build_forwarding_state(&snapshot);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: DMZ as u32,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let resolution = cookie_resolution(ForwardingDisposition::ForwardCandidate);
    let verdict = |class_dst, policy_dst| {
        super::session_admission::transit_admission_verdict(
            &fw,
            &super::session_admission::AdmissionInput {
                flow: &flow,
                meta: meta.into(),
                resolution,
                class_dst,
                translated_dst: None,
                policy_dst,
                protocol: meta.protocol,
                policy_dst_port: flow.forward_key.dst_port,
                policy_icmp: None,
                from_zone_id: TEST_DMZ_ZONE_ID,
                to_zone_id: TEST_WAN_ZONE_ID,
                fabric_arrival_zone: None,
                now_ns: 1_000,
            },
            None,
        )
        .permits()
    };

    let translated = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    assert!(
        verdict(flow.dst_ip, translated),
        "raw non-martian class tuple does not replace the translated policy tuple"
    );
    assert!(
        !verdict(flow.dst_ip, flow.dst_ip),
        "policy evaluates its explicit tuple, not the destination-class tuple"
    );
    assert!(
        !verdict(IpAddr::V4(Ipv4Addr::BROADCAST), translated),
        "the destination-class tuple is evaluated independently of policy"
    );
}

#[test]
fn syn_cookie_prescreen_defers_policy_until_effective_destination_17920() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth2.0".into(),
        zone: "dmz".into(),
        linux_name: "ge-0-0-2".into(),
        ifindex: DMZ,
        ..Default::default()
    });
    snapshot.policies[0].destination_addresses = vec!["198.51.100.77/32".into()];
    let fw = build_forwarding_state(&snapshot);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: DMZ as u32,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let sessions = SessionTable::new();
    assert!(
        super::syn_cookie_challenge_is_session_miss(&sessions, Some(&flow), 1_000),
        "the pre-translation prescreen must defer policy until admission knows the effective destination"
    );
    // The raw tuple ends in .20. The NAT rewrite destination is .88, while
    // the resolution's effective policy destination is .77 (the only address
    // permitted by the rule); ordinary miss policy evaluates the latter.
    let effective_dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    let rewrite_dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
    let resolution = cookie_resolution(ForwardingDisposition::ForwardCandidate);
    let (from_zone_id, to_zone_id) =
        super::session_miss_zone_pair_ids(&fw, DMZ, None, resolution);
    let miss_policy = crate::policy::evaluate_policy_result_without_counting_at(
        &fw.policy,
        from_zone_id,
        to_zone_id,
        flow.src_ip,
        effective_dst,
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        None,
        1_000,
    );
    assert_eq!(miss_policy.action, crate::policy::PolicyAction::Permit);
    assert!(super::syn_cookie_final_admission(
        &fw,
        &std::collections::BTreeMap::new(),
        &flow,
        meta,
        None,
        false,
        false,
        0,
        resolution,
        effective_dst,
        flow.forward_key.dst_port,
        Some(rewrite_dst),
        1_000,
        128,
    ));
}

fn fabric_cookie_forwarding_state(with_tunnel_ingress: bool) -> ForwardingState {
    let mut snapshot = nat_snapshot_with_fabric();
    snapshot.zones.push(ZoneSnapshot {
        name: "dmz".into(),
        id: TEST_DMZ_ZONE_ID,
        ..Default::default()
    });
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth2.0".into(),
        zone: "dmz".into(),
        egress_zone: "dmz".into(),
        linux_name: "ge-0-0-2".into(),
        ifindex: DMZ,
        hardware_addr: "02:bf:72:02:00:02".into(),
        ..Default::default()
    });
    let fabric_parent = snapshot
        .interfaces
        .iter_mut()
        .find(|iface| iface.ifindex == 21)
        .expect("fabric parent exists in fixture");
    fabric_parent.zone = "dmz".into();
    if with_tunnel_ingress {
        snapshot.interfaces.push(InterfaceSnapshot {
            name: "tun-17920".into(),
            zone: "dmz".into(),
            egress_zone: "dmz".into(),
            ifindex: TUNNEL_INGRESS,
            ..Default::default()
        });
    }
    snapshot.policies.clear();
    snapshot.policies.push(PolicyRuleSnapshot {
        from_zone: "dmz".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["any".into()],
        action: "permit".into(),
        name: "permit-real-route-zone".into(),
        ..PolicyRuleSnapshot::default()
    });
    let mut forwarding = build_forwarding_state(&snapshot);
    if with_tunnel_ingress {
        forwarding
            .tunnel_endpoint_by_ifindex
            .insert(TUNNEL_INGRESS, 1);
    }
    forwarding
}

#[test]
fn admission_zone_pair_follows_finalized_ha_resolution_17920() {
    let fw = fabric_cookie_forwarding_state(false);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: DMZ as u32,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let now_secs = 128;
    let now_ns = 1_000;
    let ha = std::collections::BTreeMap::from([(
        1,
        crate::afxdp::HAGroupRuntime {
            active: false,
            watchdog_timestamp: now_secs,
            lease: crate::afxdp::HAForwardingLease::Inactive,
        },
    )]);
    let routed = crate::afxdp::forwarding::lookup_forwarding_resolution(&fw, flow.dst_ip).resolution;
    assert_eq!(routed.disposition, ForwardingDisposition::ForwardCandidate);
    let (pre_from, pre_to) =
        zone_pair_ids_for_flow_with_override(&fw, DMZ, None, routed.egress_ifindex);
    assert_eq!((pre_from, pre_to), (TEST_DMZ_ZONE_ID, TEST_WAN_ZONE_ID));
    let pre_policy = crate::policy::evaluate_policy_result_without_counting_at(
        &fw.policy,
        pre_from,
        pre_to,
        flow.src_ip,
        flow.dst_ip,
        flow.forward_key.protocol,
        flow.forward_key.src_port,
        flow.forward_key.dst_port,
        None,
        now_ns,
    );
    assert_eq!(pre_policy.action, crate::policy::PolicyAction::Permit);

    let finalized = crate::afxdp::forwarding::finalize_new_flow_ha_resolution(
        &fw,
        &ha,
        now_secs,
        routed,
        false,
        false,
        DMZ,
        pre_from,
        0,
    );
    assert_eq!(
        finalized.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(finalized.egress_ifindex, 21);
    assert_eq!(fw.egress_zone_id(finalized.egress_ifindex), 0);
    let (from_zone_id, to_zone_id) =
        super::session_miss_zone_pair_ids(&fw, DMZ, None, finalized);
    assert_eq!(
        (from_zone_id, to_zone_id),
        (TEST_DMZ_ZONE_ID, 0),
        "HA redirect uses the real fabric parent egress zone"
    );
    let admission = super::session_admission::transit_admission_verdict(
        &fw,
        &super::session_admission::AdmissionInput {
            flow: &flow,
            meta: meta.into(),
            resolution: finalized,
            class_dst: flow.dst_ip,
            translated_dst: None,
            policy_dst: flow.dst_ip,
            protocol: flow.forward_key.protocol,
            policy_dst_port: flow.forward_key.dst_port,
            policy_icmp: None,
            from_zone_id,
            to_zone_id,
            fabric_arrival_zone: None,
            now_ns,
        },
        None,
    );
    // The shared MISS verdict still delegates FabricRedirect policy to
    // the peer: no local policy result, class-only permission to punt.
    assert!(
        admission.policy_result.is_none(),
        "the ordinary miss path delegates policy for a FabricRedirect"
    );
    assert!(admission.permits());
    // A locally emitted cookie reply is different: it is consumed here,
    // so it needs authorization on the FINALIZED pair. The fabric
    // parent's egress zone is 0, so the dmz->wan permit does not cover
    // (dmz, 0) and the default policy denies the reply.
    assert!(
        !super::syn_cookie_final_admission(
            &fw,
            &ha,
            &flow,
            meta,
            None,
            false,
            false,
            0,
            routed,
            flow.dst_ip,
            flow.forward_key.dst_port,
            None,
            now_ns,
            now_secs,
        ),
        "a FabricRedirect cookie reply must not be emitted without a finalized-pair permit"
    );
}

#[test]
fn syn_cookie_ha_finalizer_receives_fabric_ingress_context_17920() {
    let fw = fabric_cookie_forwarding_state(false);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: 21,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let now_secs = 128;
    let now_ns = 1_000;
    let ha = std::collections::BTreeMap::from([(
        1,
        crate::afxdp::HAGroupRuntime {
            active: false,
            watchdog_timestamp: 0,
            lease: crate::afxdp::HAForwardingLease::Inactive,
        },
    )]);
    let routed = crate::afxdp::forwarding::lookup_forwarding_resolution(&fw, flow.dst_ip).resolution;
    assert_eq!(
        crate::afxdp::forwarding::gate_fabric_zone_override_on_owner_rg(
            &fw,
            &ha,
            now_secs,
            Some(TEST_DMZ_ZONE_ID),
            routed,
        ),
        None,
        "the inactive owner gates the encoded zone; the configured fabric zone governs"
    );
    let ingress_zone_override = None;
    assert_eq!(
        zone_pair_ids_for_flow_with_override(
            &fw,
            meta.ingress_ifindex as i32,
            ingress_zone_override,
            routed.egress_ifindex,
        ),
        (TEST_DMZ_ZONE_ID, TEST_WAN_ZONE_ID),
        "the test admission pair comes from the fabric parent’s configured zone"
    );
    assert!(
        super::syn_cookie_final_admission(
            &fw,
            &ha,
            &flow,
            meta,
            ingress_zone_override,
            true,
            true,
            0,
            routed,
            flow.dst_ip,
            flow.forward_key.dst_port,
            None,
            now_ns,
            now_secs,
        ),
        "the fabric-ingress ACK's locally authorized dmz->wan reply remains admissible"
    );
}

#[test]
fn syn_cookie_ha_finalizer_preserves_tunnel_startup_grace_17920() {
    let fw = fabric_cookie_forwarding_state(true);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: TUNNEL_INGRESS as u32,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let now_secs = 128;
    let now_ns = 1_000;
    let grace_until_secs = 200;
    let ha = std::collections::BTreeMap::from([(
        1,
        crate::afxdp::HAGroupRuntime {
            active: false,
            watchdog_timestamp: 0,
            lease: crate::afxdp::HAForwardingLease::Inactive,
        },
    )]);
    let routed = crate::afxdp::forwarding::lookup_forwarding_resolution(&fw, flow.dst_ip).resolution;
    assert!(
        super::syn_cookie_final_admission(
            &fw,
            &ha,
            &flow,
            meta,
            None,
            false,
            false,
            grace_until_secs,
            routed,
            flow.dst_ip,
            flow.forward_key.dst_port,
            None,
            now_ns,
            now_secs,
        ),
        "the cookie helper must retain the session-miss startup-grace decision"
    );
    assert!(
        !super::syn_cookie_final_admission(
            &fw,
            &ha,
            &flow,
            meta,
            None,
            false,
            false,
            0,
            routed,
            flow.dst_ip,
            flow.forward_key.dst_port,
            None,
            now_ns,
            now_secs,
        ),
        "without startup grace the locally consumed cookie reply needs a permit for (dmz, 0)"
    );
}

#[test]
fn syn_cookie_missing_neighbor_preserves_local_policy_gate_17920() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth2.0".into(),
        zone: "dmz".into(),
        linux_name: "ge-0-0-2".into(),
        ifindex: DMZ,
        ..Default::default()
    });
    snapshot.policies[0].action = "deny".into();
    let fw = build_forwarding_state(&snapshot);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: DMZ as u32,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let resolution = cookie_resolution(ForwardingDisposition::MissingNeighbor);
    let (from_zone_id, to_zone_id) =
        super::session_miss_zone_pair_ids(&fw, DMZ, None, resolution);
    let verdict = super::session_admission::transit_admission_verdict(
        &fw,
        &super::session_admission::AdmissionInput {
            flow: &flow,
            meta: meta.into(),
            resolution,
            class_dst: flow.dst_ip,
            translated_dst: None,
            policy_dst: flow.dst_ip,
            protocol: flow.forward_key.protocol,
            policy_dst_port: flow.forward_key.dst_port,
            policy_icmp: None,
            from_zone_id,
            to_zone_id,
            fabric_arrival_zone: None,
            now_ns: 1_000,
        },
        None,
    );
    assert_eq!(
        verdict.policy_result.expect("MissingNeighbor evaluates policy").action,
        crate::policy::PolicyAction::Deny
    );
    assert!(!verdict.permits());
    assert!(!super::syn_cookie_final_admission(
        &fw,
        &std::collections::BTreeMap::new(),
        &flow,
        meta,
        None,
        false,
        false,
        0,
        resolution,
        flow.dst_ip,
        flow.forward_key.dst_port,
        None,
        1_000,
        128,
    ));
}


#[test]
fn syn_cookie_matches_session_miss_when_untranslated_17017() {
    let fw = forwarding(false);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: DMZ as u32,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let resolution = cookie_resolution(ForwardingDisposition::ForwardCandidate);
    let cookie_admitted = super::syn_cookie_final_admission(
        &fw,
        &std::collections::BTreeMap::new(),
        &flow,
        meta,
        None,
        false,
        false,
        0,
        resolution,
        flow.dst_ip,
        flow.forward_key.dst_port,
        None,
        1_000,
        128,
    );
    let class = super::session_admission::transit_class_verdict(
        &fw,
        &flow,
        meta.into(),
        resolution,
        flow.dst_ip,
        None,
        None,
    );
    let miss_verdict = super::session_admission::transit_admission_verdict(
        &fw,
        &super::session_admission::AdmissionInput {
            flow: &flow,
            meta: meta.into(),
            resolution,
            class_dst: flow.dst_ip,
            translated_dst: None,
            policy_dst: flow.dst_ip,
            protocol: flow.forward_key.protocol,
            policy_dst_port: flow.forward_key.dst_port,
            policy_icmp: None,
            from_zone_id: TEST_DMZ_ZONE_ID,
            to_zone_id: TEST_WAN_ZONE_ID,
            fabric_arrival_zone: None,
            now_ns: 1_000,
        },
        Some(class),
    );
    assert_eq!(
        cookie_admitted,
        miss_verdict.permits(),
        "the unchanged untranslated dmz->wan case remains parity-pinned"
    );
}

#[test]
fn syn_cookie_host_admission_three_arm_15947() {
    // Accept: fixture zones carry any-service host-inbound and no lo0
    // reject for TCP/443, so a local service is admissible.
    let fw_accept = forwarding(false);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: LAN_A as u32,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let mut frame = vec![0u8; 54];
    frame[14] = 0x45;
    assert!(super::syn_cookie_host_admission(
        &fw_accept, &flow, &frame, meta, None, flow.dst_ip, 443, 1_000,
    ), "host accept arm");

    // Host-inbound deny: remove any-service from lan by using a zone set
    // with no admitted TCP/443 service. The helper must fail closed.
    let mut denied = forwarding(false);
    denied.zone_host_inbound.insert(TEST_LAN_ZONE_ID, Default::default());
    assert!(!super::syn_cookie_host_admission(
        &denied, &flow, &frame, meta, None, flow.dst_ip, 443, 1_000,
    ), "host-inbound deny arm");

    // Lo0 deny: compile a protect-re reject for TCP/443 while keeping
    // host-inbound permissive; the lo0 verdict must suppress the reply.
    let mut lo0_denied = forwarding(false);
    lo0_denied.filter_state = crate::filter::parse_filter_state(
        &[crate::FirewallFilterSnapshot {
            name: "protect-re".into(),
            family: "inet".into(),
            terms: vec![crate::FirewallTermSnapshot {
                name: "deny-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "reject".into(),
                ..Default::default()
            }],
        }],
        &[],
        &[],
        "protect-re",
        "",
    ).expect("lo0 filter compiles");
    assert!(!super::syn_cookie_host_admission(
        &lo0_denied, &flow, &frame, meta, None, flow.dst_ip, 443, 1_000,
    ), "lo0 deny arm");
}

#[test]
fn syn_cookie_final_admission_fence_suppresses_challenge_15947() {
    // A Permit resolution that matches an unconditional miss-path drop
    // gate (L2 group / IPsec selector fence, represented by the caller's
    // fence_dropped evaluation) must not earn a challenge SYN-ACK.
    let fw = forwarding(false);
    let flow = cookie_flow();
    let meta = UserspaceDpMeta {
        ingress_ifindex: DMZ as u32,
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        pkt_len: 60,
        l3_offset: 14,
        l4_offset: 34,
        ..UserspaceDpMeta::default()
    };
    let ha = std::collections::BTreeMap::new();
    // Control: same tuple without the fence admits (dmz->wan permit).
    assert!(super::syn_cookie_final_admission_with_fence(
        &fw, &ha, &flow, meta, None,
        false, false, 0,
        cookie_resolution(ForwardingDisposition::ForwardCandidate),
        flow.dst_ip,
        443,
        None,
        false,
        1_000,
        128,
    ));
    assert!(!super::syn_cookie_final_admission_with_fence(
        &fw, &ha, &flow, meta, None,
        false, false, 0,
        cookie_resolution(ForwardingDisposition::ForwardCandidate),
        flow.dst_ip,
        443,
        None,
        true,
        1_000,
        128,
    ), "fence-matching Permit must suppress the challenge reply");
}
