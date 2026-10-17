//! #9519: the ownership decision as a pure function. The descriptor cells in
//! `afxdp/tests_session_hit_authority_9519.rs` bind the WIRING; these pin the
//! discriminator's cases a descriptor fixture cannot reach cheaply.

use super::*;
use crate::InterfaceSnapshot;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::policy_deny_snapshot;
use crate::test_zone_ids::*;
use crate::ip_proto::PROTO_ICMP;

/// `reth1.0`, zone `lan`, in `policy_deny_snapshot`.
const LAN_A: i32 = 24;
/// `reth0.80`, zone `wan`, in `policy_deny_snapshot`.
const WAN: i32 = 12;
const LAN_B: i32 = 25;
const DMZ: i32 = 26;
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

fn session(zone: u16, ingress_ifindex: i32, vlan: u16, is_reverse: bool) -> SessionMetadata {
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
    }
}

fn arrival(ifindex: i32, vlan: u16) -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: ifindex as u32,
        ingress_vlan_id: vlan,
        ..UserspaceDpMeta::default()
    }
}

fn foreign(arrival_zone: u16, on_admitting_interface: bool) -> HitAuthority {
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
        fw.policy
            .icmp_packet_verdict_may_depend_on_type(PROTO_ICMP),
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
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: crate::nat::NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
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
            &fw, &metadata, decision, &flow, icmp_meta(), &frame, SCHED_RECEIPT_NS,
        ),
        Some(OwnerHitIcmpVerdict::Forward),
        "at the fresh descriptor time the scheduled permit is live"
    );
    assert!(matches!(
        owner_hit_icmp_verdict(
            &fw, &metadata, decision, &flow, icmp_meta(), &frame, SCHED_EXPIRED_NS,
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
            &fw, &metadata, decision, &flow, icmp_meta(), &frame, SCHED_RECEIPT_NS,
        ),
        Some(OwnerHitIcmpVerdict::Forward),
        "reverse non-answer at fresh descriptor time uses the scheduled permit"
    );
    assert!(matches!(
        owner_hit_icmp_verdict(
            &fw, &metadata, decision, &flow, icmp_meta(), &frame, SCHED_EXPIRED_NS,
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
            &fw, &sessions, &key, &metadata, decision, &flow, icmp_meta(), &frame,
            TEST_DMZ_ZONE_ID, false, SCHED_RECEIPT_NS,
        ),
        ForeignHitVerdict::Forward
    ));
    assert!(matches!(
        foreign_hit_verdict(
            &fw, &sessions, &key, &metadata, decision, &flow, icmp_meta(), &frame,
            TEST_DMZ_ZONE_ID, false, SCHED_EXPIRED_NS,
        ),
        ForeignHitVerdict::Drop(_)
    ));
}
