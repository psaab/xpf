//! #9519: the ownership decision as a pure function. The descriptor cells in
//! `afxdp/tests_session_hit_authority_9519.rs` bind the WIRING; these pin the
//! discriminator's cases a descriptor fixture cannot reach cheaply.

use super::*;
use crate::InterfaceSnapshot;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::policy_deny_snapshot;
use crate::test_zone_ids::*;

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
        ingress_ifindex: ingress_ifindex as u32,
        ingress_vlan_id: vlan,
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
        session_hit_authority(&fw, &lan, SessionOrigin::ForwardFlow, arrival(LAN_A, 0), false),
        HitAuthority::Owner,
        "control: the admitting interface in the admitting zone is the owner"
    );
    assert_eq!(
        session_hit_authority(&fw, &lan, SessionOrigin::ForwardFlow, arrival(DMZ, 0), false),
        foreign(TEST_DMZ_ZONE_ID, false),
        "the same tuple from a dmz interface did not come from the zone that \
         admitted the session, and must be judged as dmz's (#9519)"
    );
}

#[test]
fn fabric_ingress_is_exempt_9519() {
    let fw = forwarding(false);
    let lan = session(TEST_LAN_ZONE_ID, 0, 0, false);
    assert_eq!(
        session_hit_authority(&fw, &lan, SessionOrigin::SyncImport, arrival(DMZ, 0), false),
        foreign(TEST_DMZ_ZONE_ID, false),
        "control: without the fabric flag this arrival is foreign, or the \
         exemption below is asserting nothing"
    );
    assert_eq!(
        session_hit_authority(&fw, &lan, SessionOrigin::SyncImport, arrival(DMZ, 0), true),
        HitAuthority::Owner,
        "a fabric-ingress packet arrives on the fabric link, whose zone is \
         structurally not the flow's. Judging it by that zone drops every \
         cross-chassis session — TCP death on failback (#9519, as #7169/#9384)"
    );
}

#[test]
fn a_second_interface_in_the_admitting_zone_is_an_owner_9519() {
    let fw = forwarding(false);
    let lan = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    assert_eq!(
        session_hit_authority(&fw, &lan, SessionOrigin::ForwardFlow, arrival(LAN_B, 0), false),
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
        session_hit_authority(&fw, &lan, SessionOrigin::ForwardFlow, arrival(LAN_A, 0), false),
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
            session_hit_authority(&fw, &lan, origin, arrival(LAN_A, 0), false),
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
        session_hit_authority(&fw, &import, SessionOrigin::SyncImport, arrival(WAN, 0), false),
        HitAuthority::Owner,
        "control: the import's packets arriving in wan here are its owner"
    );
    assert_eq!(
        session_hit_authority(&fw, &import, SessionOrigin::SyncImport, arrival(LAN_A, 0), false),
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
        session_hit_authority(&fw, &unit, SessionOrigin::ForwardFlow, arrival(TRUNK, LAN_VLAN), false),
        HitAuthority::Owner,
        "control: the lan unit's own VLAN is the owner"
    );
    assert_eq!(
        session_hit_authority(&fw, &unit, SessionOrigin::ForwardFlow, arrival(TRUNK, DMZ_VLAN), false),
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
        session_hit_authority(&fw, &reverse, SessionOrigin::ReverseFlow, arrival(WAN, 0), false),
        HitAuthority::Owner,
        "control: the reply from wan, where the flow went, is the owner"
    );
    assert_eq!(
        session_hit_authority(&fw, &reverse, SessionOrigin::ReverseFlow, arrival(DMZ, 0), false),
        foreign(TEST_DMZ_ZONE_ID, false),
        "a reply must come back from where the flow went — #7169's rule for the \
         reverse fallback, now on the direct reverse hit (#9519)"
    );
}

#[test]
fn an_arrival_that_resolves_to_no_zone_is_foreign_9519() {
    let fw = forwarding(false);
    let lan = session(TEST_LAN_ZONE_ID, LAN_A, 0, false);
    assert_eq!(
        session_hit_authority(&fw, &lan, SessionOrigin::ForwardFlow, arrival(NOT_CONFIGURED, 0), false),
        foreign(0, false),
        "an arrival the box puts in no zone cannot be the lan session's owner; it \
         is judged as a zone-0 arrival, which policy refuses to match (#3110)"
    );
}
