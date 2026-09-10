//! #9519: an established-session HIT must be validated against the packet's
//! live ingress authority — bound through the REAL poll path.
//!
//! Fixture: the inbound DNAT service of the #9382 cells. A client on the WAN
//! (`reth0.80`, zone `wan`) reaches `172.16.80.8:443`, translated to
//! `10.0.61.102:8443` behind `reth1.0` (zone `lan`). A third interface,
//! `reth2.0` in zone `dmz`, is the FOREIGN arrival: the same 5-tuple presented
//! from a zone that did not admit the flow.
//!
//! Instruments are the poll's own counters — `tx` (forwarded),
//! `policy_revoked_sessions`, `filter_revoked_sessions`, `host_inbound_deny`,
//! `foreign_authority_drops` — and the session table's row count. Every cell
//! carries a positive control on the same table, so a zero cannot come from a
//! fixture that forwards nothing. The PRIMARY assertion of each cell is written
//! on a counter that exists without this change, so the cell also reds at base
//! for the stated reason rather than failing to compile.

#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::tcp_flags::TCP_ACK;
use crate::test_zone_ids::*;
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceSnapshot, PolicyRuleSnapshot,
    ZoneSnapshot,
};
use std::net::Ipv4Addr;

const WAN_IFINDEX: i32 = 12;
const LAN_IFINDEX: i32 = 24;
const DMZ_IFINDEX: i32 = 26;
const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const VIP: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 8);
const REAL: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 102);
const LAN_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 61, 1);
const CLIENT_PORT: u16 = 54321;
const VIP_PORT: u16 = 443;
const REAL_PORT: u16 = 8443;

#[derive(Clone, Copy)]
struct Posture {
    wan_permit: bool,
    dmz_permit: bool,
    dmz_filter_discards_443: bool,
    dmz_host_inbound: bool,
    dmz_junos_host_deny: bool,
    lo0_discards_ssh: bool,
}

const WAN_ONLY: Posture = Posture {
    wan_permit: true,
    dmz_permit: false,
    dmz_filter_discards_443: false,
    dmz_host_inbound: true,
    dmz_junos_host_deny: false,
    lo0_discards_ssh: false,
};

fn forwarding(p: Posture) -> ForwardingState {
    let mut s = inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.102/32", "wan-in"));
    if !p.wan_permit {
        s.policies.retain(|rule| rule.from_zone != "wan");
    }
    s.zones.push(ZoneSnapshot {
        name: "dmz".to_string(),
        id: TEST_DMZ_ZONE_ID,
        host_inbound_configured: true,
        host_inbound_system_services: if p.dmz_host_inbound {
            vec!["any-service".to_string()]
        } else {
            Vec::new()
        },
        ..Default::default()
    });
    s.interfaces.push(InterfaceSnapshot {
        name: "reth2.0".to_string(),
        zone: "dmz".to_string(),
        linux_name: "ge-0-0-2".to_string(),
        ifindex: DMZ_IFINDEX,
        mtu: 1500,
        hardware_addr: "02:bf:72:02:00:01".to_string(),
        filter_input_v4: if p.dmz_filter_discards_443 {
            "dmz-edge".to_string()
        } else {
            String::new()
        },
        ..Default::default()
    });
    if p.dmz_permit {
        s.policies.push(PolicyRuleSnapshot {
            name: "dmz-in".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "lan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["10.0.61.102/32".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        });
    }
    if p.dmz_filter_discards_443 {
        s.filters.push(FirewallFilterSnapshot {
            name: "dmz-edge".to_string(),
            family: "inet".to_string(),
            terms: vec![FirewallTermSnapshot {
                name: "no-443".to_string(),
                protocols: vec!["tcp".to_string()],
                destination_ports: vec!["443".to_string()],
                action: "discard".to_string(),
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            }],
        });
    }
    if p.dmz_junos_host_deny {
        s.policies.push(PolicyRuleSnapshot {
            name: "dmz-no-host".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "junos-host".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "deny".to_string(),
            ..Default::default()
        });
    }
    if p.lo0_discards_ssh {
        s.filters.push(FirewallFilterSnapshot {
            name: "protect-re".to_string(),
            family: "inet".to_string(),
            terms: vec![FirewallTermSnapshot {
                name: "no-ssh".to_string(),
                protocols: vec!["tcp".to_string()],
                destination_ports: vec!["22".to_string()],
                action: "discard".to_string(),
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            }],
        });
        s.flow.lo0_filter_input_v4 = "protect-re".to_string();
    }
    build_forwarding_state(&s)
}

fn binding(ifindex: i32) -> BindingWorker {
    let mut b = BindingWorker::new_for_mirror_test(0, 0, ifindex, 0);
    b.interface = Arc::<str>::from(match ifindex {
        WAN_IFINDEX => "reth0.80",
        LAN_IFINDEX => "reth1.0",
        _ => "reth2.0",
    });
    b
}

fn tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
    arrival: i32,
) -> (Vec<u8>, UserspaceDpMeta) {
    let frame = build_txn_tcp_syn_frame_v4(src, dst, sport, dport, flags);
    let meta = txn_meta_v4(arrival as u32, flags, frame.len() as u16);
    (frame, meta)
}

fn client_ack(arrival: i32) -> (Vec<u8>, UserspaceDpMeta) {
    tcp(CLIENT, VIP, CLIENT_PORT, VIP_PORT, TCP_ACK, arrival)
}

fn server_ack(arrival: i32) -> (Vec<u8>, UserspaceDpMeta) {
    tcp(REAL, CLIENT, REAL_PORT, CLIENT_PORT, TCP_ACK, arrival)
}

fn drive_on(
    b: &mut BindingWorker,
    fw: &ForwardingState,
    sessions: &mut SessionTable,
    packet: (Vec<u8>, UserspaceDpMeta),
) -> DebugPollCounters {
    let ha_state = txn_ha_state();
    let (_batch, dbg) = txn_run_descriptor(b, sessions, fw, &ha_state, &packet.0, packet.1);
    dbg
}

/// A fresh binding per packet, so a flow-cache entry one packet seeded cannot
/// serve the next. The seeding cell is the one place that reuses a binding.
fn drive(
    fw: &ForwardingState,
    sessions: &mut SessionTable,
    packet: (Vec<u8>, UserspaceDpMeta),
) -> DebugPollCounters {
    let mut b = binding(packet.1.ingress_ifindex as i32);
    drive_on(&mut b, fw, sessions, packet)
}

fn session_count(sessions: &SessionTable) -> usize {
    let mut n = 0;
    sessions.iter_with_origin(|_k, _d, _m, _o| n += 1);
    n
}

/// Admit the WAN client's SYN under `fw`; returns the table holding the pair.
fn admitted(fw: &ForwardingState) -> SessionTable {
    let mut sessions = SessionTable::new();
    let dbg = drive(
        fw,
        &mut sessions,
        tcp(CLIENT, VIP, CLIENT_PORT, VIP_PORT, TCP_FLAG_SYN, WAN_IFINDEX),
    );
    assert_eq!(
        dbg.tx, 1,
        "the WAN SYN must be ADMITTED and forwarded, or nothing below exercises an \
         established session"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "admission must install the forward + reverse pair"
    );
    sessions
}

#[test]
fn a_denied_zone_cannot_ride_another_zones_validated_session_9519() {
    let fw = forwarding(WAN_ONLY);
    let mut sessions = admitted(&fw);
    let owner = drive(&fw, &mut sessions, client_ack(WAN_IFINDEX));
    assert_eq!(
        owner.tx, 1,
        "control: the owner's ACK forwards — and re-derives the entry, so it is now \
         FRESH for this generation, the state in which the issue says nothing is \
         checked at all"
    );
    let foreign = drive(&fw, &mut sessions, client_ack(DMZ_IFINDEX));
    assert_eq!(
        foreign.session_hit, 1,
        "the dmz packet must HIT the wan session, or this cell is exercising the \
         miss path rather than the defect"
    );
    assert_eq!(
        foreign.tx, 0,
        "dmz has no policy to lan. Forwarding this packet means it inherited wan's \
         permit and DNAT from a live session without dmz's policy ever being asked \
         (#9519)"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "the refusal drops the packet, not the session"
    );
    assert_eq!(
        foreign.foreign_authority_drops, 1,
        "and it is counted as a foreign-authority drop"
    );
}

#[test]
fn a_foreign_packet_does_not_revoke_the_session_it_hit_9519() {
    let fw = forwarding(WAN_ONLY);
    let mut sessions = admitted(&fw);
    let foreign = drive(&fw, &mut sessions, client_ack(DMZ_IFINDEX));
    assert_eq!(
        foreign.session_hit, 1,
        "the dmz packet must HIT the not-yet-revalidated wan session"
    );
    assert_eq!(
        foreign.policy_revoked_sessions, 0,
        "the session belongs to wan, and a packet from dmz cannot speak for it. On \
         3b24fe26e this was 1: one ACK spoofed from dmz tore down wan's live flow, \
         because #9384 re-derives from the packet's arrival zone and nothing \
         checked the packet belonged to the session (#9519)"
    );
    assert_eq!(
        session_count(&sessions),
        2,
        "the wan pair must still be installed"
    );
    assert_eq!(foreign.tx, 0, "the dmz packet itself is not forwarded");
    let owner = drive(&fw, &mut sessions, client_ack(WAN_IFINDEX));
    assert_eq!(
        owner.tx, 1,
        "and the owner is still SERVED: the survival is functional, not a row count"
    );
    assert_eq!(foreign.foreign_authority_drops, 1);
}

#[test]
fn a_foreign_zones_permit_does_not_shield_the_owner_from_its_own_policy_9519() {
    let admitted_under = forwarding(Posture {
        dmz_permit: true,
        ..WAN_ONLY
    });
    let mut sessions = admitted(&admitted_under);
    // The operator withdraws wan's access to the server; dmz keeps its own.
    let live = forwarding(Posture {
        wan_permit: false,
        dmz_permit: true,
        ..WAN_ONLY
    });
    let foreign = drive(&live, &mut sessions, client_ack(DMZ_IFINDEX));
    assert_eq!(foreign.session_hit, 1, "the dmz packet must HIT the wan session");
    assert_eq!(
        foreign.tx, 1,
        "dmz IS permitted to the server, so its packet is forwarded: a foreign \
         arrival is adjudicated, not blanket-dropped (#9519)"
    );
    assert_eq!(foreign.policy_revoked_sessions, 0);
    let owner = drive(&live, &mut sessions, client_ack(WAN_IFINDEX));
    assert_eq!(
        owner.policy_revoked_sessions, 1,
        "wan's permit was withdrawn, so the OWNER's next packet must revoke. 0 \
         means dmz's permit re-derived and re-stamped wan's entry FRESH and shielded \
         it from wan's own narrowed policy (#9519)"
    );
    assert_eq!(session_count(&sessions), 0, "the revoked pair must be torn down");
}

#[test]
fn a_reply_from_a_zone_the_flow_did_not_go_to_is_dropped_9519() {
    let fw = forwarding(WAN_ONLY);
    let mut sessions = admitted(&fw);
    let owner = drive(&fw, &mut sessions, server_ack(LAN_IFINDEX));
    assert_eq!(
        owner.session_hit, 1,
        "control: the server's reply from lan hits the reverse companion"
    );
    assert_eq!(owner.tx, 1, "control: and is forwarded back to the client");
    let foreign = drive(&fw, &mut sessions, server_ack(DMZ_IFINDEX));
    assert_eq!(
        foreign.session_hit, 1,
        "the dmz copy of the reply must HIT the reverse companion"
    );
    assert_eq!(
        foreign.tx, 0,
        "the flow went to lan; a reply arriving from dmz did not come back from \
         where the flow went and has no dmz policy admitting it (#9519, #7169's \
         rule on the direct reverse hit)"
    );
    assert_eq!(session_count(&sessions), 2);
    assert_eq!(foreign.foreign_authority_drops, 1);
    assert_eq!(owner.foreign_authority_drops, 0);
}

#[test]
fn a_foreign_interfaces_static_filter_does_not_revoke_the_owners_session_9519() {
    let fw = forwarding(Posture {
        dmz_permit: true,
        dmz_filter_discards_443: true,
        ..WAN_ONLY
    });
    let mut sessions = admitted(&fw);
    let foreign = drive(&fw, &mut sessions, client_ack(DMZ_IFINDEX));
    assert_eq!(foreign.session_hit, 1, "the dmz packet must HIT the wan session");
    assert_eq!(
        foreign.filter_revoked_sessions, 0,
        "dmz's input filter discards tcp/443 — for dmz's packets. #7212 revoked the \
         session on that verdict, so a packet spoofed onto dmz tore down wan's flow \
         through the FILTER exactly as #9384 did through policy (#9519)"
    );
    assert_eq!(session_count(&sessions), 2);
    assert_eq!(
        foreign.tx, 0,
        "control: dmz is PERMITTED by policy, so only the dmz filter can have \
         dropped this packet — the filter is live, the revocation is what is gone"
    );
    let owner = drive(&fw, &mut sessions, client_ack(WAN_IFINDEX));
    assert_eq!(owner.tx, 1, "and the owner is still served");
}

#[test]
fn a_foreign_packet_never_seeds_the_flow_cache_9519() {
    let fw = forwarding(Posture {
        dmz_permit: true,
        ..WAN_ONLY
    });
    let mut sessions = admitted(&fw);
    let mut wan = binding(WAN_IFINDEX);
    let o1 = drive_on(&mut wan, &fw, &mut sessions, client_ack(WAN_IFINDEX));
    let o2 = drive_on(&mut wan, &fw, &mut sessions, client_ack(WAN_IFINDEX));
    assert_eq!((o1.tx, o2.tx), (1, 1), "control: both owner ACKs forward");
    assert_eq!(
        (o1.session_hit, o2.session_hit),
        (1, 0),
        "control: the OWNER's second ACK on the same binding is served from the \
         flow cache the first one seeded. If both hit the table, this harness does \
         not seed and the foreign assertion below is vacuous"
    );
    let mut dmz = binding(DMZ_IFINDEX);
    let f1 = drive_on(&mut dmz, &fw, &mut sessions, client_ack(DMZ_IFINDEX));
    let f2 = drive_on(&mut dmz, &fw, &mut sessions, client_ack(DMZ_IFINDEX));
    assert_eq!((f1.tx, f2.tx), (1, 1), "dmz is permitted, so both forward");
    assert_eq!(
        f2.session_hit, 1,
        "a FOREIGN packet must never seed the flow cache: the cache keys on logical \
         ingress, so a descriptor seeded here would serve dmz's later packets with no \
         authority check at all (#9519)"
    );
}

/// An SSH session from the lan host to the firewall's own lan address, installed
/// by its handshake SYN. Returned fresh so the caller decides what touches it.
fn host_bound_ssh_session(fw: &ForwardingState) -> SessionTable {
    let mut sessions = SessionTable::new();
    let syn = drive(fw, &mut sessions, ssh(TCP_FLAG_SYN, LAN_IFINDEX));
    assert_eq!(
        (syn.local, session_count(&sessions)),
        (1, 1),
        "the lan host's SSH SYN to the firewall's own lan address must be delivered \
         and install one host-bound session, or nothing below hits one"
    );
    sessions
}

fn ssh(flags: u8, arrival: i32) -> (Vec<u8>, UserspaceDpMeta) {
    tcp(REAL, LAN_ADDRESS, 40000, 22, flags, arrival)
}

/// The owner control and the foreign packets use SEPARATE tables on purpose. On
/// this fixture the owner's own first ACK already tears the host-bound session
/// down, through the #8356 re-derivation judging it by a zone pair; that is not
/// this cell's subject and is #9563. Sequencing the control before
/// the foreign packet would make this cell measure that instead.
#[test]
fn a_foreign_zone_is_held_to_its_own_host_inbound_services_9519() {
    let fw = forwarding(Posture {
        dmz_host_inbound: false,
        ..WAN_ONLY
    });

    let mut control = host_bound_ssh_session(&fw);
    let owner = drive(&fw, &mut control, ssh(TCP_ACK, LAN_IFINDEX));
    assert_eq!(owner.session_hit, 1, "control: the owner's ACK hits the session");
    assert_eq!(
        owner.host_inbound_deny, 0,
        "control: lan admits any-service, so the gate itself is not what denies below"
    );

    let mut sessions = host_bound_ssh_session(&fw);
    let foreign = drive(&fw, &mut sessions, ssh(TCP_ACK, DMZ_IFINDEX));
    assert_eq!(
        foreign.session_hit, 1,
        "the dmz packet must HIT lan's host-bound session"
    );
    assert_eq!(
        foreign.host_inbound_deny, 1,
        "dmz admits NO host-inbound service. 0 means the gate judged a dmz packet by \
         the SESSION's zone and let it ride lan's SSH admission (#9519)"
    );
    assert_eq!(
        session_count(&sessions),
        1,
        "and the deny drops THAT packet: a packet from dmz cannot tear down lan's \
         host-bound session (#9519)"
    );

    let permitted = drive(&fw, &mut sessions, ssh(TCP_ACK, WAN_IFINDEX));
    assert_eq!(
        permitted.session_hit, 1,
        "a wan copy of the tuple hits the same session"
    );
    assert_eq!(
        (permitted.host_inbound_deny, permitted.policy_deny, permitted.local),
        (0, 0, 1),
        "wan DOES admit any-service, so its packet is delivered: a foreign arrival is \
         held to its own zone's services, not refused outright (#9519)"
    );
    assert_eq!(
        session_count(&sessions),
        1,
        "and a foreign packet that is admitted still does not act on the session"
    );
}

fn rule_hits(fw: &ForwardingState, name: &str) -> u64 {
    fw.policy
        .rules
        .iter()
        .find(|r| r.rule_id.contains(name))
        .map(|r| r.hit_counter.test_packet_count())
        .unwrap_or(u64::MAX)
}

#[test]
fn a_foreign_packet_is_not_counted_against_the_owners_rule_9519() {
    let fw = forwarding(WAN_ONLY);
    let mut sessions = admitted(&fw);
    let after_admit = rule_hits(&fw, "wan-in");
    assert_ne!(
        after_admit,
        u64::MAX,
        "the `wan-in` rule must exist, or every delta below is read off nothing"
    );
    let foreign = drive(&fw, &mut sessions, client_ack(DMZ_IFINDEX));
    assert_eq!(foreign.session_hit, 1, "the dmz packet must HIT the wan session");
    assert_eq!(
        rule_hits(&fw, "wan-in"),
        after_admit,
        "a dmz packet is not wan-in's traffic, whatever dmz's own policy says of it. \
         Counting it inflates `show security policies hit-count` for the rule that \
         admitted the session with packets that rule never saw (#9519)"
    );
    let owner = drive(&fw, &mut sessions, client_ack(WAN_IFINDEX));
    assert_eq!(owner.tx, 1, "control: the owner's ACK forwards");
    assert_eq!(
        rule_hits(&fw, "wan-in"),
        after_admit + 1,
        "control: the OWNER's established packet IS counted against its admitting \
         rule, or the zero delta above is not measuring the skip"
    );
}

/// The `to-zone junos-host` half of host-bound authority. dmz's services admit
/// SSH, so the coarse gate passes; dmz's own junos-host policy denies it. The
/// question must be asked FROM dmz. The owner never sends an ACK here (#9563).
#[test]
fn a_foreign_zone_is_held_to_its_own_junos_host_policy_9519() {
    let fw = forwarding(Posture {
        dmz_junos_host_deny: true,
        ..WAN_ONLY
    });
    let mut sessions = host_bound_ssh_session(&fw);
    let foreign = drive(&fw, &mut sessions, ssh(TCP_ACK, DMZ_IFINDEX));
    assert_eq!(foreign.session_hit, 1, "the dmz packet must HIT lan's host-bound session");
    assert_eq!(
        foreign.policy_deny, 1,
        "dmz has a `to-zone junos-host` deny. 0 means junos-host policy was asked from \
         the SESSION's zone, lan, which has none, and the dmz packet rode lan's host \
         access (#9519)"
    );
    assert_eq!(
        foreign.host_inbound_deny, 0,
        "control: dmz's services admit SSH, so the coarse gate is not what dropped it"
    );
    assert_eq!(
        session_count(&sessions),
        1,
        "and the deny drops THAT packet: it cannot tear down lan's session (#9519)"
    );
    let wan = drive(&fw, &mut sessions, ssh(TCP_ACK, WAN_IFINDEX));
    assert_eq!(
        (wan.host_inbound_deny, wan.policy_deny, wan.local),
        (0, 0, 1),
        "control: wan has no junos-host deny, so its copy is delivered — the deny above \
         is dmz's own"
    );
    assert_eq!(session_count(&sessions), 1);
}

/// A terminal lo0 verdict on a FOREIGN packet drops that packet and does not tear
/// the owner's session down. The session is installed and first exercised under a
/// forwarding state with no lo0 filter, so only the filter can drop the last packet.
#[test]
fn a_foreign_packets_lo0_discard_does_not_tear_down_the_session_9519() {
    let install = forwarding(WAN_ONLY);
    let mut sessions = host_bound_ssh_session(&install);
    let unfiltered = drive(&install, &mut sessions, ssh(TCP_ACK, DMZ_IFINDEX));
    assert_eq!(
        (unfiltered.session_hit, unfiltered.policy_deny, unfiltered.local),
        (1, 0, 1),
        "control: with no lo0 filter the dmz copy is delivered (dmz admits \
         any-service), so the drop below is the filter's"
    );
    let live = forwarding(Posture {
        lo0_discards_ssh: true,
        ..WAN_ONLY
    });
    let filtered = drive(&live, &mut sessions, ssh(TCP_ACK, DMZ_IFINDEX));
    assert_eq!(filtered.session_hit, 1, "the dmz packet must HIT the session");
    assert_eq!(
        (filtered.policy_deny, filtered.host_inbound_deny),
        (1, 0),
        "the lo0 filter discards tcp/22, so this packet is dropped. The host-bound drop \
         arms count `local` as well as `policy_deny`, so `policy_deny` is the \
         instrument: it is 0 for the same packet in the unfiltered run above"
    );
    assert_eq!(
        session_count(&sessions),
        1,
        "a packet from dmz cannot tear down lan's host-bound session, even through a \
         terminal lo0 verdict (#9519)"
    );
}
