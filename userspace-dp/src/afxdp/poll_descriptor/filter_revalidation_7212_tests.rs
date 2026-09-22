// #7212: the established-session-hit input-filter re-evaluation gate
// (`evaluate_input_filter_on_session_hit`).
//
// These cells drive the helper directly, so they can vary one axis at a time —
// family, logical VLAN unit, filter shape, stamp freshness. The END-TO-END
// revocation (teardown + the pinned permitted-SNAT case) is driven through the
// real poll loop in `afxdp/tests_filter_revocation_7212.rs`.

use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::policy_deny_snapshot;
use crate::ip_proto::PROTO_TCP;
use crate::session::{SessionKey, SessionMetadata, SessionOrigin};
use crate::test_zone_ids::*;
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceAddressSnapshot, InterfaceSnapshot,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The LAN-side interface every cell attaches its input filter to. It is the
/// ingress of the `policy_deny_snapshot` topology's `reth1.0`.
const LAN_IFINDEX: i32 = 24;
/// A VLAN sub-interface added on a DIFFERENT physical parent, so a
/// physical-keyed lookup would resolve no filter at all and a logical-keyed one
/// resolves this unit's own.
const VLAN_PARENT_IFINDEX: i32 = 11;
const VLAN_UNIT_IFINDEX: i32 = 13;
const VLAN_ID: i32 = 50;

fn deny_term(name: &str, dport: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        name: name.into(),
        protocols: vec!["tcp".into()],
        destination_ports: vec![dport.into()],
        action: "discard".into(),
        syslog: false,
        reject_message_type: String::new(),
        ..Default::default()
    }
}

fn accept_term(name: &str, dport: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        action: "accept".into(),
        ..deny_term(name, dport)
    }
}

/// Build a forwarding state from the shared LAN/WAN topology with `terms`
/// attached as the inet (or inet6) INPUT filter of `ifindex`.
fn forwarding_with_input_filter(
    ifindex: i32,
    v6: bool,
    terms: Vec<FirewallTermSnapshot>,
) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-in".into(),
        family: if v6 { "inet6".into() } else { "inet".into() },
        terms,
    }];
    // A second VLAN unit on a different physical parent, used only by the VLAN
    // cell. Harmless elsewhere: nothing attaches a filter to it there.
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth0.50".into(),
        zone: "lan".into(),
        linux_name: "ge-0-0-0.50".into(),
        ifindex: VLAN_UNIT_IFINDEX,
        parent_ifindex: VLAN_PARENT_IFINDEX,
        vlan_id: VLAN_ID,
        ..Default::default()
    });
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == ifindex {
            if v6 {
                iface.filter_input_v6 = "edge-in".into();
            } else {
                iface.filter_input_v4 = "edge-in".into();
            }
        }
    }
    build_forwarding_state(&snapshot)
}

/// The exact stale-hit shape for #10467: the live filter now steers this
/// tuple into `blue`, while `blue.inet.0` has only an unrelated connected
/// prefix and therefore no route to the destination. The MAIN table in the
/// shared fixture does have a default route; a hit that keeps its cached MAIN
/// decision would therefore be observably wrong.
fn forwarding_with_empty_blue_pbr() -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-in".into(),
        family: "inet".into(),
        terms: vec![pbr_term("pbr-route", "5201", "accept")],
    }];
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "blue0".into(),
        zone: "lan".into(),
        routing_instance: "blue".into(),
        linux_name: "blue0".into(),
        ifindex: 101,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".into(),
            address: "10.250.0.1/24".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == LAN_IFINDEX {
            iface.filter_input_v4 = "edge-in".into();
        }
    }
    build_forwarding_state(&snapshot)
}

fn forwarding_with_empty_blue_per_packet_pbr() -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    let mut term = pbr_term("pbr-syn", "5201", "accept");
    term.tcp_flags = Some(crate::tcp_flags::TCP_SYN);
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-in".into(),
        family: "inet".into(),
        terms: vec![term],
    }];
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "blue0".into(),
        zone: "lan".into(),
        routing_instance: "blue".into(),
        linux_name: "blue0".into(),
        ifindex: 101,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".into(),
            address: "10.250.0.1/24".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == LAN_IFINDEX {
            iface.filter_input_v4 = "edge-in".into();
        }
    }
    build_forwarding_state(&snapshot)
}

/// Native RI membership is the route-table fallback when no PBR term matches.
/// Keep this fixture separate from the empty-VRF PBR fixture so the fallback
/// identity is exercised without an explicit route-lookup-affecting filter.
fn forwarding_with_native_blue_ri() -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    let (domain, _) = crate::session::install_table_identity("blue");
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == LAN_IFINDEX {
            iface.routing_instance = "blue".into();
            iface.routing_domain = domain;
        }
    }
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "blue0".into(),
        zone: "lan".into(),
        routing_instance: "blue".into(),
        routing_domain: domain,
        linux_name: "blue0".into(),
        ifindex: 101,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".into(),
            address: "10.250.0.1/24".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    build_forwarding_state(&snapshot)
}

/// The shared topology with a DIFFERENT inet INPUT filter on each of two
/// interfaces: `permit` on `a`, `deny` on `b`.
fn forwarding_with_two_input_filters(
    a: i32,
    permit: Vec<FirewallTermSnapshot>,
    b: i32,
    deny: Vec<FirewallTermSnapshot>,
) -> ForwardingState {
    let mut snapshot = policy_deny_snapshot();
    snapshot.filters = vec![
        FirewallFilterSnapshot {
            name: "on-a".into(),
            family: "inet".into(),
            terms: permit,
        },
        FirewallFilterSnapshot {
            name: "on-b".into(),
            family: "inet".into(),
            terms: deny,
        },
    ];
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == a {
            iface.filter_input_v4 = "on-a".into();
        } else if iface.ifindex == b {
            iface.filter_input_v4 = "on-b".into();
        }
    }
    build_forwarding_state(&snapshot)
}

fn v4_flow(dst_port: u16) -> SessionFlow {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
    SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: src,
            dst_ip: dst,
            src_port: 12345,
            dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

fn v6_flow(dst_port: u16) -> SessionFlow {
    let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0x61, 0, 0, 0, 0x102));
    let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0x80, 0, 0, 0, 0x200));
    SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: src,
            dst_ip: dst,
            src_port: 12345,
            dst_port,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    }
}

fn meta(ingress_ifindex: u32, vlan: u16, v6: bool) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        ingress_vlan_id: vlan,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: 54,
        addr_family: if v6 {
            libc::AF_INET6 as u8
        } else {
            libc::AF_INET as u8
        },
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    }
}

/// #7212: `ingress_ifindex` is `LAN_IFINDEX`, the interface the cells then probe
/// against, so it is the exact `(generation, ingress)` pair an install that
/// stamped LIVE would write. Probing a DIFFERENT interface would report stale
/// for the wrong reason and stay green against such an install.
fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: LAN_IFINDEX as u32,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn decision() -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: None,
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}

/// Install `flow` as an established session stamped under generation
/// `stamped_gen`, with the table now publishing `live_gen`.
/// Install `flow` as an established session, with the table publishing
/// `live_gen`.
///
/// The install itself stamps `FilterRevalidationStamp::UNVALIDATED` (#7212: no
/// static verdict has been derived for the ENTRY yet, whichever direction it
/// is), so the session is stale on its next packet by construction. The
/// `revalidated_on` argument, when `Some`, then marks it revalidated on that
/// logical ingress under `live_gen` — which is how a cell asks for a
/// NOT-stale session.
fn table_with_session(
    flow: &SessionFlow,
    live_gen: u64,
    revalidated_on: Option<i32>,
) -> SessionTable {
    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(live_gen);
    assert!(sessions.install_with_protocol_with_origin(
        flow.forward_key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        1_000,
        PROTO_TCP,
        0,
    ));
    if let Some(ifindex) = revalidated_on {
        sessions.mark_filter_revalidated(&flow.forward_key, ifindex);
    }
    sessions
}

/// The shared LAN->WAN TCP SYN frame: 10.0.61.102:12345 -> 172.16.80.200:5201,
/// the exact tuple `v4_flow(5201)` names.
///
/// A zero-filled buffer would be enough for the STATIC cells — no static term
/// reads a packet byte — but it is NOT enough for the per-packet cell: a
/// `tcp-flags` term requires `TermMatchExtra::l4_present`, which
/// `term_match_extra_from_frame` derives from the frame, so a synthetic buffer
/// makes that term fail closed and the cell would assert Accept for a reason
/// that has nothing to do with the code under test. Using one real frame
/// everywhere removes that class of fixture lie.
fn frame() -> Vec<u8> {
    crate::afxdp::tests_support::build_policy_deny_tcp_syn_frame(crate::afxdp::tests_support::TEST_LAN_MAC)
}

/// A static `then discard` attached after the session was established revokes
/// it on the next packet: the helper reports a non-Accept action AND flags the
/// verdict as a REVOCATION, which is what makes the caller tear the pair down
/// rather than merely drop the packet.
#[test]
fn static_discard_revokes_a_stale_stamped_session_7212() {
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("a newly-denied stale session must produce a verdict");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert!(
        hit.revoked_key.as_ref() == Some(&flow.forward_key),
        "a static-filter verdict must revoke the SESSION, not just drop the \
         packet, and must name the entry it judged"
    );
}

/// THE pinned acceptance case, at the helper level: a session the same
/// interface's filter still PERMITS is not touched — no verdict is returned at
/// all — and its SNAT translated port is unchanged. This is the whole reason
/// #5858's interface-keyed family purge was rejected: a purged permitted SNAT
/// flow reinstalls on a DIFFERENT translated port and breaks.
///
/// The deny term is present and matches a SIBLING port on the SAME interface,
/// so the filter is genuinely one that can deny; an all-accept filter would
/// make this pass for the wrong reason.
#[test]
fn a_still_permitted_session_keeps_its_snat_translation_7212() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![deny_term("no-ssh", "22"), accept_term("web", "5201")],
    );
    let flow = v4_flow(5201);

    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(7);
    let mut snat = decision();
    snat.nat.rewrite_src = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    snat.nat.rewrite_src_port = Some(40001);
    assert!(sessions.install_with_protocol_with_origin(
        flow.forward_key.clone(),
        snat,
        metadata(),
        SessionOrigin::ForwardFlow,
        1_000,
        PROTO_TCP,
        0,
    ));

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    );
    assert!(
        hit.is_none(),
        "a still-permitted session must produce no verdict, no counter and no log"
    );
    let lookup = sessions
        .lookup(&flow.forward_key, 2_000, 0)
        .expect("the permitted session must survive the revalidation");
    assert_eq!(
        lookup.decision.nat.rewrite_src_port,
        Some(40001),
        "the translated port must be unchanged — a purge-and-recreate hands out \
         a different one and breaks the flow"
    );
    assert_eq!(
        lookup.decision.nat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)))
    );
    assert!(
        !sessions.filter_revalidation_stale(&flow.forward_key, LAN_IFINDEX),
        "an Accept verdict must re-stamp, or every later packet re-derives it"
    );
}

/// The STAMP is the gate, not the filter. A session whose verdict was already
/// computed under the live generation is not re-derived, so no work is done and
/// nothing is revoked.
///
/// This state is unreachable in production for a DENIED flow — the install-time
/// verdict and the install-time stamp come from the same generation, so a
/// session stamped at the live generation was admitted by this very filter —
/// but it is exactly the state that distinguishes "re-derive when stale" from
/// "re-derive on every packet", and only a fresh-stamp row can show that.
#[test]
fn a_fresh_stamp_skips_the_revalidation_entirely_7212() {
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, Some(LAN_IFINDEX));

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none(),
        "a session already revalidated under the live generation must not be \
         re-derived"
    );
}

/// inet6 parity. The family selects a different fast map, and a v4-only
/// implementation would leave every IPv6 session unrevoked.
#[test]
fn static_discard_revokes_an_ipv6_session_7212() {
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, true, vec![deny_term("no-5201", "5201")]);
    let flow = v6_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, true),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("v6 verdict");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert!(hit.revoked_key.is_some());
}

/// The filter is resolved through the LOGICAL VLAN unit, not the physical
/// parent. The filter is attached to unit ifindex 13 and the packet arrives on
/// physical ifindex 11 with VID 50; a physical-keyed lookup finds NO filter and
/// revokes nothing.
#[test]
fn static_discard_resolves_through_the_vlan_logical_unit_7212() {
    let forwarding =
        forwarding_with_input_filter(VLAN_UNIT_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(VLAN_PARENT_IFINDEX as u32, VLAN_ID as u16, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("the VLAN unit's own filter must be found");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert!(hit.revoked_key.is_some());
}

/// Term ORDER decides. The same two terms with the accept first must permit;
/// reversing them must revoke. A single-order fixture would pass for an
/// implementation that ignored ordering entirely.
#[test]
fn term_order_decides_the_static_verdict_7212() {
    for (accept_first, want_revoked) in [(true, false), (false, true)] {
        let terms = if accept_first {
            vec![accept_term("web", "5201"), deny_term("no-5201", "5201")]
        } else {
            vec![deny_term("no-5201", "5201"), accept_term("web", "5201")]
        };
        let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, terms);
        let flow = v4_flow(5201);
        let mut sessions = table_with_session(&flow, 7, None);
        let hit = evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        );
        assert_eq!(
            hit.is_some_and(|h| h.revoked_key.is_some()),
            want_revoked,
            "accept_first={accept_first}: first match wins"
        );
    }
}

/// `from source-address ... except` inverts the address match, so the same deny
/// term revokes or does not depending only on the `except` bit.
#[test]
fn source_address_except_inverts_the_static_verdict_7212() {
    for (except, want_revoked) in [(false, true), (true, false)] {
        let mut term = deny_term("no-5201", "5201");
        term.source_addresses = vec!["10.0.61.102/32".into()];
        term.source_except = except;
        let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![term]);
        let flow = v4_flow(5201);
        let mut sessions = table_with_session(&flow, 7, None);
        let hit = evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        );
        assert_eq!(
            hit.is_some_and(|h| h.revoked_key.is_some()),
            want_revoked,
            "except={except}: the deny applies only when the address matches"
        );
    }
}

/// DETACH is strictly loosening: with no filter attached, a stale stamp
/// produces no verdict and nothing is revoked.
#[test]
fn detaching_the_filter_revokes_nothing_7212() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.filters = Vec::new();
    let forwarding = build_forwarding_state(&snapshot);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none()
    );
}

/// A filter whose verdict VARIES per packet (#1430 DSCP / #2362 per-packet L4)
/// keeps its per-packet re-evaluation and must NEVER be flagged as a
/// revocation: its verdict is about THIS packet and says nothing about the
/// flow. A tcp-flags term denying a packet with no SYN set would otherwise tear
/// down the whole session on one mid-stream segment.
#[test]
fn a_per_packet_filter_drops_the_packet_without_revoking_the_session_7212() {
    let mut term = deny_term("no-syn-5201", "5201");
    term.tcp_flags = Some(crate::tcp_flags::TCP_SYN);
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![term]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);

    let mut m = meta(LAN_IFINDEX as u32, 0, false);
    m.tcp_flags = crate::tcp_flags::TCP_SYN;
    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        m,
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("a per-packet filter is re-evaluated on every hit");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert!(
        hit.revoked_key.is_none(),
        "a per-packet verdict must drop the packet, never revoke the session"
    );
    assert!(
        sessions.filter_revalidation_stale(&flow.forward_key, LAN_IFINDEX),
        "the per-packet arm must not consume the static revalidation stamp"
    );
}

/// The REPLY direction of a source-NAT'd flow, reached through the NAT
/// reverse-translated ALIAS index, must revalidate too — and the verdict must
/// name the entry's CANONICAL key, not the translated tuple the packet carried.
///
/// The subject is a reverse entry whose WIRE and CANONICAL keys diverge — the
/// shape the reverse-translated ALIAS index exists for. `lookup_with_origin`
/// finds such an entry through that index, so
/// `ResolvedFlowSessionDecision::key` is the wire tuple and names no entry in
/// the PRIMARY index. A primary-index-only stamp probe answers "not stale" for
/// it forever: never revalidated, never revoked, never re-stamped, so a
/// `then discard` on its ingress interface does nothing to it. The teardown has
/// the same dependency — handed the wire tuple it would delete nothing — which
/// is why the verdict carries the resolved key rather than a bool.
///
/// An ORDINARY source-NAT reply is not this shape and the fixture does not claim
/// to be one: the pair install stores the reverse companion under
/// `reverse_session_key(forward, nat)`, which is already the wire reply tuple,
/// so that reply resolves primary. The fixture builds the divergence directly,
/// which is what the alias index is reached by.
///
/// The fixture is built so the two keys genuinely DIFFER (an address rewrite
/// plus a port rewrite on the reverse entry); with `NatDecision::default()` the
/// translation is the identity, the alias path is never taken, and the cell
/// would pass against the primary-index-only version it exists to catch. The
/// deny term matches the reply's ON-WIRE destination port, because that is the
/// tuple an input filter on the ingress interface sees — the packet has not been
/// un-translated yet.
#[test]
fn a_snat_reply_reached_through_the_nat_alias_is_revalidated_7212() {
    let forwarding =
        forwarding_with_input_filter(LAN_IFINDEX, false, vec![deny_term("no-pool", "40001")]);
    // The reverse entry is keyed on the UNTRANSLATED reply tuple; the wire
    // reply carries the translated one.
    let reverse_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 5201,
        dst_port: 12345,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut reverse_decision = decision();
    reverse_decision.nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    reverse_decision.nat.rewrite_dst_port = Some(40001);
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;

    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(7);
    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        reverse_decision,
        reverse_metadata,
        SessionOrigin::ReverseFlow,
        1_000,
        PROTO_TCP,
        0,
    ));

    // What the poll path holds for this packet: the WIRE (translated) tuple.
    let wire_key = crate::session::translated_session_key(&reverse_key, reverse_decision.nat);
    assert_ne!(
        wire_key, reverse_key,
        "fixture liveness: the wire tuple must DIFFER from the entry key, or \
         this cell exercises the primary-index path and proves nothing"
    );
    assert!(
        sessions.filter_revalidation_stale(&wire_key, LAN_IFINDEX),
        "the wire tuple must resolve THROUGH the alias index; a \
         primary-index-only probe finds nothing and reports the session fresh, \
         which is the defect this cell pins"
    );
    assert_eq!(
        sessions
            .stale_filter_revalidation_key(&wire_key, LAN_IFINDEX)
            .as_ref(),
        Some(&reverse_key),
        "the wire tuple must resolve to the entry's canonical key through the \
         reverse-translated alias index"
    );

    // The reply's own flow, as the poll path parses it off the wire.
    let flow = SessionFlow {
        src_ip: wire_key.src_ip,
        dst_ip: wire_key.dst_ip,
        forward_key: wire_key.clone(),
    };
    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &wire_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("the reply half must be revalidated through the alias index");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert_eq!(
        hit.revoked_key.as_ref(),
        Some(&reverse_key),
        "the revocation must name the CANONICAL key — a teardown handed the \
         translated tuple deletes nothing"
    );
    assert!(
        sessions.filter_revalidation_stale(&reverse_key, LAN_IFINDEX),
        "a DENY leaves the stamp stale by design (see \
         `a_deny_verdict_does_not_re_stamp_the_session_7212`); the re-stamp \
         landing on the CANONICAL key is pinned by the permitted sibling below"
    );
}

/// The permitted sibling of the cell above: a SNAT'd reply the filter still
/// allows is re-stamped through the alias and left alone, translation intact.
/// Without this row the alias cell would be satisfied by an implementation that
/// revoked every aliased reply.
#[test]
fn a_permitted_snat_reply_through_the_nat_alias_is_untouched_7212() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![deny_term("no-ssh", "22"), accept_term("pool", "40001")],
    );
    let reverse_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 5201,
        dst_port: 12345,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut reverse_decision = decision();
    reverse_decision.nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    reverse_decision.nat.rewrite_dst_port = Some(40001);
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;

    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(7);
    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        reverse_decision,
        reverse_metadata,
        SessionOrigin::ReverseFlow,
        1_000,
        PROTO_TCP,
        0,
    ));
    let wire_key = crate::session::translated_session_key(&reverse_key, reverse_decision.nat);
    let flow = SessionFlow {
        src_ip: wire_key.src_ip,
        dst_ip: wire_key.dst_ip,
        forward_key: wire_key.clone(),
    };

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &wire_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none(),
        "a permitted reply must produce no verdict"
    );
    let lookup = sessions
        .lookup(&reverse_key, 2_000, 0)
        .expect("the permitted reply half must survive");
    assert_eq!(lookup.decision.nat.rewrite_dst_port, Some(40001));
    assert!(
        !sessions.filter_revalidation_stale(&reverse_key, LAN_IFINDEX),
        "an Accept verdict must re-stamp the aliased entry too"
    );
}

/// A NON-FIRST FRAGMENT of a PERMITTED flow must not revoke it.
///
/// `Filter::varies_per_packet_within_flow()` is not a complete purity gate:
/// `port_terms_match` reads `TermMatchExtra` too, and any term with a PORT
/// constraint fails to match when `(is_fragment && !l4_present)`. Evaluated
/// against the frame, the shape below skips its `web` permit on a fragment and
/// falls through to the catch-all `deny-rest` — revoking a session the operator
/// permits, off ONE fragment. Evaluated on the 5-tuple alone, `web` matches and
/// the session is kept.
///
/// The `deny-rest` term is what makes this distinguishing. Without a catch-all
/// behind the permit, a fragment would simply match no term and reach the
/// implicit Accept, and the cell would be green against both implementations.
#[test]
fn a_non_first_fragment_of_a_permitted_flow_does_not_revoke_it_7212() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![
            accept_term("web", "5201"),
            FirewallTermSnapshot {
                name: "deny-rest".into(),
                action: "discard".into(),
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            },
        ],
    );
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);
    let fragment = non_first_fragment_frame();
    // Fixture liveness: the frame really is a non-first fragment, so the
    // frame-derived extra really would suppress the port-constrained permit.
    let extra = crate::afxdp::frame::term_match_extra_from_frame(
        &fragment,
        meta(LAN_IFINDEX as u32, 0, false),
    );
    assert!(
        extra.is_fragment && !extra.l4_present,
        "fixture liveness: the frame must derive is_fragment && !l4_present, or \
         the port gate is never reached and this cell proves nothing"
    );

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &fragment,
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none(),
        "a fragment must not revoke a flow the filter permits on its 5-tuple"
    );
    assert!(
        !sessions.filter_revalidation_stale(&flow.forward_key, LAN_IFINDEX),
        "the permitted flow is still re-stamped"
    );
}

/// The control for the cell above: with the SAME fragment, a flow the filter
/// does NOT permit is still revoked. Evaluating on the 5-tuple must not turn
/// into "a fragment disables revalidation".
#[test]
fn a_non_first_fragment_still_revokes_a_denied_flow_7212() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![
            accept_term("web", "5201"),
            FirewallTermSnapshot {
                name: "deny-rest".into(),
                action: "discard".into(),
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            },
        ],
    );
    // Same filter, a flow on a port the permit does not cover.
    let flow = v4_flow(9999);
    let mut sessions = table_with_session(&flow, 7, None);
    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &non_first_fragment_frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("a denied flow must still be revoked when a fragment triggers it");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert_eq!(hit.revoked_key.as_ref(), Some(&flow.forward_key));
}

/// The shared TCP SYN frame with the IPv4 fragment-offset field set to a
/// NON-ZERO offset, which is what makes it a non-first fragment: no L4 header
/// lives at `l4_offset`, its bytes are payload.
fn non_first_fragment_frame() -> Vec<u8> {
    let mut frame = frame();
    // IPv4 flags+fragment-offset is bytes 6..8 of the IP header, and the IP
    // header starts at 14 (Ethernet II, untagged).
    frame[20] = 0x00;
    frame[21] = 0x01; // offset = 1 (8 bytes in), MF clear -> the LAST fragment
    frame
}

/// A DENY verdict does NOT re-stamp the session.
///
/// The caller revokes it, so in the normal case there is no entry left to
/// stamp. The case this pins is the abnormal one: if the teardown ever fails to
/// take, a stamped entry would say "already judged under the live generation"
/// and be FORWARDED for the rest of the generation under a filter that denies
/// it. Unstamped, the next packet re-derives the same DENY and drops — the same
/// failure, fail-closed instead of fail-open.
///
/// The helper is called directly here precisely because it does NOT perform the
/// teardown; that is what makes "the entry survived a DENY" reachable in a test
/// at all.
#[test]
fn a_deny_verdict_does_not_re_stamp_the_session_7212() {
    let forwarding =
        forwarding_with_input_filter(LAN_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("first packet: the session is newly denied");
    assert!(hit.revoked_key.is_some());
    assert!(
        sessions.filter_revalidation_stale(&flow.forward_key, LAN_IFINDEX),
        "a DENY must leave the stamp stale, so a teardown that did not take \
         cannot turn into a forwarded flow"
    );

    // Second packet on the surviving entry: the verdict is re-derived and it is
    // still a DENY, so the packet is dropped again rather than forwarded.
    let again = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("second packet: still denied, not forwarded under a stale-clean stamp");
    assert_eq!(again.eval.action, crate::filter::FilterAction::Discard);
    assert!(again.revoked_key.is_some());
}

/// #8114 item 1, ON #7212'S OWN FIXTURE. A route-lookup-affecting filter IS
/// revalidated now, and this is the case #7212 wrote down as the cost of
/// declining: the flow does NOT match the PBR term, so the walk reaches
/// `deny-5201` and the revocation was simply lost.
///
/// #7212 declined because the static verdict ran the NON-ROUTING walk, which
/// returns the default Accept the moment it matches a `routing-instance` term —
/// before that term's own action is examined — and could not tell "Accept
/// because nothing matched" from "Accept because it deferred". The verdict is
/// now COMPOSED the way the packet path composes it: ask the routing-instance
/// walk first, and fall back to the non-routing walk only when it reports that
/// no PBR term terminated. Here it reports exactly that (the matched
/// terminating term `deny-5201` carries no routing-instance), so the ordinary
/// static verdict applies and the session is revoked.
///
/// The cell KEEPS #7212's fixture-liveness assertions rather than starting
/// fresh: they are what stop this passing because the filter stopped being
/// route-lookup-affecting, or because the deny term stopped matching.
///
/// Fail-on-revert: restore `if filter.affects_route_lookup { return None; }` and
/// the revocation assertion reds.
#[test]
fn a_route_lookup_affecting_filter_is_revalidated_off_its_non_pbr_terms_8114() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![
            FirewallTermSnapshot {
                name: "pbr".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["9999".into()],
                routing_instance: "blue".into(),
                action: "accept".into(),
                syslog: false,
                reject_message_type: String::new(),
                ..Default::default()
            },
            deny_term("deny-5201", "5201"),
        ],
    );
    // Fixture liveness: the filter really is route-lookup-affecting, and the
    // deny term really does match this flow — so the decline is what produces
    // the `None`, not a non-matching filter.
    let filter = crate::filter::interface_input_filter(
        &forwarding.filter_state,
        LAN_IFINDEX,
        false,
    )
    .expect("the filter is attached");
    assert!(
        filter.affects_route_lookup,
        "fixture liveness: without a routing-instance term the decline is never \
         reached and this cell proves nothing"
    );
    let flow = v4_flow(5201);
    assert_eq!(
        crate::filter::filter_ref_static_verdict(
            filter,
            flow.src_ip,
            flow.dst_ip,
            PROTO_TCP,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
            0,
            crate::filter::TermMatchExtra::default(),
        ),
        crate::filter::FilterAction::Discard,
        "fixture liveness: the deny term matches this flow, so the decline is \
         costing a revocation rather than being free"
    );

    let mut sessions = table_with_session(&flow, 7, None);
    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect(
        "a PBR term the flow does not match must not cost the revocation its \
         plain deny term earns",
    );
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert_eq!(
        hit.revoked_key.as_ref(),
        Some(&flow.forward_key),
        "the verdict came from the ordinary static walk, so it REVOKES the \
         session, not merely drops the packet"
    );
    assert_eq!(
        hit.log_source,
        crate::afxdp::event_emit::FilterLogSource::Input,
        "no routing-instance term produced this verdict, so the record must NOT \
         claim a PBR source"
    );
    assert!(
        sessions.filter_revalidation_stale(&flow.forward_key, LAN_IFINDEX),
        "a DENY must leave the stamp stale, so a teardown that did not take \
         cannot turn into a forwarded flow"
    );
}

/// The eviction key set covers all THREE identities the revoked flow is known
/// by. The aliased row is the one that matters: the flow cache is keyed by the
/// WIRE tuple, so a set built only from the table's canonical key and its
/// companion leaves an aliased SNAT reply's descriptor live.
#[test]
fn revoked_flow_cache_keys_cover_the_wire_alias_7212() {
    let canonical = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 5201,
        dst_port: 12345,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut nat = crate::nat::NatDecision::default();
    nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    nat.rewrite_dst_port = Some(40001);
    let wire = crate::session::translated_session_key(&canonical, nat);
    assert_ne!(
        wire, canonical,
        "fixture liveness: the wire tuple must differ, or the alias row is not \
         being exercised"
    );

    let mut out = Vec::new();
    collect_revoked_flow_cache_keys(&wire, &canonical, nat, &mut out);
    assert!(out.contains(&canonical), "the table's key");
    assert!(
        out.contains(&crate::session::reverse_session_key(&canonical, nat)),
        "the companion the teardown also deletes"
    );
    assert!(
        out.contains(&wire),
        "the WIRE tuple the flow cache is keyed by — without it an aliased \
         reply keeps forwarding off a cached descriptor with no session"
    );
}

/// The non-aliased case emits no duplicate: when the packet's tuple IS the
/// canonical key, the wire entry is elided. Without this row the helper could
/// push unconditionally and the alias row above would still pass.
#[test]
fn revoked_flow_cache_keys_elide_the_duplicate_wire_key_7212() {
    let flow = v4_flow(5201);
    let mut out = Vec::new();
    collect_revoked_flow_cache_keys(
        &flow.forward_key,
        &flow.forward_key,
        crate::nat::NatDecision::default(),
        &mut out,
    );
    assert_eq!(
        out.iter().filter(|k| **k == flow.forward_key).count(),
        1,
        "an untranslated flow's key must appear exactly once"
    );
}

/// A session judged on interface A is NOT considered judged on interface B, at
/// the SAME generation.
///
/// The verdict is a function of the interface as well as the snapshot, and the
/// session key carries no ingress identity. A generation-only stamp reports the
/// session already judged when a same-direction packet arrives on B —
/// asymmetric routing, a zone spanning several members, a redundancy-group
/// change, two VLAN units on one trunk — and B's `then discard` is never
/// evaluated for the rest of that generation.
///
/// The generation is held FIXED across both packets, so the interface is the
/// only thing that can move the answer. Every other cell in this file uses ONE
/// ingress interface, which is exactly the fixture shape in which deleting the
/// ifindex from the stamp changes no outcome.
#[test]
fn a_verdict_on_one_interface_does_not_judge_another_7212() {
    // WAN unit `reth0.80` (ifindex 12) is the second interface; it exists in the
    // shared topology and is in a different zone, which is what makes two
    // different filters on it realistic.
    const IF_B: i32 = 12;
    let forwarding = forwarding_with_two_input_filters(
        LAN_IFINDEX,
        vec![accept_term("permit-web", "5201")],
        IF_B,
        vec![deny_term("deny-web", "5201")],
    );
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);

    // Packet 1 on A: permitted, and the session is stamped as judged on A.
    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none(),
        "A's filter permits this flow"
    );
    assert!(!sessions.filter_revalidation_stale(&flow.forward_key, LAN_IFINDEX));

    // Packet 2, SAME generation, same session, arriving on B. B denies it.
    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(IF_B as u32, 0, false),
        Some(TEST_WAN_ZONE_ID),
    )
    .expect("B's filter must be evaluated — A's verdict says nothing about B");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert_eq!(hit.revoked_key.as_ref(), Some(&flow.forward_key));
}

// ---------------------------------------------------------------------------
// #8114 item 2 — a RESOLVED decision with no local session entry.
// ---------------------------------------------------------------------------

/// THE CASE. A packet whose forwarding decision RESOLVED but for which this
/// worker holds no local entry must still have the ingress interface's static
/// input filter applied to it.
///
/// Two production populations reach this, and neither is hypothetical:
///
/// * the #2120 TRANSIENT peer-synced hit — `should_keep_synced_hit_transient`
///   serves the packet from the shared map on an inactive owner without
///   installing locally. Bounded: `maybe_promote_synced_session` installs the
///   entry UNVALIDATED on a later packet.
/// * the reverse-NAT REPAIR whose install was refused at `max_sessions`
///   (`ResolvedFlowSessionDecision::install_failed`, threaded to the caller as
///   `flow_cache_install_failed`), which still returns its synthesized
///   decision. UNBOUNDED — it lasts as long as the session table is full, which
///   is precisely when an operator is most likely to be adding a deny.
///
/// Before #8114 the probe returned `Option<SessionKey>` and this collapsed onto
/// the same `None` as "the entry's verdict is already fresh", so the caller —
/// whose single production call site is `if let Some(..)` with NO else arm —
/// skipped the block and FORWARDED the packet under a filter that denies it.
///
/// What must NOT happen is equally load-bearing and is asserted below: no stamp
/// and no teardown. `revoked_key` is `None`, because there is no entry this
/// verdict may name — revoking on a resolved-but-unstored tuple would hand the
/// caller a key that names nothing, or worse, another session's.
#[test]
fn a_sessionless_resolved_decision_still_applies_a_static_deny_8114() {
    let forwarding =
        forwarding_with_input_filter(LAN_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);

    // No install: this is the whole point. The table publishes a live
    // generation, so the ONLY thing that distinguishes this from the
    // established-session cells above is the absence of the entry.
    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(7);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect(
        "a resolved decision with no local entry must still be judged by the \
         ingress filter — master forwarded it",
    );
    assert_eq!(
        hit.eval.action,
        crate::filter::FilterAction::Discard,
        "the deny must be applied to THIS packet"
    );
    assert_eq!(
        hit.revoked_key, None,
        "there is no entry to revoke; naming one would hand the caller a key \
         that names nothing"
    );
    assert!(
        sessions.lookup(&flow.forward_key, 2_000, 0).is_none(),
        "the sessionless path must not install an entry as a side effect"
    );
}

/// THE OVER-REACH CONTROL. Same sessionless shape, filter PERMITS the flow —
/// no verdict, so the packet forwards. The deny term is present and matches a
/// SIBLING port on the same interface, so the filter is genuinely one that can
/// deny; an all-accept filter would make this pass for the wrong reason.
///
/// Without this cell the one above is satisfied by "deny every sessionless
/// packet", which would black-hole the entire #2120 transient window and every
/// reverse-NAT repair on a full table.
#[test]
fn a_sessionless_resolved_decision_is_forwarded_when_permitted_8114() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![deny_term("no-ssh", "22"), accept_term("web", "5201")],
    );
    let flow = v4_flow(5201);
    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(7);

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none(),
        "a permitted sessionless packet must forward — no verdict, no counter, \
         no log"
    );
}

/// THE HOT-PATH GUARD, and the reason `Fresh` and `NoLocalEntry` had to become
/// distinguishable rather than "derive whenever the key does not resolve".
///
/// `Fresh` is the answer for every packet but one per session per (generation,
/// ingress) — i.e. the entire population the feature serves. It must stay a
/// single hash and a compare. A change that folded the new derivation into the
/// fresh case would turn every established hit on a filtered interface into a
/// static filter walk, and nothing else in the suite would notice: the verdict
/// would be identical.
///
/// The fixture puts the filter in DENY on the flow while the stamp is fresh —
/// unreachable in production (a fresh stamp under this generation means this
/// filter already accepted it) and exactly the state that separates "re-derive
/// when stale" from "re-derive when the filter denies".
#[test]
fn a_fresh_stamp_is_not_re_derived_by_the_8114_sessionless_arm_8114() {
    let forwarding =
        forwarding_with_input_filter(LAN_IFINDEX, false, vec![deny_term("no-5201", "5201")]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, Some(LAN_IFINDEX));

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none(),
        "a fresh stamp must cost a lookup and a compare, not a filter walk"
    );
    assert!(
        sessions.lookup(&flow.forward_key, 2_000, 0).is_some(),
        "and the session must be untouched"
    );
}

// ---------------------------------------------------------------------------
// #8114 item 1 — a matched `routing-instance` term's own terminal action.
// ---------------------------------------------------------------------------

/// A PBR term: `from { protocol tcp; destination-port <dport>; } then {
/// routing-instance blue; <action>; }`, with `count` so the "charged exactly
/// once" claim is measurable.
fn pbr_term(name: &str, dport: &str, action: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        name: name.into(),
        protocols: vec!["tcp".into()],
        destination_ports: vec![dport.into()],
        routing_instance: "blue".into(),
        action: action.into(),
        count: "pbr-counter".into(),
        syslog: false,
        reject_message_type: String::new(),
        ..Default::default()
    }
}

/// THE CASE #8114 item 1 names. `then { routing-instance blue; discard; }` is a
/// DROP — #4392 established that, and `ingress_route_table_override` returns
/// `RouteOverride::Drop` for it on the session-MISS path. The revalidation must
/// reach the same verdict, and it could not before: the non-routing walk returns
/// the default Accept the moment it matches a routing-instance term, before that
/// term's own action is read.
///
/// Everything asserted here is a thing the old decline got wrong in a DIFFERENT
/// way, so no single sloppy fix satisfies them all: the action (was: no verdict
/// at all), the revocation (was: the session survived), the log source (a record
/// claiming `Input` for a term the miss path logs as `Pbr` is a mislabel an
/// operator correlates against), and the count (the verdict walk must be
/// side-effect free, so the packet is charged once by the replay, not twice).
///
/// Fail-on-revert: restore `if filter.affects_route_lookup { return None; }` and
/// the `.expect` reds.
#[test]
fn a_pbr_term_that_discards_revokes_the_session_8114() {
    use std::sync::atomic::Ordering;

    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![pbr_term("pbr-drop", "5201", "discard")],
    );
    let flow = v4_flow(5201);
    let filter =
        crate::filter::interface_input_filter(&forwarding.filter_state, LAN_IFINDEX, false)
            .expect("the filter is attached");
    assert!(
        filter.affects_route_lookup,
        "fixture liveness: without a routing-instance term this cell is about \
         nothing"
    );
    // The OLD verdict source still reads Accept for this flow — which is the
    // deferral, and the whole reason the composed verdict exists. Without this
    // the cell could pass against a filter whose plain terms happened to deny.
    assert_eq!(
        crate::filter::filter_ref_static_verdict(
            filter,
            flow.src_ip,
            flow.dst_ip,
            PROTO_TCP,
            flow.forward_key.src_port,
            flow.forward_key.dst_port,
            0,
            crate::filter::TermMatchExtra::default(),
        ),
        crate::filter::FilterAction::Accept,
        "fixture liveness: the non-routing walk DEFERS here, so a fix that only \
         consulted it would still forward this flow"
    );

    let mut sessions = table_with_session(&flow, 7, None);
    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("a PBR term that discards must produce a verdict, not a decline");
    assert_eq!(hit.eval.action, crate::filter::FilterAction::Discard);
    assert_eq!(
        hit.revoked_key.as_ref(),
        Some(&flow.forward_key),
        "the filter now denies the FLOW, so the session is revoked, not merely \
         this packet dropped"
    );
    assert_eq!(
        hit.log_source,
        crate::afxdp::event_emit::FilterLogSource::Pbr,
        "the verdict came from a routing-instance term; the session-MISS path \
         logs that term as Pbr and the two must not label it differently"
    );
    assert_eq!(
        filter.terms[0].counter.packets.load(Ordering::Relaxed),
        1,
        "charged EXACTLY once: the verdict walk is side-effect free and the \
         counted replay runs only on the DENY arm. Two means the verdict walk \
         counted too; zero means the replay did not run"
    );
}

/// THE PERMIT CONTROL, and the scope statement. A PLAIN `then { routing-instance
/// blue; }` term is a permit that changes the route table, so it must NOT revoke
/// — `ingress_route_table_override` applies the override and forwards.
///
/// Without this cell "revoke whenever a PBR term matches" satisfies the cell
/// The current-generation control for #10467: a permitted PBR session keeps
/// #8114's no-flap behavior. A separate stale-generation cell below covers a
/// newly appearing/different steer, where the hit must not keep MAIN.
#[test]
fn a_plain_pbr_term_does_not_revoke_the_session_8114() {
    use std::sync::atomic::Ordering;

    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![pbr_term("pbr-route", "5201", "accept")],
    );
    let flow = v4_flow(5201);
    let filter =
        crate::filter::interface_input_filter(&forwarding.filter_state, LAN_IFINDEX, false)
            .expect("the filter is attached");
    // Current-generation control: #8114's permitted PBR session remains
    // established without per-hit route churn.
    let mut sessions = table_with_session(&flow, 7, Some(LAN_IFINDEX));

    assert!(
        evaluate_input_filter_on_session_hit(
            &forwarding,
            &mut sessions,
            &flow.forward_key,
            &frame(),
            Some(&flow),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
        )
        .is_none(),
        "a routing-instance term with no drop action PERMITS the flow; revoking \
         here tears down every deliberately VRF-routed session"
    );
    assert_eq!(
        filter.terms[0].counter.packets.load(Ordering::Relaxed),
        0,
        "and the verdict walk must be side-effect free — a permitted \
         revalidation charges nothing, exactly as the non-PBR path does"
    );
    assert!(
        sessions.lookup(&flow.forward_key, 2_000, 0).is_some(),
        "the session survives"
    );
}

/// A stale hit whose newly matching PBR term points at an empty VRF must
/// re-resolve in that VRF, not continue with the cached MAIN route. The poll
/// caller turns this route-transition result into a pair teardown/discard, so
/// `NoRoute` here is the fail-closed route proof rather than a MAIN fallback.
#[test]
fn a_stale_pbr_steer_to_empty_vrf_does_not_keep_main_10467() {
    let forwarding = forwarding_with_empty_blue_pbr();
    let flow = v4_flow(5201);
    let sessions = table_with_session(&flow, 7, None);
    let neighbors = std::sync::Arc::new(ShardedNeighborMap::new());

    let route = revalidate_static_pbr_route_on_session_hit(
        &forwarding,
        &neighbors,
        &sessions,
        &flow.forward_key,
        &flow,
        &frame(),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
        decision(),
    )
    .expect("the stale PBR term must produce a route-transition result");
    assert_eq!(route.canonical_key, flow.forward_key);
    assert_eq!(
        route.resolution.disposition,
        crate::afxdp::ForwardingDisposition::NoRoute,
        "the explicit blue table is empty for this destination; resolving MAIN \
         would preserve the pre-fix forwarding leak"
    );
}

/// A Fresh HIT still evaluates per-packet PBR predicates against the current
/// frame. The old `varies_per_packet_within_flow()` early return silently kept
/// the cached MAIN identity and left route-changing terms unenforced.
#[test]
fn a_per_packet_pbr_route_is_revalidated_from_the_hit_frame_10467() {
    let mut term = pbr_term("pbr-syn", "5201", "accept");
    term.tcp_flags = Some(crate::tcp_flags::TCP_SYN);
    let forwarding = forwarding_with_input_filter(LAN_IFINDEX, false, vec![term]);
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);
    sessions.mark_filter_revalidated(&flow.forward_key, LAN_IFINDEX);
    let neighbors = std::sync::Arc::new(ShardedNeighborMap::new());
    let mut hit_meta = meta(LAN_IFINDEX as u32, 0, false);
    // The shim-stamped TCP flags are authoritative for the frame-derived
    // matcher extra; the builder deliberately does not trust payload bytes.
    hit_meta.tcp_flags = crate::tcp_flags::TCP_SYN;

    let route = revalidate_static_pbr_route_on_session_hit(
        &forwarding,
        &neighbors,
        &sessions,
        &flow.forward_key,
        &flow,
        &frame(),
        hit_meta,
        Some(TEST_LAN_ZONE_ID),
        decision(),
    )
    .expect("a matching per-packet PBR term must revalidate the fresh hit");
    assert_eq!(
        route.resolution.disposition,
        crate::afxdp::ForwardingDisposition::NoRoute,
        "the test table is intentionally empty; retaining cached MAIN would \
         incorrectly avoid the route-transition result"
    );
}

/// A FRESH NAT-alias HIT still carries the canonical session key into the
/// per-packet route check. The wire tuple is not a teardown key: using it for
/// revocation would leave the reverse entry alive after the steer changes.
#[test]
fn a_fresh_per_packet_pbr_nat_alias_hit_revokes_canonical_key_10467() {
    let forwarding = forwarding_with_empty_blue_per_packet_pbr();
    let reverse_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        src_port: 5201,
        dst_port: 12345,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut reverse_decision = decision();
    reverse_decision.nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    reverse_decision.nat.rewrite_dst_port = Some(5201);
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;

    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(7);
    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        reverse_decision,
        reverse_metadata,
        SessionOrigin::ReverseFlow,
        1_000,
        PROTO_TCP,
        0,
    ));
    let wire_key = crate::session::translated_session_key(&reverse_key, reverse_decision.nat);
    assert_ne!(
        wire_key, reverse_key,
        "fixture liveness: the wire tuple must differ from the canonical key"
    );
    let flow = SessionFlow {
        src_ip: wire_key.src_ip,
        dst_ip: wire_key.dst_ip,
        forward_key: wire_key.clone(),
    };
    sessions.mark_filter_revalidated(&reverse_key, LAN_IFINDEX);
    let neighbors = std::sync::Arc::new(ShardedNeighborMap::new());
    let mut hit_meta = meta(LAN_IFINDEX as u32, 0, false);
    hit_meta.tcp_flags = crate::tcp_flags::TCP_SYN;

    let route = revalidate_static_pbr_route_on_session_hit(
        &forwarding,
        &neighbors,
        &sessions,
        &wire_key,
        &flow,
        &frame(),
        hit_meta,
        Some(TEST_LAN_ZONE_ID),
        decision(),
    )
    .expect("a matching fresh per-packet PBR alias must revalidate");
    assert_eq!(route.canonical_key, reverse_key);
    assert_eq!(route.revoked_key.as_ref(), Some(&reverse_key));
    assert_eq!(
        route.resolution.disposition,
        crate::afxdp::ForwardingDisposition::NoRoute,
        "the empty blue table must win over the cached MAIN route"
    );
}

/// A PBR packet with no local session entry is a packet derivation, not a
/// revocation: the route transition still fails closed, but there is no
/// canonical entry to clear or tear down.
#[test]
fn a_per_packet_pbr_no_local_entry_derives_without_revocation_10467() {
    let forwarding = forwarding_with_empty_blue_per_packet_pbr();
    let flow = v4_flow(5201);
    let sessions = SessionTable::new();
    let neighbors = std::sync::Arc::new(ShardedNeighborMap::new());
    let mut hit_meta = meta(LAN_IFINDEX as u32, 0, false);
    hit_meta.tcp_flags = crate::tcp_flags::TCP_SYN;

    let route = revalidate_static_pbr_route_on_session_hit(
        &forwarding,
        &neighbors,
        &sessions,
        &flow.forward_key,
        &flow,
        &frame(),
        hit_meta,
        Some(TEST_LAN_ZONE_ID),
        decision(),
    )
    .expect("a matching PBR packet must derive its empty-VRF route");
    assert!(route.revoked_key.is_none());
    assert_eq!(
        route.resolution.disposition,
        crate::afxdp::ForwardingDisposition::NoRoute
    );
}

/// A sessionless packet with a route-affecting filter but no matching PBR term
/// keeps the native MAIN identity; the route revalidator must not turn that
/// ordinary nonmatch into a synthetic discard.
#[test]
fn a_per_packet_pbr_no_local_nonmatch_keeps_default_route_10467() {
    let forwarding = forwarding_with_empty_blue_per_packet_pbr();
    let flow = v4_flow(5202);
    let sessions = SessionTable::new();
    let neighbors = std::sync::Arc::new(ShardedNeighborMap::new());
    let mut hit_meta = meta(LAN_IFINDEX as u32, 0, false);
    hit_meta.tcp_flags = crate::tcp_flags::TCP_SYN;

    assert!(
        revalidate_static_pbr_route_on_session_hit(
            &forwarding,
            &neighbors,
            &sessions,
            &flow.forward_key,
            &flow,
            &frame(),
            hit_meta,
            Some(TEST_LAN_ZONE_ID),
            decision(),
        )
        .is_none(),
        "a nonmatching sessionless packet must keep native MAIN route handling"
    );
}

/// A keyed-GRE/L3-only flow carries (0,0) synthetic ports. The HIT evaluator
/// must set `ports_unknown` exactly as the MISS evaluator does, so a port
/// constrained PBR term (including a negated/except form) cannot spuriously
/// steer the session.
#[test]
fn a_zero_port_pbr_term_is_not_selected_on_a_hit_9894() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![pbr_term("pbr-port-zero", "0", "accept")],
    );
    let mut flow = v4_flow(0);
    flow.forward_key.src_port = 0;
    flow.forward_key.dst_port = 0;
    let sessions = table_with_session(&flow, 7, None);
    let neighbors = std::sync::Arc::new(ShardedNeighborMap::new());

    assert!(
        revalidate_static_pbr_route_on_session_hit(
            &forwarding,
            &neighbors,
            &sessions,
            &flow.forward_key,
            &flow,
            &frame(),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
            decision(),
        )
        .is_none(),
        "synthetic (0,0) ports must not match a port-constrained PBR term"
    );
}

/// A stale hit on an unchanged native RI keeps #10312's table identity. The
/// route revalidation must not treat "no PBR term" as an implicit MAIN switch.
#[test]
fn a_stale_native_ri_session_keeps_its_table_10312() {
    let forwarding = forwarding_with_native_blue_ri();
    let flow = v4_flow(5201);
    let sessions = table_with_session(&flow, 7, None);
    let neighbors = std::sync::Arc::new(ShardedNeighborMap::new());
    let (domain, check) = crate::session::install_table_identity("blue");
    let mut native_decision = decision();
    native_decision.install_table_domain = domain;
    native_decision.install_table_check = check;

    assert!(
        revalidate_static_pbr_route_on_session_hit(
            &forwarding,
            &neighbors,
            &sessions,
            &flow.forward_key,
            &flow,
            &frame(),
            meta(LAN_IFINDEX as u32, 0, false),
            Some(TEST_LAN_ZONE_ID),
            native_decision,
        )
        .is_none(),
        "an unchanged native RI must not be torn down on a generation bump"
    );
}

/// A `then { routing-instance blue; reject; }` term is the other half of #4392's
/// DROP set, and `enqueue_filter_reject_reply` keys on `FilterAction::Reject`,
/// so a fix that collapsed both onto `Discard` would silently stop sending the
/// RST/ICMP the operator asked for.
#[test]
fn a_pbr_term_that_rejects_keeps_its_reject_action_8114() {
    let forwarding = forwarding_with_input_filter(
        LAN_IFINDEX,
        false,
        vec![pbr_term("pbr-reject", "5201", "reject")],
    );
    let flow = v4_flow(5201);
    let mut sessions = table_with_session(&flow, 7, None);

    let hit = evaluate_input_filter_on_session_hit(
        &forwarding,
        &mut sessions,
        &flow.forward_key,
        &frame(),
        Some(&flow),
        meta(LAN_IFINDEX as u32, 0, false),
        Some(TEST_LAN_ZONE_ID),
    )
    .expect("a PBR term that rejects must produce a verdict");
    assert!(
        matches!(hit.eval.action, crate::filter::FilterAction::Reject(_)),
        "the term's REJECT must survive as a Reject — the caller keys the \
         RST/ICMP reply on it, so collapsing it to Discard silently drops the \
         reply. got {:?}",
        hit.eval.action
    );
    assert_eq!(hit.revoked_key.as_ref(), Some(&flow.forward_key));
}
