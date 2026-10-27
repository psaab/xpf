//! #17088: `translated_session_key` diverged from its twins.
//!
//! The four NAT key builders in `key.rs` are one transform
//! (`nat_applied_key`); the pre-fix hand-kept copies drifted in two
//! places, both on the REVERSE-decision path of
//! `translated_session_key`:
//!
//!   * ICMP + SNAT: a reverse decision carries the ORIGINAL ICMP id in
//!     `rewrite_dst_port` (`NatDecision::reverse` moved it there), but
//!     the old alias builder read only `rewrite_src_port`, so the alias
//!     kept the TRANSLATED id (40000) instead of the original (777).
//!   * NAT64: the old alias builder never applied the AF/protocol
//!     remap, so it produced a mixed-family key (`addr_family ==
//!     AF_INET` with a V6 `src_ip`) that no packet carries.
//!
//! Every expected key below is written independently (literal tuple
//! construction), never derived from the builder under test — the
//! pre-fix tests derived their expected keys from
//! `translated_session_key` itself and so could not fail. The matrix
//! is {TCP, UDP, ICMP, ICMPv6} x {none, SNAT-PAT, DNAT, NAT64}.

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}

fn key(af: u8, proto: u8, src: IpAddr, dst: IpAddr, sport: u16, dport: u16) -> SessionKey {
    SessionKey {
        addr_family: af,
        protocol: proto,
        src_ip: src,
        dst_ip: dst,
        src_port: sport,
        dst_port: dport,
        discriminator: TunnelDiscriminator::None,
        routing_domain: 0,
    }
}

const AF4: u8 = libc::AF_INET as u8;
const AF6: u8 = libc::AF_INET6 as u8;
/// One matrix cell: a forward flow, its forward NAT decision, and the
/// independently written translated alias. The alias is the reverse
/// entry's key with the reverse decision's rewrites applied
/// (`translated_session_key(reverse_key, reverse_nat)`, with
/// `reverse_nat = nat.reverse(forward tuple)` — the production
/// reverse-decision shape from `reverse_synth.rs`). Expected tuples
/// are written literally per cell, never derived from the builder:
/// for SNAT the alias recovers the original source/id; for DNAT it
/// equals the reverse key (the production reverse decision already
/// restored the VIP tuple); for NAT64 it is a single-family key.
struct Cell {
    name: &'static str,
    forward: SessionKey,
    nat: NatDecision,
    expected_alias: SessionKey,
}

fn cells() -> Vec<Cell> {
    let client = v4(10, 0, 0, 1);
    let server = v4(8, 8, 8, 8);
    let snat_ip = v4(198, 51, 100, 7);
    let vip = v4(203, 0, 113, 9);
    let backend = v4(10, 0, 61, 50);
    let client6 = v6("2001:db8::1");
    let server6 = v6("2001:db8:1::8");
    let snat6 = v6("2001:db8:2::7");
    let backend6 = v6("2001:db8:3::50");

    let no_nat = NatDecision::default();
    let mut out = Vec::new();

    // -- TCP -------------------------------------------------------------
    // none: alias is the reverse key itself (unchanged).
    out.push(Cell {
        name: "tcp/none",
        forward: key(AF4, PROTO_TCP, client, server, 12345, 443),
        nat: no_nat,
        expected_alias: key(AF4, PROTO_TCP, server, client, 443, 12345),
    });
    // SNAT-PAT: forward src 10.0.0.1:12345 -> 198.51.100.7:40000. The
    // reply arrives 8.8.8.8:443 -> 198.51.100.7:40000 and is un-SNATed
    // to dst 10.0.0.1:12345.
    out.push(Cell {
        name: "tcp/snat-pat",
        forward: key(AF4, PROTO_TCP, client, server, 12345, 443),
        nat: NatDecision {
            rewrite_src: Some(snat_ip),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        },
        expected_alias: key(AF4, PROTO_TCP, server, client, 443, 12345),
    });
    // DNAT: forward dst 203.0.113.9:443 -> 10.0.61.50:8443. The
    // production reverse decision (`nat.reverse(forward)`) restores
    // the VIP as the reply source, so the reverse entry is keyed on
    // (203.0.113.9:443 -> client) and its alias equals that key.
    out.push(Cell {
        name: "tcp/dnat",
        forward: key(AF4, PROTO_TCP, client, vip, 12345, 443),
        nat: NatDecision {
            rewrite_dst: Some(backend),
            rewrite_dst_port: Some(8443),
            ..NatDecision::default()
        },
        expected_alias: key(AF4, PROTO_TCP, vip, client, 443, 12345),
    });
    // NAT64 (v6 forward -> v4 wire): forward src 2001:db8::1:12345,
    // dst 64:ff9b::808:808 (8.8.8.8); NAT64 src 198.51.100.7:40000.
    // The installed NAT64 reverse key is the v4 wire tuple
    // (8.8.8.8:443 -> 198.51.100.7:40000, built by hand in
    // poll_descriptor); the builder alias of the generic
    // `reverse_session_key` companion is the v6 pre-translation tuple
    // (64:ff9b::808:808:443 -> 2001:db8::1:12345), family AF_INET6 —
    // never AF_INET with a V6 src (the pre-fix mixed key).
    out.push(Cell {
        name: "tcp/nat64",
        forward: key(AF6, PROTO_TCP, client6, v6("64:ff9b::808:808"), 12345, 443),
        nat: NatDecision {
            rewrite_src: Some(snat_ip),
            rewrite_dst: Some(server),
            rewrite_src_port: Some(40000),
            nat64: true,
            ..NatDecision::default()
        },
        expected_alias: key(AF6, PROTO_TCP, v6("64:ff9b::808:808"), client6, 443, 12345),
    });

    // -- UDP -------------------------------------------------------------
    out.push(Cell {
        name: "udp/none",
        forward: key(AF4, PROTO_UDP, client, server, 12345, 53),
        nat: no_nat,
        expected_alias: key(AF4, PROTO_UDP, server, client, 53, 12345),
    });
    out.push(Cell {
        name: "udp/snat-pat",
        forward: key(AF4, PROTO_UDP, client, server, 12345, 53),
        nat: NatDecision {
            rewrite_src: Some(snat_ip),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        },
        expected_alias: key(AF4, PROTO_UDP, server, client, 53, 12345),
    });
    out.push(Cell {
        name: "udp/dnat",
        forward: key(AF4, PROTO_UDP, client, vip, 12345, 53),
        nat: NatDecision {
            rewrite_dst: Some(backend),
            rewrite_dst_port: Some(5353),
            ..NatDecision::default()
        },
        expected_alias: key(AF4, PROTO_UDP, vip, client, 53, 12345),
    });
    out.push(Cell {
        name: "udp/nat64",
        forward: key(AF6, PROTO_UDP, client6, v6("64:ff9b::808:808"), 12345, 53),
        nat: NatDecision {
            rewrite_src: Some(snat_ip),
            rewrite_dst: Some(server),
            rewrite_src_port: Some(40000),
            nat64: true,
            ..NatDecision::default()
        },
        expected_alias: key(AF6, PROTO_UDP, v6("64:ff9b::808:808"), client6, 53, 12345),
    });

    // -- ICMP (v4) ---------------------------------------------------------
    // The Query Identifier lives in src_port; dst_port is always 0.
    out.push(Cell {
        name: "icmp/none",
        forward: key(AF4, PROTO_ICMP, client, server, 777, 0),
        nat: no_nat,
        expected_alias: key(AF4, PROTO_ICMP, server, client, 777, 0),
    });
    // SNAT: id 777 -> 40000 on the wire. The reply carries id 40000 to
    // 198.51.100.7 and is un-SNATed back to 10.0.0.1 id 777 — the alias
    // must name id 777, NOT the translated 40000 (the pre-fix bug).
    out.push(Cell {
        name: "icmp/snat-pat",
        forward: key(AF4, PROTO_ICMP, client, server, 777, 0),
        nat: NatDecision {
            rewrite_src: Some(snat_ip),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        },
        expected_alias: key(AF4, PROTO_ICMP, server, client, 777, 0),
    });
    // DNAT (address-only; ICMP DNAT is gated to no L4 port, #4074).
    // As for tcp/dnat, the production reverse decision restores the
    // VIP source, so the alias equals the reverse key (203.0.113.9,
    // id 777).
    out.push(Cell {
        name: "icmp/dnat",
        forward: key(AF4, PROTO_ICMP, client, vip, 777, 0),
        nat: NatDecision {
            rewrite_dst: Some(backend),
            ..NatDecision::default()
        },
        expected_alias: key(AF4, PROTO_ICMP, vip, client, 777, 0),
    });
    // NAT64: forward is v4 ICMP to a v6 destination via NAT64 (dst
    // rewritten to a v6 address, src to the v6 NAT64 source). The
    // builder alias is the v4 pre-translation tuple (8.8.8.8 ->
    // 10.0.0.1, id 777), family AF_INET / protocol ICMP — never
    // AF_INET with a V6 src (the pre-fix mixed key).
    out.push(Cell {
        name: "icmp/nat64",
        forward: key(AF4, PROTO_ICMP, client, server, 777, 0),
        nat: NatDecision {
            rewrite_src: Some(snat6),
            rewrite_dst: Some(server6),
            rewrite_src_port: Some(40000),
            nat64: true,
            ..NatDecision::default()
        },
        expected_alias: key(AF4, PROTO_ICMP, server, client, 777, 0),
    });

    // -- ICMPv6 ------------------------------------------------------------
    out.push(Cell {
        name: "icmpv6/none",
        forward: key(AF6, PROTO_ICMPV6, client6, server6, 777, 0),
        nat: no_nat,
        expected_alias: key(AF6, PROTO_ICMPV6, server6, client6, 777, 0),
    });
    out.push(Cell {
        name: "icmpv6/snat-pat",
        forward: key(AF6, PROTO_ICMPV6, client6, server6, 777, 0),
        nat: NatDecision {
            rewrite_src: Some(snat6),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        },
        expected_alias: key(AF6, PROTO_ICMPV6, server6, client6, 777, 0),
    });
    out.push(Cell {
        name: "icmpv6/dnat",
        forward: key(AF6, PROTO_ICMPV6, client6, server6, 777, 0),
        nat: NatDecision {
            rewrite_dst: Some(backend6),
            ..NatDecision::default()
        },
        expected_alias: key(AF6, PROTO_ICMPV6, server6, client6, 777, 0),
    });
    // NAT64: v6 ICMPv6 forward -> v4 wire (dst 8.8.8.8, src
    // 198.51.100.7, id 40000). The builder alias is the v6
    // pre-translation tuple (64:ff9b::808:808 -> 2001:db8::1, id
    // 777), family AF_INET6 / protocol ICMPv6 — never AF_INET with a
    // V6 src (the pre-fix mixed key).
    out.push(Cell {
        name: "icmpv6/nat64",
        forward: key(AF6, PROTO_ICMPV6, client6, v6("64:ff9b::808:808"), 777, 0),
        nat: NatDecision {
            rewrite_src: Some(snat_ip),
            rewrite_dst: Some(server),
            rewrite_src_port: Some(40000),
            nat64: true,
            ..NatDecision::default()
        },
        expected_alias: key(AF6, PROTO_ICMPV6, v6("64:ff9b::808:808"), client6, 777, 0),
    });

    out
}

/// #17088 twin-matrix: for every {TCP, UDP, ICMP, ICMPv6} x {none,
/// SNAT-PAT, DNAT, NAT64} cell, the reverse entry's translated alias
/// equals the independently written post-translation reply tuple, and
/// the twin builders agree on the reply identity.
///
/// RED on pre-fix master for icmp/snat-pat (alias kept the translated
/// id 40000) and for both nat64 cells (mixed-family alias). The twin
/// controls (`reverse_session_key` round-trip, `forward_wire_key`,
/// `reverse_wire_key`) pin that the refactor does not move the
/// builders that were already correct.
#[test]
fn translated_alias_matches_independent_reply_tuple_across_twin_matrix_17088() {
    for cell in cells() {
        let reverse_key = reverse_session_key(&cell.forward, cell.nat);
        let reverse_nat = cell.nat.reverse(
            cell.forward.src_ip,
            cell.forward.dst_ip,
            cell.forward.src_port,
            cell.forward.dst_port,
        );

        let alias = translated_session_key(&reverse_key, reverse_nat);
        assert_eq!(
            alias, cell.expected_alias,
            "{}: translated alias must equal the independently written \
             post-translation reply tuple",
            cell.name
        );

        // Twin control 1: the reverse companion round-trips to the
        // forward key (the #4074 property `reverse_session_key` already
        // had; the alias builder lacked it).
        assert_eq!(
            reverse_session_key(&reverse_key, reverse_nat),
            cell.forward,
            "{}: reverse_session_key(reverse) must recover the forward key",
            cell.name
        );

        // Twin control 2: the forward wire tuple is the forward key
        // with the forward NAT applied (written independently here by
        // applying the decision fields directly).
        let wire = forward_wire_key(&cell.forward, cell.nat);
        assert_eq!(
            wire.src_ip,
            cell.nat.rewrite_src.unwrap_or(cell.forward.src_ip),
            "{}: forward wire src",
            cell.name
        );
        assert_eq!(
            wire.dst_ip,
            cell.nat.rewrite_dst.unwrap_or(cell.forward.dst_ip),
            "{}: forward wire dst",
            cell.name
        );

        // Twin control 3: the reverse wire key is domain-agnostic. For
        // NAT64 cells it is the POST-translation (wire-family) reply
        // tuple — written literally here: v4 for the v6-forward cells
        // (src 8.8.8.8, the NAT64 dst), v6 for the v4-forward icmp
        // cell (src 2001:db8:1::8, the NAT64 dst). This is the family
        // the alias must NOT mix: the alias is the pre-translation
        // tuple in the forward family.
        let rev_wire = reverse_wire_key(&cell.forward, cell.nat);
        assert_eq!(
            rev_wire.routing_domain, 0,
            "{}: reverse wire key must be domain-agnostic",
            cell.name
        );
        if cell.nat.nat64 {
            let (wire_af, wire_src) = match cell.forward.addr_family {
                AF6 => (AF4, cell.nat.rewrite_dst.unwrap()),
                _ => (AF6, cell.nat.rewrite_dst.unwrap()),
            };
            assert_eq!(
                rev_wire.addr_family, wire_af,
                "{}: NAT64 reverse wire key must be in the wire family",
                cell.name
            );
            assert_eq!(
                rev_wire.src_ip, wire_src,
                "{}: NAT64 reverse wire src must be the NAT64 destination",
                cell.name
            );
            // The alias family is the forward family, single-family:
            // addr_family agrees with both address families.
            assert_eq!(
                cell.expected_alias.addr_family,
                match cell.expected_alias.src_ip {
                    IpAddr::V4(_) => AF4,
                    IpAddr::V6(_) => AF6,
                },
                "{}: alias addr_family must match its src address family",
                cell.name
            );
            assert_eq!(
                cell.expected_alias.addr_family,
                match cell.expected_alias.dst_ip {
                    IpAddr::V4(_) => AF4,
                    IpAddr::V6(_) => AF6,
                },
                "{}: alias addr_family must match its dst address family",
                cell.name
            );
        }
    }
}

/// #17088 structural pin: the NAT64 AF/protocol remap and the ICMP-id
/// rule are single-sourced in `key.rs`. The pre-fix file carried three
/// verbatim NAT64 remap copies (forward_wire / reverse_wire /
/// reverse_session) and the translated builder carried neither the
/// remap nor the direction-agnostic `.or()` id rule. A second copy
/// fails this cell even if every behavioural cell still passes (the
/// #17046 single-source pin shape).
#[test]
fn nat_key_transform_is_single_sourced_17088() {
    let src = include_str!("key.rs");
    assert_eq!(
        src.matches("fn nat64_family_protocol").count(),
        1,
        "exactly one NAT64 family/protocol remap definition may exist"
    );
    assert_eq!(
        src.matches("nat64_family_protocol(").count(),
        2,
        "the remap may be named only at its definition and its one call site in nat_applied_key"
    );
    assert_eq!(
        src.matches("fn nat_applied_key").count(),
        1,
        "exactly one nat_applied_key definition may exist"
    );
    assert_eq!(
        src.matches(".or(nat.rewrite_dst_port)").count(),
        1,
        "exactly one direction-agnostic ICMP-id rule may exist"
    );
    // The four public builders are one-line wrappers: each body is the
    // single nat_applied_key call, with no port/family logic of its own.
    for wrapper in [
        "fn forward_wire_key",
        "fn translated_session_key",
        "fn reverse_wire_key",
        "fn reverse_session_key",
    ] {
        let start = src
            .find(wrapper)
            .unwrap_or_else(|| panic!("{wrapper} must exist"));
        let body = &src[start..src[start..].find('}').map(|i| start + i).unwrap()];
        assert!(
            body.contains("nat_applied_key("),
            "{wrapper} must delegate to nat_applied_key"
        );
        assert!(
            !body.contains("unwrap_or") && !body.contains("AF_INET"),
            "{wrapper} must not carry its own port/family logic: {body}"
        );
    }
}

/// #17088 Table-level cell: a reverse entry installed with the
/// production reverse-decision shape (as `NatDecision::reverse`
/// produces it) is indexed under the independently written alias, and
/// that alias resolves through `SessionTable::lookup`; the pre-fix
/// translated tuple (translated ICMP id) does not resolve. This is
/// the production consequence of the key-level matrix above: the
/// alias bucket key is computed by `index_forward_nat_key_parts`
/// from the same builder.
#[test]
fn reverse_entry_alias_index_resolves_independent_tuple_17088() {
    // ICMP SNAT: forward 10.0.0.1 -> 8.8.8.8 id 777, SNAT to
    // 198.51.100.7 id 40000. The reverse entry is keyed on the wire
    // reply (8.8.8.8 -> 198.51.100.7, id 40000) with the reverse
    // decision; its alias must be (8.8.8.8 -> 10.0.0.1, id 777).
    let mut table = SessionTable::new();
    let now = 1_000_000_000u64;
    let forward = key(AF4, PROTO_ICMP, v4(10, 0, 0, 1), v4(8, 8, 8, 8), 777, 0);
    let fwd_nat = NatDecision {
        rewrite_src: Some(v4(198, 51, 100, 7)),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    let reverse_key = reverse_session_key(&forward, fwd_nat);
    let reverse_nat = fwd_nat.reverse(
        forward.src_ip,
        forward.dst_ip,
        forward.src_port,
        forward.dst_port,
    );
    let decision = SessionDecision {
        resolution: crate::afxdp::ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(v4(172, 16, 50, 1)),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: reverse_nat,
        install_table_domain: 0,
        install_table_check: 0,
    };
    let md = SessionMetadata {
        ingress_zone: 2,
        egress_zone: 1,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: true,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    };
    assert!(
        table.install_with_protocol(reverse_key.clone(), decision, md, now, PROTO_ICMP, 0),
        "reverse entry must install"
    );
    let alias = key(AF4, PROTO_ICMP, v4(8, 8, 8, 8), v4(10, 0, 0, 1), 777, 0);
    assert!(
        table.lookup(&alias, now + 1, 0).is_some(),
        "the independently written alias (original id 777) must resolve the reverse entry"
    );
    let wrong = key(AF4, PROTO_ICMP, v4(8, 8, 8, 8), v4(10, 0, 0, 1), 40000, 0);
    assert!(
        table.lookup(&wrong, now + 1, 0).is_none(),
        "the pre-fix alias (translated id 40000) must not resolve"
    );
    // Removal uses the same builder: deleting the reverse entry must
    // drop the alias bucket (no stale alias left behind).
    table.delete(&reverse_key);
    assert!(
        table.lookup(&alias, now + 2, 0).is_none(),
        "alias must be removed with the reverse entry"
    );
}
