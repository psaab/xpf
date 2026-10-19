// #15790 (G33-01): `StaticNatTable::from_snapshots` built `dnat_by_dst`
// with `.insert(*ip, indexed)` inside the loop over the `dnat` map, so
// when several port keys shared one external IP only the last-iterated
// key's entries survived in the index and the rest were invisible to
// every indexed probe (`dnat_port_entries_for` — the flowless /
// fragment / non-TCP-UDP probes — and, once routed through the index,
// `nat_local_match_possible`). The `snat` leg of
// `flowless_l4_translation_possible` and `nat_local_match_possible`
// also had no index at all and linearly scanned their whole maps.
//
// These tests pin the indexed behaviour with two different-port rules
// on ONE external IP (203.0.113.10:80 and :443, distinct internal
// targets so the surviving entry is identifiable), in BOTH snapshot
// orders: whichever rule the pre-fix `insert` discarded must still be
// found by its own probe. A same-port control sharing one index bucket
// and a negative control (unconfigured port / unrelated destination)
// guard against an over-broad fix.

use super::static_nat::StaticNatTable;
use super::*;
use crate::StaticNATRuleSnapshot;
use std::net::IpAddr;

const EXT: &str = "203.0.113.10";

fn snap(
    name: &str,
    external: &str,
    internal: &str,
    match_port: u16,
    mapped_port: u16,
) -> StaticNATRuleSnapshot {
    StaticNATRuleSnapshot {
        name: name.to_string(),
        external_ip: external.to_string(),
        internal_ip: internal.to_string(),
        match_destination_port: match_port,
        mapped_port,
        ..StaticNATRuleSnapshot::default()
    }
}

/// Two-port fixture on one external IP. `web` maps :80 -> 192.168.80.10,
/// `tls` maps :443 -> 192.168.43.10 (mapped ports equal match ports so
/// each rule's key is its external port). Returned in the order given
/// by `web_first`.
fn two_port_table(web_first: bool) -> StaticNatTable {
    let web = snap("web", EXT, "192.168.80.10", 80, 80);
    let tls = snap("tls", EXT, "192.168.43.10", 443, 443);
    let snaps = if web_first {
        vec![web, tls]
    } else {
        vec![tls, web]
    };
    StaticNatTable::from_snapshots(&snaps, &NatCounterStore::default())
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn multiport_same_ip_both_ports_reachable_via_indexed_probes_15790() {
    let src = ip("198.51.100.7");
    let ext = ip(EXT);
    // Repeat in both snapshot orders: the pre-fix bug discarded
    // whichever port key was NOT iterated last from the `dnat` map,
    // and map iteration order is not snapshot order, so a single order
    // cannot prove both buckets survive.
    for web_first in [true, false] {
        let table = two_port_table(web_first);

        // The main DNAT path keys the `dnat` map directly and was
        // never affected — sanity anchor for both ports.
        assert!(
            table.match_dnat_with_counter(ext, 80, "").is_some(),
            "main DNAT path must match :80 (web_first={web_first})"
        );
        assert!(
            table.match_dnat_with_counter(ext, 443, "").is_some(),
            "main DNAT path must match :443 (web_first={web_first})"
        );

        // Flowless / local probes go through `dnat_by_dst`. Restrict
        // the source per rule so each port is identifiable: re-scope
        // via distinct probes below instead — here both rules are
        // unconstrained, so the indexed probe must report possible.
        assert!(
            table.flowless_l4_dnat_translation_possible(
                crate::ip_proto::PROTO_TCP,
                src,
                ext,
                "",
                "",
                "",
            ),
            "indexed flowless DNAT probe must see a port rule on {EXT} (web_first={web_first})"
        );
        assert!(
            table.flowless_non_tcp_udp_port_map_possible(Some(253), src, ext, "", "", "",),
            "indexed port-map probe must see a mapped-port rule on {EXT} (web_first={web_first})"
        );
        assert!(
            table.flowless_l4_translation_possible(
                crate::ip_proto::PROTO_TCP,
                src,
                ext,
                "",
                "",
                "",
                "",
                "",
                "",
            ),
            "combined flowless probe must see a port rule on {EXT} (web_first={web_first})"
        );

        // `nat_local_match_possible` is port-specific: BOTH configured
        // ports must claim, an unconfigured port must NOT.
        for port in [80u16, 443] {
            assert!(
                table.nat_local_match_possible(
                    crate::ip_proto::PROTO_TCP,
                    src,
                    ext,
                    port,
                    "",
                    "",
                    "",
                ),
                "nat_local_match_possible must claim :{port} on {EXT} (web_first={web_first})"
            );
        }
        assert!(
            !table.nat_local_match_possible(crate::ip_proto::PROTO_TCP, src, ext, 22, "", "", "",),
            "nat_local_match_possible must NOT claim unconfigured :22 on {EXT} (web_first={web_first})"
        );
        // Negative control: an unrelated destination claims nothing.
        assert!(
            !table.nat_local_match_possible(
                crate::ip_proto::PROTO_TCP,
                src,
                ip("203.0.113.99"),
                80,
                "",
                "",
                "",
            ),
            "nat_local_match_possible must NOT claim an unrelated destination (web_first={web_first})"
        );
        assert!(
            !table.flowless_l4_dnat_translation_possible(
                crate::ip_proto::PROTO_TCP,
                src,
                ip("203.0.113.99"),
                "",
                "",
                "",
            ),
            "flowless DNAT probe must NOT claim an unrelated destination (web_first={web_first})"
        );
    }
}

#[test]
fn multiport_same_ip_scoped_rules_identify_each_port_15790() {
    // Give each port rule a DISTINCT source constraint so a probe with
    // a given source can only be admitted by its own port's entry.
    // Pre-fix, the discarded port's entry was invisible to the indexed
    // probes, so the matching-source probe for that port returned
    // false even though the rule was installed.
    let mut web = snap("web", EXT, "192.168.80.10", 80, 80);
    web.source_addresses = vec!["198.51.100.80/32".to_string()];
    let mut tls = snap("tls", EXT, "192.168.43.10", 443, 443);
    tls.source_addresses = vec!["198.51.100.43/32".to_string()];

    for snaps in [
        vec![web.clone(), tls.clone()],
        vec![tls.clone(), web.clone()],
    ] {
        let table = StaticNatTable::from_snapshots(&snaps, &NatCounterStore::default());
        let ext = ip(EXT);
        let web_src = ip("198.51.100.80");
        let tls_src = ip("198.51.100.43");
        let other_src = ip("198.51.100.99");

        // Each source admitted by exactly its own port's rule.
        assert!(
            table.nat_local_match_possible(
                crate::ip_proto::PROTO_TCP,
                web_src,
                ext,
                80,
                "",
                "",
                ""
            ),
            "web source must claim :80"
        );
        assert!(
            table.nat_local_match_possible(
                crate::ip_proto::PROTO_TCP,
                tls_src,
                ext,
                443,
                "",
                "",
                ""
            ),
            "tls source must claim :443"
        );
        // Cross claims must fail: web source on :443, tls source on :80.
        assert!(
            !table.nat_local_match_possible(
                crate::ip_proto::PROTO_TCP,
                web_src,
                ext,
                443,
                "",
                "",
                ""
            ),
            "web source must NOT claim :443"
        );
        assert!(
            !table.nat_local_match_possible(
                crate::ip_proto::PROTO_TCP,
                tls_src,
                ext,
                80,
                "",
                "",
                ""
            ),
            "tls source must NOT claim :80"
        );
        // A source admitted by neither rule claims nothing on either port.
        assert!(
            !table.nat_local_match_possible(
                crate::ip_proto::PROTO_TCP,
                other_src,
                ext,
                80,
                "",
                "",
                ""
            ),
            "unrelated source must NOT claim :80"
        );
        assert!(
            !table.nat_local_match_possible(
                crate::ip_proto::PROTO_TCP,
                other_src,
                ext,
                443,
                "",
                "",
                ""
            ),
            "unrelated source must NOT claim :443"
        );
        // Flowless probes (port-agnostic) must still see each rule
        // under its own source, and no rule under the unrelated source.
        assert!(
            table.flowless_l4_dnat_translation_possible(
                crate::ip_proto::PROTO_TCP,
                web_src,
                ext,
                "",
                "",
                ""
            ),
            "flowless probe must see the web rule under its source"
        );
        assert!(
            table.flowless_l4_dnat_translation_possible(
                crate::ip_proto::PROTO_TCP,
                tls_src,
                ext,
                "",
                "",
                ""
            ),
            "flowless probe must see the tls rule under its source"
        );
        assert!(
            !table.flowless_l4_dnat_translation_possible(
                crate::ip_proto::PROTO_TCP,
                other_src,
                ext,
                "",
                "",
                ""
            ),
            "flowless probe must see no rule under an unrelated source"
        );
    }
}

#[test]
fn multiport_same_ip_snat_leg_indexed_per_source_15790() {
    // The outbound leg of `flowless_l4_translation_possible` consults
    // `snat` keyed by the packet SOURCE (the internal host). Two rules
    // whose internal hosts differ but share an external IP: each
    // internal source must be reported possible via the indexed `snat`
    // leg, an unknown source must not, and the DNAT leg (dst = an
    // unrelated address, so it cannot fire) must not mask the result.
    let table = two_port_table(true);
    let unrelated_dst = ip("203.0.113.99");
    let client = ip("198.51.100.7");

    for internal in ["192.168.80.10", "192.168.43.10"] {
        assert!(
            table.flowless_l4_translation_possible(
                crate::ip_proto::PROTO_TCP,
                ip(internal),
                unrelated_dst,
                "",
                "",
                "",
                "",
                "",
                "",
            ),
            "indexed SNAT leg must report internal source {internal} possible"
        );
    }
    assert!(
        !table.flowless_l4_translation_possible(
            crate::ip_proto::PROTO_TCP,
            ip("192.168.99.10"),
            unrelated_dst,
            "",
            "",
            "",
            "",
            "",
            "",
        ),
        "indexed SNAT leg must NOT report an unknown internal source possible"
    );
    // The packet destination (original client on the reverse path) is
    // source-checked against the rule: unconstrained rules admit any.
    assert!(
        table.flowless_l4_translation_possible(
            crate::ip_proto::PROTO_TCP,
            ip("192.168.80.10"),
            client,
            "",
            "",
            "",
            "",
            "",
            "",
        ),
        "indexed SNAT leg must admit an unconstrained destination"
    );
}
