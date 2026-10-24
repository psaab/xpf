// DNAT protocol-match and protocol-number resolver tests for the nat/ module.
//
// Split out of nat/tests.rs (#4409) as a sibling `#[path]` test module
// loaded from nat/mod.rs. Pure code motion: every #[test] fn and
// test-local helper is moved verbatim.
#![allow(unused_imports)]

use super::allocator::{
    ALLOCATION_GC_BUDGET, NS_PER_SEC, PersistentLease, PersistentSourceKey, PoolAddressFamily,
    TranslatedTuple, sticky_pool_index,
};
use super::source::{PersistentNatPermit, SOURCE_NAT_PROTO_ANY, SourceNatFlowKey};
use super::destination::{PROTO_ANY, PROTO_TCP, PROTO_UDP};
use super::*;
use crate::ip_proto::{PROTO_ESP, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6};
use crate::{
    DestinationNATRuleSnapshot, NatAppTermWire, NatPortRangeWire, SourceNATRuleSnapshot,
    StaticNATRuleSnapshot,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// #2396(a): a GRE DNAT rule (protocol "gre") must install a table entry and
/// translate GRE traffic. Before #2396 the `_ => continue` arm SILENTLY
/// dropped any protocol other than tcp/udp, so this rule never reached the
/// dataplane. Fails (decision None) if the protocol is dropped again.
#[test]
fn dnat_protocol_gre_translates() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "gre-dnat".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: "gre".to_string(),
            pool_address: "192.168.1.10".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.lookup(
        PROTO_GRE,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        0,
        "",
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "GRE DNAT rule must translate GRE traffic, not be silently dropped"
    );
    // And it must NOT bleed into a different protocol (no PROTO_ANY wildcard
    // was created — this is a protocol-scoped rule).
    assert!(
        table
            .lookup(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                0,
                ""
            )
            .is_none(),
        "GRE-scoped DNAT must not match TCP"
    );
}

/// #2396(a): an ICMPv6 DNAT rule (protocol "icmp6") must install and translate.
#[test]
fn dnat_protocol_icmp6_translates() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "icmp6-dnat".to_string(),
            destination_address: "2001:db8::1".to_string(),
            destination_port: 0,
            protocol: "icmp6".to_string(),
            pool_address: "fd00::1".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.lookup(
        PROTO_ICMPV6,
        "2001:db8::100".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        0,
        "",
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_dst: Some("fd00::1".parse().unwrap()),
            ..NatDecision::default()
        }),
        "ICMPv6 DNAT rule must translate, not be silently dropped"
    );
}

/// #2396(b): an IP-only DNAT rule (no protocol, no port) must cover ALL L4
/// protocols including ICMP via the protocol wildcard (PROTO_ANY). Before
/// #2396 the `""` + port-0 arm expanded to TCP+UDP ONLY, so ICMP traffic to
/// the destination was NOT translated — contradicting the closeout doc. Fails
/// (ICMP decision None) if the rule reverts to TCP/UDP-only expansion.
#[test]
fn dnat_ip_only_covers_all_protocols_incl_icmp() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "ip-only".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            protocol: "".to_string(),
            pool_address: "192.168.1.10".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let expected = Some(NatDecision {
        rewrite_dst: Some("192.168.1.10".parse().unwrap()),
        ..NatDecision::default()
    });
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    // ICMP — the case the old TCP/UDP-only expansion missed.
    assert_eq!(
        table.lookup(PROTO_ICMP, src, dst, 0, ""),
        expected,
        "IP-only DNAT must cover ICMP"
    );
    // GRE — another non-TCP/UDP protocol.
    assert_eq!(
        table.lookup(PROTO_GRE, src, dst, 47, ""),
        expected,
        "IP-only DNAT must cover GRE"
    );
    // TCP/UDP at arbitrary ports still match (regression).
    assert_eq!(
        table.lookup(PROTO_TCP, src, dst, 443, ""),
        expected,
        "IP-only DNAT must still cover TCP"
    );
    assert_eq!(
        table.lookup(PROTO_UDP, src, dst, 53, ""),
        expected,
        "IP-only DNAT must still cover UDP"
    );
}

/// #2396(b): a CONCRETE protocol/port DNAT rule must win over a co-resident
/// IP-only (PROTO_ANY) rule on the same destination — the wildcard is only a
/// last-resort fallback, never an override.
#[test]
fn dnat_concrete_rule_wins_over_ip_only_wildcard() {
    let table = DnatTable::from_snapshots(
        &[
            // IP-only catch-all -> pool A
            DestinationNATRuleSnapshot {
                name: "catch-all".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "".to_string(),
                pool_address: "192.168.1.10".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
            // Specific TCP/443 -> pool B
            DestinationNATRuleSnapshot {
                name: "https".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "192.168.1.20".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    // TCP/443 -> the specific rule (pool B).
    assert_eq!(
        table.lookup(PROTO_TCP, src, dst, 443, ""),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.20".parse().unwrap()),
            ..NatDecision::default()
        }),
        "specific TCP/443 rule must win over the IP-only wildcard"
    );
    // ICMP -> falls through to the catch-all (pool A).
    assert_eq!(
        table.lookup(PROTO_ICMP, src, dst, 0, ""),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "ICMP must fall through to the IP-only catch-all"
    );
}

/// #2396(c) runtime sibling: a DNAT snapshot whose destination_address fails
/// to parse emits NO entry (fail-closed), and the table is empty — the commit
/// gate (validateDestinationNATAddressesStrict) is what gives the operator
/// feedback, but the dataplane must not install a bogus entry either.
#[test]
fn dnat_invalid_destination_address_yields_no_entry() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "typo".to_string(),
            destination_address: "not-an-ip".to_string(),
            destination_port: 80,
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table.is_empty(),
        "a DNAT rule with an unparseable destination must install no entry"
    );
}

/// #2396: the protocol token resolver mirrors the Go SSOT acceptance set.
#[test]
fn proto_number_resolver_matches_known_tokens() {
    use crate::ip_proto::proto_number;
    assert_eq!(proto_number("tcp"), Some(PROTO_TCP));
    assert_eq!(proto_number("udp"), Some(PROTO_UDP));
    assert_eq!(proto_number("icmp"), Some(PROTO_ICMP));
    assert_eq!(proto_number("icmp6"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number("icmpv6"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number("gre"), Some(PROTO_GRE));
    // Bare numeric protocol number.
    assert_eq!(proto_number("47"), Some(PROTO_GRE));
    // #2396 (Copilot fold): "0" is HOPOPT — a REAL, exact protocol number, NOT
    // the wildcard. The wildcard sentinel (PROTO_ANY = 256) is u16 and outside
    // proto_number's u8 range, so it can never be returned here.
    assert_eq!(proto_number("0"), Some(0u8));
    assert_eq!(u16::from(0u8) != PROTO_ANY, true, "HOPOPT must differ from PROTO_ANY");
    // Unresolvable token.
    assert_eq!(proto_number("bogus"), None);
    assert_eq!(proto_number("256"), None);
}

/// #16134: the DNAT carrier shares the strict resolver — a non-canonical
/// numeric ("+6") the Go SSOT rejects must not decode to TCP, and an
/// unknown token stays None (never default 0, which would alias HOPOPT).
#[test]
fn carrier_16134_proto_number_canonical_numeric_cells() {
    use crate::ip_proto::proto_number;
    assert_eq!(proto_number("+6"), None);
    // Padded numerics are rejected on the RAW token (the Go SSOT's
    // ParseCanonicalUint never sees the trimmed copy), while padded NAMED
    // tokens still resolve through the trim+lowercase switch above.
    assert_eq!(proto_number(" 6"), None);
    assert_eq!(proto_number("6 "), None);
    assert_eq!(proto_number(" GRE "), Some(PROTO_GRE));
    assert_eq!(proto_number("006"), Some(PROTO_TCP));
    assert_eq!(proto_number("bogus"), None);
    assert_eq!(proto_number(""), None);
}

/// #2505: the shared resolver must cover the FULL appid.ProtocolNumber
/// acceptance set — the named protocols and the specific junos-* aliases the
/// Go filter commit gate (filterProtocolResolvable) accepts. A firewall
/// filter `from protocol <token>` reaches the snapshot VERBATIM, so any token
/// the gate passes must resolve here or the filter loses its protocol
/// constraint (the #2505 fail-wide bug).
#[test]
fn proto_number_resolves_full_gate_acceptance_set() {
    use crate::ip_proto::proto_number;
    // Named protocols the stale local filter parser dropped.
    assert_eq!(proto_number("esp"), Some(50));
    assert_eq!(proto_number("ah"), Some(51));
    assert_eq!(proto_number("sctp"), Some(132));
    assert_eq!(proto_number("vrrp"), Some(112));
    assert_eq!(proto_number("igmp"), Some(2));
    assert_eq!(proto_number("pim"), Some(103));
    assert_eq!(proto_number("egp"), Some(8));
    assert_eq!(proto_number("ipip"), Some(4));
    assert_eq!(proto_number("ospf"), Some(89));
    // junos-* aliases (mirror appid.ProtocolNumber / catalog.go).
    assert_eq!(proto_number("junos-tcp-any"), Some(PROTO_TCP));
    assert_eq!(proto_number("junos-udp-any"), Some(PROTO_UDP));
    assert_eq!(proto_number("junos-icmp-all"), Some(PROTO_ICMP));
    assert_eq!(proto_number("junos-ping"), Some(PROTO_ICMP));
    assert_eq!(proto_number("junos-icmp6-all"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number("junos-pingv6"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number("junos-gre"), Some(PROTO_GRE));
    assert_eq!(proto_number("junos-ospf"), Some(89));
    assert_eq!(proto_number("junos-ip-in-ip"), Some(4));
    assert_eq!(proto_number("junos-ipip"), Some(4));
    // An UNKNOWN junos-* alias is NOT accepted (consistent with the gate).
    assert_eq!(proto_number("junos-foobar"), None);
}

/// #2396 (Copilot fold, item 1): the resolver normalizes (trim + lower-case)
/// NAMED tokens so a mixed-case or whitespace-padded name from the verbatim
/// parser path resolves to the SAME number as the canonical lower-case token.
/// #16134 narrows the numeric arm: padded numerics (" 47 ") are rejected on
/// the RAW token, mirroring the Go SSOT (ParseCanonicalUint never sees the
/// trimmed copy) — the pre-#16134 assertion that " 47 " resolved is removed
/// for exactly that reason.
#[test]
fn proto_number_normalizes_case_and_whitespace() {
    use crate::ip_proto::proto_number;
    assert_eq!(proto_number(" GRE "), proto_number("gre"));
    assert_eq!(proto_number("GRE"), Some(PROTO_GRE));
    assert_eq!(proto_number("Icmp"), Some(PROTO_ICMP));
    assert_eq!(proto_number("  TCP"), Some(PROTO_TCP));
    assert_eq!(proto_number("ICMP6"), Some(PROTO_ICMPV6));
    assert_eq!(proto_number(" 47 "), None);
}

/// #2396 (Copilot fold, item 2): a DNAT rule with `protocol "0"` (HOPOPT) is a
/// DISTINCT exact match — it must NOT alias the IP-only wildcard. A separate
/// IP-only ("") rule on the SAME destination still matches every OTHER
/// protocol via the wildcard, but the HOPOPT rule owns protocol 0 exactly.
#[test]
fn dnat_protocol_zero_hopopt_is_distinct_from_wildcard() {
    use crate::ip_proto::PROTO_TCP as P_TCP;
    let table = DnatTable::from_snapshots(
        &[
            // IP-only catch-all -> pool A (every protocol EXCEPT an exact match)
            DestinationNATRuleSnapshot {
                name: "catch-all".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "".to_string(),
                pool_address: "192.168.1.10".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
            // Exact HOPOPT (protocol 0) -> pool B
            DestinationNATRuleSnapshot {
                name: "hopopt".to_string(),
                destination_address: "203.0.113.10".to_string(),
                destination_port: 0,
                protocol: "0".to_string(),
                pool_address: "192.168.1.20".to_string(),
                ..DestinationNATRuleSnapshot::default()
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    // Protocol 0 (HOPOPT) -> the exact HOPOPT rule (pool B), NOT the wildcard.
    assert_eq!(
        table.lookup(0u8, src, dst, 0, ""),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.20".parse().unwrap()),
            ..NatDecision::default()
        }),
        "protocol 0 (HOPOPT) must hit its exact rule, not the IP-only wildcard"
    );
    // Any OTHER protocol (TCP) -> the IP-only wildcard catch-all (pool A).
    assert_eq!(
        table.lookup(P_TCP, src, dst, 80, ""),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "a non-HOPOPT protocol must still fall through to the IP-only wildcard"
    );
}

// === #3096: interface- / routing-instance-scoped NAT rule-set matching ===

