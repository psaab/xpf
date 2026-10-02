// Static (1:1) NAT tests for the nat/ module.
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

#[test]
fn static_nat_dnat_matches_external_ip_v4() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_dnat("203.0.113.10".parse().expect("ext"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().expect("int")),
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_snat_matches_internal_ip_v4() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "trust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_snat("192.168.1.10".parse().expect("int"), "trust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("203.0.113.10".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_dnat_matches_external_ip_v6() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-v6".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "2001:db8::1".to_string(),
            internal_ip: "fd00::1".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_dnat("2001:db8::1".parse().expect("ext"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("fd00::1".parse().expect("int")),
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_snat_matches_internal_ip_v6() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-v6".to_string(),
            from_zone: "trust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "2001:db8::1".to_string(),
            internal_ip: "fd00::1".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_snat("fd00::1".parse().expect("int"), "trust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("2001:db8::1".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

// #3031: block-to-block (subnet) static NAT — 1:1 by offset. A source
// host maps to the same offset in the destination block (network bits
// replaced, host bits preserved), both directions.

fn block_snapshot(ext: &str, int: &str, from_zone: &str) -> StaticNATRuleSnapshot {
    StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: "block-1".to_string(),
        from_zone: from_zone.to_string(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: ext.to_string(),
        internal_ip: int.to_string(),
        match_destination_port: 0,
        mapped_port: 0,
    }
}

#[test]
fn static_nat_block_dnat_v4_preserves_offset() {
    // 198.51.100.0/24 (external) -> 192.168.1.0/24 (internal). An inbound
    // packet to 198.51.100.7 DNATs to 192.168.1.7 (offset .7 preserved).
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_dnat("198.51.100.7".parse().expect("ext host"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.7".parse().expect("int host")),
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_block_snat_v4_reverses_offset() {
    // Reverse: an outbound packet from 192.168.1.7 SNATs back to
    // 198.51.100.7 (the inverse offset map), so return traffic matches.
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    let decision = table.match_snat("192.168.1.7".parse().expect("int host"), "untrust");
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("198.51.100.7".parse().expect("ext host")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_block_v6_preserves_offset_both_directions() {
    // /120 -> /120 v6 block map. Offset ::7 preserved both directions.
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("2001:db8:a::/120", "fd00:1::/120", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    let dnat = table.match_dnat("2001:db8:a::7".parse().expect("ext v6"), "untrust");
    assert_eq!(
        dnat,
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("fd00:1::7".parse().expect("int v6")),
            ..NatDecision::default()
        })
    );
    let snat = table.match_snat("fd00:1::7".parse().expect("int v6"), "untrust");
    assert_eq!(
        snat,
        Some(NatDecision {
            rewrite_src: Some("2001:db8:a::7".parse().expect("ext v6")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn static_nat_block_does_not_translate_outside_source_block() {
    // An address OUTSIDE the external block is not DNAT'd, and an address
    // outside the internal block is not SNAT'd.
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    assert_eq!(
        table.match_dnat("198.51.101.7".parse().expect("outside ext"), "untrust"),
        None
    );
    assert_eq!(
        table.match_snat("192.168.2.7".parse().expect("outside int"), "untrust"),
        None
    );
}

#[test]
fn static_nat_block_mismatched_length_is_skipped() {
    // A /24 -> /25 pair is not a 1:1 block map; the rule is skipped (no
    // table entry, no translation), preserving the #2122 skip rationale.
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("198.51.100.0/24", "192.168.1.0/25", "untrust")],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(table.is_empty());
    assert_eq!(
        table.match_dnat("198.51.100.7".parse().expect("ext host"), "untrust"),
        None
    );
}

#[test]
fn static_nat_block_with_port_is_dropped() {
    // #3202: a block (subnet) pair that ALSO carries a port match / mapped-port
    // is NOT representable by StaticNatBlock (address-only, all-port offset
    // remap). Installing it would silently widen "port 80 of this /24 -> 8080"
    // into "every port of the /24". The lenient-load backstop drops the rule
    // (fail closed) instead of mis-installing it. The Go strict commit-check
    // rejects this; this test pins the dataplane backstop.
    //
    // Fail-on-revert: removing the `snap.match_destination_port != 0 ||
    // snap.mapped_port != 0` skip in from_snapshots installs an all-port block
    // → table is non-empty and 198.51.100.7 DNATs to 192.168.1.7 → RED.
    let mut snap = block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust");
    snap.match_destination_port = 80;
    snap.mapped_port = 8080;
    let table = StaticNatTable::from_snapshots(&[snap], &crate::nat::NatCounterStore::default());
    assert!(
        table.is_empty(),
        "a block pair with a port mapping must be dropped, not installed as an all-port block"
    );
    assert_eq!(
        table.match_dnat("198.51.100.7".parse().expect("ext host"), "untrust"),
        None
    );
}

#[test]
fn static_nat_block_with_match_port_only_is_dropped() {
    // A block pair with only a match destination-port (no mapped-port) is
    // equally not representable — also dropped by the #3202 backstop.
    let mut snap = block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust");
    snap.match_destination_port = 80;
    let table = StaticNatTable::from_snapshots(&[snap], &crate::nat::NatCounterStore::default());
    assert!(table.is_empty());
}

#[test]
fn static_nat_block_zero_length_v4_is_rejected() {
    // #5658: a /0 <-> /0 equal-length block pair remaps the ENTIRE IPv4
    // internet 1:1 (host_mask_v4(0) == u32::MAX, so contains() matches every
    // address; the offset remap preserves all host bits → identity NAT). The
    // backstop drops it fail-closed and records a bounded parse error instead
    // of installing a whole-family block that shadows every narrower rule.
    //
    // Fail-on-revert: removing the `ext_prefix.len == 0 || int_prefix.len == 0`
    // skip in from_snapshots installs the /0 block → table non-empty and
    // 8.8.8.8 DNATs → RED.
    let counters = crate::nat::NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[block_snapshot("0.0.0.0/0", "10.0.0.0/0", "untrust")],
        &counters,
    );
    assert!(
        table.is_empty(),
        "a /0 static block must be dropped, not installed as a whole-family identity NAT"
    );
    assert_eq!(
        table.match_dnat("8.8.8.8".parse().expect("arbitrary internet host"), "untrust"),
        None,
        "no address may be translated by a rejected /0 block"
    );
    assert_eq!(
        counters.parse_errors(),
        1,
        "the rejected /0 block must record exactly one bounded parse error"
    );
}

#[test]
fn static_nat_block_zero_length_v6_is_rejected() {
    // #5658: the IPv6 equivalent — ::/0 <-> ::/0 remaps the entire v6 family
    // 1:1 (host_mask_v6(0) == u128::MAX). Same fail-closed drop + parse error.
    let counters = crate::nat::NatCounterStore::default();
    let table =
        StaticNatTable::from_snapshots(&[block_snapshot("::/0", "fd00::/0", "untrust")], &counters);
    assert!(table.is_empty(), "a ::/0 static block must be dropped");
    assert_eq!(
        table.match_dnat("2606:4700:4700::1111".parse().expect("arbitrary v6 host"), "untrust"),
        None
    );
    assert_eq!(counters.parse_errors(), 1);
}

#[test]
fn static_nat_block_zero_length_does_not_shadow_narrower_rule() {
    // #5658 (issue contract): a rejected /0 block MUST NOT shadow a valid
    // narrower block that follows it. Before the fix the /0 block installed
    // first and matched every inbound dst, short-circuiting the /24 rule.
    let counters = crate::nat::NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[
            block_snapshot("0.0.0.0/0", "10.0.0.0/0", "untrust"),
            block_snapshot("198.51.100.0/24", "192.168.1.0/24", "untrust"),
        ],
        &counters,
    );
    // The narrower rule still translates with its offset preserved.
    assert_eq!(
        table.match_dnat("198.51.100.7".parse().expect("ext host"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.7".parse().expect("int host")),
            ..NatDecision::default()
        }),
        "a rejected /0 block must not shadow the valid /24 block that follows"
    );
    // An address outside the /24 is NOT swept up by a phantom /0 block.
    assert_eq!(
        table.match_dnat("8.8.8.8".parse().expect("outside all blocks"), "untrust"),
        None
    );
}

#[test]
fn static_nat_host_v4_unchanged_with_block_support() {
    // #3031 regression: a /32 host rule still behaves byte-identical to
    // pre-#3031 (exact 1:1, no offset math). Both directions.
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10/32".to_string(),
            internal_ip: "192.168.1.10/32".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert_eq!(
        table.match_dnat("203.0.113.10".parse().expect("ext"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().expect("int")),
            ..NatDecision::default()
        })
    );
    assert_eq!(
        table.match_snat("192.168.1.10".parse().expect("int"), "untrust"),
        Some(NatDecision {
            rewrite_src: Some("203.0.113.10".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    // A non-mapped host (not the /32) is not translated.
    assert_eq!(
        table.match_dnat("203.0.113.11".parse().expect("other"), "untrust"),
        None
    );
}

#[test]
fn static_nat_zone_mismatch_returns_none_for_dnat() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // DNAT from wrong zone should fail
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
            .is_none()
    );
    // #2871: SNAT (reverse) now honors the EGRESS zone symmetrically with
    // DNAT's ingress-zone gate. A packet egressing toward a zone OTHER than
    // the rule's external `from zone` ("untrust") must NOT be source-NAT'd.
    assert!(
        table
            .match_snat("192.168.1.10".parse().expect("int"), "dmz")
            .is_none()
    );
}

/// #2871 FAIL-ON-REVERT: static-NAT reverse (SNAT) must honor the EGRESS zone,
/// mirroring the #2864 DNAT ingress-zone gate. An outbound packet sourced from
/// a static-NAT internal IP but egressing toward a DIFFERENT internal zone
/// (east-west) must NOT be source-translated to the public external IP — that
/// was the cross-zone leak. It MUST still translate when egressing toward the
/// rule's external `from zone`.
///
/// Drop the `egress_zone` gate from `match_snat_with_counter` (the pre-#2871
/// "internal IP match is sufficient" behaviour) and the wrong-zone assertion
/// below flips to Some(..) — this test goes RED.
#[test]
fn static_nat_snat_honors_egress_zone() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "web-server".to_string(),
            // External zone of the rule: reverse SNAT applies only when the
            // packet egresses toward THIS zone.
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let internal: IpAddr = "192.168.1.10".parse().expect("int");

    // RIGHT zone: egressing toward the external zone "untrust" -> SNAT applies.
    assert_eq!(
        table.match_snat(internal, "untrust"),
        Some(NatDecision {
            rewrite_src: Some("203.0.113.10".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "SNAT must apply when egressing toward the rule's external zone"
    );

    // WRONG zone: egressing toward another internal zone -> no source NAT.
    // This is the assertion that fails without the #2871 egress-zone gate.
    assert!(
        table.match_snat(internal, "trust").is_none(),
        "SNAT must NOT apply for an east-west packet egressing toward a \
         non-external zone (cross-zone leak #2871)"
    );
    assert!(
        table.match_snat(internal, "dmz").is_none(),
        "SNAT must NOT apply when egressing toward an unrelated internal zone"
    );
}

/// #2871: an empty external `from zone` ("any zone") still source-NATs on any
/// egress zone — the egress-zone gate must not regress wildcard rules.
#[test]
fn static_nat_snat_empty_zone_matches_any_egress() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "wildcard".to_string(),
            from_zone: String::new(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let internal: IpAddr = "192.168.1.10".parse().expect("int");
    for egress in ["untrust", "trust", "dmz"] {
        assert!(
            table.match_snat(internal, egress).is_some(),
            "wildcard (empty from_zone) SNAT must match any egress zone"
        );
    }
}

#[test]
fn static_nat_empty_zone_matches_any() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-any".to_string(),
            from_zone: String::new(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
            .is_some()
    );
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "trust")
            .is_some()
    );
    assert!(
        table
            .match_snat("192.168.1.10".parse().expect("int"), "trust")
            .is_some()
    );
}

#[test]
fn static_nat_bidirectional_reverse() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Inbound DNAT: external -> internal
    let dnat = table
        .match_dnat("203.0.113.10".parse().expect("ext"), "untrust")
        .expect("dnat");
    assert_eq!(
        dnat,
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("192.168.1.10".parse().expect("int")),
            ..NatDecision::default()
        }
    );
    // The reverse of DNAT should produce SNAT: on reply packets from
    // the internal host, rewrite src back to the external IP.
    // reverse().rewrite_src = self.rewrite_dst.map(|_| original_dst) = Some(external)
    // reverse().rewrite_dst = self.rewrite_src.map(|_| original_src) = None
    let original_src: IpAddr = "198.51.100.1".parse().expect("peer");
    let original_dst: IpAddr = "203.0.113.10".parse().expect("ext");
    let reverse = dnat.reverse(original_src, original_dst, 54321, 80);
    assert_eq!(
        reverse,
        NatDecision {
            rewrite_src: Some(original_dst),
            rewrite_dst: None,
            ..NatDecision::default()
        }
    );
}

#[test]
fn static_nat_no_match_returns_none() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .match_dnat("203.0.113.99".parse().expect("unknown"), "untrust")
            .is_none()
    );
    assert!(
        table
            .match_snat("192.168.1.99".parse().expect("unknown"), "trust")
            .is_none()
    );
}

#[test]
fn static_nat_invalid_ip_skipped() {
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "bad".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "not-an-ip".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "good".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    // The bad entry should be skipped, the good one should work
    assert!(
        table
            .match_dnat("203.0.113.10".parse().expect("ext"), "any")
            .is_some()
    );
}

#[test]
fn static_nat_external_ips_iterator() {
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "s1".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "s2".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.20".to_string(),
                internal_ip: "192.168.1.20".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let mut ips: Vec<IpAddr> = table.external_ips().collect();
    ips.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&"203.0.113.10".parse::<IpAddr>().unwrap()));
    assert!(ips.contains(&"203.0.113.20".parse::<IpAddr>().unwrap()));
}

#[test]
fn static_nat_canonical_cidr_mask_v4_installs_entry() {
    // #2122: Junos emits static-NAT match/then in canonical prefix form
    // ("203.0.113.5/32" / "10.0.0.5/32") and the Go compiler copies the mask
    // verbatim into the snapshot. IpAddr::from_str rejects CIDR, so pre-fix
    // every rule hit the Err/skip arm and was silently dropped — no
    // translation occurred and the external IP was never registered as a
    // local address. The parse must strip the /32 mask. This test FAILS on
    // the unfixed code (table is empty, every assertion is None).
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-cidr".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.5/32".to_string(),
            internal_ip: "10.0.0.5/32".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    // Inbound DNAT on the bare external IP -> bare internal IP.
    assert_eq!(
        table.match_dnat("203.0.113.5".parse().expect("ext"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("10.0.0.5".parse().expect("int")),
            ..NatDecision::default()
        })
    );
    // Outbound SNAT on the bare internal IP -> bare external IP.
    assert_eq!(
        table.match_snat("10.0.0.5".parse().expect("int"), "untrust"),
        Some(NatDecision {
            rewrite_src: Some("203.0.113.5".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    // The external IP must be registered (bare, no mask) for local delivery
    // recognition (forwarding_build iterates external_ips()).
    let ips: Vec<IpAddr> = table.external_ips().collect();
    assert_eq!(ips, vec!["203.0.113.5".parse::<IpAddr>().unwrap()]);
}

// #4718 FAIL-ON-REVERT: a static-NAT batch carrying rules with an UNPARSEABLE
// external-ip / internal-ip must (1) still install the VALID rules and (2)
// SURFACE each drop via the NatCounterStore parse-error counter, instead of
// the pre-#4718 silent `continue`. Reverting `record_parse_error` back to a
// bare `continue` (the old behaviour) leaves `parse_errors() == 0`, turning
// the surfacing assertion RED — while the valid-rule assertion still passes,
// proving the fix keeps the good rules installing.
#[test]
fn static_nat_unparseable_ip_surfaces_and_keeps_valid_rules() {
    let counters = crate::nat::NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[
            // Bad: external-ip is garbage — dropped, but must be surfaced.
            StaticNATRuleSnapshot {
                name: "bad-ext".to_string(),
                external_ip: "not-an-ip".to_string(),
                internal_ip: "10.0.0.5".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
            // Bad: internal-ip is garbage (external parses, internal does not)
            // — a second surfaced drop.
            StaticNATRuleSnapshot {
                name: "bad-int".to_string(),
                external_ip: "203.0.113.9".to_string(),
                internal_ip: "garbage/33".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
            // Valid: must still install despite the malformed siblings.
            StaticNATRuleSnapshot {
                name: "good".to_string(),
                from_zone: "untrust".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
        ],
        &counters,
    );
    // (1) The valid rule installed: inbound DNAT translates ext -> int.
    assert_eq!(
        table.match_dnat("203.0.113.10".parse().unwrap(), "untrust"),
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "valid static-NAT rule must install despite sibling parse failures"
    );
    // The bad rule with a valid external-ip must NOT have installed.
    assert_eq!(
        table.match_dnat("203.0.113.9".parse().unwrap(), "untrust"),
        None,
        "a static-NAT rule with an unparseable internal-ip must be dropped"
    );
    // (2) Both drops surfaced on the counter — RED on the silent-skip revert.
    assert_eq!(
        counters.parse_errors(),
        2,
        "each unparseable static-NAT field must bump the parse-error counter"
    );
}

// #4718 guard: an all-valid static-NAT batch installs its rule with ZERO
// parse errors — no false positive from the surfacing path.
#[test]
fn static_nat_all_valid_reports_no_parse_errors() {
    let counters = crate::nat::NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "good".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    assert!(
        table
            .match_dnat("203.0.113.10".parse().unwrap(), "untrust")
            .is_some(),
        "the valid rule must install"
    );
    assert_eq!(
        counters.parse_errors(),
        0,
        "an all-valid batch must report zero parse errors"
    );
}

#[test]
fn static_nat_canonical_cidr_mask_v6_installs_entry() {
    // IPv6 canonical host form carries /128; same root cause as the v4 case.
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "static-cidr-v6".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "2001:db8::1/128".to_string(),
            internal_ip: "fd00::1/128".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert_eq!(
        table.match_dnat("2001:db8::1".parse().expect("ext"), "untrust"),
        Some(NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("fd00::1".parse().expect("int")),
            ..NatDecision::default()
        })
    );
    assert_eq!(
        table.match_snat("fd00::1".parse().expect("int"), "untrust"),
        Some(NatDecision {
            rewrite_src: Some("2001:db8::1".parse().expect("ext")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    let ips: Vec<IpAddr> = table.external_ips().collect();
    assert_eq!(ips, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
}

#[test]
fn static_nat_cidr_and_bare_coexist() {
    // A masked rule and a bare-IP rule must both install — stripping the mask
    // on one must not regress the other.
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "masked".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.5/32".to_string(),
                internal_ip: "10.0.0.5".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "bare".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.6".to_string(),
                internal_ip: "10.0.0.6/32".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        table
            .match_dnat("203.0.113.5".parse().expect("ext"), "any")
            .is_some()
    );
    assert!(
        table
            .match_dnat("203.0.113.6".parse().expect("ext"), "any")
            .is_some()
    );
    assert!(
        table
            .match_snat("10.0.0.5".parse().expect("int"), "any")
            .is_some()
    );
    assert!(
        table
            .match_snat("10.0.0.6".parse().expect("int"), "any")
            .is_some()
    );
}

#[test]
fn static_nat_non_host_mask_rejected() {
    // A non-host mask (or garbage suffix) is NOT a canonical host form and
    // must be rejected (skipped), not silently coerced to a host route — it
    // would otherwise translate the wrong scope. Pre-#2122 ALL of these were
    // rejected too (the bare parser errored on any mask), so this is not a
    // regression; it keeps the hardened parse strict about misconfiguration.
    for bad in [
        "203.0.113.5/24",      // non-host v4 prefix
        "203.0.113.5/notanum", // non-numeric mask
        "203.0.113.5/",        // empty mask
        "203.0.113.5//32",     // double slash
        "203.0.113.5/128",     // v6 host length applied to a v4 address
        "2001:db8::1/64",      // non-host v6 prefix
        "2001:db8::1/32",      // v4 host length applied to a v6 address
    ] {
        let table = StaticNatTable::from_snapshots(
            &[StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "bad-mask".to_string(),
                from_zone: String::new(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: bad.to_string(),
                internal_ip: "10.0.0.5".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            }],
            &crate::nat::NatCounterStore::default(),
        );
        assert_eq!(
            table.external_ips().count(),
            0,
            "non-host/garbage mask {bad:?} must be rejected, not installed"
        );
    }
}

// --- #2491 static-NAT port / mapped-port forwarding ---

fn mapped_port_snapshot() -> StaticNATRuleSnapshot {
    StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: "port-map".to_string(),
        from_zone: "untrust".to_string(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: "203.0.113.1/32".to_string(),
        internal_ip: "10.0.0.5/32".to_string(),
        match_destination_port: 8080,
        mapped_port: 80,
    }
}

// Forward (inbound DNAT): a packet to the external IP on the matched external
// port is translated to the internal IP AND the destination port is rewritten
// to the mapped-port. A packet to the same IP on a DIFFERENT port misses (no
// port-less fallback entry, so no translation).
//
// Fail-on-revert: dropping `rewrite_dst_port: entry.mapped_port` in
// match_dnat_with_counter turns the rewrite_dst_port assertion RED.
#[test]
fn static_nat_mapped_port_dnat_rewrites_dst_port() {
    let table =
        StaticNatTable::from_snapshots(&[mapped_port_snapshot()], &crate::nat::NatCounterStore::default());
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    let int: IpAddr = "10.0.0.5".parse().unwrap();

    let (decision, _) = table
        .match_dnat_with_counter(ext, 8080, "untrust")
        .expect("matched external port");
    assert_eq!(decision.rewrite_dst, Some(int), "dst IP must be the internal host");
    assert_eq!(decision.rewrite_dst_port, Some(80), "dst port must be the mapped-port");

    // A non-matching external port must NOT translate (no whole-address
    // fallback present).
    assert!(
        table.match_dnat_with_counter(ext, 9999, "untrust").is_none(),
        "non-matching external port must miss"
    );
}

// Reverse (outbound return SNAT): the return packet from the internal host's
// mapped-port has its source IP rewritten back to the external IP AND its
// source port un-translated back to the external (match) port.
//
// Fail-on-revert: dropping `rewrite_src_port` in match_snat_with_counter (or
// keying snat on the internal IP without the mapped-port) turns the
// rewrite_src_port assertion RED / the lookup miss.
#[test]
fn static_nat_mapped_port_snat_untranslates_src_port() {
    let table =
        StaticNatTable::from_snapshots(&[mapped_port_snapshot()], &crate::nat::NatCounterStore::default());
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    let int: IpAddr = "10.0.0.5".parse().unwrap();

    let (decision, _) = table
        .match_snat_with_counter(int, 80, "untrust")
        .expect("matched internal mapped-port");
    assert_eq!(decision.rewrite_src, Some(ext), "src IP must be the external IP");
    assert_eq!(
        decision.rewrite_src_port,
        Some(8080),
        "src port must be un-translated to the external match port"
    );
}

// A whole-address rule and a port-mapped rule can coexist on the SAME external
// IP: the port-mapped entry wins on its exact port; everything else falls back
// to the whole-address mapping (no port rewrite).
#[test]
fn static_nat_port_mapped_and_whole_address_coexist() {
    let table = StaticNatTable::from_snapshots(
        &[
            mapped_port_snapshot(), // 203.0.113.1:8080 -> 10.0.0.5:80
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "whole".to_string(),
                from_zone: "untrust".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.1/32".to_string(),
                internal_ip: "10.0.0.9/32".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let ext: IpAddr = "203.0.113.1".parse().unwrap();

    // Port-mapped entry wins on 8080.
    let (port_dec, _) = table.match_dnat_with_counter(ext, 8080, "untrust").expect("port match");
    assert_eq!(port_dec.rewrite_dst, Some("10.0.0.5".parse().unwrap()));
    assert_eq!(port_dec.rewrite_dst_port, Some(80));

    // Any other port falls back to the whole-address mapping (no port rewrite).
    let (whole_dec, _) = table.match_dnat_with_counter(ext, 443, "untrust").expect("fallback match");
    assert_eq!(whole_dec.rewrite_dst, Some("10.0.0.9".parse().unwrap()));
    assert_eq!(whole_dec.rewrite_dst_port, None);
}

// Fail-closed: a mapped_port without a match_destination_port (which the Go
// strict commit-check rejects, but can slip through the lenient load path) is
// demoted to a whole-address 1:1 — no port rewrite, no orphaned port key.
#[test]
fn static_nat_mapped_port_without_match_port_demotes_to_whole_address() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "orphan".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.1/32".to_string(),
            internal_ip: "10.0.0.5/32".to_string(),
            match_destination_port: 0,
            mapped_port: 80,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    // Matches as a whole-address entry on any port, with NO port rewrite.
    let (decision, _) = table.match_dnat_with_counter(ext, 12345, "untrust").expect("whole-address match");
    assert_eq!(decision.rewrite_dst, Some("10.0.0.5".parse().unwrap()));
    assert_eq!(decision.rewrite_dst_port, None, "orphaned mapped-port must not rewrite");
}

// #2769: a `match destination-port` WITHOUT a `mapped-port` is a port-scoped
// 1:1 (no port translation). The reverse SNAT MUST stay scoped to the matched
// port — the internal service runs on, and its return packets leave from, the
// matched port (no translation happened). A return packet from ANY OTHER
// source port on the internal host MUST NOT be source-translated.
//
// Before #2769 the SNAT entry was keyed on `(internal_ip, None)`, so the
// reverse SNAT matched every source port → it source-translated every service
// on the internal host, not just the one port-scoped inbound. This is the
// whole-host NAT broadening the issue reports.
//
// Fail-on-revert: reverting the `let snat_port = mapped_port.or(match_dst_port)`
// scoping in from_snapshots back to `let snat_port = mapped_port` re-keys the
// SNAT entry on `None`; the off-port lookup then matches the fallback entry and
// the `is_none()` assertion goes RED.
#[test]
fn static_nat_match_port_without_mapped_port_scopes_reverse_snat() {
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "port-scoped-1to1".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.1/32".to_string(),
            internal_ip: "10.0.0.5/32".to_string(),
            match_destination_port: 8080,
            mapped_port: 0,
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    let int: IpAddr = "10.0.0.5".parse().unwrap();

    // Inbound DNAT is scoped to the matched port (no port-less fallback).
    let (dnat, _) = table
        .match_dnat_with_counter(ext, 8080, "untrust")
        .expect("matched external port");
    assert_eq!(dnat.rewrite_dst, Some(int), "dst IP must be the internal host");
    assert_eq!(
        dnat.rewrite_dst_port, None,
        "no mapped-port: destination port is not rewritten"
    );
    assert!(
        table.match_dnat_with_counter(ext, 9999, "untrust").is_none(),
        "off-port inbound must miss (port-scoped, no whole-address fallback)"
    );

    // Reverse SNAT: a return packet leaving the internal host on the matched
    // port (8080 — no translation happened) IS source-translated to the
    // external IP, with NO source-port rewrite.
    let (snat, _) = table
        .match_snat_with_counter(int, 8080, "untrust")
        .expect("return from the port-scoped service");
    assert_eq!(snat.rewrite_src, Some(ext), "src IP must be the external IP");
    assert_eq!(
        snat.rewrite_src_port, None,
        "no port translation: source port is not rewritten"
    );

    // The bug: a packet from ANY OTHER source port on the internal host MUST
    // NOT be source-translated. This is the whole-host broadening #2769 fixes.
    assert!(
        table.match_snat_with_counter(int, 1234, "untrust").is_none(),
        "off-port outbound must NOT be source-translated (reverse SNAT must \
         stay scoped to the matched port)"
    );
}

// #2864: a port-specific static-NAT DNAT entry whose `from_zone` does NOT match
// the packet's ingress zone MUST NOT short-circuit the lookup to `None`. It must
// fall through to the whole-address `(dst_ip, None)` entry, which carries its own
// (matching/empty) zone constraint. Before #2864 the zone check ran ONCE after
// the `or_else()` precedence resolved, so a zone-mismatched port-specific entry
// returned `None` and the whole-address rule was silently bypassed.
//
// Fail-on-revert: removing the per-candidate `.filter(zone_ok)` fall-through in
// match_dnat_with_counter (so a port-specific zone-fail short-circuits to None)
// turns the `fallback match` expect RED.
#[test]
fn static_nat_dnat_port_zone_mismatch_falls_back_to_whole_address() {
    let ext: IpAddr = "203.0.113.1".parse().unwrap();
    let table = StaticNatTable::from_snapshots(
        &[
            // Port-specific entry constrained to a DIFFERENT zone than the
            // packet will arrive on. (203.0.113.1:8080 from "dmz" -> 10.0.0.5:80)
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "port-dmz".to_string(),
                from_zone: "dmz".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.1/32".to_string(),
                internal_ip: "10.0.0.5/32".to_string(),
                match_destination_port: 8080,
                mapped_port: 80,
            },
            // Whole-address entry valid for the packet's actual ingress zone.
            StaticNATRuleSnapshot {
                source_addresses: Vec::new(),
                counter_id: 0,
                name: "whole-untrust".to_string(),
                from_zone: "untrust".to_string(),
                from_interface: String::new(),
                from_routing_instance: String::new(),
                external_ip: "203.0.113.1/32".to_string(),
                internal_ip: "10.0.0.9/32".to_string(),
                match_destination_port: 0,
                mapped_port: 0,
            },
        ],
        &crate::nat::NatCounterStore::default(),
    );

    // A packet to the port-specific port (8080) but from the WRONG zone for the
    // port entry ("untrust", not "dmz") must NOT short-circuit: it falls back to
    // the whole-address entry, whose zone ("untrust") matches.
    let (whole_dec, _) = table
        .match_dnat_with_counter(ext, 8080, "untrust")
        .expect("fallback match — port-specific zone-fail must fall through to whole-address");
    assert_eq!(
        whole_dec.rewrite_dst,
        Some("10.0.0.9".parse().unwrap()),
        "must translate via the whole-address entry, not the zone-mismatched port entry"
    );
    assert_eq!(
        whole_dec.rewrite_dst_port, None,
        "whole-address entry has no mapped-port"
    );

    // Port-specific precedence is preserved when its zone DOES match: a packet
    // to 8080 from "dmz" hits the port entry (mapped-port rewrite), NOT the
    // whole-address entry.
    let (port_dec, _) = table
        .match_dnat_with_counter(ext, 8080, "dmz")
        .expect("port-specific entry wins when its zone matches");
    assert_eq!(port_dec.rewrite_dst, Some("10.0.0.5".parse().unwrap()));
    assert_eq!(port_dec.rewrite_dst_port, Some(80));

    // A non-port packet from "dmz" — the port entry does not key, and the
    // whole-address entry's zone ("untrust") does not match "dmz" → no DNAT.
    assert!(
        table.match_dnat_with_counter(ext, 443, "dmz").is_none(),
        "no candidate matches the ingress zone → no DNAT"
    );

    // A non-port packet from "untrust" hits the whole-address entry.
    let (any_dec, _) = table
        .match_dnat_with_counter(ext, 443, "untrust")
        .expect("whole-address entry matches its own zone on any port");
    assert_eq!(any_dec.rewrite_dst, Some("10.0.0.9".parse().unwrap()));

    // No entry for an unknown IP → no DNAT.
    assert!(
        table
            .match_dnat_with_counter("203.0.113.250".parse().unwrap(), 8080, "untrust")
            .is_none(),
        "unknown destination IP → no DNAT"
    );
}

// --- DNAT table tests ---


// #5190 FAIL-ON-REVERT (cross-linked from #5727): a static-NAT rule whose
// `match source-address` entry parses as neither a CIDR prefix nor a bare
// host IP fails CLOSED — `constrained` stays true with an empty prefix list,
// so the rule matches NOTHING. That half is correct and stays asserted here.
// What was missing is TELEMETRY: the drop was a silent `Err(_) => {}`, so an
// operator saw a static-NAT rule that simply stopped matching with nothing to
// look at. Reverting `record_parse_error` back to the empty arm leaves
// `parse_errors() == 0` → the surfacing assertion goes RED while the
// fail-closed assertions stay green (proving the two are independent).
#[test]
fn static_nat_unparseable_source_constraint_surfaces_and_still_fails_closed_5190() {
    let counters = crate::nat::NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "scoped-bad-source".to_string(),
            from_zone: "untrust".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec!["not-an-ip-or-prefix".to_string()],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    // (1) Fail-closed preserved: the rule IS source-scoped, no entry parsed,
    // so no peer satisfies it — the inbound match must miss.
    assert!(
        table
            .match_dnat_with_counter_scoped(
                "203.0.113.10".parse().unwrap(),
                0,
                Some("198.51.100.7".parse().unwrap()),
                "untrust",
                "",
                "",
            )
            .is_none(),
        "#3435 fail-closed: a source-scoped rule whose only source entry is \
         unparseable must match NOTHING"
    );
    // (2) ...and the drop is now SURFACED instead of silently swallowed.
    assert_eq!(
        counters.parse_errors(),
        1,
        "#5190: an unparseable static-NAT match source-address must be \
         recorded as a NAT reconcile parse error, not silently dropped"
    );
}

// ---------------------------------------------------------------------------
// #7219: a static-NAT BLOCK rule must register every usable host for
// proxy-ARP/ND, not only the block's network base.
//
// external_ips()/external_ips_scoped() pushed `block.external.base` alone. The
// existing comment defended that as "sufficient parity for the network address
// without an unbounded blow-up", which is a true and sound argument about the
// DNAT MATCH path — that lookup is prefix-keyed and independent of `local_v*`.
// But `local_v*` has a SECOND role: it is the proxy-ARP/ND and local-delivery
// address set.
//
// So on a directly-connected external segment the firewall answered ARP/ND only
// for 203.0.113.0. Peers got no reply for .1-.254, inbound traffic to those
// addresses never reached the firewall, and the translation that would have
// handled it correctly was never reached. Silent, and indistinguishable from a
// routing problem.
//
// The DNAT sibling already solved this (DnatTable::destination_ips, #3164), and
// this is that port. Static-NAT has NO exemption concept, so DNAT's #6025
// exact_off shadowing has no analogue to port: `off` does not appear in this
// file's grammar, and an exact-host static entry is always a TRANSLATE, which
// can only duplicate an address the expansion also yields.

fn block_rule_7219(name: &str, external: &str, internal: &str) -> StaticNATRuleSnapshot {
    StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: name.to_string(),
        from_zone: String::new(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: external.to_string(),
        internal_ip: internal.to_string(),
        match_destination_port: 0,
        mapped_port: 0,
    }
}

#[test]
fn static_nat_block_registers_usable_hosts_for_proxy_arp_7219() {
    let table = StaticNatTable::from_snapshots(
        &[block_rule_7219("b1", "203.0.113.0/24", "192.168.1.0/24")],
        &NatCounterStore::default(),
    );
    let ips: Vec<IpAddr> = table.external_ips().collect();

    // The defect: only the base was present.
    for host in ["203.0.113.1", "203.0.113.42", "203.0.113.254"] {
        let want: IpAddr = host.parse().unwrap();
        assert!(
            ips.contains(&want),
            "{host} is absent from external_ips(). On a directly-connected external \
             segment the firewall answers no ARP/ND for it, so inbound traffic never \
             arrives to be translated — even though the static-NAT match itself would \
             translate it correctly (#7219). got {} entries",
            ips.len()
        );
    }
    // The scoped view must agree — the two were independent implementations
    // before this, which is exactly how one could be fixed and the other not.
    let scoped: Vec<IpAddr> = table
        .external_ips_scoped()
        .into_iter()
        .map(|(ip, _, _)| ip)
        .collect();
    for host in ["203.0.113.1", "203.0.113.254"] {
        let want: IpAddr = host.parse().unwrap();
        assert!(
            scoped.contains(&want),
            "{host} is in external_ips() but NOT in external_ips_scoped(); the deduped \
             and scoped views have drifted (#7219)"
        );
    }
}

#[test]
fn static_nat_block_over_the_bound_registers_base_only_7219() {
    // A /8 is 16M hosts. Expanding it would put 16M entries in a hot lookup
    // set; the bound is what makes the fix shippable, so it needs its own cell
    // or "register every host" is satisfied by an unbounded implementation.
    let table = StaticNatTable::from_snapshots(
        &[block_rule_7219("big", "10.0.0.0/8", "192.168.0.0/8")],
        &NatCounterStore::default(),
    );
    let ips: Vec<IpAddr> = table.external_ips().collect();
    assert_eq!(
        ips.len(),
        1,
        "a /8 block expanded to {} entries; MAX_LOCAL_PREFIX_HOSTS must bound it \
         (an oversized block relies on being ROUTED to the firewall, not proxy-ARP'd)",
        ips.len()
    );
    assert!(ips.contains(&"10.0.0.0".parse::<IpAddr>().unwrap()));
}

#[test]
fn static_nat_v6_block_expands_when_host_scale_7219() {
    let table = StaticNatTable::from_snapshots(
        &[block_rule_7219("v6", "2001:db8::/125", "fd00::/125")],
        &NatCounterStore::default(),
    );
    let ips: Vec<IpAddr> = table.external_ips().collect();
    let want: IpAddr = "2001:db8::3".parse().unwrap();
    assert!(
        ips.contains(&want),
        "a host-scale v6 block did not expand; ND for the block's hosts is the same \
         gap as ARP for v4 (#7219). got {ips:?}"
    );
}

#[test]
fn static_nat_v6_block_over_the_bound_registers_base_only_7219() {
    // A /64 is astronomically large; the v6 arm needs its own bound cell
    // because its host_count returns Option and a wrong `is_some_and` polarity
    // would expand it while the v4 cell above stayed green.
    let table = StaticNatTable::from_snapshots(
        &[block_rule_7219("v6big", "2001:db8::/64", "fd00::/64")],
        &NatCounterStore::default(),
    );
    let ips: Vec<IpAddr> = table.external_ips().collect();
    assert_eq!(ips.len(), 1, "a /64 v6 block expanded to {} entries", ips.len());
}

#[test]
fn static_nat_host_rules_are_unchanged_7219() {
    // The control. Exact-host static-NAT rules must register exactly what they
    // did before — a change that registered extra addresses for a /32 would
    // proxy-ARP for hosts the firewall does not own.
    let table = StaticNatTable::from_snapshots(
        &[block_rule_7219("h1", "203.0.113.10", "192.168.1.10")],
        &NatCounterStore::default(),
    );
    let ips: Vec<IpAddr> = table.external_ips().collect();
    assert_eq!(
        ips,
        vec!["203.0.113.10".parse::<IpAddr>().unwrap()],
        "an exact-host rule registered something other than its own address; \
         proxy-ARP'ing an address the firewall does not own hijacks that host's \
         traffic on a directly-connected segment"
    );
}

#[test]
fn static_nat_zero_length_block_is_rejected_before_expansion_7219() {
    // WHY THIS CELL EXISTS, and it is not the reason I first wrote it.
    //
    // Mutation found that flipping the v6 bound's `is_some_and` to `is_none_or`
    // reds NOTHING. A /64 does not distinguish them — host_count_v6(64) is
    // Some(2^64) and both spellings answer "too big". Only a prefix whose count
    // OVERFLOWS u128 (anything shorter than /1) separates them, and there
    // `is_none_or` would attempt to enumerate 2^128 addresses: a hang in the
    // forwarding-state build, not a wrong answer.
    //
    // My first cell here used `::/0` and asserted `ips.len() <= 1`. It passed —
    // and it was VACUOUS, because the count is 0, not 1. A /0 static-NAT rule
    // produces NO BLOCK AT ALL: #5658 rejects a zero-length block prefix
    // fail-closed before block insertion, since an equal-length /0 pair is an
    // identity translation that would shadow every narrower rule.
    //
    // So the escaped mutation is INERT rather than uncovered — the branch it
    // breaks is unreachable through this constructor, and #5658's rejection is
    // a STRONGER guarantee than the bound check it defeats. That is worth
    // pinning: this cell asserts the invariant the bound is relying on, so if
    // #5658's rejection is ever relaxed, this reds and points at the unbounded
    // expansion it would newly expose.
    for (name, ext, int) in [
        ("v6zero", "::/0", "fd00::/0"),
        ("v4zero", "0.0.0.0/0", "10.0.0.0/0"),
    ] {
        let table = StaticNatTable::from_snapshots(
            &[block_rule_7219(name, ext, int)],
            &NatCounterStore::default(),
        );
        let ips: Vec<IpAddr> = table.external_ips().collect();
        assert!(
            ips.is_empty(),
            "a /0 block prefix produced {ips:?}. #5658 rejects it fail-closed \
             before insertion, and the #7219 expansion bound relies on that: a \
             reachable /0 would enumerate the entire address family (#7219)"
        );
    }
}
