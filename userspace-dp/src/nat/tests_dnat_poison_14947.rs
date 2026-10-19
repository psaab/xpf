// #14947: a DNAT snapshot carrying lenient_match_dropped must drop claimed
// flows instead of translating them or exempting them via `off`.
#![allow(unused_imports)]

use super::destination::{DnatLookup, PROTO_TCP};
use super::*;
use crate::DestinationNATRuleSnapshot;

fn snap14947(name: &str, off: bool, poisoned: bool) -> DestinationNATRuleSnapshot {
    DestinationNATRuleSnapshot {
        name: name.to_string(),
        destination_address: "203.0.113.10".to_string(),
        destination_port: 80,
        protocol: "tcp".to_string(),
        pool_address: if off {
            String::new()
        } else {
            "192.168.1.10".to_string()
        },
        pool_port: 8080,
        off,
        lenient_match_dropped: poisoned,
        ..DestinationNATRuleSnapshot::default()
    }
}

#[test]
fn poisoned_dnat_off_drops_14947() {
    let table = DnatTable::from_snapshots(
        &[
            snap14947("exempt", true, true),
            snap14947("web", false, false),
        ],
        &crate::nat::NatCounterStore::default(),
    );
    let (lookup, _) = table.lookup_result_with_counter_scoped(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        12345,
        80,
        "",
        "",
        "",
        None,
    );
    assert_eq!(
        lookup,
        DnatLookup::Poisoned,
        "poisoned off must drop, not exempt or fall through"
    );
    // The Option surface stays None (no translation) for compatibility.
    assert_eq!(
        table.lookup(
            PROTO_TCP,
            "198.51.100.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            80,
            ""
        ),
        None
    );
}

#[test]
fn poisoned_dnat_translate_drops_14947() {
    let table = DnatTable::from_snapshots(
        &[snap14947("web", false, true)],
        &crate::nat::NatCounterStore::default(),
    );
    let (lookup, _) = table.lookup_result_with_counter_scoped(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        12345,
        80,
        "",
        "",
        "",
        None,
    );
    assert_eq!(lookup, DnatLookup::Poisoned);
}

#[test]
fn healthy_dnat_controls_14947() {
    // Healthy off exempts (NoMatch), healthy translate matches.
    let table = DnatTable::from_snapshots(
        &[
            snap14947("exempt", true, false),
            snap14947("web", false, false),
        ],
        &crate::nat::NatCounterStore::default(),
    );
    // Off is first with same key — dedup keeps both (off distinct); the
    // first-inserted wins, so this is the exemption.
    let (lookup, _) = table.lookup_result_with_counter_scoped(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        12345,
        80,
        "",
        "",
        "",
        None,
    );
    assert_eq!(
        lookup,
        DnatLookup::NoMatch,
        "healthy off must exempt, not drop"
    );

    let table2 = DnatTable::from_snapshots(
        &[snap14947("web", false, false)],
        &crate::nat::NatCounterStore::default(),
    );
    let (lookup2, _) = table2.lookup_result_with_counter_scoped(
        PROTO_TCP,
        "198.51.100.1".parse().unwrap(),
        "203.0.113.10".parse().unwrap(),
        12345,
        80,
        "",
        "",
        "",
        None,
    );
    match lookup2 {
        DnatLookup::Matched(d) => assert_eq!(d.rewrite_dst, Some("192.168.1.10".parse().unwrap())),
        other => panic!("healthy translate must match, got {other:?}"),
    }
    // Poisoned entry must not register as a local VIP.
    let table3 = DnatTable::from_snapshots(
        &[snap14947("web", false, true)],
        &crate::nat::NatCounterStore::default(),
    );
    assert_eq!(
        table3.destination_ips().count(),
        0,
        "poisoned DNAT must not register a local address"
    );
}
