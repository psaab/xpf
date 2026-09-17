// #8121 part 2: the layer that answers WHICH allocator a lease belongs to.
//
// Part 1's operations are per-allocator and cannot route. A lease with live
// flows is resolved to a rule through its flow; an idle lease has none, so the
// record carries `pool_name`. These cells bind that routing, and the one
// property routing-by-name creates that routing-by-index would not: several
// rules can point at ONE pool, and the lease must then be exported once.

use super::*;
use crate::SourceNATRuleSnapshot;
use crate::nat::parse_source_nat_rules;

const TIMEOUT_NS: u64 = 300 * 1_000_000_000;

fn pool_rule(name: &str, pool: &str, addrs: &[&str]) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: pool.to_string(),
        pool_addresses: addrs.iter().map(|a| a.to_string()).collect(),
        persistent_nat: true,
        ..SourceNATRuleSnapshot::default()
    }
}

/// Seed an idle lease through the IMPORT path. `allocate_translation` is
/// private to `nat`, and these cells are about ROUTING rather than minting —
/// part 1's cells already bind the allocator behaviour.
fn record(pool: &str, src: &str, translated: &str, port: u16) -> PoolIdleLease {
    PoolIdleLease {
        pool_name: pool.to_string(),
        lease: crate::nat::IdleLeaseRecord {
            protocol: 6,
            src_ip: src.parse().unwrap(),
            src_port: 40000,
            routing_scope: 0,
            remote: Some(("8.8.8.8".parse().unwrap(), 443)),
            translated_ip: translated.parse().unwrap(),
            translated_port: port,
            address_only: false,
            remaining_ns: TIMEOUT_NS,
            timeout_ns: TIMEOUT_NS,
        },
    }
}

/// Two rules, ONE pool. The lease must be exported ONCE — exporting per rule
/// would send it as many times as there are rules pointing at that pool, and
/// the receiver would then import a duplicate of a lease it already holds.
#[test]
fn a_shared_pool_exports_its_lease_once_8121() {
    let mut coord = Coordinator::new();
    coord.forwarding.source_nat_rules = parse_source_nat_rules(&[
        pool_rule("r1", "P", &["203.0.113.1"]),
        pool_rule("r2", "P", &["203.0.113.1"]),
    ]);
    assert_eq!(
        coord.forwarding.source_nat_rules.len(),
        2,
        "control: both rules must be present, or the dedup is untested"
    );
    let seeded = coord
        .import_idle_persistent_leases(&[record("P", "10.0.61.50", "203.0.113.1", 1024)], 3_000);
    assert_eq!(seeded.installed, 1, "setup: the lease must install");

    let exported = coord.export_idle_persistent_leases(4_000);
    assert_eq!(
        exported.len(),
        1,
        "a pool shared by two rules exports its lease once, got {exported:?}"
    );
    assert_eq!(exported[0].pool_name, "P");
}

/// Import routes by pool NAME. A record naming a pool this node does not have
/// is counted as such rather than falling into the first rule — the
/// identity-not-position rule, one layer above part 1's `addr_index`.
#[test]
fn an_import_routes_by_pool_name_and_counts_an_unknown_pool_8121() {
    let mut active = Coordinator::new();
    active.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let seeded = active
        .import_idle_persistent_leases(&[record("P", "10.0.61.50", "203.0.113.1", 1024)], 3_000);
    assert_eq!(seeded.installed, 1, "setup");
    let exported = active.export_idle_persistent_leases(4_000);
    assert_eq!(exported.len(), 1, "setup");

    // A standby that has the SAME pool installs it.
    let mut standby = Coordinator::new();
    standby.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let counts = standby.import_idle_persistent_leases(&exported, 9_000_000_000_000);
    assert_eq!(counts.installed, 1, "got {counts:?}");
    assert_eq!(counts.skipped_unknown_pool, 0);

    // A standby whose pool is named differently does NOT install it into
    // whatever rule happens to be first.
    let mut other = Coordinator::new();
    other.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "Q", &["203.0.113.1"])]);
    let counts = other.import_idle_persistent_leases(&exported, 9_000_000_000_000);
    assert_eq!(
        (counts.installed, counts.skipped_unknown_pool),
        (0, 1),
        "a record for an unknown pool must be counted, not misrouted: {counts:?}"
    );
}
