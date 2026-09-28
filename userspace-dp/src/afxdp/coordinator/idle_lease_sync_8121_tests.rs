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

/// Create a locally-owned idle lease through the coordinator's real SNAT path.
fn mint_local_idle_lease(coord: &Coordinator, pool: &str) -> PoolIdleLease {
    let src_ip: std::net::IpAddr = "10.0.61.50".parse().unwrap();
    let dst_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let nat = match coord.test_match_source_nat_result_for_tuple(
        "lan",
        "wan",
        src_ip,
        dst_ip,
        6,
        40000,
        443,
        None,
        None,
        1_000,
    ) {
        crate::nat::SourceNatLookup::Matched(nat) => nat,
        other => panic!("fixture: local source NAT must match, got {other:?}"),
    };
    let key = crate::session::SessionKey {
        addr_family: 4,
        protocol: 6,
        src_ip,
        dst_ip,
        src_port: 40000,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::default(),
        routing_domain: 0,
    };
    coord.test_release_source_nat_allocation(&key, nat, 2_000);
    coord
        .export_idle_persistent_leases(3_000)
        .into_iter()
        .find(|lease| lease.pool_name == pool)
        .expect("fixture: coordinator must export its locally-minted idle lease")
}

/// Two coordinators exercise both directions of the real route: A advertises
/// its local lease, B imports it, then B's next export is empty and A receives
/// no record to install. Imported state remains visible in SHOW elsewhere; this
/// test pins only the coordinator's HA sync routing.
#[test]
fn two_coordinators_do_not_echo_imported_idle_leases_10789_f4() {
    let mut active = Coordinator::new();
    active.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let mut standby = Coordinator::new();
    standby.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);

    let _local = mint_local_idle_lease(&active, "P");
    let advertised = active.export_idle_persistent_leases(3_000);
    assert_eq!(advertised.len(), 1, "A must advertise its local idle lease");
    assert_eq!(
        standby
            .import_idle_persistent_leases(&advertised, 10_000)
            .installed,
        1
    );
    let returned = standby.export_idle_persistent_leases(11_000);
    assert!(
        returned.is_empty(),
        "B must not advertise the imported copy: {returned:?}"
    );
    assert_eq!(
        active.import_idle_persistent_leases(&returned, 12_000).installed,
        0,
        "the additive channel has no record to reinstall on A"
    );
    assert_eq!(active.export_idle_persistent_leases(12_000).len(), 1);
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
    let local = mint_local_idle_lease(&coord, "P");
    assert_eq!(local.pool_name, "P");
    let exported = coord.export_idle_persistent_leases(4_000);
    assert_eq!(
        exported.len(),
        1,
        "a pool shared by two rules exports its local lease once, got {exported:?}"
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
    let _local = mint_local_idle_lease(&active, "P");
    let exported = active.export_idle_persistent_leases(4_000);
    assert_eq!(exported.len(), 1, "setup: A must have a local idle lease");

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

/// Repeated unique-key sync batches cannot grow the persistent table past the
/// allocator cap. This covers address-only imports too: they claim no PAT bit,
/// but still consume one bounded persistent-table entry each.
#[test]
fn repeated_unique_import_batches_remain_within_pool_capacity_11475() {
    let mut rule = pool_rule("r1", "P", &["203.0.113.1"]);
    rule.port_low = 20_000;
    rule.port_high = 20_001;
    let mut coord = Coordinator::new();
    coord.forwarding.source_nat_rules = parse_source_nat_rules(&[rule]);
    let record = |pool: &str, src_ip: &str, pool_addr: &str, translated_port| {
        PoolIdleLease {
            pool_name: pool.to_owned(),
            lease: crate::nat::IdleLeaseRecord {
                protocol: 6,
                src_ip: src_ip.parse().unwrap(),
                src_port: 40_000,
                routing_scope: 0,
                remote: Some(("8.8.8.8".parse().unwrap(), 443)),
                translated_ip: pool_addr.parse().unwrap(),
                translated_port,
                address_only: false,
                remaining_ns: TIMEOUT_NS,
                timeout_ns: TIMEOUT_NS,
            },
        }
    };


    let mut installed = 0;
    let mut skipped_capacity = 0;
    for batch in 0..4 {
        let records: Vec<PoolIdleLease> = (0..3)
            .map(|offset| {
                let mut lease = record(
                    "P",
                    &format!("10.0.{}.{}", batch + 1, offset + 1),
                    "203.0.113.1",
                    if offset == 1 { 20_001 } else { 20_000 },
                );
                if offset == 1 {
                    // Address-only import bypasses the occupancy bitmap but
                    // must still be bounded by the shared persistent table.
                    lease.lease.address_only = true;
                    lease.lease.translated_port = lease.lease.src_port;
                }
                lease
            })
            .collect();
        let counts = coord.import_idle_persistent_leases(&records, 3_000);
        installed += counts.installed;
        skipped_capacity += counts.skipped_capacity;
    }

    assert_eq!(
        (installed, skipped_capacity),
        (2, 10),
        "only the cap-sized first pair may install, got installed={installed} \
         capacity={skipped_capacity}"
    );
    assert_eq!(
        coord.export_display_persistent_leases(4_000).len(),
        2,
        "unique imported keys must not grow the persistent table beyond cap"
    );
}
