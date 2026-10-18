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
            egress_scope: 0,
            remote: Some(("8.8.8.8".parse().unwrap(), 443)),
            permit_any_remote: false,
            permitted_remotes: vec![("8.8.8.8".parse().unwrap(), 443)],
            translated_ip: translated.parse().unwrap(),
            translated_port: port,
            address_only: false,
            deterministic: false,
            deterministic_identity: None,
            remaining_ns: TIMEOUT_NS,
            timeout_ns: TIMEOUT_NS,
        },
    }
}

/// Create a locally-owned idle lease through the coordinator's real SNAT path.
fn mint_local_idle_lease(coord: &Coordinator, pool: &str) -> PoolIdleLease {
    let src_ip: std::net::IpAddr = "10.0.61.50".parse().unwrap();
    let dst_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let nat = match coord.test_match_source_nat_result_for_tuple(
        "lan", "wan", src_ip, dst_ip, 6, 40000, 443, None, None, 1_000,
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

/// Leave a locally allocated identity live in its pool. The imported lease
/// fixture mirrors that identity but has a distinct source key.
fn mint_active_local_identity(
    coord: &Coordinator,
    pool: &str,
    address_only: bool,
) -> PoolIdleLease {
    let src_ip: std::net::IpAddr = "10.0.61.50".parse().unwrap();
    let dst_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let nat = match coord.test_match_source_nat_result_for_tuple(
        "lan", "wan", src_ip, dst_ip, 6, 40000, 443, None, None, 1_000,
    ) {
        crate::nat::SourceNatLookup::Matched(nat) => nat,
        other => panic!("fixture: local source NAT must match, got {other:?}"),
    };
    PoolIdleLease {
        pool_name: pool.to_string(),
        lease: crate::nat::IdleLeaseRecord {
            protocol: 6,
            src_ip,
            src_port: 40000,
            routing_scope: 0,
            egress_scope: 0,
            remote: Some((dst_ip, 443)),
            permit_any_remote: false,
            permitted_remotes: vec![(dst_ip, 443)],
            translated_ip: nat
                .rewrite_src
                .expect("fixture: source NAT rewrites source IP"),
            translated_port: nat.rewrite_src_port.unwrap_or(40_000),
            address_only,
            deterministic: false,
            deterministic_identity: None,
            remaining_ns: TIMEOUT_NS,
            timeout_ns: TIMEOUT_NS,
        },
    }
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
        active
            .import_idle_persistent_leases(&returned, 12_000)
            .installed,
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
    let record = |pool: &str, src_ip: &str, pool_addr: &str, translated_port| PoolIdleLease {
        pool_name: pool.to_owned(),
        lease: crate::nat::IdleLeaseRecord {
            protocol: 6,
            src_ip: src_ip.parse().unwrap(),
            src_port: 40_000,
            routing_scope: 0,
            egress_scope: 0,
            remote: Some(("8.8.8.8".parse().unwrap(), 443)),
            permit_any_remote: false,
            permitted_remotes: vec![("8.8.8.8".parse().unwrap(), 443)],
            translated_ip: pool_addr.parse().unwrap(),
            translated_port,
            address_only: false,
            deterministic: false,
            deterministic_identity: None,
            remaining_ns: TIMEOUT_NS,
            timeout_ns: TIMEOUT_NS,
        },
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

/// Clearing reaches each distinct pool allocator once and keeps a pre-clear
/// full-set push from reinstalling the revoked idle lease (#10784).
#[test]
fn clear_revokes_allocator_leases_and_rejects_stale_peer_import_10784() {
    let mut coord = Coordinator::new();
    coord.forwarding.source_nat_rules = parse_source_nat_rules(&[
        pool_rule("r1", "P", &["203.0.113.1"]),
        pool_rule("r2", "P", &["203.0.113.1"]),
    ]);
    let stale = record("P", "10.0.61.50", "203.0.113.1", 1024);
    let seeded = coord.import_idle_persistent_leases(&[stale.clone()], 3_000);
    assert_eq!(
        seeded.installed, 1,
        "setup: the authoritative lease must exist"
    );
    assert_eq!(coord.export_display_persistent_leases(4_000).len(), 1);

    assert_eq!(
        coord.clear_persistent_nat_leases(),
        1,
        "a shared allocator must be counted once, not once per rule"
    );
    assert!(coord.export_idle_persistent_leases(4_001).is_empty());
    assert!(coord.export_display_persistent_leases(4_001).is_empty());

    let delayed = coord.import_idle_persistent_leases(&[stale], 4_001);
    assert_eq!(delayed.installed, 0);
    assert_eq!(
        (delayed.skipped_clear_fenced, delayed.skipped_existing),
        (1, 0),
        "a clear fence is a distinct import refusal, not an existing lease"
    );
}
/// Idle imports must not claim a wire tuple held by an overlapping peer pool.
#[test]
fn an_address_only_import_refuses_a_peer_pool_pat_identity_11496() {
    let mut p = pool_rule("r1", "P", &["203.0.113.1"]);
    p.from_zone = "dmz".to_string();
    p.port_low = 40_000;
    p.port_high = 40_000;
    let mut q = pool_rule("r2", "Q", &["203.0.113.1"]);
    q.port_low = 40_000;
    q.port_high = 40_000;
    let mut coord = Coordinator::new();
    coord.forwarding.source_nat_rules = parse_source_nat_rules(&[p, q]);

    let peer = mint_active_local_identity(&coord, "Q", false);
    let mut imported = record("P", "10.0.61.51", "203.0.113.1", peer.lease.translated_port);
    imported.lease.address_only = true;
    imported.lease.translated_port = imported.lease.src_port;
    imported.lease.remote = peer.lease.remote;

    let counts = coord.import_idle_persistent_leases(&[imported], 3_000);
    assert_eq!(
        (counts.installed, counts.skipped_identity_busy),
        (0, 1),
        "a peer PAT occupancy bit owns the same wire identity: {counts:?}"
    );
    assert_eq!(
        coord.export_display_persistent_leases(4_000).len(),
        1,
        "the refused import must not create a second lease"
    );
}

/// Address-only peer state has no PAT occupancy bit; imports must consult its
/// reverse-identity ownership index too.
#[test]
fn a_pat_import_refuses_a_peer_pool_address_only_identity_11496() {
    let mut p = pool_rule("r1", "P", &["203.0.113.1"]);
    p.from_zone = "dmz".to_string();
    p.port_low = 40_000;
    p.port_high = 40_000;
    let mut q = pool_rule("r2", "Q", &["203.0.113.1"]);
    q.pool_no_translation = true;
    let mut coord = Coordinator::new();
    coord.forwarding.source_nat_rules = parse_source_nat_rules(&[p, q]);

    let peer = mint_active_local_identity(&coord, "Q", true);
    let mut imported = record("P", "10.0.61.51", "203.0.113.1", peer.lease.translated_port);
    imported.lease.remote = peer.lease.remote;

    let counts = coord.import_idle_persistent_leases(&[imported], 3_000);
    assert_eq!(
        (counts.installed, counts.skipped_identity_busy),
        (0, 1),
        "a peer address-only reverse identity owns the same wire tuple: {counts:?}"
    );
    assert_eq!(
        coord.export_display_persistent_leases(4_000).len(),
        1,
        "the refused import must not create a second lease"
    );
}

/// Idle address-only records own their exact reverse identity across peers too.
#[test]
fn sequential_address_only_idle_imports_reject_overlapping_pool_identity_11496() {
    let mut p = pool_rule("r1", "P", &["203.0.113.1"]);
    p.from_zone = "dmz".to_string();
    let q = pool_rule("r2", "Q", &["203.0.113.1"]);
    let mut coord = Coordinator::new();
    coord.forwarding.source_nat_rules = parse_source_nat_rules(&[p, q]);

    let mut peer = record("Q", "10.0.61.50", "203.0.113.1", 40_000);
    peer.lease.address_only = true;
    peer.lease.translated_port = peer.lease.src_port;
    assert_eq!(
        coord
            .import_idle_persistent_leases(&[peer], 3_000)
            .installed,
        1,
        "the first pool's idle address-only lease must install"
    );

    let mut candidate = record("P", "10.0.61.51", "203.0.113.1", 40_000);
    candidate.lease.address_only = true;
    candidate.lease.translated_port = candidate.lease.src_port;
    let counts = coord.import_idle_persistent_leases(&[candidate], 3_001);
    assert_eq!(
        (counts.installed, counts.skipped_identity_busy),
        (0, 1),
        "the peer's idle reverse identity must block an overlapping import: {counts:?}"
    );
    assert_eq!(
        coord.export_display_persistent_leases(4_000).len(),
        1,
        "the conflicting candidate must not become a second idle lease"
    );
}

#[test]
fn deterministic_nat64_idle_bib_exports_and_imports_only_in_block_14091() {
    let snap = crate::NAT64RuleSnapshot {
        name: "napt64".into(),
        prefix: "64:ff9b::/96".into(),
        pool_addresses: vec!["203.0.113.1".into()],
        deterministic_block_size: 32,
        deterministic_blocks_per_ip: 2,
        deterministic_host_prefix_len: 32,
        deterministic_host_base_v6: "2001:db8::".into(),
        ..Default::default()
    };
    let mut active = Coordinator::new();
    active.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[snap.clone()]);
    let prefix = &active.forwarding.nat64.prefixes[0];
    let params = prefix.deterministic_v6.expect("deterministic prefix");
    let flow = crate::nat::SourceNatFlowKey {
        protocol: 6,
        src_ip: "2001:db8::1".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40000,
        dst_port: 443,
        routing_scope: 0,
    };
    let (ip, port) = crate::nat::allocate_nat64_pool_port_deterministic_v6(
        &prefix.port_allocator,
        flow,
        &prefix.pool_v4,
        params,
        "2001:db8::1".parse().unwrap(),
        1,
        crate::nat::NatHolder::Untracked,
    )
    .unwrap();
    assert!(crate::nat::release_nat64_pool_port(
        &prefix.port_allocator,
        flow,
        ip,
        port,
        20,
        false,
        crate::nat::NatHolder::Untracked
    ));
    let exported = active.export_idle_persistent_leases(21);
    assert_eq!(
        exported.len(),
        1,
        "deterministic NAT64 idle BIB must export: {exported:?}"
    );
    assert_eq!(exported[0].pool_name, "nat64-deterministic-0");
    let mut standby = Coordinator::new();
    standby.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[snap.clone()]);
    assert_eq!(
        standby
            .import_idle_persistent_leases(&exported, 1000)
            .installed,
        1,
        "matching deterministic BIB must import"
    );
    let mut stale = exported[0].clone();
    stale.lease.translated_port = stale.lease.translated_port + 32;
    let mut stale_standby = Coordinator::new();
    stale_standby.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[snap]);
    let counts = stale_standby.import_idle_persistent_leases(&[stale], 1000);
    assert_eq!(
        counts.installed, 0,
        "out-of-block deterministic BIB must not import: {counts:?}"
    );
}

/// #14638: a deterministic-shaped lease arriving under an ordinary source-NAT
/// pool name must never install through the generic path as a dynamic lease.
#[test]
fn deterministic_shaped_lease_never_installs_via_generic_pool_14638() {
    let mut coord = Coordinator::new();
    coord.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let mut rec = record("P", "10.0.61.50", "203.0.113.1", 2048);
    rec.lease.deterministic = true;
    rec.lease.deterministic_identity = Some(crate::nat::DeterministicPortedIdentity::V6(crate::nat::DeterministicV6 {
        block_size: 32,
        blocks_per_ip: 2,
        host_prefix_len: 32,
        host_base: "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().octets(),
        host_count: 2,
    }));
    let counts = coord.import_idle_persistent_leases(&[rec], 1_000);
    assert_eq!(counts.installed, 0, "deterministic lease must not install as dynamic: {counts:?}");
    assert_eq!(counts.skipped_identity_busy, 1, "deterministic-via-generic must count identity-busy: {counts:?}");
    assert_eq!(coord.export_idle_persistent_leases(2_000).len(), 0);
}

/// #14676: deterministic NAT64 leases must be visible to SHOW and revoked by
/// `clear_persistent_nat_leases`, with the clear fence refusing a stale
/// pre-clear re-import — the same legs the source-NAT pool path already has.
/// Pre-fix, display omitted NAT64 entirely and clear never touched the NAT64
/// allocator, so the count was 0 and the stale import installed.
#[test]
fn deterministic_nat64_display_and_clear_revoke_and_fence_14676() {
    let snap = crate::NAT64RuleSnapshot {
        name: "napt64".into(),
        prefix: "64:ff9b::/96".into(),
        pool_addresses: vec!["203.0.113.1".into()],
        deterministic_block_size: 32,
        deterministic_blocks_per_ip: 2,
        deterministic_host_prefix_len: 32,
        deterministic_host_base_v6: "2001:db8::".into(),
        ..Default::default()
    };
    let mut coord = Coordinator::new();
    coord.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[snap]);
    let prefix = &coord.forwarding.nat64.prefixes[0];
    let params = prefix.deterministic_v6.expect("deterministic prefix");
    let flow = crate::nat::SourceNatFlowKey {
        protocol: 6,
        src_ip: "2001:db8::1".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40000,
        dst_port: 443,
        routing_scope: 0,
    };
    let (ip, port) = crate::nat::allocate_nat64_pool_port_deterministic_v6(
        &prefix.port_allocator,
        flow,
        &prefix.pool_v4,
        params,
        "2001:db8::1".parse().unwrap(),
        1,
        crate::nat::NatHolder::Untracked,
    )
    .unwrap();
    assert!(crate::nat::release_nat64_pool_port(
        &prefix.port_allocator,
        flow,
        ip,
        port,
        20,
        false,
        crate::nat::NatHolder::Untracked
    ));
    // Precondition: idle export (already NAT64-aware) sees the lease.
    let exported = coord.export_idle_persistent_leases(21);
    assert_eq!(exported.len(), 1, "setup: idle export must see NAT64 lease");
    assert_eq!(exported[0].pool_name, "nat64-deterministic-0");
    // Display leg.
    let display = coord.export_display_persistent_leases(21);
    assert_eq!(
        display.len(),
        1,
        "deterministic NAT64 lease must appear in SHOW: {display:?}"
    );
    assert_eq!(display[0].pool_name, "nat64-deterministic-0");
    assert!(display[0].lease.deterministic, "display lease must be deterministic");
    assert_eq!(
        display[0].lease.deterministic_identity,
        Some(crate::nat::DeterministicPortedIdentity::V6(params))
    );
    // Clear leg.
    let cleared = coord.clear_persistent_nat_leases();
    assert_eq!(cleared, 1, "clear must revoke the deterministic NAT64 lease");
    assert!(
        coord.export_idle_persistent_leases(22).is_empty(),
        "cleared NAT64 lease must not export as idle"
    );
    assert!(
        coord.export_display_persistent_leases(22).is_empty(),
        "cleared NAT64 lease must not appear in SHOW"
    );
    // Fence leg: a stale pre-clear record must not reinstall.
    let counts = coord.import_idle_persistent_leases(&exported, 23);
    assert_eq!(counts.installed, 0, "stale NAT64 lease must not reinstall after clear: {counts:?}");
    assert_eq!(
        counts.skipped_clear_fenced, 1,
        "stale NAT64 import must be clear-fenced, not installed: {counts:?}"
    );
}
