// #8121 part 2: the layer that answers WHICH allocator a lease belongs to.
//
// Part 1's operations are per-allocator and cannot route. A lease with live
// flows is resolved to a rule through its flow; an idle lease has none, so the
// record carries `pool_name`. These cells bind that routing, and the one
// property routing-by-name creates that routing-by-index would not: several
// rules can point at ONE pool, and the lease must then be exported once.

use super::*;
use crate::nat::parse_source_nat_rules;
use crate::SourceNATRuleSnapshot;

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
            mint_from_zone: None,
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
            mint_from_zone: None,
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
            mint_from_zone: None,
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
    rec.lease.deterministic_identity = Some(crate::nat::DeterministicPortedIdentity::V6(
        crate::nat::DeterministicV6 {
            block_size: 32,
            blocks_per_ip: 2,
            host_prefix_len: 32,
            host_base: "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            host_count: 2,
        },
    ));
    let counts = coord.import_idle_persistent_leases(&[rec], 1_000);
    assert_eq!(
        counts.installed, 0,
        "deterministic lease must not install as dynamic: {counts:?}"
    );
    assert_eq!(
        counts.skipped_identity_busy, 1,
        "deterministic-via-generic must count identity-busy: {counts:?}"
    );
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
    assert!(
        display[0].lease.deterministic,
        "display lease must be deterministic"
    );
    assert_eq!(
        display[0].lease.deterministic_identity,
        Some(crate::nat::DeterministicPortedIdentity::V6(params))
    );
    // Clear leg.
    let cleared = coord.clear_persistent_nat_leases();
    assert_eq!(
        cleared, 1,
        "clear must revoke the deterministic NAT64 lease"
    );
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
    assert_eq!(
        counts.installed, 0,
        "stale NAT64 lease must not reinstall after clear: {counts:?}"
    );
    assert_eq!(
        counts.skipped_clear_fenced, 1,
        "stale NAT64 import must be clear-fenced, not installed: {counts:?}"
    );
}

/// #16488: round-robin NAT64 BIB leases (persistent since #13946) must be
/// visible to SHOW, exported idle, revoked by clear, and clear-fenced on
/// re-import — the same legs #14676 gave deterministic NAT64.
#[test]
fn round_robin_nat64_display_export_clear_and_fence_16488() {
    let snap = crate::NAT64RuleSnapshot {
        name: "napt64-rr".into(),
        prefix: "64:ff9b::/96".into(),
        pool_addresses: vec!["203.0.113.1".into()],
        ..Default::default()
    };
    let mut coord = Coordinator::new();
    coord.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[snap.clone()]);
    let prefix = &coord.forwarding.nat64.prefixes[0];
    assert!(
        prefix.deterministic_v6.is_none(),
        "fixture must be round-robin"
    );
    let flow = crate::nat::SourceNatFlowKey {
        protocol: 6,
        src_ip: "2001:db8::1".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40000,
        dst_port: 443,
        routing_scope: 0,
    };
    let (ip, port) = crate::nat::allocate_nat64_pool_port(
        &prefix.port_allocator,
        flow,
        &prefix.pool_v4,
        1,
        crate::nat::NatHolder::Untracked,
    )
    .unwrap();
    assert_eq!(ip.to_string(), "203.0.113.1");
    assert!(crate::nat::release_nat64_pool_port(
        &prefix.port_allocator,
        flow,
        ip,
        port,
        20,
        false,
        crate::nat::NatHolder::Untracked
    ));
    let exported = coord.export_idle_persistent_leases(21);
    assert_eq!(
        exported.len(),
        1,
        "round-robin NAT64 idle BIB must export: {exported:?}"
    );
    assert_eq!(exported[0].pool_name, "nat64-0");
    assert!(!exported[0].lease.deterministic);
    assert!(
        exported[0].lease.permit_any_remote,
        "NAT64 BIB is AnyRemoteHost"
    );
    let display = coord.export_display_persistent_leases(21);
    assert_eq!(
        display.len(),
        1,
        "round-robin NAT64 lease must appear in SHOW: {display:?}"
    );
    assert_eq!(display[0].pool_name, "nat64-0");
    let mut standby = Coordinator::new();
    standby.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[snap.clone()]);
    let counts = standby.import_idle_persistent_leases(&exported, 1000);
    assert_eq!(
        counts.installed, 1,
        "round-robin BIB must import on standby: {counts:?}"
    );
    let cleared = coord.clear_persistent_nat_leases();
    assert_eq!(cleared, 1, "clear must revoke the round-robin NAT64 lease");
    assert!(
        coord.export_idle_persistent_leases(22).is_empty(),
        "cleared BIB must not export"
    );
    assert!(
        coord.export_display_persistent_leases(22).is_empty(),
        "cleared BIB must not show"
    );
    let counts = coord.import_idle_persistent_leases(&exported, 23);
    assert_eq!(
        counts.installed, 0,
        "stale round-robin BIB must not reinstall after clear: {counts:?}"
    );
    assert_eq!(
        counts.skipped_clear_fenced, 1,
        "stale round-robin import must be clear-fenced: {counts:?}"
    );
}

/// #16488 import validation: out-of-pool / out-of-range records must not install.
#[test]
fn round_robin_nat64_import_rejects_out_of_pool_and_range_16488() {
    let snap = crate::NAT64RuleSnapshot {
        name: "napt64-rr".into(),
        prefix: "64:ff9b::/96".into(),
        pool_addresses: vec!["203.0.113.1".into()],
        ..Default::default()
    };
    let mut coord = Coordinator::new();
    coord.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[snap.clone()]);
    let prefix = &coord.forwarding.nat64.prefixes[0];
    let flow = crate::nat::SourceNatFlowKey {
        protocol: 6,
        src_ip: "2001:db8::1".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40000,
        dst_port: 443,
        routing_scope: 0,
    };
    let (ip, port) = crate::nat::allocate_nat64_pool_port(
        &prefix.port_allocator,
        flow,
        &prefix.pool_v4,
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
    let exported = coord.export_idle_persistent_leases(21);
    assert_eq!(exported.len(), 1);
    let mut standby = Coordinator::new();
    standby.forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[snap]);
    let mut bad_addr = exported[0].clone();
    bad_addr.lease.translated_ip = "203.0.113.99".parse().unwrap();
    let counts = standby.import_idle_persistent_leases(&[bad_addr], 1000);
    assert_eq!(
        counts.installed, 0,
        "out-of-pool BIB must not install: {counts:?}"
    );
    assert_eq!(counts.skipped_unknown_address, 1, "{counts:?}");
    let mut bad_port = exported[0].clone();
    bad_port.lease.translated_port = 80;
    let counts = standby.import_idle_persistent_leases(&[bad_port], 1000);
    assert_eq!(
        counts.installed, 0,
        "out-of-range BIB must not install: {counts:?}"
    );
    assert_eq!(counts.skipped_identity_busy, 1, "{counts:?}");
    let mut det_shaped = exported[0].clone();
    det_shaped.lease.deterministic = true;
    let counts = standby.import_idle_persistent_leases(&[det_shaped], 1000);
    assert_eq!(
        counts.installed, 0,
        "deterministic-shaped rr record must not install: {counts:?}"
    );
}
/// #16876: imported idle leases remain peer-owned on a standby, then become
/// exportable on RG promotion so a restarted former owner can relearn them.
/// The second arm keeps the lease alive only with an inbound holder; releasing
/// that holder rearms expiry but must not itself transfer ownership.
#[test]
fn imported_idle_lease_reaches_restarted_owner_after_promotion_16876() {
    for inbound_only in [false, true] {
        let mut active = Coordinator::new();
        active.forwarding.source_nat_rules =
            parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
        let mut standby = Coordinator::new();
        standby.forwarding.source_nat_rules =
            parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);

        let local = mint_local_idle_lease(&active, "P");
        let advertised = active.export_idle_persistent_leases(3_000);
        assert_eq!(advertised.len(), 1);
        assert_eq!(
            standby
                .import_idle_persistent_leases(&advertised, 10_000)
                .installed,
            1
        );
        assert!(
            standby.export_idle_persistent_leases(11_000).is_empty(),
            "standby must not echo before promotion (#10789-F4)"
        );
        if inbound_only {
            let key = crate::nat::PersistentSourceKey {
                protocol: local.lease.protocol,
                src_ip: local.lease.src_ip,
                src_port: local.lease.src_port,
                routing_scope: local.lease.routing_scope,
                remote: None,
            };
            let allocator = &standby.forwarding.source_nat_rules[0].pool_allocator;
            assert!(allocator.acquire_persistent_inbound(key, 11_000));
            allocator.release_persistent_inbound(key, 12_000);
            assert!(
                standby.export_idle_persistent_leases(13_000).is_empty(),
                "inbound release alone must not promote peer-owned lease"
            );
        }

        // Drive the actual HA activation path; this is when the idle lease's
        // authority changes, not merely when an imported lease is installed.
        standby
            .update_ha_state(&[crate::HAGroupStatus {
                rg_id: 1,
                active: true,
                ..crate::HAGroupStatus::default()
            }])
            .expect("RG promotion");
        let pushed = standby.export_idle_persistent_leases(14_000);
        assert_eq!(
            pushed.len(),
            1,
            "#16876: promoted node must re-advertise imported idle lease (inbound_only={inbound_only})"
        );

        let restarted = Coordinator::new();
        let mut restarted = restarted;
        restarted.forwarding.source_nat_rules =
            parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
        assert_eq!(
            restarted
                .import_idle_persistent_leases(&pushed, 15_000)
                .installed,
            1,
            "#16876: restarted former owner must relearn promoted binding"
        );
    }
}

/// #16876: the periodic peer batch can arrive after RG activation. A lease
/// imported in that order is already locally authoritative and must be
/// eligible for the next re-advertisement.
#[test]
fn imported_idle_lease_arriving_after_promotion_is_exportable_16876() {
    let mut active = Coordinator::new();
    active.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let advertised = mint_local_idle_lease(&active, "P");

    let mut primary = Coordinator::new();
    primary.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    primary
        .update_ha_state(&[crate::HAGroupStatus {
            rg_id: 1,
            active: true,
            ..crate::HAGroupStatus::default()
        }])
        .expect("RG promotion");

    let imported = primary.import_idle_persistent_leases(&[advertised], 10_000);
    assert_eq!(imported.installed, 1, "fixture: peer lease must import");
    let pushed = primary.export_idle_persistent_leases(11_000);
    assert_eq!(
        pushed.len(),
        1,
        "#16876: a lease imported after promotion must be re-advertised"
    );
}

/// #16876 F1: a node-wide lease remains peer-owned until all of this node's
/// configured RGs are active. A stale duplicate remains additive-only and
/// cannot shorten the held lease's deadline.
#[test]
fn mixed_rg_import_refresh_is_additive_without_promotion_16876() {
    let mut source = Coordinator::new();
    source.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let mut advertised = mint_local_idle_lease(&source, "P");

    let mut mixed = Coordinator::new();
    mixed.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    mixed
        .update_ha_state(&[
            crate::HAGroupStatus {
                rg_id: 1,
                active: true,
                ..crate::HAGroupStatus::default()
            },
            crate::HAGroupStatus {
                rg_id: 2,
                active: false,
                ..crate::HAGroupStatus::default()
            },
        ])
        .expect("mixed RG state");

    let imported = mixed.import_idle_persistent_leases(&[advertised.clone()], 10_000);
    assert_eq!(imported.installed, 1, "fixture: peer lease must import");
    let before = mixed
        .export_display_persistent_leases(20_000)
        .into_iter()
        .find(|row| row.pool_name == "P")
        .expect("imported lease remains held for display")
        .lease;

    advertised.lease.remaining_ns = 1;
    let refresh = mixed.import_idle_persistent_leases(&[advertised], 20_000);
    assert_eq!(
        refresh.skipped_existing, 1,
        "refresh must be additive: {refresh:?}"
    );
    let after = mixed
        .export_display_persistent_leases(20_000)
        .into_iter()
        .find(|row| row.pool_name == "P")
        .expect("existing lease must remain held after duplicate")
        .lease;
    assert_eq!(
        after.translated_ip, before.translated_ip,
        "duplicate must not displace lease"
    );
    assert_eq!(
        after.translated_port, before.translated_port,
        "duplicate must not displace lease"
    );
    assert_eq!(
        after.remaining_ns, before.remaining_ns,
        "duplicate import must not shorten lease deadline"
    );
    assert!(
        mixed.export_idle_persistent_leases(20_000).is_empty(),
        "partial RG ownership must not promote the node-wide imported lease set"
    );
}

/// A partial late batch on an already-active node promotes only the records it
/// installed; it must not sweep an unrelated imported lease in another pool.
#[test]
fn late_partial_import_promotes_only_installed_records_16876() {
    let mut primary = Coordinator::new();
    primary.forwarding.source_nat_rules = parse_source_nat_rules(&[
        pool_rule("r1", "P", &["203.0.113.1"]),
        pool_rule("r2", "Q", &["203.0.113.2"]),
    ]);
    primary
        .update_ha_state(&[crate::HAGroupStatus {
            rg_id: 1,
            active: true,
            ..crate::HAGroupStatus::default()
        }])
        .expect("primary RG");

    let unrelated = record("Q", "10.0.61.51", "203.0.113.2", 40_001);
    let q_allocator = &primary
        .forwarding
        .source_nat_rules
        .iter()
        .find(|rule| rule.pool_name == "Q")
        .expect("Q rule")
        .pool_allocator;
    assert_eq!(
        q_allocator.import_idle_lease(
            &unrelated.lease,
            &["203.0.113.2".parse().unwrap()],
            TIMEOUT_NS,
            10_000,
        ),
        crate::nat::IdleLeaseImport::Installed
    );

    let mut source = Coordinator::new();
    source.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let installed = mint_local_idle_lease(&source, "P");
    let mut refused = installed.clone();
    refused.pool_name = "unknown".to_string();
    let counts = primary.import_idle_persistent_leases(&[installed, refused], 20_000);
    assert_eq!((counts.installed, counts.skipped_unknown_pool), (1, 1));

    let exported = primary.export_idle_persistent_leases(21_000);
    assert_eq!(
        exported.len(),
        1,
        "only the newly installed lease is promoted"
    );
    assert_eq!(exported[0].pool_name, "P");
    assert!(
        primary
            .export_display_persistent_leases(21_000)
            .iter()
            .any(|row| row.pool_name == "Q"),
        "the unrelated Q lease remains held, not swept or removed"
    );
}

/// The Go manager filters its fixed 16-slot BPF arrays against its seeded HA
/// inventory before sending groups here. These coordinator tests model that
/// configured inventory, including an inactive RG with no egress interface.
fn configured_ha_inventory(active: &[i32]) -> Vec<crate::HAGroupStatus> {
    (1..=2)
        .map(|rg_id| crate::HAGroupStatus {
            rg_id,
            active: active.contains(&rg_id),
            ..crate::HAGroupStatus::default()
        })
        .collect()
}

#[test]
fn promotion_uses_configured_ha_inventory_16876_gate2() {
    // Unused slots are removed by the Go manager before this coordinator sees
    // the configured RG1/RG2 statuses.
    let groups = configured_ha_inventory(&[1, 2]);
    assert_eq!(groups.len(), 2, "coordinator receives only configured RGs");

    // Activation path.
    let mut source = Coordinator::new();
    source.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let advertised = mint_local_idle_lease(&source, "P");
    let mut standby = Coordinator::new();
    standby.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    assert_eq!(
        standby
            .import_idle_persistent_leases(&[advertised.clone()], 10_000)
            .installed,
        1
    );
    standby.update_ha_state(&groups).expect("HA update");
    assert_eq!(
        standby.export_idle_persistent_leases(14_000).len(),
        1,
        "configured-all-active must promote despite unused inactive slots"
    );

    // Late-import path on an already-active node.
    let mut primary = Coordinator::new();
    primary.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    primary.update_ha_state(&groups).expect("HA update");
    assert_eq!(
        primary
            .import_idle_persistent_leases(&[advertised], 20_000)
            .installed,
        1
    );
    assert_eq!(
        primary.export_idle_persistent_leases(21_000).len(),
        1,
        "late import must promote when only unused slots are inactive"
    );
}

#[test]
fn promotion_blocked_by_configured_inactive_rg_16876_gate2() {
    // RG2 is present in the manager-seeded inventory but has no egress entry
    // in this coordinator snapshot; its inactive status must still block.
    let groups = configured_ha_inventory(&[1]);
    let mut source = Coordinator::new();
    source.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    let advertised = mint_local_idle_lease(&source, "P");
    let mut standby = Coordinator::new();
    standby.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    assert_eq!(
        standby
            .import_idle_persistent_leases(&[advertised.clone()], 10_000)
            .installed,
        1
    );
    standby.update_ha_state(&groups).expect("HA update");
    assert!(
        standby.export_idle_persistent_leases(14_000).is_empty(),
        "a configured inactive RG must block promotion"
    );

    // The same configured inactive RG must block a late batch on an already-
    // active node, not just the activation-time promotion path.
    let mut late_primary = Coordinator::new();
    late_primary.forwarding.source_nat_rules =
        parse_source_nat_rules(&[pool_rule("r1", "P", &["203.0.113.1"])]);
    late_primary.update_ha_state(&groups).expect("HA update");
    assert_eq!(
        late_primary
            .import_idle_persistent_leases(&[advertised], 20_000)
            .installed,
        1
    );
    assert!(
        late_primary
            .export_idle_persistent_leases(21_000)
            .is_empty(),
        "configured peer-owned RG must block late-import promotion"
    );
}

/// #16877: exercise the generation-validated coordinator import rather than
/// the allocator-only test helper, so wildcard admission is checked after a
/// real failover-shaped lease import.
#[test]
fn coordinator_imported_nonzone_any_remote_lease_admits_inbound_16877() {
    let mut snapshot = pool_rule("r1", "P", &["203.0.113.1"]);
    snapshot.from_zone.clear();
    snapshot.to_zone.clear();
    snapshot.persistent_nat_permit = "any-remote-host".to_string();
    let rules = || parse_source_nat_rules(&[snapshot.clone()]);

    let mut active = Coordinator::new();
    active.forwarding.source_nat_rules = rules();
    let advertised = mint_local_idle_lease(&active, "P");
    assert!(advertised.lease.permit_any_remote);
    assert_eq!(advertised.lease.mint_from_zone.as_deref(), Some("lan"));

    let mut primary = Coordinator::new();
    primary.forwarding.source_nat_rules = rules();
    primary
        .update_ha_state(&[crate::HAGroupStatus {
            rg_id: 1,
            active: true,
            ..crate::HAGroupStatus::default()
        }])
        .expect("RG promotion");
    let imported =
        primary.import_idle_persistent_leases_after_generation_now(&[advertised.clone()]);
    assert_eq!(
        imported.installed, 1,
        "peer lease must import: {imported:?}"
    );

    let rule = &primary.forwarding.source_nat_rules[0];
    let decision = rule.pool_allocator.persistent_inbound_lookup_for_rule(
        6,
        advertised.lease.translated_ip,
        advertised.lease.translated_port,
        "203.0.113.99".parse().unwrap(),
        9_999,
        crate::afxdp::monotonic_nanos(),
        rule,
        "wan",
        "wan",
        "wan",
        &crate::nat::NatScopeCtx::default(),
    );
    assert!(
        matches!(decision, crate::nat::PersistentInbound::Permitted { .. }),
        "#16877: generation-validated coordinator import must preserve non-zone AnyRemoteHost admission"
    );
}
