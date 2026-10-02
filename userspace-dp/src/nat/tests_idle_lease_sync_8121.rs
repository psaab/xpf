//! #8121: idle persistent-NAT lease export/import.

use super::allocator::{NatHolder, PoolAddressFamily, PortAllocator, TranslatedTuple};
use super::idle_lease_sync_8121::{IdleLeaseImport, IdleLeaseRecord};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use std::net::{IpAddr, Ipv4Addr};

const TCP: u8 = 6;
const TIMEOUT_NS: u64 = 300 * 1_000_000_000;

/// A MULTI-address pool. The acceptance criteria call for this specifically:
/// with a single-address pool an address assertion passes by construction, so
/// the real assertion has to be on the PORT.
fn pool() -> [Ipv4Addr; 3] {
    [
        "203.0.113.1".parse().unwrap(),
        "203.0.113.2".parse().unwrap(),
        "203.0.113.3".parse().unwrap(),
    ]
}

fn flow(src: &str, sport: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: TCP,
        src_ip: src.parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: sport,
        dst_port: 443,
        routing_scope: 0,
    }
}

fn mint_persistent(
    alloc: &PortAllocator,
    addrs: &[Ipv4Addr],
    f: SourceNatFlowKey,
    now_ns: u64,
) -> TranslatedTuple {
    alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(addrs),
            0,
            false,
            true,
            PersistentNatPermit::TargetHostPort,
            TIMEOUT_NS,
            now_ns,
            NatHolder::Untracked,
        )
        .expect("a fresh persistent allocation must succeed")
}

fn mint_persistent_with_timeout(
    alloc: &PortAllocator,
    addrs: &[Ipv4Addr],
    f: SourceNatFlowKey,
    timeout_ns: u64,
    now_ns: u64,
) -> TranslatedTuple {
    alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(addrs),
            0,
            false,
            true,
            PersistentNatPermit::TargetHostPort,
            timeout_ns,
            now_ns,
            NatHolder::Untracked,
        )
        .expect("a fresh persistent allocation must succeed")
}

fn mint_persistent_any_remote(
    alloc: &PortAllocator,
    addrs: &[Ipv4Addr],
    f: SourceNatFlowKey,
    now_ns: u64,
) -> TranslatedTuple {
    alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(addrs),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            now_ns,
            NatHolder::Untracked,
        )
        .expect("a fresh persistent allocation must succeed")
}

fn mint_persistent_address_only_any_remote(
    alloc: &PortAllocator,
    addrs: &[Ipv4Addr],
    f: SourceNatFlowKey,
    now_ns: u64,
) -> TranslatedTuple {
    alloc
        .reserve_address_only_persistent(
            f,
            PoolAddressFamily::V4(addrs),
            0,
            false,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            now_ns,
            NatHolder::Untracked,
        )
        .expect("a fresh address-only persistent allocation must succeed")
}

fn ipv4_pool(addrs: &[Ipv4Addr]) -> Vec<IpAddr> {
    addrs.iter().copied().map(IpAddr::V4).collect()
}

fn idle_record_for(
    flow: SourceNatFlowKey,
    translated_ip: IpAddr,
    translated_port: u16,
    address_only: bool,
    remote: Option<(IpAddr, u16)>,
) -> IdleLeaseRecord {
    IdleLeaseRecord {
        protocol: flow.protocol,
        src_ip: flow.src_ip,
        src_port: flow.src_port,
        routing_scope: flow.routing_scope,
        remote,
        translated_ip,
        translated_port,
        address_only,
        remaining_ns: TIMEOUT_NS,
        timeout_ns: TIMEOUT_NS,
    }
}

/// The acceptance criterion: a client whose flows all closed shortly BEFORE the
/// failover, but within the persistence timeout, keeps its translated PORT on
/// the new primary.
///
/// A decoy client is interleaved so the port under test is not the only one the
/// allocator could hand back, and the pool is multi-address so the address
/// assertion is not true by construction.
#[test]
fn an_idle_lease_survives_export_and_import_and_keeps_the_port_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let decoy = flow("10.0.61.51", 40001);

    // ORDER IS LOAD-BEARING: the decoy mints FIRST, so the client's identity is
    // NOT the one a fresh allocator hands out first. Minted the other way round
    // this cell is mutation-INSENSITIVE — neutering the import would leave the
    // client's post-failover mint landing on that same first free
    // (address, port) by coincidence, and the assertion would pass while
    // proving nothing. Do not "tidy" this ordering.
    let theirs = mint_persistent(&active, &addrs, decoy, 1_000);
    let mine = mint_persistent(&active, &addrs, client, 1_000);
    assert_ne!(
        (mine.ip, mine.port),
        (theirs.ip, theirs.port),
        "setup: the decoy must hold a different identity or this proves nothing"
    );
    let virgin = PortAllocator::new(1, 1024, 65535);
    let first_free = mint_persistent(&virgin, &addrs, client, 1_000);
    assert_ne!(
        (mine.ip, mine.port),
        (first_free.ip, first_free.port),
        "setup: the identity under test must not be what a FRESH allocator \
         hands out first, or a neutered import passes this cell for free"
    );

    // Both clients go quiet: every flow closes, so both leases go IDLE while
    // still inside the 300s persistence timeout.
    assert!(active.release_flow(client, mine, 2_000, NatHolder::Untracked));
    assert!(active.release_flow(decoy, theirs, 2_000, NatHolder::Untracked));

    let exported = active.export_idle_leases(3_000);
    assert_eq!(exported.len(), 2, "both idle leases must be exported");

    // The standby's clock is unrelated to the active's — a far larger
    // CLOCK_MONOTONIC value, as a node with a longer uptime would have.
    let standby_now = 9_000_000_000_000_u64;
    let standby = PortAllocator::new(1, 1024, 65535);
    let local_pool = ipv4_pool(&addrs);
    for rec in &exported {
        assert_eq!(
            standby.import_idle_lease(rec, &local_pool, TIMEOUT_NS, standby_now),
            IdleLeaseImport::Installed
        );
    }

    // The client comes back on the new primary. It must get its OWN previous
    // identity, not a fresh one and not the decoy's.
    let resumed = mint_persistent(&standby, &addrs, client, standby_now + 1_000);
    assert_eq!(
        (resumed.ip, resumed.port),
        (mine.ip, mine.port),
        "#8121: a client idle within the persistence timeout must keep its \
         translated port across the failover"
    );
}

/// A lease with LIVE flows is not exported: that population is #7360's, rebuilt
/// from the sessions themselves, and sending both would race two mechanisms
/// onto one key.
#[test]
fn a_lease_with_live_flows_is_not_exported_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let busy = flow("10.0.61.50", 40000);
    let idle = flow("10.0.61.51", 40001);
    let _held = mint_persistent(&active, &addrs, busy, 1_000);
    let released = mint_persistent(&active, &addrs, idle, 1_000);
    assert!(active.release_flow(idle, released, 2_000, NatHolder::Untracked));

    let exported = active.export_idle_leases(3_000);
    assert_eq!(
        exported.len(),
        1,
        "only the IDLE lease is this channel's population"
    );
    assert_eq!(exported[0].src_port, 40001);
}

/// Acceptance bullet 3: a rebuilt idle lease has `active_flows == 0` and is
/// GC-eligible at its carried expiry — reconstructing it must not create a
/// lease that outlives what the active held.
///
/// The expiry is computed from the RECEIVER's clock. The record carries
/// remaining lifetime precisely because `expires_at_ns` is `CLOCK_MONOTONIC`
/// and boot-relative: had the absolute value been carried, this lease would
/// read as expired ~9000 seconds ago on this node.
#[test]
fn an_imported_idle_lease_expires_on_the_receivers_clock_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let t = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, t, 2_000, NatHolder::Untracked));
    let rec = active.export_idle_leases(3_000).remove(0);
    // Sanity: the remaining lifetime is what was carried, not a deadline.
    assert!(
        rec.remaining_ns > 0 && rec.remaining_ns <= TIMEOUT_NS,
        "remaining must be a lifetime, got {}",
        rec.remaining_ns
    );

    let standby_now = 9_000_000_000_000_u64;
    let standby = PortAllocator::new(1, 1024, 65535);
    let local_pool = ipv4_pool(&addrs);
    assert_eq!(
        standby.import_idle_lease(&rec, &local_pool, TIMEOUT_NS, standby_now),
        IdleLeaseImport::Installed
    );

    // CONTROL: still inside its lifetime, the lease is honoured.
    let kept = mint_persistent(&standby, &addrs, client, standby_now + 1_000);
    assert_eq!((kept.ip, kept.port), (t.ip, t.port), "control: still live");

    // GC eligibility is asserted on the LEASE, not on the identity a later mint
    // happens to get. A fresh mint on a fresh allocator lands on the same first
    // free (address, port) the original did, so an `assert_ne` there passes or
    // fails for reasons that have nothing to do with the lease — it is the
    // value the code falls back to.
    let fresh_node = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        fresh_node.import_idle_lease(&rec, &local_pool, TIMEOUT_NS, standby_now),
        IdleLeaseImport::Installed
    );
    // Exported => it is idle (active_flows == 0, or it would not qualify) AND
    // still inside its lifetime on THIS node's clock.
    assert_eq!(
        fresh_node.export_display_leases(standby_now + 1).len(),
        1,
        "SHOW must continue to include an imported idle lease"
    );
    // Past the carried remaining lifetime, measured from the RECEIVER's now,
    // it is no longer live. Had the absolute `expires_at_ns` been carried it
    // would have read as expired ~9000 s ago and failed the assertion above.
    assert_eq!(
        fresh_node
            .export_display_leases(standby_now + rec.remaining_ns + 1)
            .len(),
        0,
        "#8121: an imported lease must not outlive the lifetime the active held"
    );
}

/// Module note 4. An idle lease still HOLDS its occupancy bit, so an import
/// that installed the lease without claiming the port would let a local flow
/// mint the same translated identity — and would then have the lease's own
/// expiry free a bit belonging to that other flow.
#[test]
fn an_import_refuses_rather_than_install_over_a_held_port_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let t = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, t, 2_000, NatHolder::Untracked));
    let rec = active.export_idle_leases(3_000).remove(0);

    // A standby where a LOCAL flow already holds that exact identity.
    let standby = PortAllocator::new(1, 1024, 65535);
    let local_pool = ipv4_pool(&addrs);
    let squatter = flow("10.0.61.99", 41000);
    assert!(
        standby.reserve_flow(
            squatter,
            TranslatedTuple {
                ip: rec.translated_ip,
                port: rec.translated_port,
            },
            local_pool
                .iter()
                .position(|a| *a == rec.translated_ip)
                .expect("pool contains it"),
            false,
            10_000,
            NatHolder::Untracked,
        ),
        "setup: the squatter must actually take the identity"
    );

    assert_eq!(
        standby.import_idle_lease(&rec, &local_pool, TIMEOUT_NS, 11_000),
        IdleLeaseImport::SkippedPortBusy,
        "#8121: installing over a held identity would duplicate a translation \
         and later free someone else's occupancy bit"
    );
}

/// Module note 3. `addr_index` is a POSITION, so the record carries the
/// ADDRESS; a node whose pool does not contain it refuses rather than binding
/// the lease to whatever happens to sit at that index.
#[test]
fn an_import_refuses_an_address_this_pool_does_not_have_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let t = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, t, 2_000, NatHolder::Untracked));
    let rec = active.export_idle_leases(3_000).remove(0);

    let standby = PortAllocator::new(1, 1024, 65535);
    let different: Vec<IpAddr> = vec![
        "198.51.100.7".parse().unwrap(),
        "198.51.100.8".parse().unwrap(),
    ];
    assert_eq!(
        standby.import_idle_lease(&rec, &different, TIMEOUT_NS, 11_000),
        IdleLeaseImport::SkippedUnknownAddress
    );

    // CONTROL: the same record against the RIGHT pool installs, so the refusal
    // above is attributable to the address and not to the record being junk.
    assert_eq!(
        standby.import_idle_lease(&rec, &ipv4_pool(&addrs), TIMEOUT_NS, 11_000),
        IdleLeaseImport::Installed
    );
}

/// A local lease wins: it may hold live flows this node is forwarding, and
/// those outrank a remote idle record by definition.
#[test]
fn a_local_lease_is_not_overwritten_by_an_imported_one_8121() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let t = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, t, 2_000, NatHolder::Untracked));
    let rec = active.export_idle_leases(3_000).remove(0);

    let standby = PortAllocator::new(1, 1024, 65535);
    let local_pool = ipv4_pool(&addrs);
    let _local = mint_persistent(&standby, &addrs, client, 10_000);
    assert_eq!(
        standby.import_idle_lease(&rec, &local_pool, TIMEOUT_NS, 11_000),
        IdleLeaseImport::SkippedExisting
    );
}

/// Idle imports share the persistent-table cap with local mints. This fills one
/// slot with a PAT lease and one with address-only state, leaving a free PAT
/// port at capacity so guard-removal proves table growth rather than port
/// exhaustion.
#[test]
fn a_full_imported_table_refuses_local_mints_11475() {
    let addrs = ["203.0.113.10".parse().unwrap()];
    let pool_addrs = ipv4_pool(&addrs);
    let allocator = PortAllocator::new(1, 20_000, 20_001);
    let record =
        |src_ip: &str, src_port: u16, translated_port: u16, address_only: bool| IdleLeaseRecord {
            protocol: TCP,
            src_ip: src_ip.parse().unwrap(),
            src_port,
            routing_scope: 0,
            remote: Some(("8.8.8.8".parse().unwrap(), 443)),
            translated_ip: IpAddr::V4(addrs[0]),
            translated_port,
            address_only,
            remaining_ns: TIMEOUT_NS,
            timeout_ns: TIMEOUT_NS,
        };

    for rec in [
        record("10.0.61.50", 40_000, 20_000, false),
        record("10.0.61.51", 40_001, 40_001, true),
    ] {
        assert_eq!(
            allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 1_000),
            IdleLeaseImport::Installed
        );
    }
    assert_eq!(allocator.snapshot().persistent_leases, 2);
    assert!(
        !allocator.holds_port(0, 20_001),
        "setup: a PAT port must remain free when the table cap is reached"
    );
    assert_eq!(
        allocator.import_idle_lease(
            &record("10.0.61.52", 40_002, 20_001, false),
            &pool_addrs,
            TIMEOUT_NS,
            1_000
        ),
        IdleLeaseImport::SkippedCapacity
    );
    assert_eq!(allocator.snapshot().persistent_leases, 2);
    assert!(
        !allocator.holds_port(0, 20_001),
        "capacity refusal must not claim an otherwise-free PAT port"
    );

    let local = allocator.allocate_translation(
        flow("10.0.61.99", 40_099),
        PoolAddressFamily::V4(&addrs),
        0,
        false,
        true,
        PersistentNatPermit::TargetHostPort,
        TIMEOUT_NS,
        2_000,
        NatHolder::Untracked,
    );
    assert!(
        matches!(
            local,
            Err(super::source::SourceNatFailureReason::AllocatorExhausted)
        ),
        "a full imported lease table must leave local mints failing closed as \
         AllocatorExhausted, got {local:?}"
    );
}

/// Synced-session persistent mints obey the same hard lease-table cap as
/// imported idle leases. Fill the table with address-only idle entries so the
/// PAT arm still has a free port; the live-flow cap is independently empty.
#[test]
fn synced_persistent_mints_refuse_a_full_lease_table_11495() {
    let addrs = ["203.0.113.10".parse().unwrap()];
    let pool_addrs = ipv4_pool(&addrs);
    let allocator = PortAllocator::new(1, 20_000, 20_001);
    let record = |src_ip: &str, src_port| IdleLeaseRecord {
        protocol: TCP,
        src_ip: src_ip.parse().unwrap(),
        src_port,
        routing_scope: 0,
        remote: Some(("8.8.8.8".parse().unwrap(), 443)),
        translated_ip: IpAddr::V4(addrs[0]),
        translated_port: src_port,
        address_only: true,
        remaining_ns: TIMEOUT_NS,
        timeout_ns: TIMEOUT_NS,
    };
    for (src_ip, src_port) in [("10.0.61.50", 40_000), ("10.0.61.51", 40_001)] {
        assert_eq!(
            allocator.import_idle_lease(&record(src_ip, src_port), &pool_addrs, TIMEOUT_NS, 1_000),
            IdleLeaseImport::Installed
        );
    }
    assert_eq!(allocator.snapshot().persistent_leases, 2);
    assert_eq!(allocator.snapshot().live_flows, 0);

    let pat_flow = flow("10.0.61.52", 40_002);
    let pat_key = pat_flow.persistent_source_key(PersistentNatPermit::TargetHostPort);
    let mut previous_snapshot = None;
    assert!(
        !allocator.reserve_flow_maybe_persistent(
            pat_flow,
            TranslatedTuple {
                ip: IpAddr::V4(addrs[0]),
                port: 20_000,
            },
            0,
            false,
            2_000,
            NatHolder::Untracked,
            Some((pat_key, TIMEOUT_NS)),
            false,
            &mut previous_snapshot,
        ),
        "a synced PAT mint must refuse rather than exceed the persistent lease cap"
    );
    assert_eq!(allocator.snapshot().persistent_leases, 2);
    assert_eq!(allocator.snapshot().live_flows, 0);
    assert!(
        !allocator.holds_port(0, 20_000),
        "a lease-cap refusal must return the otherwise-free PAT port"
    );

    let address_only_flow = flow("10.0.61.53", 40_003);
    let address_only_key =
        address_only_flow.persistent_source_key(PersistentNatPermit::TargetHostPort);
    let mut previous_snapshot = None;
    assert!(
        allocator
            .reserve_address_only_maybe_persistent(
                address_only_flow,
                IpAddr::V4(addrs[0]),
                0,
                2_000,
                NatHolder::Untracked,
                Some((address_only_key, TIMEOUT_NS)),
                false,
                &mut previous_snapshot,
            )
            .is_err(),
        "a synced address-only mint must refuse rather than exceed the persistent lease cap"
    );
    assert_eq!(allocator.snapshot().persistent_leases, 2);
    assert_eq!(allocator.snapshot().live_flows, 0);
}
/// The pressure pass reclaims an expired idle lease before deciding the import
/// cannot fit; the newly admitted lease remains the only table entry.
#[test]
fn an_idle_import_pressure_pass_reclaims_expired_capacity_11475() {
    let addrs = ["203.0.113.10".parse().unwrap()];
    let pool_addrs = ipv4_pool(&addrs);
    let allocator = PortAllocator::new(1, 20_000, 20_000);
    let record = |src_ip: &str| IdleLeaseRecord {
        protocol: TCP,
        src_ip: src_ip.parse().unwrap(),
        src_port: 40_000,
        routing_scope: 0,
        remote: Some(("8.8.8.8".parse().unwrap(), 443)),
        translated_ip: IpAddr::V4(addrs[0]),
        translated_port: 20_000,
        address_only: false,
        remaining_ns: 100,
        timeout_ns: TIMEOUT_NS,
    };

    assert_eq!(
        allocator.import_idle_lease(&record("10.0.61.50"), &pool_addrs, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    assert_eq!(
        allocator.import_idle_lease(&record("10.0.61.51"), &pool_addrs, TIMEOUT_NS, 1_100),
        IdleLeaseImport::Installed,
        "one bounded pressure-GC pass must make room for a non-expired incoming lease"
    );
    assert_eq!(allocator.snapshot().persistent_leases, 1);
    assert_eq!(allocator.export_display_leases(1_100).len(), 1);
    assert_eq!(
        allocator.export_display_leases(1_100)[0].src_ip,
        "10.0.61.51".parse::<IpAddr>().unwrap()
    );
}

/// Imported remote scopes overlap live owners as exact endpoints, target hosts,
/// or any remote, and the prefix indexes stop blocking after owner teardown.
#[test]
fn an_address_only_import_refuses_live_reverse_identity_contention_11475() {
    let addrs = ["203.0.113.10".parse().unwrap()];
    let pool_addrs = ipv4_pool(&addrs);
    let mut rec = IdleLeaseRecord {
        protocol: TCP,
        src_ip: "10.0.61.50".parse().unwrap(),
        src_port: 20_000,
        routing_scope: 0,
        remote: Some(("8.8.8.8".parse().unwrap(), 443)),
        translated_ip: IpAddr::V4(addrs[0]),
        translated_port: 20_000,
        address_only: true,
        remaining_ns: TIMEOUT_NS,
        timeout_ns: TIMEOUT_NS,
    };
    let translated = TranslatedTuple {
        ip: rec.translated_ip,
        port: rec.translated_port,
    };

    let pat_allocator = PortAllocator::new(1, 20_000, 20_001);
    let pat_owner = flow("10.0.61.99", 20_000);
    assert!(pat_allocator.reserve_flow(
        pat_owner,
        translated,
        0,
        false,
        1_000,
        NatHolder::Untracked,
    ));
    assert_eq!(
        pat_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "a live PAT reverse identity must block an address-only lease import"
    );
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 0));
    assert_eq!(
        pat_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "target-host imports overlap every live PAT owner port on that host"
    );
    rec.remote = None;
    assert_eq!(
        pat_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "any-remote imports overlap live PAT owners at the translated tuple"
    );
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 444));
    assert_eq!(
        pat_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::Installed,
        "a different exact remote port remains admissible"
    );
    assert!(pat_allocator.release_flow(pat_owner, translated, 2_500, NatHolder::Untracked));
    rec.src_ip = "10.0.61.51".parse().unwrap();
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 0));
    assert_eq!(
        pat_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::Installed,
        "releasing the PAT owner must clear the host-scope index"
    );

    let address_only_allocator = PortAllocator::new(1, 20_000, 20_002);
    let address_only_owner = flow("10.0.61.99", 20_000);
    let owned = address_only_allocator
        .reserve_address_only(address_only_owner, rec.translated_ip, NatHolder::Untracked)
        .unwrap();
    rec.src_ip = "10.0.61.50".parse().unwrap();
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 443));
    assert_eq!(
        address_only_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "a live address-only reverse identity must block a duplicate lease import"
    );
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 0));
    assert_eq!(
        address_only_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "target-host imports overlap every live address-only owner port on that host"
    );
    rec.remote = None;
    assert_eq!(
        address_only_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "any-remote imports overlap live address-only owners at the translated tuple"
    );
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 444));
    assert_eq!(
        address_only_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::Installed,
        "a different exact remote port remains admissible"
    );
    assert!(address_only_allocator.release_flow(
        address_only_owner,
        owned,
        2_500,
        NatHolder::Untracked
    ));
    rec.src_ip = "10.0.61.51".parse().unwrap();
    rec.remote = None;
    assert_eq!(
        address_only_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::Installed,
        "releasing the address-only owner must clear the any-remote prefix index"
    );
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 0));
    assert_eq!(
        address_only_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::Installed,
        "releasing the address-only owner must clear the host-scope index"
    );

    rec.remote = None;
    let unscoped_allocator = PortAllocator::new(1, 20_000, 20_001);
    assert_eq!(
        unscoped_allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::Installed,
        "any-remote leases install when no live owner overlaps their tuple"
    );
}

/// PAT idle imports must enforce the same same-allocator address-only owner
/// check as local PAT mints and synced reserves, without claiming a colliding
/// bitmap bit.
#[test]
fn a_pat_import_refuses_live_address_only_reverse_identity_11475() {
    let addrs = ["203.0.113.10".parse().unwrap()];
    let pool_addrs = ipv4_pool(&addrs);
    let allocator = PortAllocator::new(1, 20_000, 20_002);
    let address_only_owner = flow("10.0.61.99", 20_000);
    let translated = allocator
        .reserve_address_only(
            address_only_owner,
            IpAddr::V4(addrs[0]),
            NatHolder::Untracked,
        )
        .unwrap();
    assert!(!allocator.holds_port(0, translated.port));

    let mut rec = IdleLeaseRecord {
        protocol: TCP,
        src_ip: "10.0.61.50".parse().unwrap(),
        src_port: 40_000,
        routing_scope: 0,
        remote: Some(("8.8.8.8".parse().unwrap(), 443)),
        translated_ip: translated.ip,
        translated_port: translated.port,
        address_only: false,
        remaining_ns: TIMEOUT_NS,
        timeout_ns: TIMEOUT_NS,
    };
    assert!(
        !allocator.reserve_flow(
            flow("10.0.61.98", 40_001),
            translated,
            0,
            false,
            1_500,
            NatHolder::Untracked,
        ),
        "control: the synced PAT reserve already rejects the same live owner"
    );
    assert_eq!(
        allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "a PAT import must match the synced reserve's same-allocator refusal"
    );
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 0));
    assert_eq!(
        allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "target-host imports overlap address-only owners at every destination port"
    );
    rec.remote = None;
    assert_eq!(
        allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "any-remote imports overlap address-only owners at the translated tuple"
    );
    rec.remote = Some(("9.9.9.9".parse().unwrap(), 443));
    assert_eq!(
        allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::Installed,
        "an unrelated remote endpoint can still use the free PAT identity"
    );
    assert!(allocator.holds_port(0, translated.port));

    assert!(allocator.release_flow(address_only_owner, translated, 2_500, NatHolder::Untracked));
    rec.src_ip = "10.0.61.51".parse().unwrap();
    rec.remote = None;
    assert_eq!(
        allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::SkippedPortBusy,
        "after owner teardown, the same tuple reaches PAT occupancy (the \
         9.9.9.9 lease holds the bit) instead of a stale identity prefix"
    );
    rec.remote = Some(("8.8.8.8".parse().unwrap(), 0));
    rec.translated_port = 20_001;
    assert_eq!(
        allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::Installed,
        "releasing the address-only owner must clear the host-scope index"
    );
    rec.src_ip = "10.0.61.52".parse().unwrap();
    rec.remote = None;
    rec.translated_port = 20_002;
    assert_eq!(
        allocator.import_idle_lease(&rec, &pool_addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::Installed,
        "any-remote imports install after the overlapping owner is released"
    );
}

/// A lease learned from a peer is not sent back to that peer. Empty pushes are
/// not re-imports; the active retains its original local lease.
#[test]
fn an_imported_idle_lease_is_not_echoed_10789_f4() {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);
    let client = flow("10.0.61.50", 40000);
    let active = PortAllocator::new(1, 1024, 65535);
    let translated = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, translated, 2_000, NatHolder::Untracked));
    let sent = active.export_idle_leases(3_000);
    assert_eq!(
        sent.len(),
        1,
        "setup: A must advertise its local idle lease"
    );

    let standby = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        standby.import_idle_lease(&sent[0], &local_pool, TIMEOUT_NS, 10_000),
        IdleLeaseImport::Installed
    );
    assert_eq!(
        standby.export_display_leases(11_000).len(),
        1,
        "the SHOW-table export must still include imported leases"
    );
    let echoed = standby.export_idle_leases(11_000);
    assert!(
        echoed.is_empty(),
        "B must not echo a lease it only imported: {echoed:?}"
    );

    // Model A applying B's next additive push. B advertised nothing, so A
    // receives no lease record and its original local binding stays present.
    for rec in &echoed {
        active.import_idle_lease(rec, &local_pool, TIMEOUT_NS, 12_000);
    }
    assert_eq!(active.export_idle_leases(12_000).len(), 1);
}

/// Once A retires its local lease and releases the port, B's periodic
/// re-advertisement must not reinstall that peer-owned copy on A.
#[test]
fn an_imported_idle_lease_cannot_resurrect_a_retired_lease_10789_f4() {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);
    let client = flow("10.0.61.50", 40000);
    let active = PortAllocator::new(1, 1024, 65535);
    let translated = mint_persistent(&active, &addrs, client, 1_000);
    assert!(active.release_flow(client, translated, 2_000, NatHolder::Untracked));
    let sent = active.export_idle_leases(3_000).remove(0);

    let standby = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        standby.import_idle_lease(&sent, &local_pool, TIMEOUT_NS, 10_000),
        IdleLeaseImport::Installed
    );
    let peer_push = standby.export_idle_leases(11_000);
    assert!(
        peer_push.is_empty(),
        "an imported lease must not be re-pushed"
    );

    // Retire L on A, as the production teardown does: remove its map/index
    // entries and release its claimed translated port before B advertises again.
    let key = client.persistent_source_key(PersistentNatPermit::TargetHostPort);
    let retired = {
        let mut live = active.debug_live();
        let lease = live
            .persistent_by_source
            .remove(&key)
            .expect("A's local lease must exist");
        let expiry = (lease.expires_at_ns, key);
        live.lease_expirations.remove(&expiry);
        live.lease_expirations_by_addr[lease.addr_index].remove(&expiry);
        lease
    };
    active.debug_clear_owner(
        retired.addr_index,
        retired.translated.ip,
        retired.translated.port,
    );
    assert_eq!(
        active.debug_occupied_count(),
        0,
        "retirement releases A's port"
    );

    for rec in &peer_push {
        active.import_idle_lease(rec, &local_pool, TIMEOUT_NS, 12_000);
    }
    assert!(
        !active.debug_live().persistent_by_source.contains_key(&key),
        "B's re-push must not resurrect the lease A retired"
    );
}

/// A local 0 -> 1 reserve stays tentative; ordinary `release_flow` promotes
/// the peer-imported idle lease to local ownership in both allocator modes.
#[test]
fn a_local_idle_adoption_promotes_only_on_release_10789_f4() {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);

    let pat_flow = flow("10.0.61.50", 40000);
    let mut pat_rec = idle_record_for(
        pat_flow,
        IpAddr::V4(addrs[0]),
        2048,
        false,
        Some((pat_flow.dst_ip, pat_flow.dst_port)),
    );
    pat_rec.timeout_ns = 60 * 1_000_000_000;
    pat_rec.remaining_ns = 45 * 1_000_000_000;
    let pat = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        pat.import_idle_lease(&pat_rec, &local_pool, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    assert!(
        pat.debug_live()
            .persistent_by_source
            .get(&pat_flow.persistent_source_key(PersistentNatPermit::TargetHostPort))
            .unwrap()
            .imported
    );
    let pat_tuple = mint_persistent(&pat, &addrs, pat_flow, 2_000);
    assert_eq!(
        (pat_tuple.ip, pat_tuple.port),
        (pat_rec.translated_ip, pat_rec.translated_port)
    );
    assert!(pat.release_flow(pat_flow, pat_tuple, 3_000, NatHolder::Untracked));
    let pat_lease = pat.debug_live().persistent_by_source
        [&pat_flow.persistent_source_key(PersistentNatPermit::TargetHostPort)];
    assert_eq!(pat_lease.timeout_ns, TIMEOUT_NS);
    assert_eq!(pat_lease.expires_at_ns, 3_000 + TIMEOUT_NS);
    assert_eq!(pat.export_idle_leases(4_000).len(), 1);
    assert!(
        !pat.debug_live()
            .persistent_by_source
            .get(&pat_flow.persistent_source_key(PersistentNatPermit::TargetHostPort))
            .unwrap()
            .imported
    );

    let address_flow = flow("10.0.61.51", 40001);
    let mut address_rec = idle_record_for(
        address_flow,
        IpAddr::V4(addrs[0]),
        address_flow.src_port,
        true,
        Some((address_flow.dst_ip, address_flow.dst_port)),
    );
    address_rec.timeout_ns = 60 * 1_000_000_000;
    address_rec.remaining_ns = 45 * 1_000_000_000;
    let address_only = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        address_only.import_idle_lease(&address_rec, &local_pool, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let address_tuple = address_only
        .reserve_address_only_persistent(
            address_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            PersistentNatPermit::TargetHostPort,
            TIMEOUT_NS,
            2_000,
            NatHolder::Untracked,
        )
        .expect("local flow joins the imported address-only lease");
    assert_eq!(address_tuple.ip, address_rec.translated_ip);
    assert!(address_only.release_flow(address_flow, address_tuple, 3_000, NatHolder::Untracked));
    let address_lease = address_only.debug_live().persistent_by_source
        [&address_flow.persistent_source_key(PersistentNatPermit::TargetHostPort)];
    assert_eq!(address_lease.timeout_ns, TIMEOUT_NS);
    assert_eq!(address_lease.expires_at_ns, 3_000 + TIMEOUT_NS);
    assert_eq!(address_only.export_idle_leases(4_000).len(), 1);
    assert!(
        !address_only
            .debug_live()
            .persistent_by_source
            .get(&address_flow.persistent_source_key(PersistentNatPermit::TargetHostPort))
            .unwrap()
            .imported
    );
}

/// A synced session joining an imported lease is not a promotion. Check both
/// peer-rebuilt lease routes: the PAT #7360 and address-only #8132 reserves.
#[test]
fn a_synced_join_does_not_promote_an_imported_idle_lease_10789_f4() {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);
    let pat_flow = flow("10.0.61.50", 40000);
    let synced_pat_flow = SourceNatFlowKey {
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        ..pat_flow
    };
    let pat_rec = idle_record_for(pat_flow, IpAddr::V4(addrs[0]), 2048, false, None);
    let pat = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        pat.import_idle_lease(&pat_rec, &local_pool, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let pat_key = pat_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    assert!(pat.reserve_flow_maybe_persistent(
        synced_pat_flow,
        TranslatedTuple {
            ip: pat_rec.translated_ip,
            port: pat_rec.translated_port,
        },
        0,
        false,
        2_000,
        NatHolder::Untracked,
        Some((pat_key, TIMEOUT_NS)),
        false,
        &mut None,
    ));
    let pat_tuple = TranslatedTuple {
        ip: pat_rec.translated_ip,
        port: pat_rec.translated_port,
    };
    assert!(pat.release_flow(synced_pat_flow, pat_tuple, 3_000, NatHolder::Untracked));
    assert!(pat.export_idle_leases(4_000).is_empty());
    assert_eq!(pat.export_display_leases(4_000).len(), 1);
    assert!(
        pat.debug_live()
            .persistent_by_source
            .get(&pat_key)
            .unwrap()
            .imported
    );

    let address_flow = flow("10.0.61.51", 40001);
    let synced_address_flow = SourceNatFlowKey {
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        ..address_flow
    };
    let address_rec = idle_record_for(
        address_flow,
        IpAddr::V4(addrs[0]),
        address_flow.src_port,
        true,
        None,
    );
    let address_only = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        address_only.import_idle_lease(&address_rec, &local_pool, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let address_key = address_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let address_tuple = address_only
        .reserve_address_only_maybe_persistent(
            synced_address_flow,
            address_rec.translated_ip,
            0,
            2_000,
            NatHolder::Untracked,
            Some((address_key, TIMEOUT_NS)),
            false,
            &mut None,
        )
        .expect("synced address-only session joins the imported lease");
    assert!(address_only.release_flow(
        synced_address_flow,
        address_tuple,
        3_000,
        NatHolder::Untracked
    ));
    assert!(address_only.export_idle_leases(4_000).is_empty());
    assert!(
        address_only
            .debug_live()
            .persistent_by_source
            .get(&address_key)
            .unwrap()
            .imported
    );
}

/// Joining an already-active imported lease is tentative until a local flow
/// completes. Once it does, the lease is locally owned even while a synced
/// flow remains active; both PAT and address-only arms must re-advertise it
/// after the final flow drains.
#[test]
fn a_local_active_lease_join_promotes_on_completion_10789_f4() {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);

    let pat_flow = flow("10.0.61.50", 40000);
    let synced_pat_flow = SourceNatFlowKey {
        dst_ip: "9.9.9.9".parse().unwrap(),
        dst_port: 443,
        ..pat_flow
    };
    let local_pat_flow = SourceNatFlowKey {
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        ..pat_flow
    };
    let pat_rec = idle_record_for(pat_flow, IpAddr::V4(addrs[0]), 2048, false, None);
    let pat = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        pat.import_idle_lease(&pat_rec, &local_pool, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let pat_key = pat_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let pat_tuple = TranslatedTuple {
        ip: pat_rec.translated_ip,
        port: pat_rec.translated_port,
    };
    assert!(pat.reserve_flow_maybe_persistent(
        synced_pat_flow,
        pat_tuple,
        0,
        false,
        2_000,
        NatHolder::Untracked,
        Some((pat_key, TIMEOUT_NS)),
        false,
        &mut None,
    ));
    let local_pat_tuple = pat
        .allocate_translation(
            local_pat_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            3_000,
            NatHolder::Untracked,
        )
        .expect("local N -> N+1 join reuses the active imported lease");
    assert!(pat.debug_live().persistent_by_source[&pat_key].imported);
    assert!(pat.rollback_flow(local_pat_flow, local_pat_tuple, 3_500, NatHolder::Untracked));
    let after_rollback = pat.debug_live().persistent_by_source[&pat_key];
    assert!(after_rollback.imported);
    assert_eq!(after_rollback.active_flows, 1);
    let local_pat_tuple = pat
        .allocate_translation(
            local_pat_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            3_600,
            NatHolder::Untracked,
        )
        .expect("a later local reserve can still join after tentative rollback");
    assert!(pat.release_flow(local_pat_flow, local_pat_tuple, 4_000, NatHolder::Untracked));
    let pat_lease = pat.debug_live().persistent_by_source[&pat_key];
    assert!(!pat_lease.imported);
    assert_eq!(pat_lease.active_flows, 1, "the synced flow remains active");
    assert_eq!(pat_lease.timeout_ns, TIMEOUT_NS);
    assert!(
        pat.export_idle_leases(4_500).is_empty(),
        "live leases are not exported"
    );
    assert!(pat.release_flow(synced_pat_flow, pat_tuple, 5_000, NatHolder::Untracked));
    assert_eq!(pat.export_idle_leases(5_001).len(), 1);

    let address_flow = flow("10.0.61.51", 40001);
    let synced_address_flow = SourceNatFlowKey {
        dst_ip: "9.9.9.9".parse().unwrap(),
        dst_port: 443,
        ..address_flow
    };
    let local_address_flow = SourceNatFlowKey {
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        ..address_flow
    };
    let address_rec = idle_record_for(
        address_flow,
        IpAddr::V4(addrs[0]),
        address_flow.src_port,
        true,
        None,
    );
    let address_only = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        address_only.import_idle_lease(&address_rec, &local_pool, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let address_key = address_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let synced_address_tuple = address_only
        .reserve_address_only_maybe_persistent(
            synced_address_flow,
            address_rec.translated_ip,
            0,
            2_000,
            NatHolder::Untracked,
            Some((address_key, TIMEOUT_NS)),
            false,
            &mut None,
        )
        .expect("synced flow joins the imported address-only lease");
    let local_address_tuple = address_only
        .reserve_address_only_persistent(
            local_address_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            3_000,
            NatHolder::Untracked,
        )
        .expect("local N -> N+1 join reuses the active imported lease");
    assert!(address_only.debug_live().persistent_by_source[&address_key].imported);
    assert!(address_only.rollback_flow(
        local_address_flow,
        local_address_tuple,
        3_500,
        NatHolder::Untracked
    ));
    let after_rollback = address_only.debug_live().persistent_by_source[&address_key];
    assert!(after_rollback.imported);
    assert_eq!(after_rollback.active_flows, 1);
    let local_address_tuple = address_only
        .reserve_address_only_persistent(
            local_address_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            3_600,
            NatHolder::Untracked,
        )
        .expect("a later local reserve can still join after tentative rollback");
    assert!(address_only.release_flow(
        local_address_flow,
        local_address_tuple,
        4_000,
        NatHolder::Untracked
    ));
    let address_lease = address_only.debug_live().persistent_by_source[&address_key];
    assert!(!address_lease.imported);
    assert_eq!(
        address_lease.active_flows, 1,
        "the synced flow remains active"
    );
    assert_eq!(address_lease.timeout_ns, TIMEOUT_NS);
    assert!(
        address_only.export_idle_leases(4_500).is_empty(),
        "live address-only leases are not exported"
    );
    assert!(address_only.release_flow(
        synced_address_flow,
        synced_address_tuple,
        5_000,
        NatHolder::Untracked
    ));
    assert_eq!(address_only.export_idle_leases(5_001).len(), 1);
}

// --- #8121: the lease POPULATION census -------------------------------------
//
// WHY THIS EXISTS. #8121, #7360 and #8132 each cover one route by which an
// active node's persistent lease reaches a standby, and the three together are
// claimed to be exhaustive.
//
// #8573 acted on that claim: the #1449 capability gate, which disarmed
// forwarding for every HA persistent-NAT config on the stated reason that
// "leases are not HA-synchronized", was REMOVED after the three routes were
// measured working on the loss userspace cluster (lease visible on the standby
// with an identical translated identity, surviving an RG0 failover, and honoured
// after failback). This census is therefore no longer an argument against a
// gate — it is the thing holding the gate's removal up, and a sixth unclassified
// insert site now means clustered persistent-NAT is silently forwarding with
// leases that do not survive a failover.
//
// A claim that load-bearing must not live in prose. Defining a population by a
// mechanism ("things that insert a lease") is a CLAIM that the mechanism is the
// only route, and the way that claim fails is a SIXTH site appearing later that
// nobody classifies — at which point the three-route argument is quietly false
// and everything resting on it inherits the error.
//
// So this pins the sites by CONTENT and by enclosing function, and a new one
// reds until somebody says which sync route carries it.

/// Every production site that creates a persistent lease, with the route by
/// which such a lease reaches a standby.
///
/// Pinned by enclosing function rather than by count: a stale entry cannot hide
/// behind a coincidental total.
const LEASE_CREATION_SITES_8121: &[(&str, &str)] = &[
    // BORN ON THE ACTIVE. Reaches a standby by one of the two routes below,
    // depending on whether it still has live flows when the sync happens.
    ("allocate_translation_locked", "local PAT mint"),
    (
        "reserve_address_only_persistent",
        "local address-only mint (#6041)",
    ),
    // REBUILT ON THE STANDBY from a synced SESSION — the population with live
    // flows. Two arms because the port-bearing and address-only reserves are
    // different functions, which is why they needed separate fixes.
    (
        "reserve_flow_maybe_persistent",
        "#7360, from synced sessions",
    ),
    (
        "reserve_address_only_maybe_persistent",
        "#8132, from synced sessions",
    ),
    // INSTALLED ON THE STANDBY from an exported lease — the IDLE population,
    // which has no session to be rebuilt from and is exactly why #8121 exists.
    ("import_idle_lease", "#8121, from the idle-lease sync"),
];

/// The census. Reds when a lease is created somewhere the three-route argument
/// has not accounted for.
///
/// FAIL-ON-REVERT is not the useful framing here — nothing to revert. What this
/// catches is ADDITION: a sixth creation site landing in a future change,
/// silently making "the population is covered by #7360 + #8132 + #8121" false
/// while every existing cell stays green, because every existing cell tests a
/// route rather than the set of routes.
#[test]
fn every_persistent_lease_creation_site_has_a_sync_route_8121() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/nat");
    let mut files = Vec::new();
    crate::afxdp::worker_queue::tests::afxdp_rs_files(&root, &mut files);

    let mut found: Vec<String> = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .expect("under src/nat")
            .to_string_lossy()
            .replace('\\', "/");
        if crate::afxdp::worker_queue::tests::is_fixture(&root, &rel) {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source");
        let cleaned = crate::afxdp::worker_queue::tests::blank_comments_and_strings(&src);
        // The enclosing `fn` of each insert: walk forward tracking the most
        // recent top-level-ish `fn` declaration, which is what makes the pin
        // survive line-number churn.
        let mut current = String::new();
        for line in cleaned.lines() {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix("fn ").or_else(|| {
                t.strip_prefix("pub fn ")
                    .or_else(|| t.split("fn ").nth(1).filter(|_| t.contains("fn ")))
            }) {
                if let Some(name) = rest.split(['(', '<']).next() {
                    current = name.trim().to_string();
                }
            }
            if t.contains("persistent_by_source.insert(") {
                found.push(current.clone());
            }
        }
    }
    found.sort();
    found.dedup();

    let mut want: Vec<String> = LEASE_CREATION_SITES_8121
        .iter()
        .map(|(f, _)| (*f).to_string())
        .collect();
    want.sort();

    assert_eq!(
        found, want,
        "the set of persistent-lease CREATION sites under src/nat changed.\n\
         Every such site is a lease that must reach a standby somehow. The three \
         routes that exist are: rebuilt from a synced session while it has live \
         flows (#7360 port-bearing, #8132 address-only), or exported and \
         imported while it is IDLE (#8121).\n\
         If the new site creates a lease on the ACTIVE, say which of those \
         carries it and add it above. If it creates one on the STANDBY, it IS a \
         new route and the exhaustiveness argument — which the #1449 capability \
         gate's stated reason rests on — has to be re-made rather than \
         inherited (#8121)"
    );
}

/// POSITIVE CONTROL for the census: it must actually FIND things.
///
/// A scanner whose pattern has rotted matches nothing and compares empty to
/// empty — passing forever while measuring no population at all. This asserts
/// the walk reaches real source and that a known site is among what it found,
/// so the census cannot degenerate into a tautology.
#[test]
fn the_lease_census_actually_finds_its_population_8121() {
    assert_eq!(
        LEASE_CREATION_SITES_8121.len(),
        5,
        "the expected-site list is empty or has been trimmed to nothing, which \
         would make the census compare empty to empty"
    );
    assert!(
        LEASE_CREATION_SITES_8121
            .iter()
            .any(|(f, _)| *f == "import_idle_lease"),
        "the idle-lease import is not in the census, so #8121's own route is \
         unpinned by the guard that exists to pin the routes"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/nat");
    let mut files = Vec::new();
    crate::afxdp::worker_queue::tests::afxdp_rs_files(&root, &mut files);
    assert!(
        files.len() > 5,
        "the source walk found {} files under src/nat — the pattern or the root \
         is wrong, and the census above is scanning nothing",
        files.len()
    );
}

// --- #8615: the DISPLAY export ------------------------------------------
//
// Read these against `a_lease_with_live_flows_is_not_exported_8121` above. That
// cell asserts the SYNC export omits a live-flow lease and is still correct —
// #8615 does not relax it. These assert the DISPLAY export includes exactly the
// population that one excludes, on the same fixture, so the two answers are
// visibly different reads of one allocator rather than two notions of liveness
// that could drift.

/// The defect #8615 is about: a binding with LIVE flows is invisible to the
/// SHOW table because the only export available was the sync one.
#[test]
fn the_display_export_carries_a_lease_the_sync_export_omits_8615() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let busy = flow("10.0.61.50", 40000);
    let idle = flow("10.0.61.51", 40001);
    let held = mint_persistent(&active, &addrs, busy, 1_000);
    let released = mint_persistent(&active, &addrs, idle, 1_000);
    assert!(active.release_flow(idle, released, 2_000, NatHolder::Untracked));

    // CONTROL, and it is the whole comparison: the sync export sees one lease.
    assert_eq!(
        active.export_idle_leases(3_000).len(),
        1,
        "control: the sync export must still omit the busy lease — #8615 does \
         not relax design rule 1, it adds a second read"
    );

    let shown = active.export_display_leases(3_000);
    assert_eq!(
        shown.len(),
        2,
        "the DISPLAY export must carry BOTH the idle lease and the one with \
         live flows. Seeing only the idle one is the #8615 defect: an operator \
         running `show security nat source persistent-nat-table` during traffic \
         is told there are no bindings"
    );
    let busy_row = shown
        .iter()
        .find(|r| r.translated_port == held.port && r.translated_ip == held.ip)
        .expect("the busy lease must appear in the display export");
    assert_eq!(
        busy_row.active_flows, 1,
        "the display record must carry the live-flow COUNT — that field is the \
         entire reason this record type exists separately from the sync one"
    );
}

/// The display filter is the ALLOCATOR's own reuse predicate
/// (`active_flows > 0 || expires_at_ns > now_ns`), so the table answers exactly
/// "which bindings will this node reuse".
///
/// The load-bearing half is the FIRST clause. A lease with live flows whose
/// deadline has passed is still honoured — `expires_at_ns` is written at the
/// last reuse and is NOT refreshed per packet — so filtering on the deadline
/// alone would hide precisely the long-lived sessions an operator is most
/// likely to be looking at.
#[test]
fn the_display_export_keeps_a_busy_lease_past_its_stale_deadline_8615() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let busy = flow("10.0.61.50", 40000);
    let held = mint_persistent(&active, &addrs, busy, 1_000);

    // Far beyond the 300s persistence timeout stamped at mint. The flow never
    // closed, so nothing refreshed the deadline.
    let long_after = 1_000 + 600 * 1_000_000_000u64;

    // CONTROL: the deadline really is stale, so the assertion below is not
    // true for free.
    assert!(
        active.export_idle_leases(long_after).is_empty(),
        "control: by this clock the lease is past its deadline, so a \
         deadline-only filter drops it"
    );

    let shown = active.export_display_leases(long_after);
    assert_eq!(
        shown.len(),
        1,
        "a lease with live flows must stay in the display export past its \
         stale deadline, because the allocator still honours it \
         (`reuse_existing_lease_locked`: active_flows > 0 || expires > now). \
         Dropping it here would hide the longest-lived sessions — the ones an \
         operator is most likely to be asking about"
    );
    assert_eq!(shown[0].translated_port, held.port);
    assert_eq!(
        shown[0].remaining_ns, 0,
        "and its RAW remaining is 0, which is why the presentation layer must \
         not render it as a countdown — see persistentNatBindingsFromDisplayLeases"
    );
}

/// A lease that is genuinely finished — no flows AND past its deadline — is not
/// shown. Without this the display filter could be "everything", which would
/// pass both cells above while reporting bindings this node will not honour.
#[test]
fn the_display_export_drops_a_lease_that_is_idle_and_expired_8615() {
    let addrs = pool();
    let active = PortAllocator::new(1, 1024, 65535);
    let done = flow("10.0.61.50", 40000);
    let minted = mint_persistent(&active, &addrs, done, 1_000);
    assert!(active.release_flow(done, minted, 2_000, NatHolder::Untracked));

    let long_after = 2_000 + 600 * 1_000_000_000u64;
    assert!(
        active.export_display_leases(long_after).is_empty(),
        "an idle, expired lease must NOT be displayed — the allocator will not \
         reuse it, so showing it would report a binding that does not exist. A \
         display export with no filter at all passes the two cells above and \
         fails here"
    );
}
/// Peer-provided lifetimes are bounded by the matching local rule timeout even
/// when the record itself carries the maximum integer values.
#[test]
fn an_imported_lifetime_is_clamped_to_the_local_timeout_10789_f4() {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);
    let f = flow("10.0.61.50", 40000);
    let mut rec = idle_record_for(f, IpAddr::V4(addrs[0]), 2048, false, None);
    rec.remaining_ns = u64::MAX;
    rec.timeout_ns = u64::MAX;
    let local_timeout_ns = 30 * 1_000_000_000;
    assert_eq!(
        PortAllocator::new(1, 1024, 65535).import_idle_lease(&rec, &local_pool, 0, 100),
        IdleLeaseImport::SkippedExpired,
        "a direct allocator call with an unconfigured timeout must not \
         synthesize a minimum lifetime"
    );
    let alloc = PortAllocator::new(1, 1024, 65535);

    assert_eq!(
        alloc.import_idle_lease(&rec, &local_pool, local_timeout_ns, 100),
        IdleLeaseImport::Installed
    );
    let shown = alloc.export_display_leases(100);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].remaining_ns, local_timeout_ns);
    assert_eq!(shown[0].timeout_ns, local_timeout_ns);

    let translated = alloc
        .allocate_translation(
            f,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            local_timeout_ns,
            200,
            NatHolder::Untracked,
        )
        .expect("local flow adopts the bounded imported lease");
    assert!(alloc.release_flow(f, translated, 500, NatHolder::Untracked));
    let key = f.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let lease = alloc.debug_live().persistent_by_source[&key];
    assert_eq!(lease.timeout_ns, local_timeout_ns);
    assert_eq!(lease.expires_at_ns, 500 + local_timeout_ns);
    let exported = alloc.export_idle_leases(500);
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].remaining_ns, local_timeout_ns);
    assert_eq!(exported[0].timeout_ns, local_timeout_ns);
}

/// A local reserve is tentative until the production admission path accepts it.
/// For both allocator modes, the imported origin, expiry, and re-arm timeout
/// remain peer-owned until a successful release completes.
#[test]
fn rollback_preserves_imported_origin_and_timeout_for_both_modes_10789_f4() {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);
    let local_timeout_ns = TIMEOUT_NS;
    let imported_timeout_ns = 60 * 1_000_000_000;
    let remaining_ns = 45 * 1_000_000_000;

    let pat_flow = flow("10.0.61.50", 40000);
    let mut pat_rec = idle_record_for(
        pat_flow,
        IpAddr::V4(addrs[0]),
        2048,
        false,
        Some((pat_flow.dst_ip, pat_flow.dst_port)),
    );
    pat_rec.remaining_ns = remaining_ns;
    pat_rec.timeout_ns = imported_timeout_ns;
    let pat = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        pat.import_idle_lease(&pat_rec, &local_pool, local_timeout_ns, 1_000),
        IdleLeaseImport::Installed
    );
    let pat_tuple = pat
        .allocate_translation(
            pat_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::TargetHostPort,
            local_timeout_ns,
            2_000,
            NatHolder::Untracked,
        )
        .expect("the local flow must tentatively adopt the imported PAT lease");
    assert_eq!(
        pat.debug_live().persistent_by_source
            [&pat_flow.persistent_source_key(PersistentNatPermit::TargetHostPort)]
            .timeout_ns,
        imported_timeout_ns
    );
    assert!(pat.rollback_flow(pat_flow, pat_tuple, 3_000, NatHolder::Untracked));
    let pat_lease = pat.debug_live().persistent_by_source
        [&pat_flow.persistent_source_key(PersistentNatPermit::TargetHostPort)];
    assert!(pat_lease.imported);
    assert_eq!(pat_lease.timeout_ns, imported_timeout_ns);
    assert_eq!(pat_lease.expires_at_ns, 1_000 + remaining_ns);
    assert!(pat.export_idle_leases(4_000).is_empty());

    let address_flow = flow("10.0.61.51", 40001);
    let mut address_rec = idle_record_for(
        address_flow,
        IpAddr::V4(addrs[0]),
        address_flow.src_port,
        true,
        Some((address_flow.dst_ip, address_flow.dst_port)),
    );
    address_rec.remaining_ns = remaining_ns;
    address_rec.timeout_ns = imported_timeout_ns;
    let address_only = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        address_only.import_idle_lease(&address_rec, &local_pool, local_timeout_ns, 1_000),
        IdleLeaseImport::Installed
    );
    let address_tuple = address_only
        .reserve_address_only_persistent(
            address_flow,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            PersistentNatPermit::TargetHostPort,
            local_timeout_ns,
            2_000,
            NatHolder::Untracked,
        )
        .expect("the local flow must tentatively adopt the imported address-only lease");
    assert_eq!(
        address_only.debug_live().persistent_by_source
            [&address_flow.persistent_source_key(PersistentNatPermit::TargetHostPort)]
            .timeout_ns,
        imported_timeout_ns
    );
    assert!(address_only.rollback_flow(address_flow, address_tuple, 3_000, NatHolder::Untracked));
    let address_lease = address_only.debug_live().persistent_by_source
        [&address_flow.persistent_source_key(PersistentNatPermit::TargetHostPort)];
    assert!(address_lease.imported);
    assert_eq!(address_lease.timeout_ns, imported_timeout_ns);
    assert_eq!(address_lease.expires_at_ns, 1_000 + remaining_ns);
    assert!(address_only.export_idle_leases(4_000).is_empty());
}

fn assert_pat_rollback_with_concurrent_synced_flow(synced_completes_first: bool) {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);
    let source = flow("10.0.61.60", 40060);
    let local = SourceNatFlowKey {
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        ..source
    };
    let synced = SourceNatFlowKey {
        dst_ip: "9.9.9.9".parse().unwrap(),
        dst_port: 443,
        ..source
    };
    let peer_timeout_ns = 60 * 1_000_000_000;
    let rec = {
        let mut rec = idle_record_for(source, IpAddr::V4(addrs[0]), 2048, false, None);
        rec.remaining_ns = 45 * 1_000_000_000;
        rec.timeout_ns = peer_timeout_ns;
        rec
    };
    let alloc = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        alloc.import_idle_lease(&rec, &local_pool, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let key = source.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let local_tuple = alloc
        .allocate_translation(
            local,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            2_000,
            NatHolder::Untracked,
        )
        .expect("local 0 -> 1 reserve adopts imported PAT identity");
    let tentative = alloc.debug_live().persistent_by_source[&key];
    assert!(tentative.imported);
    assert_eq!(tentative.timeout_ns, peer_timeout_ns);

    let peer_tuple = TranslatedTuple {
        ip: rec.translated_ip,
        port: rec.translated_port,
    };
    assert!(alloc.reserve_flow_maybe_persistent(
        synced,
        peer_tuple,
        0,
        false,
        3_000,
        NatHolder::Untracked,
        Some((key, TIMEOUT_NS)),
        false,
        &mut None,
    ));
    assert_eq!(
        alloc.debug_live().persistent_by_source[&key].active_flows,
        2
    );
    if synced_completes_first {
        assert!(alloc.release_flow(synced, peer_tuple, 4_000, NatHolder::Untracked));
        let between = alloc.debug_live().persistent_by_source[&key];
        assert!(between.imported, "synced completion must not promote PAT");
        assert_eq!(between.active_flows, 1);
        assert_eq!(between.timeout_ns, peer_timeout_ns);
        assert!(alloc.rollback_flow(local, local_tuple, 5_000, NatHolder::Untracked));
    } else {
        assert!(alloc.rollback_flow(local, local_tuple, 4_000, NatHolder::Untracked));
        let between = alloc.debug_live().persistent_by_source[&key];
        assert!(
            between.imported,
            "rollback with a peer flow active must preserve origin"
        );
        assert_eq!(between.active_flows, 1);
        assert_eq!(between.timeout_ns, peer_timeout_ns);
        assert!(alloc.release_flow(synced, peer_tuple, 5_000, NatHolder::Untracked));
    }
    let idle = alloc.debug_live().persistent_by_source[&key];
    assert!(idle.imported);
    assert_eq!(idle.active_flows, 0);
    assert_eq!(idle.timeout_ns, peer_timeout_ns);
    assert_eq!(idle.expires_at_ns, 5_000 + peer_timeout_ns);
    assert!(alloc.export_idle_leases(5_001).is_empty());
    assert_eq!(alloc.export_display_leases(5_001).len(), 1);
}

fn assert_address_only_rollback_with_concurrent_synced_flow(synced_completes_first: bool) {
    let addrs = pool();
    let local_pool = ipv4_pool(&addrs);
    let source = flow("10.0.61.61", 40061);
    let local = SourceNatFlowKey {
        dst_ip: "1.1.1.1".parse().unwrap(),
        dst_port: 443,
        ..source
    };
    let synced = SourceNatFlowKey {
        dst_ip: "9.9.9.9".parse().unwrap(),
        dst_port: 443,
        ..source
    };
    let peer_timeout_ns = 60 * 1_000_000_000;
    let rec = {
        let mut rec = idle_record_for(source, IpAddr::V4(addrs[0]), source.src_port, true, None);
        rec.remaining_ns = 45 * 1_000_000_000;
        rec.timeout_ns = peer_timeout_ns;
        rec
    };
    let alloc = PortAllocator::new(1, 1024, 65535);
    assert_eq!(
        alloc.import_idle_lease(&rec, &local_pool, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let key = source.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let local_tuple = alloc
        .reserve_address_only_persistent(
            local,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            PersistentNatPermit::AnyRemoteHost,
            TIMEOUT_NS,
            2_000,
            NatHolder::Untracked,
        )
        .expect("local 0 -> 1 reserve adopts imported address-only identity");
    let tentative = alloc.debug_live().persistent_by_source[&key];
    assert!(tentative.imported);
    assert_eq!(tentative.timeout_ns, peer_timeout_ns);

    let peer_tuple = TranslatedTuple {
        ip: rec.translated_ip,
        port: rec.translated_port,
    };
    let synced_tuple = alloc
        .reserve_address_only_maybe_persistent(
            synced,
            rec.translated_ip,
            0,
            3_000,
            NatHolder::Untracked,
            Some((key, TIMEOUT_NS)),
            false,
            &mut None,
        )
        .expect("synced flow joins imported address-only lease");
    assert_eq!(synced_tuple, peer_tuple);
    assert_eq!(
        alloc.debug_live().persistent_by_source[&key].active_flows,
        2
    );
    if synced_completes_first {
        assert!(alloc.release_flow(synced, synced_tuple, 4_000, NatHolder::Untracked));
        let between = alloc.debug_live().persistent_by_source[&key];
        assert!(
            between.imported,
            "synced completion must not promote address-only"
        );
        assert_eq!(between.active_flows, 1);
        assert_eq!(between.timeout_ns, peer_timeout_ns);
        assert!(alloc.rollback_flow(local, local_tuple, 5_000, NatHolder::Untracked));
    } else {
        assert!(alloc.rollback_flow(local, local_tuple, 4_000, NatHolder::Untracked));
        let between = alloc.debug_live().persistent_by_source[&key];
        assert!(
            between.imported,
            "rollback with a peer flow active must preserve origin"
        );
        assert_eq!(between.active_flows, 1);
        assert_eq!(between.timeout_ns, peer_timeout_ns);
        assert!(alloc.release_flow(synced, synced_tuple, 5_000, NatHolder::Untracked));
    }
    let idle = alloc.debug_live().persistent_by_source[&key];
    assert!(idle.imported);
    assert_eq!(idle.active_flows, 0);
    assert_eq!(idle.timeout_ns, peer_timeout_ns);
    assert_eq!(idle.expires_at_ns, 5_000 + peer_timeout_ns);
    assert!(alloc.export_idle_leases(5_001).is_empty());
    assert_eq!(alloc.export_display_leases(5_001).len(), 1);
}

struct TwoLocalLeaseFixture {
    allocator: PortAllocator,
    addresses: [Ipv4Addr; 3],
    source: SourceNatFlowKey,
    first: SourceNatFlowKey,
    second: SourceNatFlowKey,
    imported_expires_at_ns: u64,
}

fn two_local_lease_fixture(address_only: bool) -> TwoLocalLeaseFixture {
    const IMPORTED_AT_NS: u64 = 1_000;
    const PEER_REMAINING_NS: u64 = 45_000_000_000;
    const PEER_TIMEOUT_NS: u64 = 60_000_000_000;
    const PEER_PORT: u16 = 51_010;

    let addresses = pool();
    let source = flow("10.0.61.70", 40_070);
    let first = SourceNatFlowKey {
        dst_ip: "1.1.1.1".parse().unwrap(),
        ..source
    };
    let second = SourceNatFlowKey {
        dst_ip: "9.9.9.9".parse().unwrap(),
        ..source
    };
    let translated_port = if address_only {
        source.src_port
    } else {
        PEER_PORT
    };
    let mut record = idle_record_for(
        source,
        IpAddr::V4(addresses[1]),
        translated_port,
        address_only,
        None,
    );
    record.remaining_ns = PEER_REMAINING_NS;
    record.timeout_ns = PEER_TIMEOUT_NS;
    let allocator = PortAllocator::new(addresses.len(), 1024, 65535);
    assert_eq!(
        allocator.import_idle_lease(&record, &ipv4_pool(&addresses), TIMEOUT_NS, IMPORTED_AT_NS),
        IdleLeaseImport::Installed
    );
    TwoLocalLeaseFixture {
        allocator,
        addresses,
        source,
        first,
        second,
        imported_expires_at_ns: IMPORTED_AT_NS + PEER_REMAINING_NS,
    }
}

fn reserve_two_local_fixture_flow(
    fixture: &TwoLocalLeaseFixture,
    flow: SourceNatFlowKey,
    address_only: bool,
    now_ns: u64,
    holder: NatHolder,
) -> TranslatedTuple {
    if address_only {
        fixture
            .allocator
            .reserve_address_only_persistent(
                flow,
                PoolAddressFamily::V4(&fixture.addresses),
                0,
                false,
                PersistentNatPermit::AnyRemoteHost,
                TIMEOUT_NS,
                now_ns,
                holder,
            )
            .expect("local address-only flow adopts the imported lease")
    } else {
        fixture
            .allocator
            .allocate_translation(
                flow,
                PoolAddressFamily::V4(&fixture.addresses),
                0,
                false,
                true,
                PersistentNatPermit::AnyRemoteHost,
                TIMEOUT_NS,
                now_ns,
                holder,
            )
            .expect("local PAT flow adopts the imported lease")
    }
}

fn assert_two_local_tentatives(address_only: bool, complete_one: bool) {
    let fixture = two_local_lease_fixture(address_only);
    let key = fixture
        .source
        .persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let first_tuple = reserve_two_local_fixture_flow(
        &fixture,
        fixture.first,
        address_only,
        2_000,
        NatHolder::Worker(0),
    );
    let second_tuple = reserve_two_local_fixture_flow(
        &fixture,
        fixture.second,
        address_only,
        3_000,
        NatHolder::Worker(1),
    );
    assert_eq!(first_tuple, second_tuple);
    let active = fixture.allocator.debug_live().persistent_by_source[&key];
    assert!(active.imported);
    assert_eq!(active.active_flows, 2);
    assert_eq!(active.timeout_ns, 60_000_000_000);
    assert!(!active.activation_saw_completion);

    if complete_one {
        assert!(fixture.allocator.release_flow(
            fixture.first,
            first_tuple,
            4_000,
            NatHolder::Worker(0)
        ));
        let after_completion = fixture.allocator.debug_live().persistent_by_source[&key];
        assert!(!after_completion.imported);
        assert_eq!(after_completion.active_flows, 1);
        assert_eq!(after_completion.timeout_ns, TIMEOUT_NS);
        assert!(after_completion.activation_saw_completion);
        assert!(fixture.allocator.rollback_flow(
            fixture.second,
            second_tuple,
            5_000,
            NatHolder::Worker(1)
        ));
        let idle = fixture.allocator.debug_live().persistent_by_source[&key];
        assert!(!idle.imported);
        assert_eq!(idle.active_flows, 0);
        assert_eq!(idle.completed_flows, 1);
        assert_eq!(idle.timeout_ns, TIMEOUT_NS);
        assert_eq!(idle.expires_at_ns, 5_000 + TIMEOUT_NS);
        assert_eq!(fixture.allocator.export_idle_leases(5_001).len(), 1);
    } else {
        assert!(fixture.allocator.rollback_flow(
            fixture.first,
            first_tuple,
            4_000,
            NatHolder::Worker(0)
        ));
        assert!(fixture.allocator.rollback_flow(
            fixture.second,
            second_tuple,
            5_000,
            NatHolder::Worker(1)
        ));
        let idle = fixture.allocator.debug_live().persistent_by_source[&key];
        assert!(idle.imported);
        assert_eq!(idle.active_flows, 0);
        assert_eq!(idle.completed_flows, 0);
        assert_eq!(idle.timeout_ns, 60_000_000_000);
        assert_eq!(idle.expires_at_ns, fixture.imported_expires_at_ns);
        assert!(fixture.allocator.export_idle_leases(5_001).is_empty());
        let display = fixture.allocator.export_display_leases(5_001);
        assert_eq!(display.len(), 1);
        assert_eq!(
            display[0].remaining_ns,
            fixture.imported_expires_at_ns - 5_001
        );
        assert_eq!(display[0].timeout_ns, 60_000_000_000);
    }
}

#[test]
fn multiple_local_tentatives_preserve_or_promote_imported_lease_10789_f4() {
    for address_only in [false, true] {
        assert_two_local_tentatives(address_only, false);
        assert_two_local_tentatives(address_only, true);
    }
}

#[test]
fn imported_zero_to_one_rollback_preserves_origin_across_synced_completion_10789_f4() {
    for synced_completes_first in [false, true] {
        assert_pat_rollback_with_concurrent_synced_flow(synced_completes_first);
        assert_address_only_rollback_with_concurrent_synced_flow(synced_completes_first);
    }
}

/// Clearing revokes idle allocator leases, returns their occupancy, and
/// prevents a lease exported before the clear from being re-imported (#10784).
#[test]
fn clearing_idle_leases_revokes_allocator_and_stale_ha_import_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let decoy = flow("10.0.61.51", 40001);
    let client = flow("10.0.61.50", 40000);
    let decoy_translation = mint_persistent(&allocator, &addrs, decoy, 1_000);
    let original = mint_persistent(&allocator, &addrs, client, 1_000);
    assert!(
        allocator.debug_is_port_occupied(
            addrs.iter().position(|ip| *ip == original.ip).unwrap(),
            original.port,
        ),
        "control: the target translation must own its allocator port before clear"
    );
    assert!(allocator.release_flow(client, original, 2_000, NatHolder::Untracked));
    assert!(allocator.release_flow(decoy, decoy_translation, 2_000, NatHolder::Untracked));
    let stale = allocator
        .export_idle_leases(3_000)
        .into_iter()
        .find(|lease| lease.src_ip == client.src_ip && lease.src_port == client.src_port)
        .expect("control: the target idle lease must be exportable before clear");

    assert_eq!(allocator.clear_persistent_leases(3_000), 2);
    assert!(allocator.export_idle_leases(3_001).is_empty());
    assert!(allocator.export_display_leases(3_001).is_empty());
    let original_index = addrs.iter().position(|ip| *ip == original.ip).unwrap();
    assert!(
        !allocator.debug_is_port_occupied(original_index, original.port),
        "an idle PAT lease clear must return the port occupancy token"
    );
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), TIMEOUT_NS, 3_001),
        IdleLeaseImport::SkippedExisting,
        "a pre-clear HA export must not reinstall a revoked mapping"
    );

    let replacement = mint_persistent(&allocator, &addrs, client, 4_000);
    assert_ne!(
        (replacement.ip, replacement.port),
        (original.ip, original.port),
        "a post-clear allocation must not reuse the revoked translation merely \
         because the old lease survived in the allocator"
    );
    assert_eq!(allocator.export_display_leases(4_000).len(), 1);
}
/// Snapshot refreshes reclaim expired per-key and global clear fences without
/// needing a later clear to trigger pruning (#11486).
#[test]
fn lease_exports_prune_expired_clear_fences_11486() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let original = mint_persistent(&allocator, &addrs, client, 1_000);
    assert!(allocator.release_flow(client, original, 2_000, NatHolder::Untracked));
    let stale = allocator.export_idle_leases(3_000).remove(0);
    let clear_ns = 3_000_u64;
    assert_eq!(allocator.clear_persistent_leases(clear_ns), 1);
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), TIMEOUT_NS, clear_ns + 1),
        IdleLeaseImport::SkippedExisting
    );

    let expires_at = clear_ns
        .saturating_add(super::allocator::PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS)
        .saturating_add(1);
    assert!(allocator.export_idle_leases(expires_at).is_empty());
    assert!(allocator.debug_live().revoked_persistent.is_empty());
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), TIMEOUT_NS, expires_at),
        IdleLeaseImport::Installed,
        "snapshot pruning should expire the short replay fence without a second clear"
    );
}

/// A successful fresh same-key lease must not erase the original clear fence:
/// if that replacement expires and GC removes it before T+60s, a delayed
/// pre-clear import is still rejected (#10784).
#[test]
fn clear_fence_survives_expired_same_key_replacement_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let min_timeout_ns = super::allocator::MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS;
    let original =
        mint_persistent_with_timeout(&allocator, &addrs, client, min_timeout_ns, 1_000_000_000);
    assert!(allocator.release_flow(client, original, 2_000_000_000, NatHolder::Untracked));
    let stale = allocator
        .export_idle_leases(2_500_000_000)
        .into_iter()
        .find(|lease| lease.src_ip == client.src_ip && lease.src_port == client.src_port)
        .expect("control: pre-clear lease must be captured");

    assert_eq!(allocator.clear_persistent_leases(3_000_000_000), 1);
    let key = client.persistent_source_key(PersistentNatPermit::TargetHostPort);
    let replacement =
        mint_persistent_with_timeout(&allocator, &addrs, client, min_timeout_ns, 3_100_000_000);
    assert!(allocator.release_flow(client, replacement, 3_200_000_000, NatHolder::Untracked));
    assert_eq!(allocator.debug_gc_expired_chunked(5_000_000_000, 8), 1);
    let live = allocator.debug_live();
    assert!(!live.persistent_by_source.contains_key(&key));
    assert_eq!(
        live.revoked_persistent.get(&key).copied(),
        Some(63_000_000_000),
        "a successful replacement must not delete or restart the original clear deadline"
    );
    drop(live);
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), min_timeout_ns, 5_100_000_000),
        IdleLeaseImport::SkippedExisting
    );
    assert!(allocator.debug_live().persistent_by_source.is_empty());
}

/// Address-only local replacement expiry must preserve the same pre-clear
/// import fence as PAT replacement expiry (#10784).
#[test]
fn clear_fence_survives_expired_address_only_replacement_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(addrs.len(), 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let min_timeout_ns = super::allocator::MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS;
    let original = allocator
        .reserve_address_only_persistent(
            client,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            PersistentNatPermit::AnyRemoteHost,
            min_timeout_ns,
            1_000_000_000,
            NatHolder::Untracked,
        )
        .expect("a fresh address-only lease must succeed");
    assert!(allocator.release_flow(client, original, 2_000_000_000, NatHolder::Untracked));
    let stale = allocator
        .export_idle_leases(2_500_000_000)
        .into_iter()
        .find(|lease| lease.src_ip == client.src_ip && lease.src_port == client.src_port)
        .expect("control: pre-clear address-only lease must be captured");
    assert!(stale.address_only);

    assert_eq!(allocator.clear_persistent_leases(3_000_000_000), 1);
    let key = client.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let replacement = allocator
        .reserve_address_only_persistent(
            client,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            PersistentNatPermit::AnyRemoteHost,
            min_timeout_ns,
            3_100_000_000,
            NatHolder::Untracked,
        )
        .expect("fresh local address-only replacement must succeed");
    assert!(allocator.release_flow(client, replacement, 3_200_000_000, NatHolder::Untracked));
    assert_eq!(allocator.debug_gc_expired_chunked(5_000_000_000, 8), 1);

    let live = allocator.debug_live();
    assert!(!live.persistent_by_source.contains_key(&key));
    assert_eq!(
        live.revoked_persistent.get(&key).copied(),
        Some(63_000_000_000),
        "address-only replacement must preserve the original clear deadline"
    );
    drop(live);
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), min_timeout_ns, 5_100_000_000),
        IdleLeaseImport::SkippedExisting
    );
    assert!(allocator.debug_live().persistent_by_source.is_empty());
}

/// A stale PAT session cannot reactivate an expired replacement that is still
/// present in the map but has not yet been visited by GC (#10784 round 2).
#[test]
fn expired_pat_replacement_is_not_reactivated_by_stale_synced_session_10784() {
    let addrs = [pool()[0]];
    let allocator = PortAllocator::new(1, 1024, 1024);
    let client = flow("10.0.61.50", 40000);
    let original = mint_persistent_any_remote(&allocator, &addrs, client, 1_000_000_000);
    let stale_flow = client;
    let stale_tuple = original;
    assert!(allocator.release_flow(client, original, 2_000_000_000, NatHolder::Untracked));
    assert_eq!(allocator.clear_persistent_leases(3_000_000_000), 1);

    let min_timeout_ns = super::allocator::MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS;
    let replacement = allocator
        .allocate_translation(
            client,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            true,
            PersistentNatPermit::AnyRemoteHost,
            min_timeout_ns,
            3_100_000_000,
            NatHolder::Untracked,
        )
        .expect("fresh same-key replacement must succeed");
    assert_eq!(
        replacement, stale_tuple,
        "single-port pool fixes the stale tuple"
    );
    assert!(allocator.release_flow(client, replacement, 4_200_000_000, NatHolder::Untracked));
    let key = client.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let expiry = 5_200_000_000;
    {
        let live = allocator.debug_live();
        let lease = live.persistent_by_source.get(&key).unwrap();
        assert!(!lease.revoked);
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.expires_at_ns, expiry);
        assert!(live.lease_expirations.contains(&(expiry, key)));
        assert!(live.lease_expirations_by_addr[0].contains(&(expiry, key)));
    }

    let mut previous_snapshot = None;
    assert!(
        !allocator.reserve_flow_maybe_persistent(
            stale_flow,
            stale_tuple,
            0,
            false,
            5_300_000_000,
            NatHolder::Untracked,
            Some((key, TIMEOUT_NS)),
            false,
            &mut previous_snapshot,
        ),
        "the stale tuple is still occupied, so it must not attach to the expired lease"
    );
    let live = allocator.debug_live();
    let lease = live.persistent_by_source.get(&key).unwrap();
    assert_eq!(
        lease.active_flows, 0,
        "stale sync must not reactivate the lease"
    );
    assert_eq!(lease.expires_at_ns, expiry);
    assert!(live.lease_expirations.contains(&(expiry, key)));
    assert!(live.lease_expirations_by_addr[0].contains(&(expiry, key)));
    assert!(allocator.debug_is_port_occupied(0, stale_tuple.port));
}

/// The address-only synced path has the same stale replacement race, although
/// its wire tuple does not own a PAT occupancy bit (#10784 round 2).
#[test]
fn expired_address_only_replacement_is_not_reactivated_by_stale_synced_session_10784() {
    let addrs = [pool()[0]];
    let allocator = PortAllocator::new(1, 1024, 1024);
    let client = flow("10.0.61.50", 40000);
    let original =
        mint_persistent_address_only_any_remote(&allocator, &addrs, client, 1_000_000_000);
    let stale_flow = client;
    let stale_tuple = original;
    assert!(allocator.release_flow(client, original, 2_000_000_000, NatHolder::Untracked));
    assert_eq!(allocator.clear_persistent_leases(3_000_000_000), 1);

    let min_timeout_ns = super::allocator::MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS;
    let replacement = allocator
        .reserve_address_only_persistent(
            client,
            PoolAddressFamily::V4(&addrs),
            0,
            false,
            PersistentNatPermit::AnyRemoteHost,
            min_timeout_ns,
            3_100_000_000,
            NatHolder::Untracked,
        )
        .expect("fresh same-key address-only replacement must succeed");
    assert_eq!(replacement, stale_tuple);
    assert!(allocator.release_flow(client, replacement, 4_200_000_000, NatHolder::Untracked));
    let key = client.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let expiry = 5_200_000_000;
    {
        let live = allocator.debug_live();
        let lease = live.persistent_by_source.get(&key).unwrap();
        assert!(lease.address_only);
        assert!(!lease.revoked);
        assert_eq!(lease.active_flows, 0);
        assert_eq!(lease.expires_at_ns, expiry);
        assert!(live.lease_expirations.contains(&(expiry, key)));
        assert!(live.lease_expirations_by_addr[0].contains(&(expiry, key)));
    }

    let mut previous_snapshot = None;
    assert_eq!(
        allocator.reserve_address_only_maybe_persistent(
            stale_flow,
            stale_tuple.ip,
            0,
            5_300_000_000,
            NatHolder::Untracked,
            Some((key, TIMEOUT_NS)),
            false,
            &mut previous_snapshot,
        ),
        Ok(stale_tuple)
    );
    let live = allocator.debug_live();
    let lease = live.persistent_by_source.get(&key).unwrap();
    assert_eq!(
        lease.active_flows, 0,
        "stale sync must not reactivate the lease"
    );
    assert_eq!(lease.expires_at_ns, expiry);
    assert!(live.lease_expirations.contains(&(expiry, key)));
    assert!(live.lease_expirations_by_addr[0].contains(&(expiry, key)));
}

/// A clear on an empty receiver still fences a pre-clear batch for an unknown
/// key; per-key tombstones alone cannot cover import ordering (#10784).
#[test]
fn clear_fences_preclear_import_for_unknown_key_10784() {
    let addrs = pool();
    let source = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let translated = mint_persistent(&source, &addrs, client, 1_000_000_000);
    assert!(source.release_flow(client, translated, 2_000_000_000, NatHolder::Untracked));
    let stale = source
        .export_idle_leases(2_500_000_000)
        .into_iter()
        .next()
        .expect("control: source must have a pre-clear idle export");

    let receiver = PortAllocator::new(1, 1024, 65535);
    assert_eq!(receiver.clear_persistent_leases(3_000_000_000), 0);
    assert_eq!(
        receiver.import_idle_lease(&stale, &ipv4_pool(&addrs), TIMEOUT_NS, 3_100_000_000),
        IdleLeaseImport::SkippedExisting
    );
    assert!(receiver.debug_live().persistent_by_source.is_empty());
    assert_eq!(
        receiver.import_idle_lease(&stale, &ipv4_pool(&addrs), TIMEOUT_NS, 63_000_000_001,),
        IdleLeaseImport::Installed,
        "the batch-wide barrier ends at the documented replay horizon"
    );
}

/// Active leases keep their occupied tuple until their existing flows drain;
/// the drain expires the shell rather than rearming persistence (#10784).
#[test]
fn clearing_live_lease_drains_without_reuse_or_port_leak_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let original = mint_persistent_any_remote(&allocator, &addrs, client, 1_000);
    let original_index = addrs.iter().position(|ip| *ip == original.ip).unwrap();

    assert_eq!(allocator.clear_persistent_leases(2_000), 1);
    assert_eq!(
        allocator.clear_persistent_leases(2_000),
        0,
        "repeated clear reports only newly revoked leases"
    );
    assert!(
        allocator.debug_is_port_occupied(original_index, original.port),
        "a live flow must keep its translated tuple occupied during clear"
    );
    assert!(allocator.export_display_leases(2_000).is_empty());

    let mut new_flow = flow("10.0.61.50", 40000);
    new_flow.dst_ip = "1.1.1.1".parse().unwrap();
    let unpinned = mint_persistent_any_remote(&allocator, &addrs, new_flow, 2_000);
    assert_ne!(
        (unpinned.ip, unpinned.port),
        (original.ip, original.port),
        "a new flow must not reuse a mapping after the operator revoked it"
    );

    assert!(allocator.release_flow(client, original, 3_000, NatHolder::Untracked));
    assert!(allocator.release_flow(new_flow, unpinned, 3_000, NatHolder::Untracked));
    let _other = mint_persistent_any_remote(&allocator, &addrs, flow("10.0.61.52", 40002), 4_000);
    assert!(
        !allocator.debug_is_port_occupied(original_index, original.port),
        "the final holder release must make the revoked tuple reclaimable"
    );
    let replacement = mint_persistent_any_remote(&allocator, &addrs, client, 5_000);
    assert_ne!(
        (replacement.ip, replacement.port),
        (original.ip, original.port),
        "the first new mapping after drain must be minted afresh"
    );
}

/// A target revoked active lease is the ninth expired entry, behind eight
/// earlier idle expiries. Same-key allocation must retire its drained shell
/// and free its PAT bit even when the allocation GC budget is exhausted (#10784).
#[test]
fn drained_clear_shell_overwrite_releases_pat_port_after_gc_budget_10784() {
    let addrs = [pool()[0]];
    let allocator = PortAllocator::new(1, 1024, 1043);
    let min_timeout_ns = super::allocator::MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS;

    // Advance the cursor without a release-triggered GC, so the same-key mint
    // after drain cannot immediately claim the shell's old port.
    allocator.debug_set_cursor(0, 1);

    let client = flow("10.0.61.50", 40000);
    let original =
        mint_persistent_with_timeout(&allocator, &addrs, client, min_timeout_ns, 1_200_000_000);
    assert_eq!(original.port, 1025, "control: cursor must skip port 1024");
    assert_eq!(allocator.clear_persistent_leases(2_000_000_000), 1);

    for i in 0..8 {
        let src = format!("10.0.62.{}", i + 1);
        let decoy = flow(&src, 41000 + i as u16);
        let translated =
            mint_persistent_with_timeout(&allocator, &addrs, decoy, min_timeout_ns, 2_100_000_000);
        assert!(allocator.release_flow(decoy, translated, 2_200_000_000, NatHolder::Untracked));
    }
    assert!(allocator.release_flow(client, original, 4_000_000_000, NatHolder::Untracked));
    let expired = allocator.debug_live();
    assert_eq!(
        expired.lease_expirations.len(),
        9,
        "control: eight earlier decoys and the target shell must await allocation GC"
    );
    assert!(
        expired
            .lease_expirations
            .iter()
            .take(8)
            .all(|(expires_at_ns, _)| *expires_at_ns == 3_200_000_000),
        "control: the eight decoys must precede the target in expiry order"
    );
    assert_eq!(
        expired
            .lease_expirations
            .iter()
            .last()
            .map(|(expires_at_ns, _)| *expires_at_ns),
        Some(4_000_000_000),
        "control: the drained target shell must be the ninth expired entry"
    );
    drop(expired);

    let replacement =
        mint_persistent_with_timeout(&allocator, &addrs, client, min_timeout_ns, 4_000_000_000);
    assert_ne!(replacement.port, original.port);
    assert!(
        !allocator.debug_is_port_occupied(0, original.port),
        "overwriting the drained revoked shell must release its old PAT bit"
    );
    assert_eq!(
        allocator.debug_occupied_count(),
        1,
        "only the fresh replacement lease may own a PAT bit"
    );
    let live = allocator.debug_live();
    assert_eq!(live.persistent_by_source.len(), 1);
    assert!(live.lease_expirations.is_empty());
    assert!(live.lease_expirations_by_addr[0].is_empty());
}

/// Address-only leases share the same clear/tombstone contract as PAT leases,
/// despite owning no translated-port bit (#10784).
#[test]
fn clearing_address_only_lease_blocks_reuse_and_stale_import_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(addrs.len(), 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let original = mint_persistent_address_only_any_remote(&allocator, &addrs, client, 1_000);
    assert_eq!(allocator.export_display_leases(1_000).len(), 1);

    assert_eq!(allocator.clear_persistent_leases(2_000), 1);
    let mut next_flow = client;
    next_flow.dst_ip = "1.1.1.1".parse().unwrap();
    let next = mint_persistent_address_only_any_remote(&allocator, &addrs, next_flow, 2_000);
    assert!(
        allocator.export_display_leases(2_000).is_empty(),
        "a new flow must not reactivate the address-only lease while its old holder drains"
    );
    assert!(allocator.release_flow(client, original, 3_000, NatHolder::Untracked));
    assert!(allocator.release_flow(next_flow, next, 3_000, NatHolder::Untracked));

    let replacement = mint_persistent_address_only_any_remote(&allocator, &addrs, client, 4_000);
    assert_eq!(allocator.export_display_leases(4_000).len(), 1);
    assert_eq!(replacement.port, client.src_port);
}

#[test]
fn clearing_idle_address_only_lease_rejects_stale_import_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(addrs.len(), 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let translated = mint_persistent_address_only_any_remote(&allocator, &addrs, client, 1_000);
    assert!(allocator.release_flow(client, translated, 2_000, NatHolder::Untracked));
    let stale = allocator
        .export_idle_leases(3_000)
        .into_iter()
        .find(|lease| lease.src_ip == client.src_ip && lease.src_port == client.src_port)
        .expect("address-only lease must be exportable before clear");

    assert_eq!(allocator.clear_persistent_leases(3_000), 1);
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), TIMEOUT_NS, 3_001),
        IdleLeaseImport::SkippedExisting
    );
    assert!(allocator.export_display_leases(3_001).is_empty());
}

#[test]
fn cleared_idle_pat_key_cannot_be_recreated_by_synced_session_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let original = mint_persistent_any_remote(&allocator, &addrs, client, 1_000);
    assert!(allocator.release_flow(client, original, 2_000, NatHolder::Untracked));
    assert_eq!(allocator.clear_persistent_leases(3_000), 1);

    let mut synced_flow = client;
    synced_flow.dst_ip = "1.1.1.1".parse().unwrap();
    let key = synced_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let addr_index = addrs
        .iter()
        .position(|ip| IpAddr::V4(*ip) == original.ip)
        .unwrap();
    let mut previous_holders = None;
    assert!(allocator.reserve_flow_maybe_persistent(
        synced_flow,
        original,
        addr_index,
        false,
        4_000,
        NatHolder::Untracked,
        Some((key, TIMEOUT_NS)),
        false,
        &mut previous_holders,
    ));
    assert!(
        allocator.debug_live().persistent_by_source.is_empty(),
        "session sync may reserve the live tuple, but must not recreate the cleared lease"
    );
    assert!(allocator.export_display_leases(4_000).is_empty());
    assert!(allocator.debug_is_port_occupied(addr_index, original.port));
    assert!(allocator.release_flow(synced_flow, original, 5_000, NatHolder::Untracked));
    assert!(!allocator.debug_is_port_occupied(addr_index, original.port));
}

#[test]
fn cleared_idle_address_only_key_cannot_be_recreated_by_synced_session_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(addrs.len(), 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let original = mint_persistent_address_only_any_remote(&allocator, &addrs, client, 1_000);
    assert!(allocator.release_flow(client, original, 2_000, NatHolder::Untracked));
    assert_eq!(allocator.clear_persistent_leases(3_000), 1);

    let mut synced_flow = client;
    synced_flow.dst_ip = "1.1.1.1".parse().unwrap();
    let key = synced_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let addr_index = addrs
        .iter()
        .position(|ip| IpAddr::V4(*ip) == original.ip)
        .unwrap();
    let mut previous_holders = None;
    assert_eq!(
        allocator.reserve_address_only_maybe_persistent(
            synced_flow,
            original.ip,
            addr_index,
            4_000,
            NatHolder::Untracked,
            Some((key, TIMEOUT_NS)),
            false,
            &mut previous_holders,
        ),
        Ok(original)
    );
    assert!(
        allocator.debug_live().persistent_by_source.is_empty(),
        "address-only session sync must not recreate the cleared lease"
    );
    assert!(allocator.export_display_leases(4_000).is_empty());
    assert!(allocator.release_flow(synced_flow, original, 5_000, NatHolder::Untracked));
}

#[test]
fn synced_session_can_join_active_cleared_shell_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let original = mint_persistent_any_remote(&allocator, &addrs, client, 1_000);
    assert_eq!(allocator.clear_persistent_leases(2_000), 1);

    let mut synced_flow = client;
    synced_flow.dst_ip = "1.1.1.1".parse().unwrap();
    let key = synced_flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost);
    let addr_index = addrs
        .iter()
        .position(|ip| IpAddr::V4(*ip) == original.ip)
        .unwrap();
    let mut previous_holders = None;
    assert!(allocator.reserve_flow_maybe_persistent(
        synced_flow,
        original,
        addr_index,
        false,
        3_000,
        NatHolder::Untracked,
        Some((key, TIMEOUT_NS)),
        false,
        &mut previous_holders,
    ));
    assert_eq!(
        allocator
            .debug_live()
            .persistent_by_source
            .get(&key)
            .unwrap()
            .active_flows,
        2,
        "a still-live cleared shell must retain active-session ownership"
    );
    assert!(allocator.export_display_leases(3_000).is_empty());
    assert!(allocator.release_flow(synced_flow, original, 4_000, NatHolder::Untracked));
    assert!(allocator.release_flow(client, original, 5_000, NatHolder::Untracked));
    assert!(allocator.export_display_leases(5_000).is_empty());
}

#[test]
fn cleared_idle_key_expires_after_ha_replay_horizon_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let translated = mint_persistent(&allocator, &addrs, client, 1_000);
    assert!(allocator.release_flow(client, translated, 2_000, NatHolder::Untracked));
    let stale = allocator
        .export_idle_leases(3_000)
        .into_iter()
        .next()
        .expect("control: idle lease must be exportable before clear");
    assert_eq!(allocator.clear_persistent_leases(3_000), 1);
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), TIMEOUT_NS, 3_001),
        IdleLeaseImport::SkippedExisting
    );

    let after_horizon_ns = 60_000_003_001;
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), TIMEOUT_NS, after_horizon_ns),
        IdleLeaseImport::Installed,
        "after the documented replay horizon, the allocator stops retaining the tombstone"
    );
    assert_eq!(allocator.export_display_leases(after_horizon_ns).len(), 1);
}
