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
            standby.import_idle_lease(rec, &local_pool, standby_now),
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
        standby.import_idle_lease(&rec, &local_pool, standby_now),
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
        fresh_node.import_idle_lease(&rec, &local_pool, standby_now),
        IdleLeaseImport::Installed
    );
    // Exported => it is idle (active_flows == 0, or it would not qualify) AND
    // still inside its lifetime on THIS node's clock.
    assert_eq!(
        fresh_node.export_idle_leases(standby_now + 1).len(),
        1,
        "an imported idle lease is idle and live on the receiver's clock"
    );
    // Past the carried remaining lifetime, measured from the RECEIVER's now,
    // it is no longer live. Had the absolute `expires_at_ns` been carried it
    // would have read as expired ~9000 s ago and failed the assertion above.
    assert_eq!(
        fresh_node
            .export_idle_leases(standby_now + rec.remaining_ns + 1)
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
        standby.import_idle_lease(&rec, &local_pool, 11_000),
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
        standby.import_idle_lease(&rec, &different, 11_000),
        IdleLeaseImport::SkippedUnknownAddress
    );

    // CONTROL: the same record against the RIGHT pool installs, so the refusal
    // above is attributable to the address and not to the record being junk.
    assert_eq!(
        standby.import_idle_lease(&rec, &ipv4_pool(&addrs), 11_000),
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
        standby.import_idle_lease(&rec, &local_pool, 11_000),
        IdleLeaseImport::SkippedExisting
    );
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

/// Clearing revokes idle allocator leases, returns their occupancy, and
/// prevents a lease exported before the clear from being re-imported (#10784).
#[test]
fn clearing_idle_leases_revokes_allocator_and_stale_ha_import_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let decoy = flow("10.0.61.51", 40001);
    let client = flow("10.0.61.50", 40000);
    let _decoy_translation = mint_persistent(&allocator, &addrs, decoy, 1_000);
    let original = mint_persistent(&allocator, &addrs, client, 1_000);
    assert!(
        allocator.debug_is_port_occupied(
            addrs.iter().position(|ip| *ip == original.ip).unwrap(),
            original.port,
        ),
        "control: the target translation must own its allocator port before clear"
    );
    assert!(allocator.release_flow(client, original, 2_000, NatHolder::Untracked));
    assert!(allocator.release_flow(decoy, _decoy_translation, 2_000, NatHolder::Untracked));
    let stale = allocator
        .export_idle_leases(3_000)
        .into_iter()
        .find(|lease| lease.src_ip == client.src_ip && lease.src_port == client.src_port)
        .expect("control: the target idle lease must be exportable before clear");

    assert_eq!(allocator.clear_persistent_leases(), 2);
    assert!(allocator.export_idle_leases(3_001).is_empty());
    assert!(allocator.export_display_leases(3_001).is_empty());
    let original_index = addrs.iter().position(|ip| *ip == original.ip).unwrap();
    assert!(
        !allocator.debug_is_port_occupied(original_index, original.port),
        "an idle PAT lease clear must return the port occupancy token"
    );
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), 3_001),
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

/// A live lease keeps its occupied tuple until its existing flows drain, while
/// new flows bypass the revoked mapping. The drain then expires the shell rather
/// than rearming persistence (#10784).
#[test]
fn clearing_live_lease_drains_without_reuse_or_port_leak_10784() {
    let addrs = pool();
    let allocator = PortAllocator::new(1, 1024, 65535);
    let client = flow("10.0.61.50", 40000);
    let original = mint_persistent_any_remote(&allocator, &addrs, client, 1_000);
    let original_index = addrs.iter().position(|ip| *ip == original.ip).unwrap();

    assert_eq!(allocator.clear_persistent_leases(), 1);
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

    // A new allocation runs the ordinary bounded GC and proves the draining
    // shell released its port instead of leaking it after the last flow closed.
    let _other = mint_persistent_any_remote(&allocator, &addrs, flow("10.0.61.52", 40002), 4_000);
    assert!(
        !allocator.debug_is_port_occupied(original_index, original.port),
        "the final holder release must make the revoked tuple reclaimable"
    );
    let replacement = mint_persistent_any_remote(&allocator, &addrs, client, 5_000);
    assert_eq!(allocator.export_display_leases(5_000).len(), 2);
    assert_ne!(
        (replacement.ip, replacement.port),
        (original.ip, original.port),
        "the first new mapping after drain must be minted afresh"
    );
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

    assert_eq!(allocator.clear_persistent_leases(), 1);
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

    assert_eq!(allocator.clear_persistent_leases(), 1);
    assert_eq!(
        allocator.import_idle_lease(&stale, &ipv4_pool(&addrs), 3_001),
        IdleLeaseImport::SkippedExisting
    );
    assert!(allocator.export_display_leases(3_001).is_empty());
}
