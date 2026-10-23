//! #16013: per-source fairness for persistent NAT leases.
//!
//! Before the fix the only persistent-lease ceiling in the allocator was
//! the pool-global `max_tracked_flows`. A single host churns lease keys by
//! varying its source port, so open/close churn accumulated idle leases
//! (300s-24h retention) that were charged to nobody: after enough churn
//! one host held the whole lease table and every other source was refused
//! (or, on a single-address pool, one host's idle lease held the only port
//! its closed flows had used).
//!
//! The fix charges every lease to `(src_ip, routing_scope)` at the single
//! insert/remove seam and refuses a NEW lease key once that source reaches
//! `MAX_PERSISTENT_LEASES_PER_SOURCE`, on every mint path (local PAT,
//! local address-only, HA-synced PAT, HA-synced address-only, idle-lease
//! import, deterministic NAT64 BIB). Joining an existing lease is never
//! refused by this gate.
//!
//! Decisive regression (from the issue): single-host persistent churn —
//! after cap-many *closed* flows, new leases from that source are refused
//! while a second source still allocates (small-pool poll test). The cap
//! mirrors the session default (4096), so the decisive cell drives the
//! real cap with distinct source ports on a large-enough pool; the
//! small-pool cells pin the second-source fairness and the charge/release
//! invariant without minting thousands of leases.

use super::allocator::{
    NatHolder, PoolAddressFamily, PortAllocator, MAX_PERSISTENT_LEASES_PER_SOURCE,
};
use super::idle_lease_sync_8121::{IdleLeaseImport, IdleLeaseRecord};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use std::net::{IpAddr, Ipv4Addr};

const TCP: u8 = 6;
const TIMEOUT_NS: u64 = 300 * 1_000_000_000;
const NOW: u64 = 1_000_000_000;

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

fn pool_addr() -> Ipv4Addr {
    "203.0.113.1".parse().unwrap()
}

fn mint(
    alloc: &PortAllocator,
    addrs: &[Ipv4Addr],
    f: SourceNatFlowKey,
    now_ns: u64,
) -> Result<super::allocator::TranslatedTuple, ()> {
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
            0,
        )
        .map_err(|_| ())
}

/// Decisive churn cell: one host opens and closes cap-many persistent
/// flows (each a distinct source port, hence a distinct lease key). Every
/// closed flow leaves an idle lease charged to that host. The next new
/// lease from the same host must be refused, while a second host still
/// allocates — and the refused mint must leave the second host's lease
/// and the first host's retained leases untouched.
#[test]
fn single_host_persistent_churn_refused_second_source_allocates_16013() {
    let addrs = [pool_addr()];
    // One address, enough ports for cap + a second source's lease.
    let alloc = PortAllocator::new(
        1,
        1024,
        1024 + (MAX_PERSISTENT_LEASES_PER_SOURCE as u16) + 16,
    );
    let host_a = "10.0.0.1";
    let host_b = "10.0.0.2";

    assert_eq!(
        MAX_PERSISTENT_LEASES_PER_SOURCE, 4096,
        "cap mirrors the session per-source default"
    );

    for i in 0..MAX_PERSISTENT_LEASES_PER_SOURCE {
        let f = flow(host_a, 4000u16.wrapping_add(i as u16));
        let t = mint(&alloc, &addrs, f, NOW)
            .unwrap_or_else(|_| panic!("churn mint {i} must succeed before the cap"));
        assert!(
            alloc.release_flow(f, t, NOW, NatHolder::Untracked),
            "churn release {i}"
        );
    }
    // All of A's flows are closed, yet A retains cap-many idle leases.
    assert_eq!(
        alloc.snapshot().live_flows,
        0,
        "fixture: every churn flow is closed"
    );
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(host_a.parse().unwrap(), 0),
        MAX_PERSISTENT_LEASES_PER_SOURCE,
        "fixture: closed flows left cap-many idle leases charged to host A"
    );
    assert_eq!(
        alloc.snapshot().persistent_leases,
        MAX_PERSISTENT_LEASES_PER_SOURCE as u64
    );

    // The next NEW lease key from A is refused even though ports remain.
    let extra = flow(
        host_a,
        4000u16.wrapping_add(MAX_PERSISTENT_LEASES_PER_SOURCE as u16),
    );
    assert!(
        mint(&alloc, &addrs, extra, NOW).is_err(),
        "host A at its per-source lease cap must be refused a new lease"
    );
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(host_a.parse().unwrap(), 0),
        MAX_PERSISTENT_LEASES_PER_SOURCE,
        "refusal must not mint or drop a lease"
    );

    // A second source still allocates on the same pool.
    let fb = flow(host_b, 5000);
    let tb =
        mint(&alloc, &addrs, fb, NOW).expect("second source must still allocate after A is capped");
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(host_b.parse().unwrap(), 0),
        1
    );
    assert!(alloc.release_flow(fb, tb, NOW, NatHolder::Untracked));
    // B's closed lease is idle-retained and charged to B, not to A.
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(host_b.parse().unwrap(), 0),
        1,
        "B's idle lease charges B"
    );
    assert_eq!(alloc.debug_persistent_source_count(), 2);
}

/// Re-joining an existing lease is never a new charge: a second flow from
/// the same source port (different remote) reuses the idle lease after the
/// first flow closes, even at the cap boundary shape (one lease, many
/// flows over its life).
#[test]
fn rejoining_existing_lease_is_not_a_new_charge_16013() {
    let addrs = [pool_addr()];
    let alloc = PortAllocator::new(1, 1024, 2048);
    let host = "10.0.0.1";
    let f1 = flow(host, 4000);
    let t1 = mint(&alloc, &addrs, f1, NOW).expect("first mint");
    assert!(alloc.release_flow(f1, t1, NOW, NatHolder::Untracked));
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(host.parse().unwrap(), 0),
        1
    );

    // Same source port, different remote port: same PersistentSourceKey.
    let mut f2 = flow(host, 4000);
    f2.dst_port = 8443;
    let t2 = mint(&alloc, &addrs, f2, NOW).expect("rejoining the idle lease must succeed");
    assert_eq!(
        t2, t1,
        "persistent NAT reuses the retained translated tuple"
    );
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(host.parse().unwrap(), 0),
        1,
        "rejoin charges nothing new"
    );
    assert!(alloc.release_flow(f2, t2, NOW, NatHolder::Untracked));
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(host.parse().unwrap(), 0),
        1,
        "idle lease still charged after close"
    );
}

/// Routing scope separates charges: the same source IP in two routing
/// scopes is two budgets (the #10018 lease-identity partition), so scope
/// churn in one VRF does not consume the other's allowance.
#[test]
fn routing_scope_separates_per_source_charge_16013() {
    let addrs = [pool_addr()];
    let alloc = PortAllocator::new(1, 1024, 2048);
    let mut f0 = flow("10.0.0.1", 4000);
    f0.routing_scope = 0;
    let mut f7 = flow("10.0.0.1", 4000);
    f7.routing_scope = 7;
    let t0 = mint(&alloc, &addrs, f0, NOW).expect("scope 0 mint");
    let t7 = mint(&alloc, &addrs, f7, NOW).expect("scope 7 mint");
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(alloc.debug_persistent_lease_count_for_source(ip, 0), 1);
    assert_eq!(alloc.debug_persistent_lease_count_for_source(ip, 7), 1);
    assert_eq!(alloc.debug_persistent_source_count(), 2);
    assert!(alloc.release_flow(f0, t0, NOW, NatHolder::Untracked));
    assert!(alloc.release_flow(f7, t7, NOW, NatHolder::Untracked));
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(ip, 0),
        1,
        "idle scope-0 lease still charged"
    );
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(ip, 7),
        1,
        "idle scope-7 lease still charged"
    );
}

/// Expiry releases the charge: once A's idle leases pass their timeout,
/// pressure GC on the next mint reclaims them and A can mint again. This
/// is the fairness recovery leg — the cap is a retention bound, not a
/// lifetime ban.
#[test]
fn expired_idle_leases_release_the_source_charge_16013() {
    let addrs = [pool_addr()];
    let alloc = PortAllocator::new(1, 1024, 2048);
    let host = "10.0.0.1";
    let f1 = flow(host, 4000);
    let t1 = mint(&alloc, &addrs, f1, NOW).expect("mint");
    assert!(alloc.release_flow(f1, t1, NOW, NatHolder::Untracked));
    let ip: IpAddr = host.parse().unwrap();
    assert_eq!(alloc.debug_persistent_lease_count_for_source(ip, 0), 1);

    // Well past the 300s idle timeout, a fresh mint from a new source port
    // triggers the pressure/expiry GC and succeeds; the expired lease's
    // charge is gone (replaced by the new lease's charge).
    let later = NOW + TIMEOUT_NS + 1_000_000_000;
    let f2 = flow(host, 4001);
    let _t2 = mint(&alloc, &addrs, f2, later).expect("mint after expiry must succeed");
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(ip, 0),
        1,
        "expired charge released, new lease charged"
    );
    assert_eq!(alloc.snapshot().persistent_leases, 1);
}

/// Address-only persistent leases are charged the same way: address-only
/// churn (no port consumed) still retains one lease per source port, so
/// the per-source cap is the only thing bounding a single host's address
/// pinning on a multi-address pool.
#[test]
fn address_only_leases_charge_their_source_16013() {
    let addrs = [pool_addr(), "203.0.113.2".parse().unwrap()];
    let alloc = PortAllocator::new(2, 1024, 2048);
    let host = "10.0.0.1";
    for sport in [4000u16, 4001] {
        let f = flow(host, sport);
        let t = alloc
            .reserve_address_only_persistent(
                f,
                PoolAddressFamily::V4(&addrs),
                0,
                false,
                PersistentNatPermit::AnyRemoteHost,
                TIMEOUT_NS,
                NOW,
                NatHolder::Untracked,
                0,
            )
            .expect("address-only mint");
        assert!(alloc.release_flow(f, t, NOW, NatHolder::Untracked));
    }
    let ip: IpAddr = host.parse().unwrap();
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(ip, 0),
        2,
        "two idle address-only leases charge host"
    );
    assert_eq!(alloc.snapshot().persistent_leases, 2);
}

/// Idle-lease imports charge the importing allocator's per-source budget:
/// a peer cannot install unbounded idle leases for one source on the
/// standby. Imports of cap-many distinct leases for one source succeed,
/// the next is SkippedCapacity, and another source still imports.
#[test]
fn idle_lease_import_charges_source_16013() {
    // Ports 1024..9216: translated ports 3000..7096 stay inside the range.
    let alloc = PortAllocator::new(1, 1024, 9216);
    let pool = vec![IpAddr::V4(pool_addr())];
    let mk = |src: &str, sport: u16, port: u16| IdleLeaseRecord {
        protocol: TCP,
        src_ip: src.parse().unwrap(),
        src_port: sport,
        routing_scope: 0,
        egress_scope: 0,
        remote: None,
        permit_any_remote: true,
        permitted_remotes: Vec::new(),
        translated_ip: IpAddr::V4(pool_addr()),
        translated_port: port,
        address_only: false,
        deterministic: false,
        deterministic_identity: None,
        remaining_ns: TIMEOUT_NS,
        timeout_ns: TIMEOUT_NS,
    };
    for i in 0..MAX_PERSISTENT_LEASES_PER_SOURCE {
        let rec = mk(
            "10.0.0.1",
            4000u16.wrapping_add(i as u16),
            3000u16.wrapping_add(i as u16),
        );
        assert_eq!(
            alloc.import_idle_lease(&rec, &pool, TIMEOUT_NS, NOW),
            IdleLeaseImport::Installed,
            "import {i} before cap"
        );
    }
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(
        alloc.debug_persistent_lease_count_for_source(ip, 0),
        MAX_PERSISTENT_LEASES_PER_SOURCE
    );

    let over = mk("10.0.0.1", 9000, 8000);
    assert_eq!(
        alloc.import_idle_lease(&over, &pool, TIMEOUT_NS, NOW),
        IdleLeaseImport::SkippedCapacity,
        "import past the per-source cap is refused"
    );
    let other = mk("10.0.0.2", 9000, 8001);
    assert_eq!(
        alloc.import_idle_lease(&other, &pool, TIMEOUT_NS, NOW),
        IdleLeaseImport::Installed,
        "a second source still imports"
    );
}
