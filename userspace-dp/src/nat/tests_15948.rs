//! #15948 regression cells for the NAT allocator claims:
//! H31-01 displaced restore, H31-02 idle-lease merge counts,
//! H31-03 deterministic-v6 expiry indexing.

use super::allocator::{DeterministicV6, NatHolder, PortAllocator, TranslatedTuple};
use super::idle_lease_sync_8121::{IdleLeaseImport, IdleLeaseRecord};
use super::source::{PersistentNatPermit, SourceNatFlowKey};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const POOL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const TIMEOUT_NS: u64 = 300_000_000_000;

fn v4_flow(src_port: u16) -> SourceNatFlowKey {
    SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port,
        dst_port: 443,
        routing_scope: 0,
    }
}

/// H31-01: reserve T1, capture+replace with T2, rollback T2 (sole holder),
/// then restore_displaced must bring T1 back.
#[test]
fn restore_displaced_after_sole_holder_rollback_15948() {
    let alloc = PortAllocator::new(1, 1024, 65535);
    let flow = v4_flow(40000);
    let t1 = TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: 20001,
    };
    let t2 = TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: 20002,
    };
    assert!(alloc.reserve_flow(flow, t1, 0, false, 1_000, NatHolder::Untracked));
    let mut snapshot = None;
    assert!(alloc.reserve_flow_maybe_persistent(
        flow,
        t2,
        0,
        false,
        2_000,
        NatHolder::Untracked,
        None,
        true,
        &mut snapshot,
    ));
    let snapshot = snapshot.expect("capture must produce a snapshot");
    assert!(alloc.rollback_flow(flow, t2, 3_000, NatHolder::Untracked));
    assert!(
        snapshot.restore_displaced(t2, 4_000),
        "sole-holder rollback must leave restore_displaced able to restore T1"
    );
    assert_eq!(
        alloc.debug_live_flow_translated(&flow),
        Some(t1),
        "displaced incumbent tuple must be restored"
    );
}

/// H31-01 guard (review fold): when another holder survives rollback,
/// the replacement is deliberately retained — restore must REFUSE and
/// leave T2 (and its holder mask) untouched, not overwrite it and
/// strand Worker(1)'s ownership. After Worker(1) releases, the sole-
/// holder restore shape is what may proceed.
#[test]
fn restore_displaced_refuses_surviving_holder_15948() {
    let alloc = PortAllocator::new(1, 1024, 65535);
    let flow = v4_flow(40001);
    let t1 = TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: 20011,
    };
    let t2 = TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: 20012,
    };
    assert!(alloc.reserve_flow(flow, t1, 0, false, 1_000, NatHolder::Worker(0)));
    let mut snapshot = None;
    assert!(alloc.reserve_flow_maybe_persistent(
        flow,
        t2,
        0,
        false,
        2_000,
        NatHolder::Worker(0),
        None,
        true,
        &mut snapshot,
    ));
    // Second worker joins T2 so rollback by worker 0 does not unlink.
    assert!(alloc.reserve_flow(flow, t2, 0, false, 2_500, NatHolder::Worker(1)));
    let snapshot = snapshot.expect("snapshot");
    assert!(!alloc.rollback_flow(flow, t2, 3_000, NatHolder::Worker(0)));
    assert!(
        !snapshot.restore_displaced(t2, 4_000),
        "restore must refuse while Worker(1) still holds the replacement"
    );
    assert_eq!(
        alloc.debug_live_flow_translated(&flow),
        Some(t2),
        "the surviving holder's replacement must be left untouched"
    );
    let mask = alloc.holder_mask_for_flow(&flow).expect("holder mask");
    assert_ne!(mask, 0, "the surviving holder mask must be preserved");
    // Worker(1) can still release T2 cleanly (would be refused had
    // restore overwritten the tuple).
    assert!(alloc.release_flow(flow, t2, 5_000, NatHolder::Worker(1)));
    assert_eq!(alloc.debug_live_flow_translated(&flow), None);
}

/// H31-01 guard: an address-only incumbent whose reverse identity was
/// retaken by another flow while the snapshot was outstanding must
/// not be restored over that flow.
#[test]
fn restore_displaced_refuses_retaken_address_only_15948() {
    let alloc = PortAllocator::new(1, 1024, 65535);
    let flow = v4_flow(40002);
    let other = SourceNatFlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        ..v4_flow(40003)
    };
    // Address-only preserves the source port, so flow's tuple is
    // (POOL, 40002) and other's would collide only via the same dst.
    let a1 = alloc
        .reserve_address_only(flow, IpAddr::V4(POOL), 0, NatHolder::Untracked)
        .expect("address-only reserve");
    assert_eq!(a1.port, 40002);
    let t2 = TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: 20022,
    };
    let mut snapshot = None;
    assert!(alloc.reserve_flow_maybe_persistent(
        flow,
        t2,
        0,
        false,
        2_000,
        NatHolder::Untracked,
        None,
        true,
        &mut snapshot,
    ));
    let snapshot = snapshot.expect("snapshot");
    // A flow with the SAME source port + dst retakes the freed
    // address-only reverse identity (POOL, 40002, dst).
    let retaker = SourceNatFlowKey {
        src_port: 40002,
        ..other
    };
    let retaken = alloc
        .reserve_address_only(retaker, IpAddr::V4(POOL), 0, NatHolder::Untracked)
        .expect("retake of the freed address-only identity");
    assert_eq!(retaken, a1);
    assert!(alloc.rollback_flow(flow, t2, 3_000, NatHolder::Untracked));
    assert!(
        !snapshot.restore_displaced(t2, 4_000),
        "restore must refuse when another flow retook the address-only identity"
    );
    assert_eq!(alloc.debug_live_flow_translated(&retaker), Some(retaken));
}

/// H31-01 fold 4 — the exact lifecycle the reviewer specified:
/// reserve an address-only incumbent, capture_and_replace it with a
/// PAT replacement, roll the replacement back, let an IDLE LEASE
/// IMPORT acquire the same reverse identity during the gap, then
/// restore. The live-map guard cannot see the imported lease (it
/// owns through the persistent indexes), so a restore that only
/// checked live owners would overwrite the identity. Assert the
/// restore refuses, the imported lease survives, and the owner
/// counts are untouched.
#[test]
fn restore_displaced_refuses_persistent_retake_in_gap_15948() {
    let alloc = PortAllocator::new(1, 1024, 65535);
    let flow = v4_flow(40002);
    let a1 = alloc
        .reserve_address_only(flow, IpAddr::V4(POOL), 0, NatHolder::Untracked)
        .expect("address-only reserve");
    assert_eq!(a1.port, 40002);
    let t2 = TranslatedTuple {
        ip: IpAddr::V4(POOL),
        port: 20022,
    };
    let mut snapshot = None;
    assert!(alloc.reserve_flow_maybe_persistent(
        flow,
        t2,
        0,
        false,
        2_000,
        NatHolder::Untracked,
        None,
        true,
        &mut snapshot,
    ));
    let snapshot = snapshot.expect("snapshot");
    assert!(alloc.rollback_flow(flow, t2, 3_000, NatHolder::Untracked));
    assert_eq!(alloc.debug_live_flow_translated(&flow), None);

    // During the gap: an idle address-only lease import acquires
    // (POOL, 40002) granting flow's exact remote (dst 8.8.8.8:443).
    let addrs = vec![IpAddr::V4(POOL)];
    let remote = (flow.dst_ip, flow.dst_port);
    let src2 = Ipv4Addr::new(10, 0, 5, 5);
    let rec = idle_record(src2, 11, remote, 40002);
    assert_eq!(
        alloc.import_idle_lease(&rec, &addrs, TIMEOUT_NS, 3_500),
        IdleLeaseImport::Installed,
        "the idle import must acquire the freed identity in the gap"
    );
    let counts_before = alloc.debug_persistent_address_only_owner_count();
    assert!(counts_before > 0);

    assert!(
        !snapshot.restore_displaced(t2, 4_000),
        "restore must refuse when an imported idle lease owns the identity"
    );
    // The imported lease and its accounting survive; the flow stays
    // unrestored (fail-closed) rather than overwriting the identity.
    assert_eq!(alloc.debug_live_flow_translated(&flow), None);
    assert_eq!(
        alloc.debug_persistent_address_only_owner_count(),
        counts_before,
        "refused restore must not disturb persistent owner counts"
    );
    // And the imported lease still contends a fresh import (it is the
    // live owner of the identity, not debris).
    let rec_again = idle_record(Ipv4Addr::new(10, 0, 6, 6), 12, remote, 40002);
    assert_eq!(
        alloc.import_idle_lease(&rec_again, &addrs, TIMEOUT_NS, 5_000),
        IdleLeaseImport::SkippedIdentityBusy
    );
}

fn idle_record(
    src: Ipv4Addr,
    egress_scope: u32,
    remote: (IpAddr, u16),
    translated_port: u16,
) -> IdleLeaseRecord {
    IdleLeaseRecord {
        protocol: 6,
        src_ip: IpAddr::V4(src),
        src_port: 40000,
        routing_scope: 0,
        egress_scope,
        mint_from_zone: None,
        remote: None,
        permit_any_remote: false,
        permitted_remotes: vec![remote],
        translated_ip: IpAddr::V4(POOL),
        translated_port,
        address_only: true,
        deterministic: false,
        deterministic_identity: None,
        remaining_ns: TIMEOUT_NS,
        timeout_ns: TIMEOUT_NS,
    }
}

/// H31-02: two records for one key with disjoint scopes/remotes. The
/// second record's grants must enter the owner counts, and a third
/// lease owning that remote must make the merge contended.
#[test]
fn idle_lease_merge_updates_owner_counts_15948() {
    let addrs = vec![IpAddr::V4(POOL)];
    let standby = PortAllocator::new(1, 1024, 65535);
    let src = Ipv4Addr::new(10, 0, 1, 1);
    let r1 = (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443u16);
    let r2 = (IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 443u16);
    let rec1 = idle_record(src, 11, r1, 21001);
    let rec2 = idle_record(src, 22, r2, 21001);
    assert_eq!(
        standby.import_idle_lease(&rec1, &addrs, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let before = standby.debug_persistent_address_only_owner_count();
    assert_eq!(
        standby.import_idle_lease(&rec2, &addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedExisting
    );
    let after = standby.debug_persistent_address_only_owner_count();
    assert!(
        after > before,
        "merge of a second scope/remote must add owner-count keys ({before} -> {after})"
    );

    // A second lease that already owns (translated, R2) must refuse a
    // fresh merge attempt carrying R2 under a new key.
    let other_src = Ipv4Addr::new(10, 0, 2, 2);
    let rec_other = idle_record(other_src, 33, r2, 21001);
    assert_eq!(
        standby.import_idle_lease(&rec_other, &addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "the merged R2 grant must contend against a colliding lease"
    );
}

/// H31-02 fold: merging a remote already owned by a LIVE flow (or
/// widening to any-remote over another owner) must be refused with
/// counts unchanged — contention may not be cleared by the
/// candidate's own idle grants.
#[test]
fn idle_lease_merge_refuses_live_contended_remote_15948() {
    let addrs = vec![IpAddr::V4(POOL)];
    let standby = PortAllocator::new(1, 1024, 65535);
    let src = Ipv4Addr::new(10, 0, 1, 1);
    let r1 = (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443u16);
    let r2 = (IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 443u16);
    let rec1 = idle_record(src, 11, r1, 21002);
    assert_eq!(
        standby.import_idle_lease(&rec1, &addrs, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed
    );
    let live_flow = SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 7, 7)),
        dst_ip: r2.0,
        src_port: 21002,
        dst_port: r2.1,
        routing_scope: 0,
    };
    let live_tuple = standby
        .reserve_address_only(live_flow, IpAddr::V4(POOL), 0, NatHolder::Untracked)
        .expect("live flow must own the disjoint remote");
    assert_eq!(live_tuple.port, 21002);
    let counts_before = standby.debug_persistent_address_only_owner_count();
    let rec2 = idle_record(src, 22, r2, 21002);
    assert_eq!(
        standby.import_idle_lease(&rec2, &addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "merge into a live-contended remote must be refused"
    );
    assert_eq!(
        standby.debug_persistent_address_only_owner_count(),
        counts_before,
        "a refused merge must not change owner counts"
    );
    let mut rec_any = idle_record(src, 23, r1, 21002);
    rec_any.permit_any_remote = true;
    rec_any.permitted_remotes = Vec::new();
    assert_eq!(
        standby.import_idle_lease(&rec_any, &addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "any-remote widening over another owner must be refused"
    );
    assert_eq!(
        standby.import_idle_lease(&rec1, &addrs, TIMEOUT_NS, 4_000),
        IdleLeaseImport::SkippedExisting,
        "idempotent self-merge must not be refused"
    );
}

/// H31-02 fold 3: an IDLE PAT lease holds its tuple via the occupancy
/// bit (no live owner count). Merging an address-only lease at the
/// same tuple to add a remote the PAT lease already grants — or
/// widening to any-remote — must refuse, exactly as a fresh PAT
/// import's bitmap claim refuses an occupied port.
#[test]
fn idle_lease_merge_refuses_idle_pat_contended_15948() {
    let addrs = vec![IpAddr::V4(POOL)];
    let standby = PortAllocator::new(1, 1024, 65535);
    let r1 = (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443u16);
    let r2 = (IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 443u16);
    // Idle PAT lease at (POOL, 21003) granting R2.
    let pat_src = Ipv4Addr::new(10, 0, 3, 3);
    let mut pat_rec = idle_record(pat_src, 11, r2, 21003);
    pat_rec.address_only = false;
    assert_eq!(
        standby.import_idle_lease(&pat_rec, &addrs, TIMEOUT_NS, 1_000),
        IdleLeaseImport::Installed,
        "idle PAT import must claim its port"
    );
    // Address-only lease at the same tuple granting only disjoint R1.
    let src = Ipv4Addr::new(10, 0, 1, 1);
    let rec1 = idle_record(src, 11, r1, 21003);
    assert_eq!(
        standby.import_idle_lease(&rec1, &addrs, TIMEOUT_NS, 2_000),
        IdleLeaseImport::Installed
    );
    let counts_before = standby.debug_persistent_address_only_owner_count();
    // Merge R2: the idle PAT lease already grants it.
    let rec2 = idle_record(src, 22, r2, 21003);
    assert_eq!(
        standby.import_idle_lease(&rec2, &addrs, TIMEOUT_NS, 3_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "merge must refuse a remote an idle PAT lease already grants"
    );
    assert_eq!(
        standby.debug_persistent_address_only_owner_count(),
        counts_before,
        "refused idle-PAT merge must not change owner counts"
    );
    // Any-remote widening over the idle PAT tuple must also refuse.
    let mut rec_any = idle_record(src, 23, r1, 21003);
    rec_any.permit_any_remote = true;
    rec_any.permitted_remotes = Vec::new();
    assert_eq!(
        standby.import_idle_lease(&rec_any, &addrs, TIMEOUT_NS, 4_000),
        IdleLeaseImport::SkippedIdentityBusy,
        "any-remote widening over an idle PAT lease must be refused"
    );
    // Control: merging a genuinely disjoint remote still succeeds.
    let r3 = (IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)), 443u16);
    let rec3 = idle_record(src, 24, r3, 21003);
    assert_eq!(
        standby.import_idle_lease(&rec3, &addrs, TIMEOUT_NS, 5_000),
        IdleLeaseImport::SkippedExisting,
        "disjoint merge must still succeed"
    );
}

/// H31-03: a freshly minted deterministic BIB is active and must not be
/// in either idle-expiry index; after release of all flows the indexes
/// are empty again (no stale key left by an active join).
#[test]
fn deterministic_v6_active_bib_not_in_expiry_index_15948() {
    let alloc = PortAllocator::new(1, 1024, 1087);
    let params = DeterministicV6 {
        block_size: 32,
        blocks_per_ip: 2,
        host_prefix_len: 32,
        host_base: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(),
        host_count: 1,
    };
    let sub: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let f1 = SourceNatFlowKey {
        protocol: 6,
        src_ip: IpAddr::V6(sub),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 40000,
        dst_port: 443,
        routing_scope: 0,
    };
    let t1 = alloc
        .allocate_deterministic_v6_at(f1, &[POOL], params, sub, 1_000, NatHolder::Untracked)
        .expect("mint BIB");
    {
        let live = alloc.debug_live();
        assert!(
            live.lease_expirations.is_empty() && live.lease_expirations_by_addr[0].is_empty(),
            "active BIB must not be indexed for idle expiry"
        );
    }
    // Join a second flow on the same BIB (active join), then release both.
    let f2 = SourceNatFlowKey {
        dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        dst_port: 53,
        ..f1
    };
    let t2 = alloc
        .allocate_deterministic_v6_at(f2, &[POOL], params, sub, 2_000, NatHolder::Untracked)
        .expect("join BIB");
    assert_eq!(t1, t2);
    assert!(alloc.release_flow(f1, t1, 3_000, NatHolder::Untracked));
    assert!(alloc.release_flow(f2, t2, 4_000, NatHolder::Untracked));
    alloc.debug_gc_expired_chunked(u64::MAX / 2, 16);
    let live = alloc.debug_live();
    assert!(
        live.lease_expirations.is_empty() && live.lease_expirations_by_addr[0].is_empty(),
        "no stale expiry key may remain after BIB release + GC"
    );
    let _ = PersistentNatPermit::AnyRemoteHost;
}

/// #15956 fold: displaced restore must respect the tracked-flow
/// cap when the incumbent slot is ABSENT (sole-holder rollback
/// already unlinked it). Pre-fold the tail inserted
/// unconditionally, pushing the count past `max_tracked_flows`.
#[test]
fn restore_displaced_refuses_at_cap_15956() {
    // 10 ports -> max_tracked_flows == 10 (capacity = ports x
    // addresses, capped by MAX_SOURCE_NAT_POOL_TRACKED_FLOWS).
    let alloc = PortAllocator::new(1, 1024, 1033);
    let flow = v4_flow(40000);
    let t1 = TranslatedTuple { ip: IpAddr::V4(POOL), port: 1024 };
    let t2 = TranslatedTuple { ip: IpAddr::V4(POOL), port: 1025 };
    assert!(alloc.reserve_flow(flow, t1, 0, false, 1_000, NatHolder::Untracked));
    let mut snapshot = None;
    assert!(alloc.reserve_flow_maybe_persistent(
        flow, t2, 0, false, 2_000, NatHolder::Untracked, None, true, &mut snapshot,
    ));
    let snapshot = snapshot.expect("capture must produce a snapshot");
    assert!(alloc.rollback_flow(flow, t2, 3_000, NatHolder::Untracked));
    assert_eq!(alloc.live_flow_count(), 0);
    // Fill to the cap with ADDRESS-ONLY records: each consumes a
    // tracked-flow slot but no bitmap bit, so T1's port (1024)
    // stays free for the restore's bitmap precheck and the CAP
    // is provably the refusing check.
    for i in 0..10u16 {
        let f = v4_flow(41000 + i);
        alloc
            .reserve_address_only(f, IpAddr::V4(POOL), 0, NatHolder::Untracked)
            .expect("address-only fill must succeed");
    }
    assert_eq!(alloc.live_flow_count(), 10);
    assert!(
        !snapshot.restore_displaced(t2, 4_000),
        "restore of an absent incumbent at cap must refuse, not overshoot max_tracked_flows"
    );
    assert_eq!(alloc.live_flow_count(), 10, "refusal must not change the tracked count");
    assert_eq!(alloc.debug_live_flow_translated(&flow), None);
    // Free one slot: the same restore now fits exactly.
    let f0 = v4_flow(41000);
    let t0 = TranslatedTuple { ip: IpAddr::V4(POOL), port: 41000 };
    assert!(alloc.release_flow(f0, t0, 5_000, NatHolder::Untracked));
    assert!(snapshot.restore_displaced(t2, 6_000), "restore fits once a slot frees");
    assert_eq!(alloc.debug_live_flow_translated(&flow), Some(t1));
    assert_eq!(alloc.live_flow_count(), 10);
}

/// #16713: steady-state REFRESH re-import must not walk the pool's
/// persistent-lease table. Before the fix every refresh record
/// evaluated `idle_merge_any_contended_by_other` (and
/// `idle_pat_lease_covers` for any new remote), both of which scanned
/// `persistent_by_source` end to end, so re-importing N records cost
/// O(N^2) — measured 84 s for one 64K push in the research probe.
/// The fix answers both helpers through the `persistent_by_translated`
/// per-tuple index and evaluates the any-remote contention lazily,
/// so a steady refresh does no per-record table walk at all.
///
/// Instead of a wall-clock ratio (flaky under load and orders of
/// magnitude slower in debug builds), this cell counts every
/// `persistent_by_source` iteration on the refresh path via the
/// `debug_persistent_by_source_scans` test seam, which counts every
/// contention-helper visit (full-table scan or indexed owner-set
/// walk) plus the remaining full-table scan site: installing N
/// leases and re-importing the same N (asserting `SkippedExisting`,
/// i.e. the refresh/merge branch) must perform ZERO such visits on
/// the steady path. A regression that reintroduces any per-record
/// contention walk — eager or indexed — fails deterministically at
/// any N, in any build profile.
#[test]
fn idle_lease_refresh_does_not_scan_persistent_table_16713() {
    const N: usize = 1_000;
    // One pool address, N ports: capacity = N tracked flows.
    let alloc = PortAllocator::new(1, 1024, (1024 + N - 1) as u16);
    let addrs = vec![IpAddr::V4(POOL)];
    let remote = (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443u16);
    let mut records = Vec::with_capacity(N);
    for i in 0..N {
        let src = Ipv4Addr::new(
            10,
            ((i >> 16) & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
        );
        records.push(idle_record(src, 11, remote, (1024 + i) as u16));
    }
    for rec in &records {
        assert_eq!(
            alloc.import_idle_lease(rec, &addrs, TIMEOUT_NS, 1_000),
            IdleLeaseImport::Installed,
            "fresh install must succeed"
        );
    }
    alloc.debug_reset_persistent_by_source_scans();
    for rec in &records {
        assert_eq!(
            alloc.import_idle_lease(rec, &addrs, TIMEOUT_NS, 2_000),
            IdleLeaseImport::SkippedExisting,
            "re-import must take the refresh/merge branch"
        );
    }
    assert_eq!(
        alloc.debug_persistent_by_source_scans(),
        0,
        "refresh of {N} leases must not visit any contention helper at all"
    );
}
