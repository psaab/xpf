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

/// H31-01 control: multi-holder persistent restore still works (the arm
/// the triage says survives). Exercised via the non-persistent twin's
/// holder mask: a second holder keeps the entry present.
#[test]
fn restore_displaced_multi_holder_still_restores_15948() {
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
    assert!(snapshot.restore_displaced(t2, 4_000));
    assert_eq!(alloc.debug_live_flow_translated(&flow), Some(t1));
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
