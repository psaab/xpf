// #19173: what the fix adds, on the production poll path: the seed binds the
// entry to the backing row's install incarnation, and a hit refused for a
// replaced row is counted under its own eviction arm. The defect cells (and
// the fixture) are in `tests_flow_cache_incarnation_19173.rs`, which compiles
// on the pre-fix tree; these name fix-only API and do not.
use super::tests_flow_cache_incarnation_19173::*;
use super::tests_support::*;
use super::*;
use crate::afxdp::flow_cache::FlowCacheEvictionArm as Arm;

/// The single cached entry for K on the fixture's binding.
fn bound_epoch(fx: &Fixture) -> u64 {
    let entries: Vec<_> = fx.binding.flow.flow_cache.entries.iter().flatten().collect();
    assert_eq!(entries.len(), 1, "fixture caches exactly K");
    entries[0].backing_install_epoch
}

fn live_epoch(fx: &Fixture) -> u64 {
    fx.sessions
        .backing_install_epoch_for_cache_hit(&key(), fx.now_ns)
        .expect("K has a row")
}

/// The seed binds the entry to the row the slow path served, and a hit on a
/// replaced row is refused under `post_hit_session_replaced`, never the
/// no-record arm (the row exists; it is another incarnation).
#[test]
fn seed_binds_the_backing_row_and_replacement_counts_its_own_arm_19173() {
    let mut fx = Fixture::seeded();
    let seeded = bound_epoch(&fx);
    assert_eq!(seeded, live_epoch(&fx), "the seed binds row A's incarnation");
    assert_ne!(seeded, crate::session::PROBE_ANY_INCARNATION);
    assert_ne!(seeded, crate::session::PROBE_NO_BACKING_ROW);
    replace_with_table_t_row(&mut fx, false);
    assert_ne!(live_epoch(&fx), seeded, "premise: the replacement is a new incarnation");
    assert_eq!(fx.send(0), Sent { cache_hit: false, egress: None });
    let arms = fx.binding.flow.flow_cache.evictions_by_arm;
    assert_eq!(arms[Arm::PostHitSessionReplaced as usize], 1, "{arms:?}");
    assert_eq!(arms[Arm::PostHitSessionDeadNoRecord as usize], 0, "{arms:?}");
    assert_eq!(arms[Arm::PostHitSessionDeadIdleCrossed as usize], 0, "{arms:?}");
}

/// The re-seed after a replacement binds the REPLACING row, so the flow
/// re-seeds once and then hits: an identical re-import (same table, same
/// session id) costs one slow-path segment, attributed to the arm.
#[test]
fn re_seed_binds_the_replacing_row_19173() {
    let mut fx = Fixture::seeded();
    let seeded = bound_epoch(&fx);
    let mut b = fx
        .sessions
        .synced_entry_for(&key())
        .expect("row A");
    b.session_id = fx.sessions.session_id_for(&key());
    let queue = Arc::new(Mutex::new(VecDeque::from(vec![WorkerCommand::UpsertSynced(b)])));
    crate::afxdp::session_glue::apply_worker_commands(
        &queue,
        &mut fx.sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &fx.forwarding,
        &restamped_ha_state(&txn_ha_state(), monotonic_nanos()),
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );
    let replaced = live_epoch(&fx);
    assert_ne!(replaced, seeded, "premise: a re-import is a new incarnation");
    assert_eq!(fx.send(0), Sent { cache_hit: false, egress: Some(E1) });
    assert_eq!(
        fx.binding.flow.flow_cache.evictions_by_arm[Arm::PostHitSessionReplaced as usize],
        1
    );
    assert_eq!(bound_epoch(&fx), replaced, "the re-seed binds the replacing row");
    assert_eq!(fx.send(0), Sent { cache_hit: true, egress: Some(E1) });
}

/// No-spurious-miss, attributed: ten in-place-updating hits leave the bound
/// incarnation equal to the live row's and evict nothing on any arm.
#[test]
fn in_place_hits_keep_the_bound_incarnation_19173() {
    let mut fx = Fixture::seeded();
    let seeded = bound_epoch(&fx);
    for n in 0..10 {
        assert_eq!(
            fx.send(if n % 2 == 0 { 0 } else { 64 }),
            Sent { cache_hit: true, egress: Some(E1) },
            "segment {n}"
        );
    }
    assert_eq!(live_epoch(&fx), seeded, "a hit never moves the row's incarnation");
    assert_eq!(bound_epoch(&fx), seeded);
    assert!(
        fx.binding.flow.flow_cache.evictions_by_arm.iter().all(|n| *n == 0),
        "{:?}",
        fx.binding.flow.flow_cache.evictions_by_arm
    );
}
