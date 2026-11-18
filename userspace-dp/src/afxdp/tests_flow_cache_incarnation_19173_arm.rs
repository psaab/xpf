// #19173: what the fix adds, on the production poll path: the seed binds the
// entry to the backing row's install incarnation, a hit refused for a
// replaced row is counted under the no-record eviction arm (and, since the
// fold, in the cold `FLOW_CACHE_REPLACED_EVICTIONS` counter), and an
// identical re-import keeps the incarnation so the entry keeps hitting. The
// defect cells (and the fixture) are in `tests_flow_cache_incarnation_19173.rs`,
// which compiles on the pre-fix tree; these name fix-only API and do not.
use super::tests_flow_cache_incarnation_19173::*;
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

/// This thread's count of `Replaced` refusals (the test mirror of the
/// process-global `FLOW_CACHE_REPLACED_EVICTIONS`, exact under parallel cells).
fn replaced_this_thread() -> u64 {
    crate::afxdp::flow_cache::FLOW_CACHE_REPLACED_EVICTIONS_THIS_THREAD.with(|count| count.get())
}

fn global_replaced() -> u64 {
    crate::afxdp::flow_cache::flow_cache_replaced_evictions()
}

/// Row A's own wire entry, re-imported under `session_id`.
fn reimport_of_row_a(fx: &Fixture, session_id: u64) -> SyncedSessionEntry {
    let mut entry = fx.sessions.synced_entry_for(&key()).expect("row A");
    entry.session_id = session_id;
    entry
}

/// The seed binds the entry to the row the slow path served, and a hit on a
/// replaced row is refused and counted under `post_hit_session_dead_no_record`
/// (the seeded record is gone), never the idle-crossed arm, and once in the
/// cold replaced counter (the no-record arm's replaced subset, P3-2).
#[test]
fn seed_binds_the_backing_row_and_replacement_counts_as_no_record_19173() {
    let mut fx = Fixture::seeded();
    let seeded = bound_epoch(&fx);
    assert_eq!(seeded, live_epoch(&fx), "the seed binds row A's incarnation");
    assert_ne!(seeded, crate::session::PROBE_ANY_INCARNATION);
    assert_ne!(seeded, crate::session::PROBE_NO_BACKING_ROW);
    replace_with_table_t_row(&mut fx, false);
    assert_ne!(live_epoch(&fx), seeded, "premise: the replacement is a new incarnation");
    let (thread_before, global_before) = (replaced_this_thread(), global_replaced());
    assert_eq!(fx.send(0), Sent { cache_hit: false, egress: None });
    let arms = fx.binding.flow.flow_cache.evictions_by_arm;
    assert_eq!(arms[Arm::PostHitSessionDeadNoRecord as usize], 1, "{arms:?}");
    assert_eq!(arms[Arm::PostHitSessionDeadIdleCrossed as usize], 0, "{arms:?}");
    assert_eq!(arms.iter().sum::<u64>(), 1, "one eviction, on one arm: {arms:?}");
    assert_eq!(replaced_this_thread() - thread_before, 1, "one replaced refusal counted");
    assert!(global_replaced() > global_before, "the exported counter moved");
}

/// The re-seed after a replacement binds the REPLACING row, so the flow
/// re-seeds once and then hits. The replacement here is a new incarnation by
/// identity (another wire session id) with every forwarding input equal, so
/// the slow path forwards it via E1 as before.
#[test]
fn re_seed_binds_the_replacing_row_19173() {
    let mut fx = Fixture::seeded();
    let seeded = bound_epoch(&fx);
    let b = reimport_of_row_a(&fx, fx.row_a_session_id() + 1);
    fx.apply(vec![WorkerCommand::UpsertSynced(b)]);
    let replaced = live_epoch(&fx);
    assert_ne!(replaced, seeded, "premise: another incarnation mints a new epoch");
    let thread_before = replaced_this_thread();
    assert_eq!(fx.send(0), Sent { cache_hit: false, egress: Some(E1) });
    assert_eq!(
        fx.binding.flow.flow_cache.evictions_by_arm[Arm::PostHitSessionDeadNoRecord as usize],
        1
    );
    assert_eq!(replaced_this_thread() - thread_before, 1);
    assert_eq!(bound_epoch(&fx), replaced, "the re-seed binds the replacing row");
    assert_eq!(fx.send(0), Sent { cache_hit: true, egress: Some(E1) });
}

/// #19173 fold (r24 P3-1): an IDENTICAL re-import keeps the row's
/// incarnation, so the cached entry keeps hitting with no eviction on any
/// arm and no replaced refusal. Both production replacement commands:
/// `UpsertSynced` with the row's own wire id (a primary-liveness or bulk
/// resend) and `UpsertLocal` with no wire id (the local-tunnel refresh
/// shape, which installs under a fresh node-local session id).
/// RED at 5c7154090a: the first segment after the re-import is a no-record
/// eviction and a slow-path re-seed.
#[test]
fn identical_reimport_keeps_the_cache_hit_19173() {
    for local in [false, true] {
        let mut fx = Fixture::seeded();
        let seeded = bound_epoch(&fx);
        let command = if local {
            WorkerCommand::UpsertLocal(reimport_of_row_a(&fx, 0))
        } else {
            WorkerCommand::UpsertSynced(reimport_of_row_a(&fx, fx.row_a_session_id()))
        };
        fx.apply(vec![command]);
        assert_eq!(
            live_epoch(&fx),
            seeded,
            "local={local}: the identical re-import kept the row's incarnation"
        );
        let thread_before = replaced_this_thread();
        for n in 0..3 {
            assert_eq!(
                fx.send(if n % 2 == 0 { 0 } else { 64 }),
                Sent { cache_hit: true, egress: Some(E1) },
                "local={local}: segment {n} after the identical re-import"
            );
        }
        assert!(
            fx.binding.flow.flow_cache.evictions_by_arm.iter().all(|n| *n == 0),
            "local={local}: {:?}",
            fx.binding.flow.flow_cache.evictions_by_arm
        );
        assert_eq!(replaced_this_thread(), thread_before, "local={local}: nothing refused");
        assert_eq!(bound_epoch(&fx), seeded, "local={local}: no re-seed");
    }
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
