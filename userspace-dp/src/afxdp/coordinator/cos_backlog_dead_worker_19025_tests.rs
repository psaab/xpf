//! #19025 review (Codex F3): a worker that dies by panic never runs its CoS
//! teardown (`clear_all_cos_exact_backlogs_for_binding`), so whatever its
//! bindings last published in each interface's `SharedCoSExactBacklog` stays
//! there. A stale exact-demand mask keeps the dead binding's exact rate
//! reserved, so every surviving binding's non-exact surplus stays held to the
//! residual for the life of the backlog object, and its claim on the residual
//! pool would hold a part until it lapsed (one epoch). The dead-worker sweep
//! must clear every slot the dead worker's bindings own, and only those.

use super::*;
use crate::afxdp::types::{ExactDemandQueueMask, SharedCoSExactBacklog};
use std::sync::atomic::Ordering;

fn handle_19025() -> WorkerHandle {
    WorkerHandle {
        stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        heartbeat: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        commands: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        session_export_ack: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cos_status: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
        cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
    }
}

fn identity_19025(slot: u32, worker_id: u32) -> BindingIdentity {
    BindingIdentity {
        slot,
        queue_id: slot,
        worker_id,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 42,
    }
}

#[test]
fn dead_worker_sweep_clears_its_cos_backlog_slots_19025() {
    let mut coordinator = Coordinator::new();
    let dead_rec = WorkerRuntimeRecord::for_test(handle_19025());
    let dead_atomics = dead_rec.handle.runtime_atomics.clone();
    coordinator.workers.register(0, dead_rec, None);
    coordinator
        .workers
        .register(1, WorkerRuntimeRecord::for_test(handle_19025()), None);
    // Slot 2 belongs to worker 0, slot 3 to worker 1.
    coordinator
        .workers
        .identities
        .insert(2, identity_19025(2, 0));
    coordinator
        .workers
        .identities
        .insert(3, identity_19025(3, 1));
    let backlog = Arc::new(SharedCoSExactBacklog::new(3));
    backlog.publish_demand(2, 1500, ExactDemandQueueMask::EMPTY.with_queue(0));
    backlog.publish_demand(3, 1500, ExactDemandQueueMask::EMPTY.with_queue(1));
    coordinator
        .cos
        .exact_backlogs
        .store(Arc::new(std::collections::BTreeMap::from([(
            42,
            backlog.clone(),
        )])));

    // Both bindings hold a claim on the residual pool.
    let (rate, burst) = (125_000_000u64, 10_000_000u64);
    let start = 1_000_000_000u64;
    let _ = backlog.residual_surplus_budget(start, rate, burst);
    // Mid-epoch: at an epoch boundary nothing has accrued, so a claim the
    // sweep failed to clear would reserve nothing and the last assertion
    // could not see it.
    let now = start + 50_500_000;
    let _ = backlog.nonexact_surplus_budget(2, now, rate, burst);
    let pool = backlog.residual_surplus_budget(now, rate, burst);
    assert!(
        backlog.nonexact_surplus_budget(3, now, rate, burst) < pool,
        "control: the dead worker's fresh claim reserves part of the pool before the sweep"
    );

    // Control: both workers alive, nothing is cleared.
    coordinator.retire_dead_worker_holders();
    assert!(
        backlog.peer_exact_demand_queue_mask(3).counts(0),
        "a LIVE worker's published exact demand must survive the sweep"
    );

    dead_atomics.dead.store(true, Ordering::Relaxed);
    coordinator.retire_dead_worker_holders();
    assert!(
        !backlog.peer_exact_demand_queue_mask(3).counts(0),
        "the dead worker's exact demand survived the sweep: its rate stays reserved \
         and every surviving binding's surplus stays held to the residual"
    );
    assert!(
        !backlog.has_peer_backlog(3),
        "the dead worker's queued exact bytes survived the sweep"
    );
    assert!(
        backlog.peer_exact_demand_queue_mask(2).counts(1),
        "the sweep must clear only the dead worker's slots: worker 1's demand was cleared too"
    );
    assert_eq!(
        backlog.nonexact_surplus_budget(3, now, rate, burst),
        backlog.residual_surplus_budget(now, rate, burst),
        "after the sweep the survivor's budget must be the whole pool: the dead worker's \
         claim survived"
    );
}
