//! #9654: `Coordinator::learned_route_import_capped_now` answers from the
//! PUBLISHED runtime view, and only while a live worker serves it.
//!
//! A worker thread cannot bind AF_XDP in a unit test, so "a live worker" here
//! is a registered runtime record whose `dead` flag is clear. That is exactly
//! what the accessor reads. The same-plan refresh and the first-worker spawn
//! failure are driven through the real `refresh_runtime_snapshot` and
//! `reconcile` (the latter with the #4952 `force_worker_spawn_fail` seam).

use super::*;
use crate::afxdp::worker_runtime::WorkerRuntimeAtomics;
use std::sync::atomic::Ordering as AtomicOrdering;

fn register_worker_9654(coord: &mut Coordinator, worker_id: u32) -> Arc<WorkerRuntimeAtomics> {
    let atomics = Arc::new(WorkerRuntimeAtomics::new());
    let handle = WorkerHandle {
        stop: Arc::new(AtomicBool::new(false)),
        heartbeat: Arc::new(AtomicU64::new(0)),
        commands: Arc::new(Mutex::new(VecDeque::new())),
        session_export_ack: Arc::new(AtomicU64::new(0)),
        cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
        runtime_atomics: Arc::clone(&atomics),
        cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
    };
    coord
        .workers
        .register(worker_id, WorkerRuntimeRecord::for_test(handle), None);
    atomics
}

fn publish_capped_9654(coord: &mut Coordinator, capped: bool) {
    let mut forwarding = ForwardingState::default();
    forwarding.learned_route_import_capped = capped;
    coord.set_forwarding_for_test(forwarding);
}

fn published_capped_9654(coord: &Coordinator) -> bool {
    coord
        .ha
        .runtime
        .load()
        .forwarding()
        .learned_route_import_capped
}

/// No worker record: nothing serves the published view, so the answer is
/// unknown however that view is flagged. A helper before its first bring-up
/// and a deferred-worker apply (`defer_workers`, no spawn) are in this state.
#[test]
fn capped_now_is_unknown_without_a_live_worker_9654() {
    let mut coord = Coordinator::new();
    publish_capped_9654(&mut coord, true);
    assert!(
        published_capped_9654(&coord),
        "fixture: the published view must be capped, or None here proves nothing"
    );
    assert_eq!(coord.learned_route_import_capped_now(), None);
}

#[test]
fn capped_now_follows_the_published_view_while_a_worker_is_live_9654() {
    let mut coord = Coordinator::new();
    register_worker_9654(&mut coord, 0);
    publish_capped_9654(&mut coord, true);
    assert_eq!(coord.learned_route_import_capped_now(), Some(true));
    publish_capped_9654(&mut coord, false);
    assert_eq!(coord.learned_route_import_capped_now(), Some(false));
}

/// A candidate installed in `self.forwarding` but not yet published is not what
/// workers serve. Design 2 read from there, and that was its HIGH finding.
#[test]
fn capped_now_ignores_an_unpublished_candidate_9654() {
    let mut coord = Coordinator::new();
    register_worker_9654(&mut coord, 0);
    publish_capped_9654(&mut coord, false);
    coord.forwarding.learned_route_import_capped = true;
    assert_eq!(
        coord.learned_route_import_capped_now(),
        Some(false),
        "an unpublished candidate must not change the answer"
    );
    coord.publish_runtime_view();
    assert_eq!(coord.learned_route_import_capped_now(), Some(true));
}

#[test]
fn capped_now_is_unknown_once_every_worker_is_dead_9654() {
    let mut coord = Coordinator::new();
    let first = register_worker_9654(&mut coord, 0);
    publish_capped_9654(&mut coord, true);
    first.dead.store(true, AtomicOrdering::Relaxed);
    assert_eq!(
        coord.learned_route_import_capped_now(),
        None,
        "a dead worker serves nothing"
    );
    let second = register_worker_9654(&mut coord, 1);
    assert_eq!(
        coord.learned_route_import_capped_now(),
        Some(true),
        "one live worker is enough"
    );
    second.dead.store(true, AtomicOrdering::Relaxed);
    assert_eq!(coord.learned_route_import_capped_now(), None);
}

/// AF_XDP teardown while the process still answers status: `stop` joins and
/// clears every record, so the answer returns to unknown.
#[test]
fn capped_now_is_unknown_after_teardown_9654() {
    let mut coord = Coordinator::new();
    register_worker_9654(&mut coord, 0);
    publish_capped_9654(&mut coord, true);
    assert_eq!(coord.learned_route_import_capped_now(), Some(true));
    coord.stop();
    assert_eq!(coord.learned_route_import_capped_now(), None);
}

/// Same-plan refresh through the real `refresh_runtime_snapshot`: it builds
/// forwarding from the snapshot, which carries the flag, and publishes it.
#[test]
fn capped_now_tracks_a_real_snapshot_refresh_9654() {
    let mut coord = Coordinator::new();
    register_worker_9654(&mut coord, 0);
    let capped = ConfigSnapshot {
        generation: 1,
        learned_route_import_capped: true,
        ..Default::default()
    };
    coord
        .refresh_runtime_snapshot(&capped)
        .expect("capped refresh must succeed");
    assert_eq!(coord.learned_route_import_capped_now(), Some(true));
    let uncapped = ConfigSnapshot {
        generation: 2,
        ..Default::default()
    };
    coord
        .refresh_runtime_snapshot(&uncapped)
        .expect("uncapped refresh must succeed");
    assert_eq!(coord.learned_route_import_capped_now(), Some(false));
}

/// Design 2's HIGH finding, driven through the real `reconcile`. The first
/// worker's spawn fails after teardown, so no record exists, while the
/// candidate's capped view is what was published. Status must say unknown.
#[test]
fn capped_now_is_unknown_after_a_first_worker_spawn_failure_9654() {
    let mut coord = Coordinator::new();
    let mut bindings: Vec<BindingStatus> = vec![BindingStatus {
        slot: 1,
        worker_id: 0,
        queue_id: 0,
        interface: "ge-0-0-0".into(),
        ifindex: 10,
        registered: true,
        ..BindingStatus::default()
    }];
    coord.force_worker_spawn_fail = 1;
    let ok = crate::afxdp::bpf_map::TEST_MAP_PIN_OK;
    let snap = ConfigSnapshot {
        generation: 5,
        map_pins: crate::protocol::snapshot::MapPins {
            xsk: format!("{ok}xsk"),
            heartbeat: format!("{ok}heartbeat"),
            sessions: format!("{ok}sessions"),
            ..Default::default()
        },
        learned_route_import_capped: true,
        ..Default::default()
    };
    let result = coord.reconcile(Some(&snap), &mut bindings, 64);
    assert!(
        matches!(result, Err(crate::afxdp::ReconcileError::WorkerSpawn(_))),
        "fixture: expected the forced first-worker spawn failure, got {result:?}"
    );
    assert!(
        coord.workers.records().is_empty(),
        "fixture: a failed first spawn registers no record"
    );
    assert!(
        published_capped_9654(&coord),
        "fixture: the failed reconcile must have published the capped candidate, \
         or this cell cannot tell the view from the liveness gate"
    );
    assert_eq!(coord.learned_route_import_capped_now(), None);
}

/// The status projection and the wire. Unknown is `None` and the key is
/// omitted; a live worker on a capped view serializes `true`.
#[test]
fn refresh_status_projects_capped_now_and_omits_it_when_unknown_9654() {
    let mut state = crate::server::state::ServerState {
        status: Default::default(),
        snapshot: None,
        afxdp: Coordinator::new(),
        state_writer: std::sync::Arc::new(crate::state_writer::StateWriter::new()),
    };
    publish_capped_9654(&mut state.afxdp, true);
    crate::server::helpers::status::refresh_status(&mut state);
    assert_eq!(state.status.learned_route_import_capped, None);
    let json = serde_json::to_value(&state.status).expect("status serializes");
    assert!(
        json.get("learned_route_import_capped").is_none(),
        "unknown must be omitted on the wire, got {:?}",
        json.get("learned_route_import_capped")
    );

    register_worker_9654(&mut state.afxdp, 0);
    crate::server::helpers::status::refresh_status(&mut state);
    assert_eq!(state.status.learned_route_import_capped, Some(true));
    let json = serde_json::to_value(&state.status).expect("status serializes");
    assert_eq!(
        json.get("learned_route_import_capped"),
        Some(&serde_json::Value::Bool(true))
    );
}
