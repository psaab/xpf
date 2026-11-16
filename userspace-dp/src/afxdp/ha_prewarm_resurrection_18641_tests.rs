//! #19145 (found in #18641): the RG-activation prewarm resurrects a session that a concurrent
//! delete has just closed.
//!
//! `prewarm_reverse_synced_sessions_for_owner_rgs` (shared_ops/owner_rg.rs)
//! snapshots its candidates under the shared-session lock and RELEASES it. Only
//! then does it:
//! 1. publish each forward's steering row;
//! 2. publish each synthesized reverse into the shared map, and publish its
//!    steering row;
//! 3. push a SNAPSHOT `UpsertSynced` of every forward and reverse to every
//!    worker queue.
//!
//! A `sync_session` delete is served on its own socket and thread, off the
//! server lock that `update_ha_state` runs under (#452,
//! server/handlers/mod.rs). So it can run between the snapshot and those
//! writes. The delete removes the shared rows, deletes their steering rows and
//! pushes `DeleteSynced` to every worker (ha/session_import.rs). The prewarm's
//! later writes then land BEHIND it, and nothing fences them:
//! - the worker upsert has no tombstone check, so the worker re-installs the
//!   closed session;
//! - the shared map regains a reverse whose forward is gone;
//! - the steering map regains rows for the deleted tuples.
//!
//! `PREWARM_AFTER_COLLECT_HOOK_18641` runs a real peer delete at exactly that
//! point.
//!
//! **The control arm** is the same activation with the seam empty. It must
//! produce every row the defect arm says must be absent, or an "absent" would
//! also pass for an activation that writes nothing.

use super::*;
use crate::afxdp::bpf_map::{
    RECORDER_ONLY_MAP_FD, clear_session_map_writes, session_map_writes,
};

const WORKER_ID: u32 = 0;

struct Activation {
    coordinator: Coordinator,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    forward: SessionKey,
    reverse: SessionKey,
}

/// Which RG the activation under test brings up, on the split-RG forwarding
/// fixture (WAN on RG1, LAN on RG2). The session's forward is owned by RG1
/// and its reverse resolves to RG2.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// RG2 is already active and RG1, the forward's owner, activates. The
    /// forward is in the owner index (S), so the republish writes its steering
    /// row (#18641 step 1).
    OwnerActivates,
    /// RG1 stays inactive and RG2, the reverse's RG, activates. The forward is
    /// a candidate only through the reverse-prewarm index, so the PREWARM
    /// writes its steering row (#287/#524).
    SplitReverseActivates,
}

/// The split-RG fixture of
/// `update_ha_state_prewarms_split_rg_reverse_sessions_on_activation`, with
/// RG2 already active for `Shape::OwnerActivates` and inactive for
/// `Shape::SplitReverseActivates`.
///
/// The session is imported through the production verb, so the worker's
/// queue starts with the import's own `UpsertSynced`: the worker held the
/// session before the delete, as it would in production. The steering map
/// is the recorder-only descriptor, so every steering write and delete is
/// observable.
fn seeded_for(shape: Shape) -> Activation {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(test_forwarding_state_split_rgs());
    coordinator
        .bpf_maps
        .store(Arc::new(crate::afxdp::coordinator::BpfMaps {
            session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd {
                fd: RECORDER_ONLY_MAP_FD,
            }),
            ..Default::default()
        }));
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        WORKER_ID,
        WorkerRuntimeRecord::for_test(test_worker_handle(commands.clone())),
        None,
    );
    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: false,
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: matches!(shape, Shape::OwnerActivates),
                ..HAGroupStatus::default()
            },
        ])
        .expect("seed initial HA state");
    let entry = synced_entry_port(52_641, 1);
    let forward = entry.key.clone();
    let reverse = reverse_session_key(&entry.key, entry.decision.nat);
    let imported = coordinator.upsert_synced_session(entry);
    assert!(
        coordinator.synced_session_contains(&forward),
        "FIXTURE: the import must file the forward in the shared map ({imported:?})"
    );
    Activation {
        coordinator,
        commands,
        forward,
        reverse,
    }
}

fn activate(coordinator: &Coordinator, shape: Shape) {
    coordinator
        .update_ha_state(&[
            HAGroupStatus {
                rg_id: 1,
                active: matches!(shape, Shape::OwnerActivates),
                ..HAGroupStatus::default()
            },
            HAGroupStatus {
                rg_id: 2,
                active: true,
                ..HAGroupStatus::default()
            },
        ])
        .expect("activate rg1");
}

/// Drain the worker queue into a real worker table, the way the worker loop
/// does: in queue order, under the now-current HA runtime.
fn drain(a: &Activation) -> SessionTable {
    let mut worker_sessions = SessionTable::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = a.coordinator.ha.rg_runtime.load_full();
    let mut scratch = VecDeque::new();
    for _ in 0..64 {
        if a.commands.lock().expect("commands").is_empty() {
            break;
        }
        let _ = apply_worker_commands(
            &a.commands,
            &mut worker_sessions,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            &a.coordinator.forwarding,
            &ha_state,
            &dynamic_neighbors,
            WORKER_ID,
            &mut scratch,
        );
    }
    assert!(
        a.commands.lock().expect("commands").is_empty(),
        "FIXTURE: the drain must empty the worker queue"
    );
    worker_sessions
}

/// The LAST steering record for `key` is a write: the row exists after the
/// activation.
fn steering_row_present(key: &SessionKey) -> bool {
    session_map_writes()
        .iter()
        .rev()
        .find(|record| &record.key == key)
        .is_some_and(|record| record.value.is_some())
}

/// The control arm. With no concurrent delete, the activation must leave:
/// - the forward and its reverse in the shared map;
/// - both steering rows;
/// - both halves installed on the worker.
///
/// These are exactly the rows the defect arm requires to be absent, so the
/// defect arm cannot pass on an activation that writes nothing.
#[test]
fn activation_prewarm_without_a_concurrent_delete_restores_both_halves_18641() {
    assert_activation_restores_both_halves(Shape::OwnerActivates);
}

/// #19145: the control for the split-RG shape, where the prewarm (not the
/// republish) writes the forward's steering row.
#[test]
fn split_rg_activation_without_a_concurrent_delete_restores_both_halves_19145() {
    assert_activation_restores_both_halves(Shape::SplitReverseActivates);
}

fn assert_activation_restores_both_halves(shape: Shape) {
    let a = seeded_for(shape);
    clear_session_map_writes();

    activate(&a.coordinator, shape);

    let mut missing: Vec<&str> = Vec::new();
    if !a.coordinator.synced_session_contains(&a.forward) {
        missing.push("shared forward");
    }
    if !a.coordinator.synced_session_contains(&a.reverse) {
        missing.push("shared reverse (the prewarm synthesizes and publishes it)");
    }
    if !steering_row_present(&a.forward) {
        missing.push("forward steering row");
    }
    if !steering_row_present(&a.reverse) {
        missing.push("reverse steering row");
    }
    let worker = drain(&a);
    if worker.entry_with_origin(&a.forward).is_none() {
        missing.push("worker forward");
    }
    if worker.entry_with_origin(&a.reverse).is_none() {
        missing.push("worker reverse");
    }
    assert!(
        missing.is_empty(),
        "CONTROL ({shape:?}): the activation did not produce {missing:?}; the defect \
         arm's absences would be vacuous"
    );
}

/// Run the activation with a real peer delete at `seam`, then check that
/// nothing of the deleted session remains: no shared row, no steering row and
/// no worker row, for either half. `window` names the race in the report.
fn assert_delete_at_seam_is_not_undone(
    seam: &'static std::thread::LocalKey<std::cell::RefCell<Option<Box<dyn FnOnce()>>>>,
    window: &str,
    shape: Shape,
) {
    let a = seeded_for(shape);
    clear_session_map_writes();

    let domain = a.coordinator.session_domain().clone();
    let key = a.forward.clone();
    let outcome: std::rc::Rc<std::cell::Cell<Option<SyncedDeleteOutcome>>> =
        std::rc::Rc::new(std::cell::Cell::new(None));
    let record = std::rc::Rc::clone(&outcome);
    seam.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            record.set(Some(domain.delete_synced(key, SyncedDeleteMode::PEER, false)));
        }));
    });

    activate(&a.coordinator, shape);

    assert_eq!(
        outcome.get(),
        Some(SyncedDeleteOutcome::Applied),
        "FIXTURE ({window}, {shape:?}): the seam must have run, and the peer delete must \
         have applied"
    );
    // Properties COLLECTED, not asserted in sequence, so that one run reports
    // every layer that resurrects.
    let mut violations: Vec<String> = Vec::new();
    if a.coordinator.synced_session_contains(&a.forward) {
        violations.push("the shared map holds the deleted forward again".to_string());
    }
    if a.coordinator.synced_session_contains(&a.reverse) {
        violations.push(
            "the shared map holds a reverse whose forward was deleted (the prewarm's \
             reverse publish ran after the delete)"
                .to_string(),
        );
    }
    let writes = session_map_writes();
    let row_records = |key: &SessionKey| {
        writes
            .iter()
            .filter(|r| &r.key == key)
            .map(|r| r.value)
            .collect::<Vec<_>>()
    };
    if steering_row_present(&a.forward) {
        violations.push(format!(
            "the deleted forward's steering row was re-written after the delete. Writes: \
             {:?}",
            row_records(&a.forward)
        ));
    }
    if steering_row_present(&a.reverse) {
        violations.push(format!(
            "the deleted reverse's steering row was re-written after the delete. Writes: \
             {:?}",
            row_records(&a.reverse)
        ));
    }
    let queued: Vec<String> = a
        .commands
        .lock()
        .expect("commands")
        .iter()
        .map(|command| match command {
            WorkerCommand::UpsertSynced(entry) if entry.key == a.forward => {
                "UpsertSynced(forward)".to_string()
            }
            WorkerCommand::UpsertSynced(entry) if entry.key == a.reverse => {
                "UpsertSynced(reverse)".to_string()
            }
            WorkerCommand::PrewarmSynced { entry, .. } if entry.key == a.forward => {
                "PrewarmSynced(forward)".to_string()
            }
            WorkerCommand::PrewarmSynced { entry, .. } if entry.key == a.reverse => {
                "PrewarmSynced(reverse)".to_string()
            }
            WorkerCommand::DeleteSynced(key) if *key == a.forward => {
                "DeleteSynced(forward)".to_string()
            }
            WorkerCommand::DeleteSynced(key) if *key == a.reverse => {
                "DeleteSynced(reverse)".to_string()
            }
            WorkerCommand::RefreshOwnerRGS { .. } => "RefreshOwnerRGS".to_string(),
            _ => "other".to_string(),
        })
        .collect();
    let worker = drain(&a);
    if worker.entry_with_origin(&a.forward).is_some() {
        violations.push(format!(
            "the worker re-installed the deleted forward. Queue order: {queued:?}"
        ));
    }
    if worker.entry_with_origin(&a.reverse).is_some() {
        violations.push(format!(
            "the worker re-installed the deleted session's reverse. Queue order: {queued:?}"
        ));
    }
    assert!(
        violations.is_empty(),
        "#19145 resurrection ({window}, {shape:?}): {} of 6 properties violated:\n  - {}",
        violations.len(),
        violations.join("\n  - ")
    );
}

/// The defect arm. A peer delete lands after the prewarm's snapshot and
/// before its writes. After the activation and the worker drain, nothing of
/// the deleted session may remain.
#[test]
fn activation_prewarm_does_not_resurrect_a_session_deleted_after_its_snapshot_18641() {
    assert_delete_at_seam_is_not_undone(
        &crate::afxdp::shared_ops::PREWARM_AFTER_COLLECT_HOOK_18641,
        "after the prewarm's snapshot",
        Shape::OwnerActivates,
    );
}

/// #19145: the same window in the split-RG shape. Here the PREWARM writes the
/// forward's steering row, an R-only forward that the republish does not
/// reach, so that write's own fence is what keeps the deleted row deleted.
#[test]
fn split_rg_activation_prewarm_does_not_resurrect_a_session_deleted_after_its_snapshot_19145() {
    assert_delete_at_seam_is_not_undone(
        &crate::afxdp::shared_ops::PREWARM_AFTER_COLLECT_HOOK_18641,
        "after the prewarm's snapshot",
        Shape::SplitReverseActivates,
    );
}

/// #19145: a delete between the prewarm's admitted reverse publish and that
/// reverse's steering write. The reverse IS in the shared map when it is
/// admitted, so only the steering write's own fence can see the delete.
#[test]
fn activation_prewarm_does_not_resurrect_a_session_deleted_after_its_reverse_publish_19145() {
    assert_delete_at_seam_is_not_undone(
        &crate::afxdp::shared_ops::PREWARM_AFTER_REVERSE_PUBLISH_HOOK_19145,
        "after the prewarm's reverse publish",
        Shape::OwnerActivates,
    );
}

/// #19145: the same race in the republish's own window, between its snapshot
/// and its writes. Since #18641 step 1, the republish is the only activation
/// writer of an owner-index forward's steering row. This delete lands after
/// the prewarm has published the reverse and queued both worker restores, so
/// every layer has to see the delete at its own later point.
#[test]
fn activation_republish_does_not_resurrect_a_session_deleted_after_its_snapshot_19145() {
    assert_delete_at_seam_is_not_undone(
        &crate::afxdp::shared_ops::REPUBLISH_AFTER_COLLECT_HOOK_19145,
        "after the republish's snapshot",
        Shape::OwnerActivates,
    );
}
