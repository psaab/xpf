// #17111: parity guards for the single-source bring-up statements.
//
// The SA gate and the supervised worker spawn must each be written ONCE
// in `bringup.rs`, with the `#[cfg(test)]` force seams in `test_seams.rs`
// only pre-empting them. A `#[cfg(not(test))]` twin (or a copy of either
// production call) in `bringup.rs` fails these cells.
use super::*;

const BRINGUP_SRC: &str = include_str!("bringup.rs");

#[test]
fn bringup_has_no_not_test_twin_of_production_statements_17111() {
    assert_eq!(
        BRINGUP_SRC.matches("cfg(not(test))").count(),
        0,
        "bringup.rs must not restate a production statement under cfg(not(test)); \
         seams live in test_seams.rs and return an override instead"
    );
}

#[test]
fn bringup_writes_each_production_statement_once_17111() {
    assert_eq!(
        BRINGUP_SRC.matches("wait_ready(").count(),
        1,
        "the SA readiness wait must appear exactly once in bringup.rs"
    );
    assert_eq!(
        BRINGUP_SRC.matches("spawn_supervised_worker(").count(),
        1,
        "the supervised worker spawn must appear exactly once in bringup.rs"
    );
}

/// With no force flag set, the SA seam falls through (`None`) and the
/// spawn seam hands the worker body back untouched, so the test build
/// executes the same production statements the release build does.
#[test]
fn test_seams_fall_through_when_no_force_flag_set_17111() {
    let mut coord = Coordinator::new();
    assert!(
        super::super::test_seams::test_sa_ready_override(&mut coord).is_none(),
        "SA seam must fall through to the production monitor gate"
    );
    coord.force_ipsec_sa_not_ready = true;
    assert_eq!(
        super::super::test_seams::test_sa_ready_override(&mut coord),
        Some(false),
    );
    coord.force_ipsec_sa_not_ready = false;

    let planned_slots = std::collections::BTreeSet::new();
    let spawn_slots: Vec<(u32, u32, Arc<str>, i32, Arc<BindingLiveState>)> = Vec::new();
    let startup_gate = Arc::new(std::sync::Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let heartbeat = Arc::new(AtomicU64::new(0));
    let (tx, _rx) = mpsc::channel::<WorkerStartupReport>();
    let runtime_atomics = Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new());
    let panic_slot = Arc::new(Mutex::new(None::<String>));
    let ctx = super::super::test_seams::test_spawn_ctx(
        &spawn_slots,
        &planned_slots,
        &startup_gate,
        &stop,
        &heartbeat,
        &tx,
    );
    match super::super::test_seams::test_spawn_override(
        &mut coord,
        ctx,
        0,
        runtime_atomics,
        panic_slot,
        || {},
    ) {
        super::super::test_seams::TestSpawnOutcome::FallThrough(_body) => {}
        super::super::test_seams::TestSpawnOutcome::Override(_) => {
            panic!("spawn seam must fall through when no force flag is set")
        }
    }

    coord.force_worker_spawn_fail = 1;
    let ctx = super::super::test_seams::test_spawn_ctx(
        &spawn_slots,
        &planned_slots,
        &startup_gate,
        &stop,
        &heartbeat,
        &tx,
    );
    let runtime_atomics = Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new());
    let panic_slot = Arc::new(Mutex::new(None::<String>));
    match super::super::test_seams::test_spawn_override(
        &mut coord,
        ctx,
        0,
        runtime_atomics,
        panic_slot,
        || {},
    ) {
        super::super::test_seams::TestSpawnOutcome::Override(result) => {
            assert!(result.is_err(), "forced spawn failure must synthesize Err");
        }
        super::super::test_seams::TestSpawnOutcome::FallThrough(_) => {
            panic!("forced spawn failure must pre-empt the production spawn")
        }
    }
    assert_eq!(coord.force_worker_spawn_fail, 0, "seam consumes the credit");
}
