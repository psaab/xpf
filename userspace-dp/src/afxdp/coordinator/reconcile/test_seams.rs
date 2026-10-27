//! #17111: test-injection seams for the bring-up production statements.
//!
//! A seam pre-empts a production statement only when a `#[cfg(test)]`
//! force flag requests it. Otherwise production in `bringup.rs` writes
//! each statement ONCE and executes it:
//!
//! - the IPsec-SA readiness gate (`ensure_ipsec_sa_monitor` + `wait_ready`);
//! - the supervised worker spawn (`spawn_supervised_worker`).
//!
//! Before #17111 both statements were also restated in a `#[cfg(not(test))]`
//! twin in `bringup.rs`, so tests executed a copy and an edit to only the
//! release copy reached production with no test signal. In release builds
//! both seams below are `#[inline]` no-ops; the single production statement
//! in `bringup.rs` is what every build executes.
use super::super::super::*;
use super::super::supervisor::spawn_supervised_worker;
use super::super::Coordinator;

/// #17111: IPsec-SA readiness override for `bring_up_workers`.
///
/// `Some(false)` forces the not-ready unwind, `Some(true)` pins an empty
/// ready baseline; `None` lets production run its single monitor gate.
#[cfg(test)]
pub(super) fn test_sa_ready_override(coord: &mut Coordinator) -> Option<bool> {
    if coord.force_ipsec_sa_not_ready {
        // #14130: forced not-ready so the unwinding is verifiable without a
        // privileged monitor. Production retains the gate.
        Some(false)
    } else if coord.force_ipsec_sa_ready {
        // #10694: explicit empty baseline pin for worker bring-up seam tests.
        // Production retains the mandatory monitor gate on `None`.
        coord
            .neighbors
            .ipsec_sa_monitor
            .store
            .reset_for_monitor_start();
        coord
            .neighbors
            .ipsec_sa_monitor
            .store
            .publish_empty_dump_for_test();
        Some(true)
    } else {
        None
    }
}

/// #17111: release no-op — see the `cfg(test)` twin above.
#[cfg(not(test))]
#[inline]
pub(super) fn test_sa_ready_override(_coord: &mut Coordinator) -> Option<bool> {
    None
}

/// #17111: whether the spawn seam pre-empted the production spawn.
/// `FallThrough` hands the untouched worker body back so `bringup.rs`
/// runs its single `spawn_supervised_worker` call with it.
pub(super) enum TestSpawnOutcome<F> {
    Override(std::io::Result<JoinHandle<()>>),
    FallThrough(F),
}
/// #17111: the per-worker context the spawn seam needs in test builds.
/// `stub_lives` is owned (built from the caller's `spawn_slots`, the same
/// `BindingLiveState` allocations the plans carry); the rest are borrows
/// the stub arms clone into the stub thread, exactly as the pre-#17111
/// inline arms did.
#[cfg(test)]
pub(super) struct TestSpawnCtx<'a> {
    planned_slots: &'a std::collections::BTreeSet<u32>,
    stub_lives: BTreeMap<u32, Arc<BindingLiveState>>,
    startup_gate: &'a Arc<std::sync::Barrier>,
    stop: &'a Arc<AtomicBool>,
    heartbeat: &'a Arc<AtomicU64>,
    startup_report_tx: &'a mpsc::Sender<WorkerStartupReport>,
}

/// #17111: release placeholder — carries nothing, costs nothing.
#[cfg(not(test))]
pub(super) struct TestSpawnCtx<'a> {
    _marker: std::marker::PhantomData<&'a ()>,
}

/// #17111: one signature for both builds so `bringup.rs` needs no
/// `cfg` attribute at the call site. The test build derives the stub
/// live-state map from `spawn_slots`; the release build ignores every
/// argument and the seam is an inline no-op.
pub(super) fn test_spawn_ctx<'a>(
    spawn_slots: &[(u32, u32, Arc<str>, i32, Arc<BindingLiveState>)],
    planned_slots: &'a std::collections::BTreeSet<u32>,
    startup_gate: &'a Arc<std::sync::Barrier>,
    stop: &'a Arc<AtomicBool>,
    heartbeat: &'a Arc<AtomicU64>,
    startup_report_tx: &'a mpsc::Sender<WorkerStartupReport>,
) -> TestSpawnCtx<'a> {
    #[cfg(test)]
    {
        TestSpawnCtx {
            planned_slots,
            stub_lives: spawn_slots
                .iter()
                .map(|(slot, _, _, _, live)| (*slot, Arc::clone(live)))
                .collect(),
            startup_gate,
            stop,
            heartbeat,
            startup_report_tx,
        }
    }
    #[cfg(not(test))]
    {
        let _ = (
            spawn_slots,
            planned_slots,
            startup_gate,
            stop,
            heartbeat,
            startup_report_tx,
        );
        TestSpawnCtx {
            _marker: std::marker::PhantomData,
        }
    }
}
/// #17111: worker-spawn override for `spawn_workers`.
///
/// Returns `Override(join)` when a force seam pre-empts the real spawn
/// (stub thread or synthesized spawn error, `body` dropped unspawned)
/// and `FallThrough(body)` when production must run its single
/// `spawn_supervised_worker` call with the untouched body.
#[cfg(test)]
pub(super) fn test_spawn_override<F>(
    coord: &mut Coordinator,
    ctx: TestSpawnCtx<'_>,
    worker_id: u32,
    runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
    panic_slot: Arc<Mutex<Option<String>>>,
    body: F,
) -> TestSpawnOutcome<F>
where
    F: FnOnce() + Send + 'static,
{
    let planned_slots = ctx.planned_slots;
    let stub_lives = &ctx.stub_lives;
    // #4952 test seam: force the fallible worker spawn to fail so the
    // post-teardown fail-closed propagation is unit-verifiable without a
    // real (unprovokable) pthread_create EAGAIN/ENOMEM. Declines the real
    // spawn, drops the worker body unspawned, and synthesizes the same
    // `std::io::Error` a resource-exhausted spawn returns. Always 0 in
    // release builds (`force_worker_spawn_fail` is `#[cfg(test)]`).
    //
    // #5143 test seam: force a SPAWNED worker to report an INCOMPLETE
    // startup bound-slot set (a worker whose in-thread XSK/UMEM bind failed
    // for one or more planned bindings but keeps heartbeating). A real
    // `worker_loop` cannot bind a real XSK in-process, so instead spawn a
    // joinable STUB thread that reports a bound set MISSING one planned
    // slot, then heartbeats until stopped — exercising the readiness
    // barrier's fail-close + stop/join end to end. Checked BEFORE the
    // spawn-fail seam so the two are mutually exclusive per worker.
    if coord.force_worker_bind_incomplete > 0 {
        coord.force_worker_bind_incomplete -= 1;
        drop(body);
        // Report every planned slot EXCEPT one (`skip(1)`), so with a
        // single planned binding the reported set is empty and with N it
        // is short by one — either way bound != planned -> barrier fails
        // closed.
        let incomplete_bound: Vec<u32> = planned_slots.iter().copied().skip(1).collect();
        // #8388: publish the bound live state for the slots this stub
        // reports bound. Synchronous (before the spawn) rather than inside
        // the stub body so the surface is race-free: the `SpawnFailed` arm
        // returns without ever reaching the readiness barrier, so a
        // stub-thread publish would not be ordered against the reconcile's
        // closing `refresh_bindings`.
        for slot in &incomplete_bound {
            if let Some(live) = stub_lives.get(slot) {
                live.set_bound(-1);
            }
        }
        // #6245: the omitted slot is the SMALLEST planned slot (`skip(1)`
        // drops the first of the sorted BTreeSet). Report it as an EXPLICIT
        // per-slot failure so the barrier surfaces the cause, exercising the
        // #6245 explicit-failure contract end-to-end (a real `worker_loop`
        // cannot bind an XSK in-process). Empty when no slots are planned.
        let stub_failures: Vec<BindingSetupFailure> = planned_slots
            .iter()
            .copied()
            .next()
            .map(|slot| BindingSetupFailure {
                slot,
                interface: "ge-0-0-1".to_string(),
                queue_id: slot,
                phase: BindingSetupPhase::Private,
                // #8558: shaped like the real `bind.rs` failure text so the
                // cause a cell reads back is the cause production
                // publishes — including the "Device or resource busy"
                // substring `hasBusyBindingsWedgeLocked` keys on. The
                // original seam wording is retained verbatim inside it, so
                // the #6245 stage-rendering cell that pins that phrase is
                // unaffected.
                reason: "libxdp private bind(flags=0x0004): Device or resource \
busy — forced private bind failure (test seam #6245)"
                    .to_string(),
            })
            .into_iter()
            .collect();
        // #8558: mirror `worker_loop_setup`'s `live.set_error(reason)` on
        // the slot whose bind failed. The stub is the only in-process stand
        // -in for a real bind failure, and a stub that reports the shortfall
        // without publishing the cause into its `BindingLiveState` would let
        // a fix that reads the cause from `live` (rather than from the
        // fail-closed stage) look correct here while doing nothing in
        // production — `stop_inner` drops `live` before anything reads it.
        for failure in &stub_failures {
            if let Some(live) = stub_lives.get(&failure.slot) {
                live.set_error(failure.reason.clone());
            }
        }
        let startup_gate_for_stub = Arc::clone(ctx.startup_gate);
        let stub_stop = ctx.stop.clone();
        let stub_heartbeat = ctx.heartbeat.clone();
        let stub_tx = ctx.startup_report_tx.clone();
        let stub_worker_id = worker_id;
        TestSpawnOutcome::Override(spawn_supervised_worker(
            worker_id,
            runtime_atomics,
            panic_slot,
            move || {
                startup_gate_for_stub.wait();
                let _ = stub_tx.send(WorkerStartupReport {
                    worker_id: stub_worker_id,
                    bound_slots: incomplete_bound,
                    binding_failures: stub_failures,
                    recovered_fallbacks: Vec::new(),
                });
                // Heartbeat while "live-but-unbound" until the barrier
                // stops us — bounded so a REVERTED (barrier removed) build
                // does not leak a thread forever.
                let mut ticks = 0u32;
                while !stub_stop.load(Ordering::Relaxed) && ticks < 5_000 {
                    stub_heartbeat.store(monotonic_nanos(), Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(1));
                    ticks += 1;
                }
            },
        ))
    } else if coord.force_worker_spawn_fail > 0 && coord.force_worker_spawn_fail_skip == 0 {
        // #4952 / #6242: the forced spawn failure fires once the skip credit
        // is exhausted. With `force_worker_spawn_fail_skip == 0` (the #4952
        // default) this fails the FIRST planned worker; with a positive skip
        // it fails the `(skip+1)`th, after the first `skip` workers launched
        // (as healthy stubs, below) — exercising PARTIAL-success rollback.
        coord.force_worker_spawn_fail -= 1;
        drop(body);
        TestSpawnOutcome::Override(Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "forced worker spawn failure (test seam #4952/#6242)",
        )))
    } else if coord.force_worker_healthy_stub {
        // #6242: benign HEALTHY stub — reports the FULL planned bound set so
        // the readiness barrier passes, then heartbeats until stopped. Used
        // to launch the workers that PRECEDE a fail-at-K spawn failure (or
        // that coexist with a single bind-incomplete worker) WITHOUT running
        // the real `worker_loop`, which cannot bind a real XSK in-process.
        // When skipping toward a forced failure, consume one skip credit so
        // the failure fires on the intended Kth worker.
        if coord.force_worker_spawn_fail > 0 && coord.force_worker_spawn_fail_skip > 0 {
            coord.force_worker_spawn_fail_skip -= 1;
        }
        drop(body);
        let full_bound: Vec<u32> = planned_slots.iter().copied().collect();
        // #8388: see the sibling publish in the bind-incomplete arm. A
        // HEALTHY stub reports its full planned set, so it publishes bound
        // live state for all of it — that is what makes "the fail-close
        // stopped the healthy siblings too" observable on the binding
        // surface instead of only in `workers.records`.
        for slot in &full_bound {
            if let Some(live) = stub_lives.get(slot) {
                live.set_bound(-1);
            }
        }
        let startup_gate_for_stub = Arc::clone(ctx.startup_gate);
        let stub_stop = ctx.stop.clone();
        let stub_heartbeat = ctx.heartbeat.clone();
        let stub_tx = ctx.startup_report_tx.clone();
        let stub_worker_id = worker_id;
        TestSpawnOutcome::Override(spawn_supervised_worker(
            worker_id,
            runtime_atomics,
            panic_slot,
            move || {
                startup_gate_for_stub.wait();
                let _ = stub_tx.send(WorkerStartupReport {
                    worker_id: stub_worker_id,
                    bound_slots: full_bound,
                    binding_failures: Vec::new(),
                    recovered_fallbacks: Vec::new(),
                });
                let mut ticks = 0u32;
                while !stub_stop.load(Ordering::Relaxed) && ticks < 5_000 {
                    stub_heartbeat.store(monotonic_nanos(), Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(1));
                    ticks += 1;
                }
            },
        ))
    } else {
        TestSpawnOutcome::FallThrough(body)
    }
}

/// #17111: release no-op — see the `cfg(test)` twin above. The single
/// `spawn_supervised_worker` call in `bringup.rs` runs in every build.
#[cfg(not(test))]
#[inline]
pub(super) fn test_spawn_override<F>(
    _coord: &mut Coordinator,
    _ctx: TestSpawnCtx<'_>,
    _worker_id: u32,
    _runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
    _panic_slot: Arc<Mutex<Option<String>>>,
    body: F,
) -> TestSpawnOutcome<F>
where
    F: FnOnce() + Send + 'static,
{
    TestSpawnOutcome::FallThrough(body)
}
