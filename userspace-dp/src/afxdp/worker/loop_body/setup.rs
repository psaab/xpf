// #1776 — one-shot `worker_loop` setup, extracted from
// loop_body/mod.rs (pure code motion per the converged v3.1 plan on
// research/1776-loop-body-decomp).
//
// Everything here runs EXACTLY ONCE per worker thread, before the
// main `loop {}` in `worker_loop`: thread pinning, cold-path TSC
// calibration, the initial ArcSwap `load_full`s, binding
// construction from plans, CoS fast-interface wiring, the
// interrupt-mode pollfd set, the BPF-map-FD cache, and the initial
// `cos_status` publish. The returned `WorkerLoopSetup` is
// destructured back into the same-named locals in `worker_loop`, so
// the loop body itself is textually unchanged.
//
// Cold by construction (`#[inline(never)]`): hoisting this out of
// `worker_loop` shrinks the hot function without adding any call
// boundary to the per-tick path.
//
// `use super::*;` chains through loop_body/mod.rs to worker/mod.rs —
// the same glob pattern lifecycle.rs and loop_body/mod.rs use.

use super::*;

use crate::afxdp::worker_runtime::current_tid;

/// Initial mutable state for the worker loop, produced once by
/// [`worker_loop_setup`]. Field order mirrors construction order in
/// the original inline setup block.
pub(super) struct WorkerLoopSetup {
    pub(super) ha_startup_grace_until_secs: u64,
    pub(super) validation: ValidationState,
    pub(super) forwarding: Arc<ForwardingState>,
    pub(super) cos_owner_worker_by_queue: Arc<BTreeMap<(i32, u8), u32>>,
    pub(super) cos_owner_live_by_queue: Arc<BTreeMap<(i32, u8), Arc<BindingLiveState>>>,
    pub(super) cos_shared_root_leases: Arc<BTreeMap<i32, Arc<SharedCoSRootLease>>>,
    pub(super) cos_shared_exact_backlogs: Arc<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>,
    pub(super) cos_shared_queue_leases: Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>,
    pub(super) cos_shared_queue_vtime_floors:
        Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    pub(super) mirror_targets: Arc<MirrorTargetMap>,
    pub(super) sessions: SessionTable,
    pub(super) screen_state: ScreenState,
    pub(super) bindings: Vec<BindingWorker>,
    pub(super) binding_lookup: WorkerBindingLookup,
    pub(super) interrupt_poll_fds: Vec<libc::pollfd>,
    pub(super) session_map_fd: c_int,
    pub(super) conntrack_v4_fd: c_int,
    pub(super) conntrack_v6_fd: c_int,
    pub(super) last_cos_status_ns: u64,
    // #6245: EXPLICIT per-slot terminal binding-setup failures (private
    // bind, or a shared-group bind whose private fallback also failed).
    // Pre-#6245 these were recorded ONLY by leaving the failed slot out of
    // `bindings`; now they are carried through to the WorkerStartupReport so
    // the readiness barrier's fail-closed diagnostic names the cause. Sorted
    // by slot before return for a stable report.
    pub(super) binding_failures: Vec<BindingSetupFailure>,
    // #6245: shared-UMEM groups that failed their group bind but fully
    // recovered via private fallback — a diagnostic degradation, NOT a
    // failure (all slots still bound). Sorted by group before return.
    pub(super) recovered_fallbacks: Vec<BindingRecoveredFallback>,
}

/// One-shot worker setup (moved verbatim from the head of
/// `worker_loop`; only binding `mut`-ness and variable access
/// changed — statements, order, and side-effect sequence are
/// preserved).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn worker_loop_setup(
    worker_id: u32,
    node_id: u8,
    binding_plans: Vec<BindingPlan>,
    shared_runtime: &RuntimeViewReader,
    shared_cos_owner_worker_by_queue: &ArcSwap<BTreeMap<(i32, u8), u32>>,
    shared_cos_owner_live_by_queue: &ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>,
    shared_cos_root_leases: &ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>,
    shared_cos_exact_backlogs: &ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>,
    shared_cos_queue_leases: &ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>,
    shared_cos_queue_vtime_floors: &ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    shared_mirror_targets: &ArcSwap<MirrorTargetMap>,
    poll_mode: crate::PollMode,
    cos_status: &ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>,
    runtime_atomics: &crate::afxdp::worker_runtime::WorkerRuntimeAtomics,
    cold_path_atomics: &crate::afxdp::cold_path_hist::WorkerColdPathAtomics,
) -> WorkerLoopSetup {
    pin_current_thread(worker_id);
    // #1620: per-worker cold-path TSC calibration. Runs ONCE at
    // worker_loop entry, AFTER pin_current_thread has pinned the
    // worker to its core (so the Instant↔TSC ratio reflects this
    // core's clock). The probe + calibrate together take ~10 ms
    // (one-shot 10 ms sleep window + ~80 µs of back-to-back rdtscp
    // pairs); workers calibrate concurrently across cores so the
    // wall-clock startup overhead stays at ~10 ms total.
    //
    // Per plan v4 §4.6: probe_clock_source runs once; calibration is
    // skipped (returning 0) when the clock source is not TSC, avoiding
    // redundant /proc/cpuinfo + /sys probes inside the calibrators.
    let cp_clock_source =
        crate::afxdp::cold_path_hist::probe_clock_source();
    let (cp_ns_per_tsc_q32, cp_wrapper_baseline) =
        if cp_clock_source == crate::afxdp::cold_path_hist::ClockSource::Tsc {
            let q32 =
                crate::afxdp::cold_path_hist::calibrate_ns_per_tsc_q32();
            let baseline =
                crate::afxdp::cold_path_hist::calibrate_wrapper_baseline_ns(
                    q32,
                );
            (q32, baseline)
        } else {
            (0, 0)
        };
    // Single-line startup log per worker (~6 lines total per daemon
    // startup). Goes to journald via stderr per project logging rules.
    eprintln!(
        "xpf-cold-path: worker={} clock_source={} ns_per_tsc_q32={} wrapper_ns_baseline={}",
        worker_id,
        cp_clock_source.as_str(),
        cp_ns_per_tsc_q32,
        cp_wrapper_baseline,
    );
    let ha_startup_grace_until_secs =
        (monotonic_nanos() / 1_000_000_000).saturating_add(TUNNEL_HA_STARTUP_GRACE_SECS);
    // #6592: seed BOTH halves from ONE view load, exactly as the per-tick
    // refresh does (`refresh_runtime_view`, loop_body/mod.rs). Two separate
    // loads here would let a coordinator publish land between them and seed a
    // brand-new worker with a torn pair — in either orientation — before it
    // has processed a single packet. The CoS `load_full`s below still follow
    // this load per #5166.
    let (validation, forwarding) = {
        let view = shared_runtime.load();
        (view.validation(), view.forwarding().clone())
    };
    let cos_owner_worker_by_queue = shared_cos_owner_worker_by_queue.load_full();
    let cos_owner_live_by_queue = shared_cos_owner_live_by_queue.load_full();
    let cos_shared_root_leases = shared_cos_root_leases.load_full();
    let cos_shared_exact_backlogs = shared_cos_exact_backlogs.load_full();
    let cos_shared_queue_leases = shared_cos_queue_leases.load_full();
    let cos_shared_queue_vtime_floors = shared_cos_queue_vtime_floors.load_full();
    let mirror_targets = shared_mirror_targets.load_full();
    let mut sessions = SessionTable::new();
    // #4915 + #6311: namespace this worker's session ids so the STABLE session
    // id (`SessionEntry.session_id`, encoded on the RT_FLOW SESSION_CREATE/CLOSE
    // wire) is unique across the node's shared-nothing per-worker session tables
    // AND across the two cluster nodes. The node half is what keeps a peer id
    // adopted verbatim on import (#5212) from colliding with a local id — both
    // nodes run the same worker set with counters that both start at 1.
    sessions.set_session_id_namespace(node_id, worker_id);
    let mut screen_state = ScreenState::new();
    screen_state.update_profiles(forwarding.screen_profiles.clone());
    // #3082: thread the references-missing-profile set so the screen None
    // branch can WARN (still Pass) for the lenient/HA-sync fail-open.
    screen_state.update_missing_profiles(forwarding.screen_missing_profiles.clone());
    screen_state.update_inert_profiles(forwarding.screen_inert_profiles.clone());
    screen_state.update_syn_cookie_keys(
        forwarding.syn_cookie_master_key.0,
        forwarding.syn_cookie_key_ring.clone(),
    );
    sessions.set_timeouts(forwarding.session_timeouts);
    // #3527: push the per-screened-zone half-open (`syn-flood timeout`)
    // overrides next to `set_timeouts`. Empty in the common case (no zone
    // configures a syn-flood timeout).
    sessions.set_opening_overrides(forwarding.session_opening_overrides.clone());
    // #2134: drive the per-IP session-limit OFF-gate from the applied
    // screen profiles. Off when no zone configures `limit-session`, so
    // install/remove counter maintenance is skipped for the ~99% case.
    sessions.set_session_limit_active(screen_state.any_session_limit_configured());
    let mut bindings = Vec::with_capacity(binding_plans.len());
    // #6245: accumulate EXPLICIT per-slot terminal failures and recovered
    // shared-group fallbacks so the WorkerStartupReport can carry the causal
    // error, not just the survivor set. Empty in the common (all-bound) case.
    let mut binding_failures: Vec<BindingSetupFailure> = Vec::new();
    let mut recovered_fallbacks: Vec<BindingRecoveredFallback> = Vec::new();
    let (private_plans, shared_groups) = partition_binding_plans(binding_plans);
    for plan in private_plans {
        let live = plan.live.clone();
        // #6245: capture the slot BEFORE `plan` is moved into the bind call so
        // a failure can be reported explicitly (was lost with the moved plan).
        let slot = plan.status.slot;
        // #7497: the NIC coordinate, captured at the same moment and for the
        // same reason — `plan` is moved into the bind call below.
        let coord = BindingCoordinate::of(&plan.status);
        match create_private_binding_from_plan(plan) {
            Ok(binding) => bindings.push(binding),
            Err(err) => {
                // #5143: an in-thread XSK/UMEM bind failure. Continuing past it
                // (rather than aborting the whole worker) is intentional — but
                // the failed binding is NOT pushed into `bindings`, so its slot
                // is ABSENT from the startup readiness report `worker_loop`
                // sends to the `bring_up_workers` barrier. That OMISSION is how
                // the barrier learns this worker came up with a PARTIAL binding
                // set and fails the reconcile closed (HEARTBEAT != READINESS).
                // #6245: ALSO record the failure EXPLICITLY (slot + phase +
                // owned error) so the barrier's fail-closed diagnostic can name
                // the cause instead of inferring it from the missing slot.
                let reason = err.to_string();
                eprintln!("xpf-userspace-dp: private binding creation failed: {reason}");
                live.set_error(reason.clone());
                binding_failures.push(BindingSetupFailure::at(
                    &coord,
                    BindingSetupPhase::Private,
                    reason,
                ));
            }
        }
    }
    for (group_key, plans) in shared_groups {
        match create_shared_binding_group(&group_key, plans) {
            Ok(mut group_bindings) => bindings.append(&mut group_bindings),
            Err(err) => fallback_shared_group_to_private(
                err,
                &mut bindings,
                &mut binding_failures,
                &mut recovered_fallbacks,
            ),
        }
    }
    bindings.sort_by_key(|binding| (binding.queue_id, binding.ifindex, binding.slot));
    // #1620: install per-worker cold-path calibration into each
    // binding's worker-local counters. The calibration values are
    // shared across all bindings owned by this worker — they reflect
    // the worker thread's pinned core, not the binding identity.
    for binding in bindings.iter_mut() {
        binding.cold_path.ns_per_tsc_q32 = cp_ns_per_tsc_q32;
        binding.cold_path.wrapper_ns_baseline = cp_wrapper_baseline;
        binding.cold_path.clock_source = cp_clock_source;
    }
    // #1621: install the same calibration into the sibling atomics
    // so the first /metrics scrape sees q32 + clock_source even
    // before the first publish-tick fires. install_calibration writes
    // outside the cold_window_gen seqlock (calibration is set-once;
    // readers always observe a consistent value).
    cold_path_atomics.install_calibration(
        cp_ns_per_tsc_q32,
        cp_wrapper_baseline,
        cp_clock_source,
    );
    let binding_lookup = WorkerBindingLookup::from_bindings(&bindings);
    let cos_owner_live_by_tx_ifindex = build_worker_cos_owner_live_by_tx_ifindex(
        bindings
            .iter()
            .map(|binding| (binding.ifindex, binding.live.clone())),
    );
    let cos_fast_interfaces = build_worker_cos_fast_interfaces(
        forwarding.as_ref(),
        worker_id,
        &cos_owner_live_by_tx_ifindex,
        cos_owner_worker_by_queue.as_ref(),
        cos_owner_live_by_queue.as_ref(),
        cos_shared_root_leases.as_ref(),
        cos_shared_exact_backlogs.as_ref(),
        cos_shared_queue_leases.as_ref(),
        cos_shared_queue_vtime_floors.as_ref(),
    );
    for binding in bindings.iter_mut() {
        binding.cos.cos_fast_interfaces = cos_fast_interfaces.clone();
    }
    let interrupt_poll_fds = if poll_mode == crate::PollMode::Interrupt {
        bindings
            .iter()
            .map(|binding| libc::pollfd {
                fd: binding.xsk.device.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    // Cache BPF map FDs — they don't change during the worker's lifetime.
    let session_map_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.session_map_fd)
        .unwrap_or(-1);
    let conntrack_v4_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.conntrack_v4_fd)
        .unwrap_or(-1);
    let conntrack_v6_fd = bindings
        .first()
        .map(|binding| binding.bpf_maps.conntrack_v6_fd)
        .unwrap_or(-1);
    let last_cos_status_ns = monotonic_nanos();
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
        last_cos_status_ns,
    )));
    runtime_atomics.set_tid(current_tid());
    // #6245: stable ordering for the startup report — failures by slot,
    // recovered fallbacks by group — so the surfaced diagnostic is
    // deterministic regardless of plan/partition iteration order.
    binding_failures.sort_by_key(|failure| failure.slot);
    recovered_fallbacks.sort_by(|a, b| a.group.cmp(&b.group));
    WorkerLoopSetup {
        ha_startup_grace_until_secs,
        validation,
        forwarding,
        cos_owner_worker_by_queue,
        cos_owner_live_by_queue,
        cos_shared_root_leases,
        cos_shared_exact_backlogs,
        cos_shared_queue_leases,
        cos_shared_queue_vtime_floors,
        mirror_targets,
        sessions,
        screen_state,
        bindings,
        binding_lookup,
        interrupt_poll_fds,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        last_cos_status_ns,
        binding_failures,
        recovered_fallbacks,
    }
}

#[cfg(test)]
mod worker_setup_harness {
    use super::*;
    /// The Send-able observations of one `worker_loop_setup` run.
    ///
    /// `WorkerLoopSetup` itself is NOT `Send` — it owns an
    /// `Rc<WorkerUmemInner>` — so it cannot cross the thread boundary and the
    /// facts a cell wants have to be reduced inside the closure rather than
    /// carried out of it.
    pub(super) struct SetupObservation {
        pub(super) binding_failures: usize,
        pub(super) bindings: usize,
        pub(super) elapsed_ns: u64,
        pub(super) returned_at_ns: u64,
    }

    /// Drive the REAL `worker_loop_setup`.
    ///
    /// WHY THIS EXISTS. Until now `worker_loop` and `worker_loop_setup` had NO
    /// test callers anywhere in the tree — they were reachable only from
    /// `reconcile/bringup.rs`, and the spawn seams that exercise the #5143
    /// readiness barrier substitute STUB threads rather than the real body. So
    /// every cell over this code was green BY CONSTRUCTION rather than by
    /// coverage: a mutation that deleted a load-bearing line from worker setup
    /// passed the entire suite, because nothing ran it.
    ///
    /// Runs on its OWN thread, deliberately. `worker_loop_setup` opens with
    /// `pin_current_thread(worker_id)`, and pinning a cargo test thread would
    /// outlive the cell and follow whatever test that thread is reused for.
    /// Spawning also matches production, where setup always runs on a freshly
    /// spawned worker.
    pub(super) fn drive_worker_setup(binding_plans: Vec<BindingPlan>) -> SetupObservation {
        // DO NOT "simplify" this to an inline call. `worker_loop_setup` opens
        // with `pin_current_thread(worker_id)`, so calling it on the cargo test
        // thread PINS that thread — and the pin outlives this cell and follows
        // the thread into whatever test the runner reuses it for. The symptom
        // would be an unrelated timing flake, weeks later, in a file with no
        // connection to this one. Spawning also matches production, where setup
        // always runs on a freshly spawned worker.
        std::thread::spawn(move || {
            let t0 = crate::afxdp::monotonic_nanos();
            let runtime = RuntimeViewChannel::default();
            let shared_runtime = runtime.reader();
            let owner_worker_by_queue = ArcSwap::from_pointee(BTreeMap::new());
            let owner_live_by_queue = ArcSwap::from_pointee(BTreeMap::new());
            let root_leases = ArcSwap::from_pointee(BTreeMap::new());
            let exact_backlogs = ArcSwap::from_pointee(BTreeMap::new());
            let queue_leases = ArcSwap::from_pointee(BTreeMap::new());
            let queue_vtime_floors = ArcSwap::from_pointee(BTreeMap::new());
            let mirror_targets = ArcSwap::from_pointee(MirrorTargetMap::default());
            let cos_status = ArcSwap::from_pointee(Vec::new());
            let runtime_atomics = crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new();
            let cold_path_atomics = crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new();
            let setup = worker_loop_setup(
                0,
                0,
                binding_plans,
                &shared_runtime,
                &owner_worker_by_queue,
                &owner_live_by_queue,
                &root_leases,
                &exact_backlogs,
                &queue_leases,
                &queue_vtime_floors,
                &mirror_targets,
                crate::PollMode::Interrupt,
                &cos_status,
                &runtime_atomics,
                &cold_path_atomics,
            );
            let returned_at_ns = crate::afxdp::monotonic_nanos();
            SetupObservation {
                binding_failures: setup.binding_failures.len(),
                bindings: setup.bindings.len(),
                elapsed_ns: returned_at_ns - t0,
                returned_at_ns,
            }
        })
        .join()
        .expect("worker setup thread")
    }

    /// One private-UMEM plan with closed (-1) map fds on a nonexistent ifindex,
    /// so the real bind is ATTEMPTED and fails.
    pub(super) fn unbindable_plan() -> BindingPlan {
        BindingPlan {
            status: BindingStatus {
                slot: 0,
                ifindex: 999_000,
                queue_id: 0,
                ..BindingStatus::default()
            },
            live: Arc::new(BindingLiveState::new()),
            xsk_map_fd: -1,
            heartbeat_map_fd: -1,
            session_map_fd: -1,
            conntrack_v4_fd: -1,
            conntrack_v6_fd: -1,
            ring_entries: 256,
            bind_strategy: AfXdpBindStrategy::UmemOwnerSocket,
            poll_mode: crate::PollMode::Interrupt,
            shared_umem: SharedUmemBindingPlan::private(),
        }
    }

    /// THE POSITIVE CONTROL FOR THE HARNESS ITSELF, and the reason this file
    /// is worth landing on its own.
    ///
    /// A harness that ran `worker_loop_setup` but returned before the bind
    /// partition would look exactly like coverage while testing nothing — which
    /// is the failure mode the existing stub-thread seams already have. So
    /// assert something ONLY the real body produces: an explicit per-slot
    /// `BindingSetupFailure` for a plan whose map fds are all closed.
    ///
    /// If this ever goes empty, the harness stopped reaching the bind and every
    /// future cell built on it is vacuous.
    #[test]
    fn the_harness_reaches_the_real_bind_path() {
        let setup = drive_worker_setup(vec![unbindable_plan()]);
        assert!(
            setup.binding_failures > 0,
            "the harness returned with NO per-slot binding failure for a plan \
             whose map fds are all -1. The real body records an explicit \
             BindingSetupFailure for such a slot, so an empty list means setup \
             returned before the bind partition and this harness is not \
             reaching the code it claims to"
        );
        assert_eq!(
            setup.bindings, 0,
            "an unbindable plan produced a live binding, so the fixture is not \
             exercising the failure path it was built for"
        );
    }

    /// The complement: with NOTHING to bind, setup still completes and reports
    /// neither a binding nor a failure.
    ///
    /// Without this the control above cannot distinguish "the bind path ran and
    /// failed" from "the bind path fails for everything, including nothing" —
    /// a body that pushed a failure unconditionally would satisfy it.
    #[test]
    fn the_harness_reports_no_failure_when_there_is_nothing_to_bind() {
        let setup = drive_worker_setup(Vec::new());
        assert_eq!(
            setup.binding_failures, 0,
            "setup reported a per-slot binding failure with NO plans to bind, \
             so the failure list is not attributable to a slot"
        );
        assert_eq!(setup.bindings, 0, "no plans must produce no bindings");
        assert!(
            setup.returned_at_ns >= setup.elapsed_ns,
            "monotonic clock sanity"
        );
    }
}
