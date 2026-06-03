// #1326 — extracted from worker/mod.rs (pure code motion).
// The `worker_loop` per-tick orchestrator was previously a ~1278 LOC
// function in worker/mod.rs (L995-L2273). It is moved here verbatim
// as the first phase of the #1326 refactor; subsequent phases will
// carve named tick sub-fns out of this file (setup/tick/poll_drive/
// debug_report) per plan v4.0 (docs/pr/1326-worker-loop-extract/plan.md).
//
// `use super::*;` brings every type, helper, and sibling-submodule
// item from worker/mod.rs into scope — the same pattern lifecycle.rs
// and cos.rs use. Pure relocation — no production logic touched.

use super::*;

pub(crate) fn worker_loop(
    worker_id: u32,
    binding_plans: Vec<BindingPlan>,
    shared_validation: Arc<ArcSwap<ValidationState>>,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    slow_path: Option<Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    recent_session_deltas: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: Arc<Mutex<Option<PacketResolution>>>,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    worker_commands_by_id: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>,
    stop: Arc<AtomicBool>,
    heartbeat: Arc<AtomicU64>,
    session_export_ack: Arc<AtomicU64>,
    // #1748: structured rebalance command ack slot + lock-free published seq.
    // Written only when this worker applies a Promote/Demote rebalance command.
    rebalance_ack: Arc<Mutex<Option<crate::afxdp::RebalanceAck>>>,
    rebalance_ack_seq: Arc<AtomicU64>,
    poll_mode: crate::PollMode,
    dnat_fds: DnatTableFds,
    shared_fabrics: Arc<ArcSwap<Vec<FabricLink>>>,
    event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    rg_epochs: Arc<[AtomicU32; MAX_RG_EPOCHS]>,
    shared_cos_owner_worker_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), u32>>>,
    shared_cos_owner_live_by_queue: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<BindingLiveState>>>>,
    shared_cos_root_leases: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSRootLease>>>>,
    shared_cos_exact_backlogs: Arc<ArcSwap<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>>,
    shared_cos_queue_leases: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>>,
    shared_cos_queue_vtime_floors: Arc<ArcSwap<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>>,
    shared_mirror_targets: Arc<ArcSwap<MirrorTargetMap>>,
    cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    // #869: worker-runtime telemetry publish slot.  Worker writes its
    // local counters here on a ~1s cadence; coordinator reads for status.
    runtime_atomics: Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>,
    // #1621: sibling per-worker cold-path histogram publish slot.
    // Worker calls publish_from_local() each ~1s tick alongside the
    // runtime_atomics.publish(). Coordinator status path reads via
    // snapshot() at each /metrics scrape.
    cold_path_atomics:
        Arc<crate::afxdp::cold_path_hist::WorkerColdPathAtomics>,
) {
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
    const COS_STATUS_INTERVAL_NS: u64 = 100_000_000;
    let ha_startup_grace_until_secs =
        (monotonic_nanos() / 1_000_000_000).saturating_add(TUNNEL_HA_STARTUP_GRACE_SECS);
    let mut validation = **shared_validation.load();
    let mut forwarding = shared_forwarding.load_full();
    let mut cos_owner_worker_by_queue = shared_cos_owner_worker_by_queue.load_full();
    let mut cos_owner_live_by_queue = shared_cos_owner_live_by_queue.load_full();
    let mut cos_shared_root_leases = shared_cos_root_leases.load_full();
    let mut cos_shared_exact_backlogs = shared_cos_exact_backlogs.load_full();
    let mut cos_shared_queue_leases = shared_cos_queue_leases.load_full();
    let mut cos_shared_queue_vtime_floors = shared_cos_queue_vtime_floors.load_full();
    let mut mirror_targets = shared_mirror_targets.load_full();
    let mut sessions = SessionTable::new();
    let mut screen_state = ScreenState::new();
    screen_state.update_profiles(forwarding.screen_profiles.clone());
    screen_state.update_syn_cookie_master_key(forwarding.syn_cookie_master_key);
    sessions.set_timeouts(forwarding.session_timeouts);
    let mut bindings = Vec::with_capacity(binding_plans.len());
    let (private_plans, shared_groups) = partition_binding_plans(binding_plans);
    for plan in private_plans {
        let live = plan.live.clone();
        match create_private_binding_from_plan(plan) {
            Ok(binding) => bindings.push(binding),
            Err(err) => {
                eprintln!("xpf-userspace-dp: private binding creation failed: {err}");
                live.set_error(err.to_string());
            }
        }
    }
    for (group_key, plans) in shared_groups {
        match create_shared_binding_group(&group_key, plans) {
            Ok(mut group_bindings) => bindings.append(&mut group_bindings),
            Err(err) => fallback_shared_group_to_private(err, &mut bindings),
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
    let mut interrupt_poll_fds = if poll_mode == crate::PollMode::Interrupt {
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
    let mut idle_iters = 0u32;
    let mut poll_start = 0usize;
    let mut shared_recycles = Vec::with_capacity((RX_BATCH_SIZE as usize).saturating_mul(2));
    // Debug: periodic summary counters
    let mut dbg_last_report_ns = monotonic_nanos();
    let mut dbg_rx_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_total = 0u64;
    let mut dbg_forward_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_local_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_hit = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_miss = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_session_create = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_no_route = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_missing_neigh = 0u64;
    // #1651 B3: dead-host negative-cache fast-fail count.
    #[cfg(feature = "debug-log")]
    let mut dbg_neg_neigh_fast_fail = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_policy_deny = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_ha_inactive = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_no_egress_binding = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_build_fail = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_err = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_metadata_err = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_disposition_other = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_ok = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_inplace = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_direct = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_enqueue_copy = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_from_trust = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_from_wan = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_trust_to_wan = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_wan_to_trust = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_snat = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_dnat = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_nat_none = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_frame_build_none = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_fin = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_synack = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_tcp_zero_window = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_fin = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_rst = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_fwd_tcp_zero_window = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_bytes_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_bytes_total = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_oversized = 0u64;
    #[cfg(feature = "debug-log")]
    let mut dbg_rx_max_frame = 0u32;
    #[cfg(feature = "debug-log")]
    let mut dbg_tx_max_frame = 0u32;
    #[cfg(feature = "debug-log")]
    let mut dbg_seg_needed_but_none = 0u64;
    let mut prev_rx_total = 0u64;
    let mut prev_fwd_total = 0u64;
    let mut stall_prev_fwd = 0u64;
    let mut stall_reported = false;
    const DBG_REPORT_INTERVAL_NS: u64 = 1_000_000_000; // 1 second
    // Throttle for BPF conntrack last_seen refresh (~10s).
    // Keeps `show security flow session` idle times accurate without
    // per-second syscall overhead per session.  See issue #333.
    const CT_REFRESH_INTERVAL_NS: u64 = 10_000_000_000;
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
    let mut last_ct_refresh_ns: u64 = 0;
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
    )));
    let mut last_cos_status_ns = monotonic_nanos();
    // #869: worker-runtime telemetry.  Local counters, published to
    // `runtime_atomics` on the ~1s cadence below.
    use crate::afxdp::worker_runtime::{
        WorkerRuntimeCounters, WorkerRuntimeState, current_tid, sample_thread_cpu_ns,
    };
    let mut wr_counters = WorkerRuntimeCounters::default();
    let mut wr_state = WorkerRuntimeState::IdleBlock;
    let mut wr_last_loop_ns = monotonic_nanos();
    let mut wr_last_publish_ns = wr_last_loop_ns;
    const WR_PUBLISH_INTERVAL_NS: u64 = 1_000_000_000;
    runtime_atomics.set_tid(current_tid());
    while !stop.load(Ordering::Relaxed) {
        let loop_now_ns = monotonic_nanos();
        // #869: attribute elapsed delta to the previous loop's state.
        {
            let delta = loop_now_ns.saturating_sub(wr_last_loop_ns);
            wr_counters.wall_ns = wr_counters.wall_ns.wrapping_add(delta);
            match wr_state {
                WorkerRuntimeState::Active => {
                    wr_counters.active_ns = wr_counters.active_ns.wrapping_add(delta);
                }
                WorkerRuntimeState::IdleSpin => {
                    wr_counters.idle_spin_ns = wr_counters.idle_spin_ns.wrapping_add(delta);
                }
                WorkerRuntimeState::IdleBlock => {
                    wr_counters.idle_block_ns = wr_counters.idle_block_ns.wrapping_add(delta);
                }
            }
            wr_last_loop_ns = loop_now_ns;
            if loop_now_ns.saturating_sub(wr_last_publish_ns) >= WR_PUBLISH_INTERVAL_NS {
                // Skip on transient clock_gettime failure (sample == 0):
                // overwriting a previously-published nonzero value with 0
                // would make the Prometheus counter go backwards and
                // break `rate()` queries.
                let sampled_cpu_ns = sample_thread_cpu_ns();
                if sampled_cpu_ns != 0 {
                    wr_counters.thread_cpu_ns = sampled_cpu_ns;
                }
                refresh_worker_cos_queue_lease_runtime_counters(&mut wr_counters, &bindings);
                wr_counters.session_table_entries = sessions.len() as u64;
                wr_counters.max_sessions = sessions.max_sessions() as u64;
                runtime_atomics.publish(&wr_counters, loop_now_ns);
                // #1621: alongside the runtime publish, merge each
                // binding's cold-path worker-local counters into a
                // single WorkerColdPathCounters and publish via the
                // sibling atomics' own cold_window_gen seqlock.
                //
                // Per plan v1 §4.2: saturating_add buckets / sum_ns /
                // samples / sample_phase / wrapper_underflow_count;
                // OR alias_seen; first-non-zero first_key (cross-
                // binding aliasing detected when bindings disagree).
                {
                    use crate::afxdp::cold_path_hist as cph;
                    let mut merged = cph::WorkerColdPathCounters::default();
                    for binding in bindings.iter() {
                        let src = &binding.cold_path;
                        merged.sample_phase = merged
                            .sample_phase
                            .saturating_add(src.sample_phase);
                        merged.wrapper_underflow_count = merged
                            .wrapper_underflow_count
                            .saturating_add(src.wrapper_underflow_count);
                        for slot in 0..cph::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                            merged.sum_ns[slot] = merged.sum_ns[slot]
                                .saturating_add(src.sum_ns[slot]);
                            merged.samples[slot] = merged.samples[slot]
                                .saturating_add(src.samples[slot]);
                            for b in 0..cph::POLICY_COLD_PATH_HIST_BUCKETS {
                                merged.buckets[slot][b] = merged.buckets
                                    [slot][b]
                                    .saturating_add(src.buckets[slot][b]);
                            }
                            // first_key + builder_collision cross-binding merge.
                            if merged.first_key[slot] == 0 {
                                merged.first_key[slot] = src.first_key[slot];
                            } else if src.first_key[slot] != 0
                                && src.first_key[slot] != merged.first_key[slot]
                            {
                                merged.builder_collision[slot] = true;
                            }
                            merged.builder_collision[slot] |= src.builder_collision[slot];
                        }
                    }
                    // All bindings on this worker share the same pinned
                    // core ⇒ same TSC calibration. Take any binding's
                    // value (default = 0 if no bindings — calibration
                    // not yet installed).
                    if let Some(first) = bindings.first() {
                        merged.ns_per_tsc_q32 = first.cold_path.ns_per_tsc_q32;
                        merged.wrapper_ns_baseline =
                            first.cold_path.wrapper_ns_baseline;
                        merged.clock_source = first.cold_path.clock_source;
                    }
                    cold_path_atomics.publish_from_local(&merged);
                }
                wr_last_publish_ns = loop_now_ns;
            }
        }
        let loop_now_secs = loop_now_ns / 1_000_000_000;
        let live_validation = shared_validation.load();
        if **live_validation != validation {
            validation = **live_validation;
        }
        let mut rebuild_cos_fast_interfaces = false;
        // #1188: per-tick Arc refresh — `.load() + Arc::ptr_eq`
        // short-circuits the unconditional `.load_full()` clone
        // when the coordinator hasn't rotated the Arc.
        if let Some(new_forwarding) = load_arc_if_changed(&forwarding, &shared_forwarding) {
            // Compare BEFORE assignment — needs both old and new.
            let cos_changed =
                cos_runtime_config_changed(forwarding.as_ref(), new_forwarding.as_ref());
            let (purge_input_dscp_v4, purge_input_dscp_v6) =
                crate::filter::input_dscp_filter_families_changed(
                    &forwarding.filter_state,
                    &new_forwarding.filter_state,
                );

            // Use NEW values for dependent state updates (forwarding-site
            // ordering — old `forwarding` is stale once rotated).
            screen_state.update_profiles(new_forwarding.screen_profiles.clone());
            screen_state.update_syn_cookie_master_key(new_forwarding.syn_cookie_master_key);
            sessions.set_timeouts(new_forwarding.session_timeouts);

            // #1635 (plan §2.4): a config apply may have reassigned
            // cold-path histogram slots to new zone-pairs. Zero those
            // slots in every binding's worker-local accumulator BEFORE
            // any record_sample into the reused slot, so a reused slot
            // never carries the previous zone-pair's counts.
            //
            // Copilot code-r2: derive the zero-set from THIS WORKER's
            // OWN old map vs the new map, NOT from the coordinator's
            // `slots_to_zero` list. A worker can skip intermediate
            // ForwardingState generations (ArcSwap only ever delivers
            // the latest), and the coordinator computes `slots_to_zero`
            // relative to its immediately-previous map — so a slot
            // reassigned in a skipped generation would be absent from
            // the latest list (it now looks "retained"). Comparing the
            // worker's actual old slot-map inverse against the new one
            // is generation-independent: any slot whose mapping changed
            // since the worker last observed it gets zeroed. The
            // sibling atomics are overwritten at the next publish merge
            // from the freshly-zeroed local accumulator.
            {
                let old_inverse = &forwarding.cold_path_slot_map.inverse;
                let new_inverse = &new_forwarding.cold_path_slot_map.inverse;
                for slot in 0..crate::afxdp::cold_path_hist::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                    let new_pair = new_inverse.get(slot).copied().flatten();
                    // Zero when the slot now maps to a pair that differs
                    // from what the worker last saw there. A freed slot
                    // (new == None) keeps its stale local data harmlessly
                    // — it is unmapped, never sampled, and gets zeroed
                    // when next reassigned.
                    if new_pair.is_some()
                        && new_pair != old_inverse.get(slot).copied().flatten()
                    {
                        for binding in bindings.iter_mut() {
                            binding.cold_path.zero_slot(slot);
                        }
                    }
                }
            }

            forwarding = new_forwarding;
            let purged_input_dscp = purge_sessions_for_input_dscp_filter_revalidation(
                &mut sessions,
                session_map_fd,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &peer_worker_commands,
                &forwarding,
                purge_input_dscp_v4,
                purge_input_dscp_v6,
                loop_now_ns,
            );
            if purged_input_dscp > 0 {
                debug_log!(
                    "INPUT_DSCP_FILTER_PURGE: worker={} sessions={}",
                    worker_id,
                    purged_input_dscp,
                );
            }
            let republished = republish_local_delivery_sessions_for_lo0_filter(
                &sessions,
                session_map_fd,
                &forwarding,
            );
            if republished > 0 {
                debug_log!(
                    "LO0_FILTER_REPUBLISH: worker={} local_delivery_sessions={}",
                    worker_id,
                    republished,
                );
            }

            if cos_changed {
                reset_worker_cos_runtimes(&mut bindings, &mut shared_recycles);
                apply_shared_recycles_to_bindings(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                );
                rebuild_cos_fast_interfaces = true;
            }
        }
        if let Some(new_x) = load_arc_if_changed(&mirror_targets, &shared_mirror_targets) {
            mirror_targets = new_x;
        }
        if let Some(new_x) = load_arc_if_changed(
            &cos_owner_worker_by_queue,
            &shared_cos_owner_worker_by_queue,
        ) {
            cos_owner_worker_by_queue = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_owner_live_by_queue, &shared_cos_owner_live_by_queue)
        {
            cos_owner_live_by_queue = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(&cos_shared_root_leases, &shared_cos_root_leases) {
            for binding in bindings.iter_mut() {
                release_all_cos_root_leases(binding);
                release_all_cos_queue_leases(binding);
            }
            cos_shared_root_leases = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_shared_exact_backlogs, &shared_cos_exact_backlogs)
        {
            cos_shared_exact_backlogs = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(&cos_shared_queue_leases, &shared_cos_queue_leases)
        {
            for binding in bindings.iter_mut() {
                release_all_cos_queue_leases(binding);
            }
            cos_shared_queue_leases = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(
            &cos_shared_queue_vtime_floors,
            &shared_cos_queue_vtime_floors,
        ) {
            // #917: Arc-replacement of the V_min floors map.
            // Each shared_exact queue's per-worker slots default
            // to NOT_PARTICIPATING in the new Arc. Workers will
            // re-publish their committed vtime on the next
            // commit-boundary publish; until then peers reading
            // this slot see "not participating" and skip it in
            // V_min reduction (per plan §3.4 / §3.7 lifecycle
            // rules).
            cos_shared_queue_vtime_floors = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if rebuild_cos_fast_interfaces {
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
            // The new SharedCoSExactBacklog slots in the freshly built
            // cos_fast_interfaces start at zero. Republish the current
            // exact-queue backlog for every binding/ifindex so peer workers
            // do not observe a false-zero window until the next organic
            // enqueue or drain refresh.
            for binding in bindings.iter() {
                for &root_ifindex in binding.cos.cos_interfaces.keys() {
                    publish_cos_exact_backlog(binding, root_ifindex);
                }
            }
        }
        let ha_runtime = ha_state.load();
        // Only apply commands when pending — avoids lock overhead on
        // every loop iteration in the common (empty-queue) case.
        let has_commands = commands.try_lock().map(|q| !q.is_empty()).unwrap_or(false);
        let command_results = if has_commands {
            apply_worker_commands(
                &commands,
                &mut sessions,
                session_map_fd,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
            )
        } else {
            WorkerCommandResults {
                cancelled_keys: Vec::new(),
                exported_sequences: Vec::new(),
                shaped_tx_requests: Vec::new(),
                vacate_all_shared_exact_slots: false,
                rebalance_acks: Vec::new(),
            }
        };
        let WorkerCommandResults {
            cancelled_keys,
            exported_sequences,
            shaped_tx_requests,
            vacate_all_shared_exact_slots,
            rebalance_acks,
        } = command_results;
        // #1748: publish each rebalance command ack. Write the structured
        // {seq,key,origin,result} into the slot, THEN publish the seq
        // (Release) so the controller that observes the seq (Acquire) is
        // guaranteed to read the matching slot. Acks are applied in command
        // order; the controller barriers on one outstanding seq at a time, so
        // the last write for its pending seq is the one it reads.
        if !rebalance_acks.is_empty() {
            for ack in rebalance_acks {
                let seq = ack.seq;
                // #1751 exactly-once count fix: when a DemoteRebalanced ack
                // reports the flow is now RebalancedOut on THIS worker (W_old),
                // evict its abandoned forward copy from every local flow cache
                // immediately. The ntuple HW rule has already steered new
                // packets of this 5-tuple to W_new, so W_old's flow-cache entry
                // would otherwise linger for the ~650ms active-flow window and
                // be DOUBLE-COUNTED by `active_flow_debug_entries` — inflating
                // the per-worker count the rebalance controller selects on, so
                // it keeps moving flows off an already-drained W_old and never
                // converges (over-installs ntuple rules). Dropping the entry
                // here means W_old's count reflects the flow's departure on the
                // very next debug-state publish. Session ownership/state is
                // untouched (the SessionTable still holds the RebalancedOut
                // entry for local-only GC) — only the fast-path cache copy that
                // drives the count is removed. Mirrors the RST-teardown and
                // cancelled-keys eviction patterns (invalidate_slot is keyed by
                // (forward_key, ingress_ifindex)).
                if ack.result
                    && ack.origin == Some(crate::session::SessionOrigin::RebalancedOut)
                {
                    for binding in bindings.iter_mut() {
                        binding
                            .flow
                            .flow_cache
                            .invalidate_slot(&ack.key, binding.ifindex);
                    }
                }
                if let Ok(mut slot) = rebalance_ack.lock() {
                    *slot = Some(ack);
                }
                rebalance_ack_seq.store(seq, Ordering::Release);
            }
        }
        // #941 Work item C: HA-demotion vacate. The
        // VacateAllSharedExactSlots WorkerCommand cannot be processed
        // inside `apply_worker_commands` (no BindingWorker access);
        // it sets this flag and the dispatch happens here, where we
        // hold `&mut bindings`. Single-writer invariant: only this
        // worker writes its own slots.
        if vacate_all_shared_exact_slots {
            for binding in bindings.iter_mut() {
                vacate_all_shared_exact_slots_for_binding(binding);
            }
        }
        if !shaped_tx_requests.is_empty() {
            apply_worker_shaped_tx_requests(
                &mut bindings,
                forwarding.as_ref(),
                &binding_lookup,
                loop_now_ns,
                shaped_tx_requests,
                &mut shared_recycles,
            );
            apply_shared_recycles_to_bindings(&mut bindings, &binding_lookup, &mut shared_recycles);
        }
        if !cancelled_keys.is_empty() {
            for key in &cancelled_keys {
                for binding in bindings.iter_mut() {
                    cancel_queued_flow_on_binding(binding, key, key, Some(&mut shared_recycles));
                }
                apply_shared_recycles_to_bindings(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                );
                if let Some((decision, metadata, origin)) = sessions.entry_with_origin(key) {
                    // Demotion keeps the session in the standby table, but the
                    // stale owner must stop advertising local XSK redirect
                    // aliases immediately or XDP will keep steering packets to
                    // the old node after RG handoff.
                    delete_session_map_redirect_for_session(
                        session_map_fd,
                        key,
                        decision,
                        &metadata,
                        origin,
                    );
                }
            }
        }
        heartbeat.store(loop_now_ns, Ordering::Relaxed);
        let expired_entries = sessions.expire_stale_entries(loop_now_ns);
        let expired = expired_entries.len() as u64;
        for expired_entry in expired_entries {
            // #1748: the abandoned W_old copy (RebalancedOut) must NOT release
            // the SNAT allocation on its local-only GC expiry — W_new owns the
            // session and releases the SNAT port on its own real close. A
            // double-release here would free a port W_new is still using.
            if !expired_entry.origin.is_rebalanced_out() {
                release_source_nat_allocation(
                    &forwarding.source_nat_rules,
                    &expired_entry.key,
                    expired_entry.decision.nat,
                    expired_entry.metadata.is_reverse,
                    loop_now_ns,
                );
            }
            delete_session_map_entry_for_removed_session_with_origin(
                session_map_fd,
                &expired_entry.key,
                expired_entry.decision,
                &expired_entry.metadata,
                expired_entry.origin,
                conntrack_v4_fd,
                conntrack_v6_fd,
            );
        }
        if expired > 0 {
            if let Some(binding) = bindings.first() {
                binding
                    .live
                    .session_expires
                    .fetch_add(expired, Ordering::Relaxed);
            }
        }
        // Periodically refresh last_seen in BPF conntrack entries so Go-side
        // callers of IterateSessions (CLI, gRPC, Prometheus) see accurate
        // session idle times.  Issue #333.
        if loop_now_ns.saturating_sub(last_ct_refresh_ns) >= CT_REFRESH_INTERVAL_NS {
            last_ct_refresh_ns = loop_now_ns;
            refresh_bpf_conntrack_last_seen(
                conntrack_v4_fd,
                conntrack_v6_fd,
                &sessions,
                loop_now_ns,
            );
        }
        // Check if fabric links were updated by the coordinator (e.g. after
        // RG failover when peer MAC was resolved). If so, rebuild the
        // forwarding Arc with the new fabric links so fabric redirect works.
        {
            let live_fabrics = shared_fabrics.load();
            if !live_fabrics.is_empty() && live_fabrics.as_ref() != &forwarding.fabrics {
                let mut updated = (*forwarding).clone();
                updated.fabrics = live_fabrics.as_ref().clone();
                forwarding = Arc::new(updated);
            }
        }
        let mut did_work = false;
        let mut dbg_poll = DebugPollCounters::default();
        // #1620: read the cold-path sample mask from forwarding state once
        // per poll cycle (rather than per-binding) — it's a daemon-wide
        // setting and rarely changes. Workers load the ArcSwap-protected
        // forwarding state above so this is L1-hot.
        let cold_path_sample_mask = forwarding.cold_path_sample_mask;
        for offset in 0..bindings.len() {
            let idx = if bindings.is_empty() {
                0
            } else {
                (poll_start + offset) % bindings.len()
            };
            if poll_binding(
                idx,
                &mut bindings,
                &binding_lookup,
                mirror_targets.as_ref(),
                &mut sessions,
                &mut screen_state,
                validation,
                loop_now_ns,
                loop_now_secs,
                ha_startup_grace_until_secs,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                slow_path.as_ref(),
                event_stream.as_ref(),
                &local_tunnel_deliveries,
                &recent_exceptions,
                &recent_session_deltas,
                &last_resolution,
                &peer_worker_commands,
                worker_id,
                worker_commands_by_id.as_ref(),
                &mut shared_recycles,
                &dnat_fds,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &mut dbg_poll,
                &rg_epochs,
                cold_path_sample_mask,
            ) {
                did_work = true;
            }
        }
        crate::filter::flush_recorded_filter_counters();
        dbg_rx_total += dbg_poll.rx;
        #[cfg(feature = "debug-log")]
        {
            dbg_tx_total += dbg_poll.tx;
        }
        dbg_forward_total += dbg_poll.forward;
        #[cfg(feature = "debug-log")]
        {
            dbg_local_total += dbg_poll.local;
            dbg_session_hit += dbg_poll.session_hit;
            dbg_session_miss += dbg_poll.session_miss;
            dbg_session_create += dbg_poll.session_create;
            dbg_no_route += dbg_poll.no_route;
            dbg_missing_neigh += dbg_poll.missing_neigh;
            dbg_neg_neigh_fast_fail += dbg_poll.neg_neigh_fast_fail;
            dbg_policy_deny += dbg_poll.policy_deny;
            dbg_ha_inactive += dbg_poll.ha_inactive;
            dbg_no_egress_binding += dbg_poll.no_egress_binding;
            dbg_build_fail += dbg_poll.build_fail;
            dbg_tx_err += dbg_poll.tx_err;
            dbg_metadata_err += dbg_poll.metadata_err;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_disposition_other += dbg_poll.disposition_other;
            dbg_enqueue_ok += dbg_poll.enqueue_ok;
            dbg_enqueue_inplace += dbg_poll.enqueue_inplace;
            dbg_enqueue_direct += dbg_poll.enqueue_direct;
            dbg_enqueue_copy += dbg_poll.enqueue_copy;
            dbg_rx_from_trust += dbg_poll.rx_from_trust;
            dbg_rx_from_wan += dbg_poll.rx_from_wan;
            dbg_fwd_trust_to_wan += dbg_poll.fwd_trust_to_wan;
            dbg_fwd_wan_to_trust += dbg_poll.fwd_wan_to_trust;
            dbg_nat_snat += dbg_poll.nat_applied_snat;
            dbg_nat_dnat += dbg_poll.nat_applied_dnat;
            dbg_nat_none += dbg_poll.nat_applied_none;
            dbg_frame_build_none += dbg_poll.frame_build_none;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_rx_tcp_rst += dbg_poll.rx_tcp_rst;
            dbg_rx_tcp_fin += dbg_poll.rx_tcp_fin;
            dbg_rx_tcp_synack += dbg_poll.rx_tcp_synack;
            dbg_rx_tcp_zero_window += dbg_poll.rx_tcp_zero_window;
            dbg_fwd_tcp_fin += dbg_poll.fwd_tcp_fin;
            dbg_fwd_tcp_rst += dbg_poll.fwd_tcp_rst;
            dbg_fwd_tcp_zero_window += dbg_poll.fwd_tcp_zero_window;
        }
        #[cfg(feature = "debug-log")]
        {
            dbg_rx_bytes_total += dbg_poll.rx_bytes_total;
            dbg_tx_bytes_total += dbg_poll.tx_bytes_total;
            dbg_rx_oversized += dbg_poll.rx_oversized;
            if dbg_poll.rx_max_frame > dbg_rx_max_frame {
                dbg_rx_max_frame = dbg_poll.rx_max_frame;
            }
            if dbg_poll.tx_max_frame > dbg_tx_max_frame {
                dbg_tx_max_frame = dbg_poll.tx_max_frame;
            }
            dbg_seg_needed_but_none += dbg_poll.seg_needed_but_none;
        }
        if !bindings.is_empty() {
            poll_start = (poll_start + 1) % bindings.len();
        }
        if loop_now_ns.saturating_sub(last_cos_status_ns) >= COS_STATUS_INTERVAL_NS {
            cos_status.store(Arc::new(build_worker_cos_statuses(
                &bindings,
                forwarding.as_ref(),
            )));
            last_cos_status_ns = loop_now_ns;
        }
        if !exported_sequences.is_empty() {
            while sessions.has_pending_deltas() {
                let deltas = sessions.drain_deltas(256);
                purge_queued_flows_for_closed_deltas(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                    &deltas,
                );
                if let Some(binding) = bindings.first() {
                    let ident = binding.identity();
                    flush_session_deltas(
                        &ident,
                        &binding.live,
                        binding.bpf_maps.session_map_fd,
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        &deltas,
                        &shared_sessions,
                        &shared_nat_sessions,
                        &shared_forward_wire_sessions,
                        &shared_owner_rg_indexes,
                        &recent_session_deltas,
                        &peer_worker_commands,
                        &event_stream,
                        forwarding.as_ref(),
                    );
                }
            }
            if let Some(sequence) = exported_sequences.iter().copied().max() {
                session_export_ack.store(sequence, Ordering::Release);
            }
        } else if sessions.has_pending_deltas() {
            let deltas = sessions.drain_deltas(256);
            purge_queued_flows_for_closed_deltas(
                &mut bindings,
                &binding_lookup,
                &mut shared_recycles,
                &deltas,
            );
            if let Some(binding) = bindings.first() {
                let ident = binding.identity();
                flush_session_deltas(
                    &ident,
                    &binding.live,
                    binding.bpf_maps.session_map_fd,
                    conntrack_v4_fd,
                    conntrack_v6_fd,
                    &deltas,
                    &shared_sessions,
                    &shared_nat_sessions,
                    &shared_forward_wire_sessions,
                    &shared_owner_rg_indexes,
                    &recent_session_deltas,
                    &peer_worker_commands,
                    &event_stream,
                    forwarding.as_ref(),
                );
            }
        }
        // Debug: periodic summary report
        {
            let elapsed = loop_now_ns.saturating_sub(dbg_last_report_ns);
            if elapsed >= DBG_REPORT_INTERVAL_NS {
                #[cfg(feature = "debug-log")]
                let secs = elapsed as f64 / 1_000_000_000.0;
                let session_count = sessions.len();
                let mut binding_summary = String::new();
                for (i, b) in bindings.iter().enumerate() {
                    use std::fmt::Write;
                    let fill_pending = b.xsk.device.pending();
                    let rx_avail = b.xsk.rx.available_relaxed();
                    let xsk_stats = b.xsk.device.statistics_v2().ok();
                    let inflight_recycles = b.tx_pipeline.in_flight_prepared_recycles.len() as u32;
                    let scratch_recycle_len = b.scratch.scratch_recycle.len() as u32;
                    let ptx_prepared = b.tx_pipeline.pending_tx_prepared.len() as u32;
                    let ptx_local = b.tx_pipeline.pending_tx_local.len() as u32;
                    let total_accounted = b.tx_pipeline.pending_fill_frames.len() as u32
                        + fill_pending
                        + rx_avail
                        + b.tx_pipeline.free_tx_frames.len() as u32
                        + b.tx_pipeline.outstanding_tx
                        + inflight_recycles
                        + scratch_recycle_len
                        + ptx_prepared; // prepared TX holds UMEM frames
                    let expected_total = b.umem.total_frames();
                    let _ = write!(
                        binding_summary,
                        " [{}:if{}q{} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} scr={} ptxp={} ptxl={} total={}/{} fill_ok={} polls={} bp={} rx_empty={} wake={}",
                        i,
                        b.ifindex,
                        b.queue_id,
                        b.tx_pipeline.pending_fill_frames.len(),
                        fill_pending,
                        rx_avail,
                        b.tx_pipeline.free_tx_frames.len(),
                        b.tx_pipeline.outstanding_tx,
                        inflight_recycles,
                        scratch_recycle_len,
                        ptx_prepared,
                        ptx_local,
                        total_accounted,
                        expected_total,
                        b.telemetry.dbg_fill_submitted,
                        b.telemetry.dbg_poll_cycles,
                        b.telemetry.dbg_backpressure,
                        b.telemetry.dbg_rx_empty,
                        b.telemetry.dbg_rx_wakeups,
                    );
                    // TX pipeline debug counters
                    #[cfg(feature = "debug-log")]
                    {
                        dbg_tx_tcp_rst += b.telemetry.dbg_tx_tcp_rst;
                    }
                    let _ = write!(
                        binding_summary,
                        " TX:ring_sub={}/ring_full={}/compl={}/sendto={}/err={}/eagain={}/enobufs={}/bp_overflow={}/cos_overflow={}",
                        b.telemetry.dbg_tx_ring_submitted,
                        b.telemetry.dbg_tx_ring_full,
                        b.telemetry.dbg_completions_reaped,
                        b.telemetry.dbg_sendto_calls,
                        b.telemetry.dbg_sendto_err,
                        b.telemetry.dbg_sendto_eagain,
                        b.telemetry.dbg_sendto_enobufs,
                        b.telemetry.dbg_bound_pending_overflow,
                        b.telemetry.dbg_cos_queue_overflow,
                    );
                    #[cfg(feature = "debug-log")]
                    let _ = write!(binding_summary, "/rst={}", b.telemetry.dbg_tx_tcp_rst);
                    if let Some(s) = xsk_stats {
                        let _ = write!(
                            binding_summary,
                            " xsk:drop={}/inv={}/rfull={}/fempty={}/tinv={}/tempty={}",
                            s.rx_dropped,
                            s.rx_invalid_descs,
                            s.rx_ring_full,
                            s.rx_fill_ring_empty_descs,
                            s.tx_invalid_descs,
                            s.tx_ring_empty_descs,
                        );
                    }
                    // Socket error check (SO_ERROR) — detect kernel-side errors
                    {
                        let fd = b.xsk.rx.as_raw_fd();
                        let mut so_err: c_int = 0;
                        let mut so_err_len: libc::socklen_t = core::mem::size_of::<c_int>() as _;
                        let rc = unsafe {
                            libc::getsockopt(
                                fd,
                                libc::SOL_SOCKET,
                                libc::SO_ERROR,
                                &mut so_err as *mut c_int as *mut c_void,
                                &mut so_err_len,
                            )
                        };
                        if rc == 0 && so_err != 0 {
                            let _ = write!(binding_summary, " SO_ERR={so_err}");
                        }
                    }
                    // Ring diagnostics from xsk_ffi API
                    if cfg!(feature = "debug-log") {
                        let _ = write!(
                            binding_summary,
                            " RING:rx_nz={}/rx_max={}/fill_pend={}/dev_avail={} RX_WAKE:ok={}/err={}/errno={}",
                            b.telemetry.dbg_rx_avail_nonzero,
                            b.telemetry.dbg_rx_avail_max,
                            b.telemetry.dbg_fill_pending,
                            b.telemetry.dbg_device_avail,
                            b.telemetry.dbg_rx_wake_sendto_ok,
                            b.telemetry.dbg_rx_wake_sendto_err,
                            b.telemetry.dbg_rx_wake_sendto_errno,
                        );
                        // Direct mmap diagnosis: read raw ring producer/consumer
                        if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) =
                            diagnose_raw_ring_state(b.xsk.rx.as_raw_fd())
                        {
                            let _ = write!(
                                binding_summary,
                                " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                            );
                        }
                    }
                    // Frame leak detection
                    if total_accounted != expected_total {
                        let _ = write!(
                            binding_summary,
                            " FRAME_LEAK:{}",
                            expected_total as i64 - total_accounted as i64,
                        );
                    }
                    binding_summary.push(']');
                }
                #[cfg(feature = "debug-log")]
                eprintln!(
                    "DBG w{}: {:.1}s rx={} tx={} fwd={} local={} sess_hit={} sess_miss={} sess_create={} \
                     no_route={} miss_neigh={} neg_ff={} pol_deny={} ha_inact={} no_egress={} build_fail={} \
                     tx_err={} meta_err={} other={} enq_ok={} enq_ip={} enq_dir={} enq_cp={} sessions={} \
                     DIR:trust_rx={}/wan_rx={}/t2w={}/w2t={} NAT:snat={}/dnat={}/none={}/bld_none={} RST:rx={}/tx={} \
                     SIZE:rx_avg={}/rx_max={}/tx_avg={}/tx_max={}/rx_over={}/seg_miss={} \
                     TCP_RX:fin={}/synack={}/zwin={} TCP_FWD:fin={}/rst={}/zwin={} \
                     CSUM:verified={}/bad_ip={}/bad_l4={} \
                     SESS_BPF:verify_ok={}/verify_fail={}/bpf_entries={} bindings:{}",
                    worker_id,
                    secs,
                    dbg_rx_total,
                    dbg_tx_total,
                    dbg_forward_total,
                    dbg_local_total,
                    dbg_session_hit,
                    dbg_session_miss,
                    dbg_session_create,
                    dbg_no_route,
                    dbg_missing_neigh,
                    dbg_neg_neigh_fast_fail,
                    dbg_policy_deny,
                    dbg_ha_inactive,
                    dbg_no_egress_binding,
                    dbg_build_fail,
                    dbg_tx_err,
                    dbg_metadata_err,
                    dbg_disposition_other,
                    dbg_enqueue_ok,
                    dbg_enqueue_inplace,
                    dbg_enqueue_direct,
                    dbg_enqueue_copy,
                    session_count,
                    dbg_rx_from_trust,
                    dbg_rx_from_wan,
                    dbg_fwd_trust_to_wan,
                    dbg_fwd_wan_to_trust,
                    dbg_nat_snat,
                    dbg_nat_dnat,
                    dbg_nat_none,
                    dbg_frame_build_none,
                    dbg_rx_tcp_rst,
                    dbg_tx_tcp_rst,
                    if dbg_rx_total > 0 {
                        dbg_rx_bytes_total / dbg_rx_total
                    } else {
                        0
                    },
                    dbg_rx_max_frame,
                    if dbg_enqueue_ok > 0 {
                        dbg_tx_bytes_total / dbg_enqueue_ok
                    } else {
                        0
                    },
                    dbg_tx_max_frame,
                    dbg_rx_oversized,
                    dbg_seg_needed_but_none,
                    dbg_rx_tcp_fin,
                    dbg_rx_tcp_synack,
                    dbg_rx_tcp_zero_window,
                    dbg_fwd_tcp_fin,
                    dbg_fwd_tcp_rst,
                    dbg_fwd_tcp_zero_window,
                    CSUM_VERIFIED_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_IP_TOTAL.swap(0, Ordering::Relaxed),
                    CSUM_BAD_L4_TOTAL.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_OK.swap(0, Ordering::Relaxed),
                    SESSION_PUBLISH_VERIFY_FAIL.swap(0, Ordering::Relaxed),
                    if let Some(b) = bindings.first() {
                        count_bpf_session_entries(b.bpf_maps.session_map_fd)
                    } else {
                        0
                    },
                    binding_summary,
                );
                // Non-debug builds: no per-second stats dump (use debug-log feature for verbose output).
                // Print retained-shim degraded-path stats — tells us WHY
                // packets stop being redirected to XSK.
                if cfg!(feature = "debug-log") {
                    if let Some(stats) = read_degraded_path_stats() {
                        if !stats.is_empty() {
                            let s: Vec<String> =
                                stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                            eprintln!("DBG w{}: XDP_DEGRADED: {}", worker_id, s.join(" "));
                        }
                    }
                }
                // Save prev counters BEFORE reset for stall detection below
                if cfg!(feature = "debug-log") {
                    prev_rx_total = dbg_rx_total;
                    prev_fwd_total = dbg_forward_total;
                }
                dbg_last_report_ns = loop_now_ns;
                dbg_rx_total = 0;
                #[cfg(feature = "debug-log")]
                {
                    dbg_tx_total = 0;
                }
                dbg_forward_total = 0;
                #[cfg(feature = "debug-log")]
                {
                    dbg_local_total = 0;
                    dbg_session_hit = 0;
                    dbg_session_miss = 0;
                    dbg_session_create = 0;
                    dbg_no_route = 0;
                    dbg_missing_neigh = 0;
                    dbg_neg_neigh_fast_fail = 0;
                    dbg_policy_deny = 0;
                    dbg_ha_inactive = 0;
                    dbg_no_egress_binding = 0;
                    dbg_build_fail = 0;
                    dbg_tx_err = 0;
                    dbg_metadata_err = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_disposition_other = 0;
                    dbg_enqueue_ok = 0;
                    dbg_enqueue_inplace = 0;
                    dbg_enqueue_direct = 0;
                    dbg_enqueue_copy = 0;
                    dbg_rx_from_trust = 0;
                    dbg_rx_from_wan = 0;
                    dbg_fwd_trust_to_wan = 0;
                    dbg_fwd_wan_to_trust = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_rx_bytes_total = 0;
                    dbg_tx_bytes_total = 0;
                    dbg_rx_oversized = 0;
                    dbg_rx_max_frame = 0;
                    dbg_tx_max_frame = 0;
                    dbg_seg_needed_but_none = 0;
                }
                // Stall detection: stall_prev_fwd is PREVIOUS interval's fwd count,
                // prev_fwd_total is THIS interval's fwd count (saved before reset).
                if cfg!(feature = "debug-log") {
                    if stall_prev_fwd > 10 && prev_fwd_total == 0 && !stall_reported {
                        stall_reported = true;
                        eprintln!(
                            "DBG STALL_DETECTED: w{} two_ago_fwd={} this_interval_fwd={} this_interval_rx={} sessions={}",
                            worker_id, stall_prev_fwd, prev_fwd_total, prev_rx_total, session_count
                        );
                        // Dump comprehensive per-binding state at stall moment
                        for (si, sb) in bindings.iter().enumerate() {
                            use std::fmt::Write;
                            let fill_p = sb.xsk.device.pending();
                            let rx_a = sb.xsk.rx.available_relaxed();
                            let ifl = sb.tx_pipeline.in_flight_prepared_recycles.len() as u32;
                            let ptxp = sb.tx_pipeline.pending_tx_prepared.len() as u32;
                            let ptxl = sb.tx_pipeline.pending_tx_local.len() as u32;
                            let total = sb.tx_pipeline.pending_fill_frames.len() as u32
                                + fill_p
                                + rx_a
                                + sb.tx_pipeline.free_tx_frames.len() as u32
                                + sb.tx_pipeline.outstanding_tx
                                + ifl
                                + sb.scratch.scratch_recycle.len() as u32
                                + ptxp;
                            let raw = diagnose_raw_ring_state(sb.xsk.rx.as_raw_fd());
                            let mut stall_line = format!(
                                "DBG STALL_BINDING[{}]: if={} q={} pfill={} fring={} rxring={} free_tx={} otx={} ifl={} ptxp={} ptxl={} total={}/{}",
                                si,
                                sb.ifindex,
                                sb.queue_id,
                                sb.tx_pipeline.pending_fill_frames.len(),
                                fill_p,
                                rx_a,
                                sb.tx_pipeline.free_tx_frames.len(),
                                sb.tx_pipeline.outstanding_tx,
                                ifl,
                                ptxp,
                                ptxl,
                                total,
                                sb.umem.total_frames(),
                            );
                            if let Some((rxp, rxc, frp, frc, txp, txc, crp, crc)) = raw {
                                let _ = write!(
                                    stall_line,
                                    " RAW:rxP={rxp}/rxC={rxc}/frP={frp}/frC={frc}/txP={txp}/txC={txc}/crP={crp}/crC={crc}"
                                );
                            }
                            if let Ok(Some(stats)) = sb.xsk.device.statistics_v2().map(Some) {
                                let _ = write!(
                                    stall_line,
                                    " xsk:drop={}/rfull={}/fempty={}/tempty={}",
                                    stats.rx_dropped,
                                    stats.rx_ring_full,
                                    stats.rx_fill_ring_empty_descs,
                                    stats.tx_ring_empty_descs
                                );
                            }
                            eprintln!("{stall_line}");
                        }
                        // Dump all session keys for this worker
                        let mut sess_dump = String::new();
                        let mut count = 0;
                        sessions.iter_with_origin(|key, decision, metadata, origin| {
                            if count < 20 {
                                use std::fmt::Write;
                                let _ = write!(
                                    sess_dump,
                                    "\n  SESS: {}:{} -> {}:{} proto={} nat=({:?},{:?}) is_rev={} origin={}",
                                    key.src_ip,
                                    key.src_port,
                                    key.dst_ip,
                                    key.dst_port,
                                    key.protocol,
                                    decision.nat.rewrite_src,
                                    decision.nat.rewrite_dst,
                                    metadata.is_reverse,
                                    origin.as_str(),
                                );
                                count += 1;
                            }
                        });
                        if !sess_dump.is_empty() {
                            eprintln!("DBG STALL_SESSIONS:{sess_dump}");
                        }
                        // Dump degraded-path stats at stall time.
                        if let Some(stats) = read_degraded_path_stats() {
                            if !stats.is_empty() {
                                let s: Vec<String> =
                                    stats.iter().map(|(n, v)| format!("{n}={v}")).collect();
                                eprintln!("DBG STALL_DEGRADED: {}", s.join(" "));
                            }
                        }
                        // Also dump BPF session count
                        if let Some(b) = bindings.first() {
                            eprintln!(
                                "DBG STALL_BPF_SESSIONS: entries={}",
                                count_bpf_session_entries(b.bpf_maps.session_map_fd)
                            );
                        }
                    } else if prev_fwd_total > 0 {
                        stall_reported = false;
                    }
                    stall_prev_fwd = prev_fwd_total;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_nat_snat = 0;
                    dbg_nat_dnat = 0;
                    dbg_nat_none = 0;
                    dbg_frame_build_none = 0;
                }
                #[cfg(feature = "debug-log")]
                {
                    dbg_rx_tcp_rst = 0;
                    dbg_tx_tcp_rst = 0;
                    dbg_rx_tcp_fin = 0;
                    dbg_rx_tcp_synack = 0;
                    dbg_rx_tcp_zero_window = 0;
                    dbg_fwd_tcp_fin = 0;
                    dbg_fwd_tcp_rst = 0;
                    dbg_fwd_tcp_zero_window = 0;
                }
                for b in bindings.iter_mut() {
                    // #802: publish ring-pressure counters into BindingLiveState
                    // BEFORE resetting the worker-local window. The worker-local
                    // counters (b.telemetry.dbg_tx_ring_full, etc.) are accumulated by the
                    // hot path and reset each ~1s debug tick; without this
                    // publish they'd never be visible outside the worker thread.
                    // fetch_add is used because the atomic holds the cumulative
                    // total while the local counter holds only the current
                    // window. Relaxed is sufficient — diagnostic counters, no
                    // synchronization contract.
                    if b.telemetry.dbg_tx_ring_full != 0 {
                        b.live
                            .dbg_tx_ring_full
                            .fetch_add(b.telemetry.dbg_tx_ring_full, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_sendto_enobufs != 0 {
                        b.live
                            .dbg_sendto_enobufs
                            .fetch_add(b.telemetry.dbg_sendto_enobufs, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_bound_pending_overflow != 0 {
                        b.live
                            .dbg_bound_pending_overflow
                            .fetch_add(b.telemetry.dbg_bound_pending_overflow, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_cos_queue_overflow != 0 {
                        b.live
                            .dbg_cos_queue_overflow
                            .fetch_add(b.telemetry.dbg_cos_queue_overflow, Ordering::Relaxed);
                    }
                    // #802: kernel xdp_statistics.rx_fill_ring_empty_descs is
                    // already absolute (kernel-cumulative), so publish with
                    // store() not fetch_add. Sampling failures are silently
                    // ignored — the atomic simply retains its last good value.
                    if let Ok(stats) = b.xsk.device.statistics_v2() {
                        b.live
                            .rx_fill_ring_empty_descs
                            .store(stats.rx_fill_ring_empty_descs, Ordering::Relaxed);
                    }
                    // #802: outstanding_tx is a transient gauge on
                    // BindingWorker.tx_pipeline (current in-flight TX).
                    // Publish to the existing atomic mirror on
                    // BindingLiveState so the snapshot reader sees a
                    // recent value. store() because it's a gauge, not a
                    // counter. (#959 Phase 10 moved the field from
                    // BindingWorker to WorkerTxPipeline.)
                    b.live
                        .debug_outstanding_tx
                        .store(b.tx_pipeline.outstanding_tx, Ordering::Relaxed);
                    publish_tx_completion_ring_telemetry(&b.live, &mut b.telemetry);
                    // #878: publish UMEM in-flight gauge as a single atomic
                    // so the daemon's `show chassis forwarding` Buffer% can
                    // divide by `umem_total_frames` without torn-load risk.
                    // Computed in this thread from worker-local state, so
                    // the inputs are mutually consistent at sample time.
                    //
                    // "Idle" frames are: free_tx_frames (worker's TX-available
                    // pool), pending_fill_frames (worker's queue waiting to
                    // push to the kernel's fill ring), AND fill_pending (the
                    // kernel's fill ring itself, which holds frames the
                    // kernel can place RX data into — those are NOT in
                    // flight). Without subtracting fill_pending the gauge
                    // reads ~70-80% at idle because AF_XDP keeps the fill
                    // ring pre-populated by design.
                    let total = b.umem.total_frames();
                    let free_tx = b.tx_pipeline.free_tx_frames.len() as u32;
                    let pending_fill = b.tx_pipeline.pending_fill_frames.len() as u32;
                    let kernel_fill = b.xsk.device.pending();
                    let inflight = total
                        .saturating_sub(free_tx)
                        .saturating_sub(pending_fill)
                        .saturating_sub(kernel_fill);
                    b.live
                        .umem_inflight_frames
                        .store(inflight, Ordering::Relaxed);

                    b.telemetry.dbg_fill_submitted = 0;
                    b.telemetry.dbg_fill_failed = 0;
                    b.telemetry.dbg_poll_cycles = 0;
                    b.telemetry.dbg_backpressure = 0;
                    b.telemetry.dbg_rx_empty = 0;
                    b.telemetry.dbg_rx_wakeups = 0;
                    b.telemetry.dbg_tx_ring_submitted = 0;
                    b.telemetry.dbg_tx_ring_full = 0;
                    b.telemetry.dbg_completions_reaped = 0;
                    b.telemetry.dbg_sendto_calls = 0;
                    b.telemetry.dbg_sendto_err = 0;
                    b.telemetry.dbg_sendto_eagain = 0;
                    b.telemetry.dbg_sendto_enobufs = 0;
                    b.telemetry.dbg_bound_pending_overflow = 0;
                    b.telemetry.dbg_cos_queue_overflow = 0;
                    #[cfg(feature = "debug-log")]
                    {
                        b.telemetry.dbg_tx_tcp_rst = 0;
                    }
                    b.telemetry.dbg_rx_avail_nonzero = 0;
                    b.telemetry.dbg_rx_avail_max = 0;
                    b.telemetry.dbg_rx_wake_sendto_ok = 0;
                    b.telemetry.dbg_rx_wake_sendto_err = 0;
                    b.telemetry.dbg_rx_wake_sendto_errno = 0;
                }
            }
        }
        if did_work {
            idle_iters = 0;
            // #869: classify this iteration for next-loop-top accounting.
            wr_state = WorkerRuntimeState::Active;
            wr_counters.work_loops = wr_counters.work_loops.wrapping_add(1);
            continue;
        }
        idle_iters = idle_iters.saturating_add(1);
        wr_counters.idle_loops = wr_counters.idle_loops.wrapping_add(1);
        match poll_mode {
            crate::PollMode::BusyPoll => {
                if idle_iters <= IDLE_SPIN_ITERS {
                    wr_state = WorkerRuntimeState::IdleSpin;
                    std::hint::spin_loop();
                } else {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    thread::sleep(Duration::from_micros(IDLE_SLEEP_US));
                }
            }
            crate::PollMode::Interrupt => {
                // Interrupt mode still needs a short local spin before blocking.
                // Firewall-local TCP flows are ACK-latency-sensitive; blocking
                // immediately on the first empty poll collapses cwnd badly.
                if idle_iters <= IDLE_SPIN_ITERS {
                    wr_state = WorkerRuntimeState::IdleSpin;
                    std::hint::spin_loop();
                } else if !interrupt_poll_fds.is_empty() {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    for pfd in &mut interrupt_poll_fds {
                        pfd.revents = 0;
                    }
                    unsafe {
                        libc::poll(
                            interrupt_poll_fds.as_mut_ptr(),
                            interrupt_poll_fds.len() as libc::nfds_t,
                            INTERRUPT_POLL_TIMEOUT_MS,
                        );
                    }
                } else {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    thread::sleep(Duration::from_millis(INTERRUPT_POLL_TIMEOUT_MS as u64));
                }
            }
        }
    }
    crate::filter::flush_recorded_filter_counters();
    for binding in bindings.iter_mut() {
        clear_all_cos_exact_backlogs_for_binding(binding);
        release_all_cos_root_leases(binding);
        release_all_cos_queue_leases(binding);
    }
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
    )));
    heartbeat.store(monotonic_nanos(), Ordering::Relaxed);
}
