// BindingWorker per-poll lifecycle (Issue 73 step 2). The function
// `poll_binding` was the central RX/TX orchestrator extracted from
// the root afxdp/mod.rs. It is called once per BindingWorker per
// worker-loop iteration from worker/mod.rs::worker_loop().
//
// `use super::*;` brings every type, helper, and sibling-submodule
// item from worker/mod.rs into scope (which itself does
// `use super::*;` to pull from afxdp/mod.rs). Pure relocation —
// no production logic touched.

use super::*;

// Pins the invariant that `poll_binding` relies on: the RX batch loop
// must run at least once. Cheap compile-time guard.
const _: () = assert!(MAX_RX_BATCHES_PER_POLL >= 1);

pub(super) fn poll_binding(
    binding_index: usize,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    _recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: &Arc<Mutex<Option<PacketResolution>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    shared_recycles: &mut Vec<(u32, u64)>,
    dnat_fds: &DnatTableFds,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    dbg: &mut DebugPollCounters,
    rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    cos_owner_worker_by_queue: &BTreeMap<(i32, u8), u32>,
    cos_owner_live_by_queue: &BTreeMap<(i32, u8), Arc<BindingLiveState>>,
) -> bool {
    let (left, rest) = bindings.split_at_mut(binding_index);
    let Some((binding, right)) = rest.split_first_mut() else {
        return false;
    };
    let area = binding.umem.area() as *const MmapArea;
    maybe_touch_heartbeat(binding, now_ns);
    let tx_work = drain_pending_tx(
        binding,
        now_ns,
        shared_recycles,
        forwarding,
        worker_id,
        worker_commands_by_id,
        cos_owner_worker_by_queue,
        cos_owner_live_by_queue,
    );
    apply_shared_recycles(
        left,
        binding_index,
        binding,
        right,
        binding_lookup,
        shared_recycles,
    );
    let fill_work = drain_pending_fill(binding, now_ns);
    let mut did_work = tx_work || fill_work;
    binding.telemetry.dbg_poll_cycles += 1;
    let mut counters = BatchCounters::default();
    let mut ident: Option<BindingIdentity> = None;
    for _ in 0..MAX_RX_BATCHES_PER_POLL {
        // Backpressure: skip RX when TX queues are heavily loaded to prevent
        // fill ring exhaustion. The NIC holds packets until we refill (#201).
        let tx_backlog = binding.tx_pipeline.pending_tx_local.len()
            + binding.tx_pipeline.pending_tx_prepared.len();
        if tx_backlog >= binding.tx_pipeline.max_pending_tx {
            binding.telemetry.dbg_backpressure += 1;
            // Try to drain TX first — completions free frames for both TX and fill.
            let _ = drain_pending_tx(
                binding,
                now_ns,
                shared_recycles,
                forwarding,
                worker_id,
                worker_commands_by_id,
                cos_owner_worker_by_queue,
                cos_owner_live_by_queue,
            );
            apply_shared_recycles(
                left,
                binding_index,
                binding,
                right,
                binding_lookup,
                shared_recycles,
            );
            // Critical: drain fill ring even under backpressure so the NIC can
            // still receive packets. Without this, fill ring starvation causes
            // mlx5 to fall back to non-XSK NAPI, leaking packets to the kernel.
            let _ = drain_pending_fill(binding, now_ns);
            counters.flush(&binding.live);
            update_binding_debug_state(binding);
            return did_work;
        }

        let raw_avail = binding.xsk.rx.available();
        let available = raw_avail.min(RX_BATCH_SIZE);
        if raw_avail > 0 && !binding.bind_meta.xsk_rx_confirmed {
            binding.bind_meta.xsk_rx_confirmed = true;
        }
        if cfg!(feature = "debug-log") {
            if raw_avail > 0 {
                binding.telemetry.dbg_rx_avail_nonzero += 1;
                if raw_avail > binding.telemetry.dbg_rx_avail_max {
                    binding.telemetry.dbg_rx_avail_max = raw_avail;
                }
            }
            // Ring diagnostics are only consumed by debug-log summaries.
            binding.telemetry.dbg_fill_pending = binding.xsk.device.pending();
            binding.telemetry.dbg_device_avail = binding.xsk.device.available();
        }
        if available == 0 {
            binding.telemetry.dbg_rx_empty += 1;
            maybe_wake_rx(binding, false, now_ns);
            // Check pending neighbor buffer even when RX is empty.
            // Without this, buffered SYN packets wait until the next
            // RX packet arrives (TCP retransmit ~1s) instead of being
            // retried as soon as the netlink monitor resolves ARP.
            retry_pending_neigh(
                binding,
                left,
                binding_index,
                right,
                binding_lookup,
                forwarding,
                dynamic_neighbors,
                now_ns,
                unsafe { &*(binding.umem.area() as *const MmapArea) },
            );
            counters.flush(&binding.live);
            update_binding_idle_debug_state(binding, now_ns);
            return did_work;
        }
        binding.timers.empty_rx_polls = 0;
        if ident.is_none() {
            ident = Some(binding.identity());
        }
        let ident = ident
            .as_ref()
            .expect("identity initialized when RX has work");

        // #945: WorkerContext groups 16 shared/passed-through references
        // (interior mutability via locks is preserved). TelemetryContext
        // groups the two mutable counter sinks. Named-field shorthand
        // ensures the compiler verifies field name == local-variable
        // name; any swap of two shared-typed fields would require
        // renaming a local elsewhere and break compilation.
        let worker_ctx = WorkerContext {
            ident,
            binding_lookup,
            forwarding,
            ha_state,
            dynamic_neighbors,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            slow_path,
            local_tunnel_deliveries,
            recent_exceptions,
            last_resolution,
            peer_worker_commands,
            dnat_fds,
            rg_epochs,
        };
        let mut telemetry = TelemetryContext {
            dbg,
            counters: &mut counters,
        };
        poll_binding_process_descriptor(
            binding,
            binding_index,
            area,
            available,
            sessions,
            screen,
            validation,
            now_ns,
            now_secs,
            ha_startup_grace_until_secs,
            worker_id,
            conntrack_v4_fd,
            conntrack_v6_fd,
            &worker_ctx,
            &mut telemetry,
        );
        let mut pending_forwards = core::mem::take(&mut binding.scratch.scratch_forwards);
        let mut rst_teardowns = core::mem::take(&mut binding.scratch.scratch_rst_teardowns);
        for (forward_key, nat) in rst_teardowns.drain(..) {
            // Evict from flow cache so stale entries aren't used after RST.
            // #918: 4-way set-associative cache requires walking the set
            // for the matching key — `invalidate_slot` does that.
            binding
                .flow
                .flow_cache
                .invalidate_slot(&forward_key, binding.ifindex);
            teardown_tcp_rst_flow(
                left,
                binding,
                right,
                sessions,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                peer_worker_commands,
                &forward_key,
                nat,
                &mut pending_forwards,
                shared_recycles,
            );
        }
        binding.scratch.scratch_rst_teardowns = rst_teardowns;
        if !pending_forwards.is_empty() {
            // Use raw pointer to avoid Arc::clone (~5% CPU from lock incq).
            // Safety: the Arc<BindingLiveState> outlives this function call;
            // binding is borrowed mutably by enqueue_pending_forwards but
            // ingress_live is only used for read-only error logging inside it.
            let ingress_live: *const BindingLiveState = &*binding.live;
            let mut scratch_post_recycles =
                core::mem::take(&mut binding.scratch.scratch_post_recycles);
            enqueue_pending_forwards(
                left,
                binding_index,
                binding,
                right,
                binding_lookup,
                &mut pending_forwards,
                &mut scratch_post_recycles,
                now_ns,
                forwarding,
                &ident,
                unsafe { &*ingress_live },
                slow_path,
                local_tunnel_deliveries,
                recent_exceptions,
                dbg,
                worker_id,
                worker_commands_by_id,
                cos_owner_worker_by_queue,
                cos_owner_live_by_queue,
            );
            binding.scratch.scratch_post_recycles = scratch_post_recycles;
        }
        binding.scratch.scratch_forwards = pending_forwards;
        // Reserved: cross-binding in-place TX from flow cache fast path.
        // Currently only self-target (hairpin) uses the inline path;
        // cross-binding goes through enqueue_pending_forwards above.
        // Eager TX completion reaping: free TX frames immediately after
        // enqueueing forwards so they can be recycled to fill ring within
        // the same poll cycle. Without this, completions wait until next
        // poll entry, starving the fill ring during sustained forwarding.
        reap_tx_completions(binding, shared_recycles);
        // Also reap completions on the egress bindings that just transmitted.
        for other in left.iter_mut().chain(right.iter_mut()) {
            reap_tx_completions(other, shared_recycles);
        }
        apply_shared_recycles(
            left,
            binding_index,
            binding,
            right,
            binding_lookup,
            shared_recycles,
        );
        if !binding.scratch.scratch_recycle.is_empty() {
            binding
                .tx_pipeline
                .pending_fill_frames
                .extend(binding.scratch.scratch_recycle.drain(..));
        }
        let _ = drain_pending_fill(binding, now_ns);
        counters.rx_batches += 1;
        did_work = true;
    }
    retry_pending_neigh(
        binding,
        left,
        binding_index,
        right,
        binding_lookup,
        forwarding,
        dynamic_neighbors,
        now_ns,
        unsafe { &*area },
    );
    counters.flush(&binding.live);
    update_binding_debug_state(binding);
    did_work
}
