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
    mirror_targets: &MirrorTargetMap,
    sessions: &mut SessionTable,
    screen: &mut ScreenState,
    validation: ValidationState,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    pptp_control: &Arc<crate::session::pptp_control::PptpControlInbox>,
    neighbor_resolver: Option<&Arc<NeighborResolver>>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    ike_exchanges: &crate::afxdp::forwarding::SharedIkeExchangeTable,
    slow_path: Option<&Arc<SlowPathReinjector>>,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    local_tunnel_deliveries: &Arc<ArcSwap<BTreeMap<i32, LocalTunnelDelivery>>>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    _recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    last_resolution: &Arc<Mutex<Option<ResolutionEvent>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_id: u32,
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    shared_recycles: &mut Vec<(u32, u64)>,
    dnat_fds: &DnatTableFds,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    dbg: &mut DebugPollCounters,
    rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    cold_path_sample_mask: u64,
) -> bool {
    let (left, rest) = bindings.split_at_mut(binding_index);
    let Some((binding, right)) = rest.split_first_mut() else {
        return false;
    };
    // Raw-pointer contract for every `unsafe { &*area }` reborrow on the
    // poll path (here and in poll_descriptor): `area` is cast from a
    // `&MmapArea` borrowed out of `binding.umem` (an `Rc<WorkerUmemInner>`
    // allocation). The pointee outlives the whole poll call — nothing on
    // the poll path drops or replaces `binding.umem`, and the only
    // `&mut WorkerUmemInner` escape hatch (`WorkerUmem::umem_mut` via
    // `Rc::get_mut`) is exercised solely at bind time (bind.rs), never
    // while a worker is polling — so the shared reborrows can never alias
    // a mutable reference. The raw pointer exists only to decouple the
    // immutable UMEM-area borrow from the `&mut BindingWorker` borrows
    // taken by the same calls.
    let area = binding.umem.area() as *const MmapArea;
    maybe_touch_heartbeat(binding, now_ns);
    let tx_work = drain_pending_tx(
        binding,
        now_ns,
        shared_recycles,
        forwarding,
        worker_id,
        worker_commands_by_id,
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
            // still receive packets. With no free fill-ring frames, mlx5 cannot
            // post RX WQEs: it counts `rx_xsk_buff_alloc_err` and drops the
            // incoming packets (see `maybe_wake_rx` in `tx/rings.rs`). There is
            // no fallback to the regular RQ in upstream v6.18 (#9695).
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
                mirror_targets,
                forwarding,
                dynamic_neighbors,
                neighbor_resolver,
                now_ns,
                // SAFETY: fresh round-trip through the same `&MmapArea`
                // borrow `area` was created from; see the `area` contract
                // at the top of this function — the pointee outlives the
                // call and is never aliased mutably on the poll path.
                unsafe { &*(binding.umem.area() as *const MmapArea) },
                shared_recycles,
                event_stream,
                &mut counters,
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

        // #945: WorkerContext groups the shared/passed-through references
        // (interior mutability via locks is preserved). TelemetryContext
        // groups the two mutable counter sinks. Named-field shorthand
        // ensures the compiler verifies field name == local-variable
        // name; any swap of two shared-typed fields would require
        // renaming a local elsewhere and break compilation.
        let worker_ctx = WorkerContext {
            ident,
            binding_lookup,
            mirror_targets,
            forwarding,
            ha_state,
            dynamic_neighbors,
            pptp_control,
            neighbor_resolver,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            ike_exchanges,
            slow_path,
            event_stream,
            local_tunnel_deliveries,
            recent_exceptions,
            last_resolution,
            peer_worker_commands,
            worker_commands_by_id,
            dnat_fds,
            rg_epochs,
            cold_path_sample_mask,
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
        // #7212: evict the flow-cache slots backing every session this pass
        // REVOKED against a changed static interface INPUT filter.
        //
        // This runs on EVERY binding of this worker — `left`, the current
        // binding, and `right` — because the session key does not carry the
        // ingress ifindex the cache is keyed on, and the forward and reverse
        // directions of one flow are routinely cached on different bindings.
        // `invalidate_slot` drops only a slot whose key AND ingress_ifindex both
        // match, and the session table is keyed by the 5-tuple alone, so at most
        // one VALID descriptor exists per key: on a non-owning binding the call
        // either no-ops or drops a stale prior-flow slot with the same tuple,
        // never another live flow's entry. Same ownership argument as the #3776
        // GC-reap and #6457 delete-sync evictions.
        //
        // It runs in the SAME tick as the teardown, before another packet is
        // processed, so the revoked flow cannot be served off a cached
        // `RewriteDescriptor` on this worker even once. Sibling WORKERS evict on
        // their next tick via the `replicate_session_delete` -> `DeleteSynced`
        // -> #6457 path the teardown already queued.
        drain_revoked_flow_cache_keys(left, binding, right);
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
                mirror_targets,
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
                &mut counters,
                worker_id,
                worker_commands_by_id,
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
        mirror_targets,
        forwarding,
        dynamic_neighbors,
        neighbor_resolver,
        now_ns,
        // SAFETY: see the `area` contract at the top of this function —
        // the pointee outlives the call and is never aliased mutably on
        // the poll path.
        unsafe { &*area },
        shared_recycles,
        event_stream,
        &mut counters,
    );
    counters.flush(&binding.live);
    update_binding_debug_state(binding);
    did_work
}

/// #7212: evict the flow-cache slots backing every session the poll pass
/// REVOKED against a changed static interface INPUT filter, on EVERY binding of
/// this worker.
///
/// A named helper rather than an inline loop so the all-binding property is
/// bindable by a test: the enclosing poll function is not callable on its own,
/// and an inline `for` over `left`/`current`/`right` can be narrowed to the
/// current binding alone with no test going red.
///
/// Every binding is walked because a session key does not carry the ingress
/// ifindex the cache is keyed on, and the forward and reverse directions of one
/// flow are routinely cached on different bindings. `invalidate_slot` drops only
/// a slot whose key AND ingress_ifindex both match, and the session table is
/// keyed by the 5-tuple alone, so at most one VALID descriptor exists per key:
/// on a non-owning binding the call either no-ops or drops a stale prior-flow
/// slot with the same tuple, never another live flow's entry. Same ownership
/// argument as the #3776 GC-reap and #6457 delete-sync evictions.
///
/// `keys` is DRAINED so the caller can hand its scratch vector straight back to
/// the binding with its capacity intact.
/// #7212: take the revoked keys `current` accumulated during its RX batch,
/// evict them from every binding of this worker, and hand the emptied vector
/// back so its capacity is reused.
///
/// The take/evict/restore is ONE named function rather than three statements at
/// the call site because the call site is inside a poll function no test can
/// invoke: with it inline, deleting it left every #7212 cell green while the
/// revoked flow kept forwarding off a cached descriptor AND the scratch vector
/// grew without bound, since nothing else clears it. This is the repo's
/// "bind the WIRING, not the function it calls" rule — the cell that drives this
/// starts from a binding whose scratch is populated, which is the state the poll
/// pass actually leaves behind.
/// #8114 item 3: the exact extent of the same-worker revocation window,
/// derived rather than written down.
///
/// [`drain_revoked_flow_cache_keys`] runs INSIDE `poll_binding`, after that
/// binding's descriptor loop and before the worker polls any other binding. So
/// the slots a revocation leaves live are live for exactly the descriptors that
/// were already queued behind the revoking one in THIS `poll_binding` call —
/// at most `MAX_RX_BATCHES_PER_POLL` batches of `RX_BATCH_SIZE`, minus the
/// revoking descriptor itself.
///
/// Two things this bound is NOT, both worth stating because #8114 states the
/// first and a reader would assume the second:
///
/// - It is not a SIBLING-BINDING window. #8114 describes "a later descriptor in
///   the same batch, arriving on a sibling binding of the same worker". No such
///   descriptor exists: one `poll_binding` call processes ONE binding's ring,
///   and the drain below evicts across `left` + `current` + `right` before the
///   worker's loop reaches any sibling. A sibling's slot is already gone by the
///   time its own poll runs. The window is on the SAME binding — the revoked
///   flow's own packets, already in the ring.
/// - It is not a SIBLING-WORKER window. Those evict on their next tick through
///   the `replicate_session_delete` -> `DeleteSynced` -> #6457 path, which is a
///   different (larger) window and is entangled with #8114 item 4: a delete a
///   full queue refuses is never delivered at all.
///
/// Expressed as a product of the two constants that actually bound it, so a
/// change to either moves this figure instead of leaving a stale number in a
/// comment. Today that is **255**.
///
/// A companion cell asserting `== 255` was WRITTEN AND THEN REMOVED, and the
/// reason is worth keeping: `afxdp/mod.rs` already carries
/// `const _: () = assert!(RX_BATCH_SIZE == 64, ..)`, so the figure cannot move
/// without failing to COMPILE. A runtime assertion behind a compile-time gate
/// can never fail, and a check that cannot fail is not a guard — it is a
/// sentence that looks like one. The derivation above is the guard; the
/// compile-time pin is what makes 255 stable.
pub(crate) const REVOCATION_FLOW_CACHE_WINDOW_DESCRIPTORS: usize =
    MAX_RX_BATCHES_PER_POLL * (RX_BATCH_SIZE as usize) - 1;

pub(super) fn drain_revoked_flow_cache_keys(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
) {
    let mut keys = core::mem::take(&mut current.scratch.scratch_filter_revoked_keys);
    invalidate_flow_cache_slots_for_revoked_sessions(left, current, right, &mut keys);
    current.scratch.scratch_filter_revoked_keys = keys;
}

pub(super) fn invalidate_flow_cache_slots_for_revoked_sessions(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    keys: &mut Vec<SessionKey>,
) {
    if keys.is_empty() {
        return;
    }
    for key in keys.drain(..) {
        for binding in left
            .iter_mut()
            .chain(core::iter::once(&mut *current))
            .chain(right.iter_mut())
        {
            invalidate_flow_cache_key_on_binding(binding, &key);
        }
    }
}

/// The per-binding step of both eviction walks, single-sourced.
///
/// `invalidate_slot` drops only a slot whose key AND ingress_ifindex both match,
/// so a call on a non-owning binding either no-ops or drops a stale prior-flow
/// slot with the same tuple — never another live flow's entry.
#[inline]
pub(super) fn invalidate_flow_cache_key_on_binding(
    binding: &mut BindingWorker,
    key: &SessionKey,
) {
    binding.flow.flow_cache.invalidate_slot(key, binding.ifindex);
}

/// #8586: the FLAT sibling of `invalidate_flow_cache_slots_for_revoked_sessions`.
///
/// The split-borrow form exists because `poll_binding` holds one binding
/// mutably and its siblings as `left`/`right` slices. The #8586 reconcile runs
/// from the worker LOOP, which owns the whole `bindings` vector, so it needs no
/// split — and forcing one would be a workaround for a borrow shape that is not
/// there. Both walk every binding and share the per-binding step above, so they
/// cannot drift on WHAT an eviction does.
pub(in crate::afxdp) fn invalidate_flow_cache_slots_for_keys(
    bindings: &mut [BindingWorker],
    keys: &[SessionKey],
) {
    if keys.is_empty() {
        return;
    }
    for key in keys {
        for binding in bindings.iter_mut() {
            invalidate_flow_cache_key_on_binding(binding, key);
        }
    }
}

// #7212: the all-binding, same-tick eviction of a revoked session's flow-cache
// slots.
#[cfg(test)]
#[path = "lifecycle_revoked_flow_cache_7212_tests.rs"]
mod lifecycle_revoked_flow_cache_7212_tests;
