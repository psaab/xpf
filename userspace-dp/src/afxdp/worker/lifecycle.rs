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
use crate::afxdp::poll_descriptor::poll_binding_process_descriptor_in_view;

// Pins the invariant that `poll_binding` relies on: the RX batch loop
// must run at least once. Cheap compile-time guard.
const _: () = assert!(MAX_RX_BATCHES_PER_POLL >= 1);

/// #18560: the view a batch runs under. With parked packets it is the
/// retained view matching the first parked stamp (its tables and its
/// validation); with none, or when that view has expired, the current pair.
pub(in crate::afxdp) fn held_pass_view<'a>(
    view_held: &[(XdpDesc, UserspaceDpMeta)],
    prev_views: &'a crate::afxdp::PrevViews,
    now_ns: u64,
    forwarding: &'a ForwardingState,
    validation: ValidationState,
) -> (Option<usize>, &'a ForwardingState, ValidationState) {
    let held_view = view_held.first().and_then(|(_, meta)| {
        prev_views.find(meta.config_generation, meta.fib_generation, now_ns)
    });
    match held_view.and_then(|index| prev_views.get(index)) {
        Some(view) => (held_view, view.forwarding.as_ref(), view.validation),
        None => (None, forwarding, validation),
    }
}

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
    ha_state_fresh: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
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
    worker_commands_by_id: &WorkerCommandQueues,
    shared_recycles: &mut Vec<(u32, u64)>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    dbg: &mut DebugPollCounters,
    rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    cold_path_sample_mask: u64,
    injected_packet: Option<(Vec<u8>, UserspaceDpMeta)>,
    // #18560: the forwarding views this worker has left (matched-view grace).
    prev_views: &crate::afxdp::PrevViews,
) -> bool {
    let (left, rest) = bindings.split_at_mut(binding_index);
    let Some((binding, right)) = rest.split_first_mut() else {
        return false;
    };
    // #16184: mint the owned UMEM-area handle BEFORE `binding` is
    // handed out mutably below. The handle is an `Rc<WorkerUmemInner>`
    // clone, so it keeps the mmap'd area alive independently of the
    // `&mut BindingWorker` borrows the poll helpers take; every
    // reborrow on this path goes through `area.area()`. The only
    // `&mut Umem` escape hatch (`WorkerUmem::umem_mut`, a `RefCell`
    // borrow — #15730) runs solely at bind time, never while
    // polling, so those shared reborrows cannot alias it.
    // #16217 (ownership lag): authoritative RG forwarding-active set
    // freshly loaded from the coordinator snapshot for THIS poll --
    // the adoption gate reads this, not the cached `ha_state`.
    let forwarding_active_rgs: std::collections::BTreeSet<i32> = ha_state_fresh
        .load()
        .iter()
        .filter(|(_, g)| g.is_forwarding_active(now_secs))
        .map(|(rg, _)| *rg)
        .collect();
    let area = UmemAreaHandle::from_umem(&binding.umem);
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
    let mut injected_packet = injected_packet;
    let mut ident: Option<BindingIdentity> = None;
    for _ in 0..MAX_RX_BATCHES_PER_POLL {
        // Backpressure: skip RX when TX queues are heavily loaded to prevent
        // fill ring exhaustion. The NIC holds packets until we refill (#201).
        let tx_backlog = binding.tx_pipeline.pending_tx_local.len()
            + binding.tx_pipeline.pending_tx_prepared.len();
        if tx_backlog >= binding.tx_pipeline.max_pending_tx && injected_packet.is_none() {
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
        // #18560: packets an earlier batch parked (stamped with a forwarding
        // view this worker has left) run first, in a held pass under that
        // view's tables and validation. No RX is read in that batch.
        let held_pass = !binding.view_held.is_empty();
        let available = if held_pass { 0 } else { available };
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
        if available == 0
            && !held_pass
            && injected_packet.is_none()
            && binding.pending_pmech_reverse.is_empty()
        {
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
                area.area(),
                shared_recycles,
                event_stream,
                &mut counters,
                recent_exceptions,
                dbg,
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
            .expect("identity initialized for RX work or PMech replay");
        let had_injected_packet = injected_packet.is_some();
        let pending_pmech_before = binding.pending_pmech_reverse.len();

        // #945: WorkerContext groups the shared/passed-through references
        // (interior mutability via locks is preserved). TelemetryContext
        // groups the two mutable counter sinks. Named-field shorthand
        // ensures the compiler verifies field name == local-variable
        // name; any swap of two shared-typed fields would require
        // renaming a local elsewhere and break compilation.
        // #18560: the held pass's view. An expired view (or a parked packet
        // whose view is gone) falls back to the current one, which then drops
        // the packet as a generation mismatch, as before.
        let (held_view, pass_forwarding, pass_validation) =
            held_pass_view(&binding.view_held, prev_views, now_ns, forwarding, validation);
        let pass = crate::afxdp::PassView {
            prev_views: (!prev_views.is_empty()).then_some(prev_views),
            held_pass,
            view: held_view,
        };
        let worker_ctx = WorkerContext {
            ident,
            binding_lookup,
            mirror_targets,
            forwarding: pass_forwarding,
            ha_state,
            forwarding_active_rgs: &forwarding_active_rgs,
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
            rg_epochs,
            cold_path_sample_mask,
        };
        let mut telemetry = TelemetryContext {
            dbg,
            counters: &mut counters,
        };
        // #14945 (3): hand the stage the split sibling bindings so a
        // cross-binding cache hit that shares this UMEM can take the
        // inline TX path. `binding` is disjoint from `left`/`right`.
        poll_binding_process_descriptor_in_view(
            binding,
            binding_index,
            left,
            right,
            &area,
            available,
            if held_pass { None } else { injected_packet.take() },
            sessions,
            screen,
            pass_validation,
            now_ns,
            now_secs,
            ha_startup_grace_until_secs,
            worker_id,
            conntrack_v4_fd,
            conntrack_v6_fd,
            &worker_ctx,
            &mut telemetry,
            pass,
        );
        if available == 0 {
            did_work |= binding.pending_pmech_reverse.len() < pending_pmech_before;
        }
        let mut pending_forwards = core::mem::take(&mut binding.scratch.scratch_forwards);
        drain_rst_teardowns(
            left,
            binding,
            right,
            sessions,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            peer_worker_commands,
            &mut pending_forwards,
            shared_recycles,
            forwarding,
            worker_commands_by_id,
            worker_id,
            now_ns,
        );
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
            enqueue_pending_forwards_with_dynamic(
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
                event_stream,
                &ident,
                unsafe { &*ingress_live },
                slow_path,
                local_tunnel_deliveries,
                recent_exceptions,
                dbg,
                &mut counters,
                worker_id,
                worker_commands_by_id,
                Some(dynamic_neighbors),
            );
            binding.scratch.scratch_post_recycles = scratch_post_recycles;
        }
        binding.scratch.scratch_forwards = pending_forwards;
        // #14945 (3): cross-binding in-place TX from the flow-cache fast
        // path is live above (shared-UMEM targets only); a foreign-UMEM
        // target still goes through enqueue_pending_forwards.
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
        did_work |= available > 0
            || had_injected_packet
            || binding.pending_pmech_reverse.len() < pending_pmech_before;
        if available == 0 {
            break;
        }
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
        area.area(),
        shared_recycles,
        event_stream,
        &mut counters,
        recent_exceptions,
        dbg,
    );
    counters.flush(&binding.live);
    update_binding_debug_state(binding);
    did_work
}
/// #16504: drain one batch's queued RST teardowns and return both
/// scratch buffers to `current` with their capacities intact.
///
/// A named helper rather than inline statements in `poll_binding` for
/// the same reason as `drain_revoked_flow_cache_keys` below: the poll
/// function is not callable from a test (it needs live XSK rings), so
/// with the take/drain/restore inline, dropping the restore left every
/// existing cell green while the next RST batch reallocated both
/// buffers from zero. This helper IS the production path — the test
/// drives it directly and asserts the capacities survive.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(super) fn drain_rst_teardowns(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    pending_forwards: &mut Vec<PendingForwardRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
    forwarding: &ForwardingState,
    worker_commands_by_id: &WorkerCommandQueues,
    worker_id: u32,
    now_ns: u64,
) {
    let mut rst_teardowns = core::mem::take(&mut current.scratch.scratch_rst_teardowns);
    // #15947 (H29-01): two accepted RSTs for one session in the same
    // batch must not cross-cancel. Collect every triggering request's
    // (flow key, desc.addr) exception BEFORE any teardown mutates
    // pending_forwards; each teardown then keeps that batch's entire
    // trigger set (duplicates are harmless), rather than only its own.
    // #16504: fill the reusable scratch keeps buffer instead of a
    // per-batch `collect`, and return both buffers to the binding
    // below so their pre-sized capacities survive the take/drain
    // cycle (a dropped Vec here forced the next RST batch to
    // reallocate both from zero).
    let mut rst_trigger_keeps = core::mem::take(&mut current.scratch.scratch_rst_trigger_keeps);
    rst_trigger_keeps.clear();
    rst_trigger_keeps.extend(
        rst_teardowns
            .iter()
            .filter_map(|(_, _, trigger)| trigger.clone()),
    );
    for (forward_key, nat, _trigger) in rst_teardowns.drain(..) {
        // Evict from flow cache so stale entries aren't used after RST.
        // #918: 4-way set-associative cache requires walking the set
        // for the matching key — `invalidate_slot` does that.
        invalidate_rst_flow_cache_slot(current, &forward_key);
        teardown_tcp_rst_flow(
            left,
            current,
            right,
            sessions,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            peer_worker_commands,
            &forward_key,
            nat,
            pending_forwards,
            shared_recycles,
            &rst_trigger_keeps,
            forwarding,
            worker_commands_by_id,
            worker_id,
            now_ns,
        );
    }
    current.scratch.scratch_rst_teardowns = rst_teardowns;
    current.scratch.scratch_rst_trigger_keeps = rst_trigger_keeps;
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
pub(super) fn invalidate_flow_cache_key_on_binding(binding: &mut BindingWorker, key: &SessionKey) {
    binding
        .flow
        .flow_cache
        .invalidate_slot(key, binding.ifindex);
}
/// The per-binding flow-cache eviction in the TCP RST teardown path.
///
/// This is the exact helper called by `poll_binding`, and gives its targeted
/// invalidation a direct behavioral test without constructing the full poll
/// loop.
#[inline]
fn invalidate_rst_flow_cache_slot(binding: &mut BindingWorker, key: &SessionKey) {
    binding
        .flow
        .flow_cache
        .invalidate_slot(key, binding.ifindex);
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

// #16504: the RST teardown drain returns both scratch buffers with
// their capacities intact, without a per-batch collect.
#[cfg(test)]
#[path = "lifecycle_rst_scratch_16504_tests.rs"]
mod lifecycle_rst_scratch_16504_tests;
