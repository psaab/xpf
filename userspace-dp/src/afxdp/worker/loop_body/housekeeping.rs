// #13075 (D4-12) — per-tick session housekeeping, extracted from
// `worker_loop` in loop_body/mod.rs (pure code motion).
//
// One call per worker tick: build the #2120 standby-retention HA context,
// expire stale sessions, forget expired PPTP control channels (#11053),
// count create-counted local expiries (#2428), retire missing-neighbor
// seeds (#10419), reap expired sessions, and drain/flush the resulting
// close deltas (including the #10309 overflow suffix) before any packet
// or control work runs. Returns `true` when the old in-loop `continue`
// sites fired (deferred cleanup): the caller skips the rest of the tick.
// #19026: that skip is bounded by `close_barrier::ClosePermitBarrier` —
// Closes that cannot take their tuple permits hold RX for at most
// `CLOSE_PERMIT_BARRIER_NS` per run of held ticks; at the bound the blocked
// Close is parked out of the FIFO and the rest drains before RX polls.
//
// This is an ordinary out-of-line fn, NOT a hot-path call boundary in the
// #1776 sense: the per-tick packet path is `poll_binding`
// (worker/lifecycle.rs), which this fn never touches, and the expiry/GC
// work was never inlined into it. `#[inline(never)]` pins that separation
// so the expiry drain cannot be folded back into `worker_loop`'s frame.
// The flush itself stays in the loop: `flush_drained_session_deltas!` is
// a loop-local `macro_rules!` in mod.rs and is passed in as `flush_deltas`,
// so the #5468 lossless-wedge latch and #2874 delta-loss latch keep their
// exact loop semantics.
//
// `use super::*;` chains through loop_body/mod.rs to worker/mod.rs.

use super::*;

use super::close_barrier::{
    BlockedAt, BlockedVerdict, close_permits_available, front_close_still_blocked,
};
// Re-exported under its pre-split path so cells that predate the
// close_barrier.rs split (and run unchanged against older heads) name it.
pub(super) use super::close_barrier::ClosePermitBarrier;

#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
#[inline(never)]
pub(super) fn run_session_housekeeping(
    mut sessions: &mut crate::session::SessionTable,
    mut bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    forwarding: &ForwardingState,
    ha_runtime: &BTreeMap<i32, HAGroupRuntime>,
    loop_now_ns: u64,
    loop_now_secs: u64,
    rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    session_map: crate::afxdp::bpf_map::SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    worker_id: u32,
    worker_command_queues: &crate::afxdp::types::WorkerCommandQueues,
    pptp_control: &crate::session::pptp_control::PptpControlInbox,
    worker_commands_by_id: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    shared_runtime: &RuntimeViewReader,
    worker_lossless_wedged: &mut bool,
    shared_recycles: &mut Vec<(u32, u64)>,
    deferred_expiry_overflow_deltas: &mut Vec<SessionDelta>,
    close_barrier: &mut ClosePermitBarrier,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
) -> bool {
    // #2120: build the standby retention context so the wheel HOLDS
    // peer-synced sessions this node does not forward (restoring the
    // dead Go-GC `IsLocalPrimary` contract), self-heals them on RG
    // promotion (edge via rg_epochs), and reaps them at a bounded
    // ceiling if a primary delete is lost. The HA-forwarding logic
    // stays here (HAGroupRuntime's lease predicate is afxdp-private);
    // the session wheel only sees the closures + node_active.
    let ha_map = ha_runtime;
    let rg_epochs_for_gate = &rg_epochs;
    // node_active: does this node forward at least one RG right now?
    // Excludes a standalone node (empty/all-inactive map) from ever
    // holding (mirrors session_glue's forwards-any pattern).
    let node_active = ha_map
        .values()
        .any(|group| group.is_forwarding_active(loop_now_secs));
    let forwards_rg = |rg: i32| -> bool {
        if rg > 0 {
            ha_map
                .get(&rg)
                .map(|group| group.is_forwarding_active(loop_now_secs))
                .unwrap_or(false)
        } else {
            // owner_rg_id <= 0 (fabric / unresolved-owner reverse):
            // "forwards here" == the node forwards anything.
            node_active
        }
    };
    let epoch_of = |rg: i32| -> u32 {
        // A valid per-RG index uses rg_epochs[rg]; everything else
        // (rg <= 0 or out of range) uses the node-level rg_epochs[0]
        // activation edge. As of #2466 the flow-cache consumer guard
        // (flow_cache::rg_epoch_index) applies the SAME fallback, so the
        // two gates agree: an out-of-range owner RG (>= MAX_RG_EPOCHS) and
        // owner_rg_id == 0 (fabric / unresolved-owner reverse) both
        // self-heal on the node-level rg_epochs[0] edge rather than never.
        rg_epochs_for_gate[crate::afxdp::flow_cache::rg_epoch_index(rg)].load(Ordering::Relaxed)
    };
    // #16223: node-level served evidence for the expiry retention arm:
    // the shared synced map's Established wire for the tuple (the
    // counter half is merged from this table's own serving stamps
    // inside the expire pass). #18663 keeps alias resolution keyed and
    // maintains its index with primary publish/remove.
    let shared_evidence_max_cadence_ns =
        crate::session::NODE_SERVED_EVIDENCE_DEFAULT_CADENCE_NS.max(
            super::slice_pacing::shared_evidence_max_cadence_ns(sessions.ct_refresh_slab_len()),
        );
    let node_served = |key: &crate::session::SessionKey| {
        let mut evidence =
            crate::afxdp::shared_ops::shared_node_served_evidence(
                shared_sessions,
                shared_owner_rg_indexes,
                key,
            );
        evidence.shared_evidence_max_cadence_ns = Some(shared_evidence_max_cadence_ns);
        evidence
    };
    let ha_ctx = crate::session::ExpireHaContext {
        node_active,
        forwards_rg: &forwards_rg,
        epoch_of: &epoch_of,
        ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
        node_served: &node_served,
    };
    retry_deferred_pressure_sheds(
        &mut sessions,
        &mut bindings,
        forwarding,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        worker_id,
        &peer_worker_commands,
        worker_command_queues,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        loop_now_ns,
    );
    retry_deferred_conntrack_deletes(
        &mut sessions,
        conntrack_v4_fd,
        conntrack_v6_fd,
        shared_sessions,
        shared_owner_rg_indexes,
    );
    // #19026 (R13 F1): parked Closes are the oldest pending work (each was
    // the oldest delta of its store when it parked); retry them first, every
    // tick, before anything queued since.
    retry_parked_closes(
        sessions,
        bindings,
        binding_lookup,
        shared_recycles,
        shared_runtime,
        shared_sessions,
        shared_owner_rg_indexes,
        worker_lossless_wedged,
        close_barrier,
        flush_deltas,
    );
    let expired_entries = sessions.expire_stale_entries_ha(loop_now_ns, Some(&ha_ctx));
    // #11053: if the control TCP session idles out, forget its PPTP calls
    // and replicate the exact control tuple to peer workers. The delete
    // command also clears a peer's channel even if this worker's call rows
    // already expired on their independent data-idle clock.
    for expired in &expired_entries {
        let key = &expired.key;
        if key.protocol == crate::ip_proto::PROTO_TCP
            && (key.src_port == crate::session::pptp_control::PPTP_CONTROL_PORT
                || key.dst_port == crate::session::pptp_control::PPTP_CONTROL_PORT)
        {
            crate::afxdp::poll_descriptor::forget_pptp_control_channel(
                &mut sessions,
                &pptp_control,
                worker_commands_by_id,
                &peer_worker_commands,
                key,
                loop_now_ns,
            );
        }
    }
    // #2428: the "Current sessions" gauge Go derives as
    // (session_creates - session_expires) is a LOCAL-forwarding gauge.
    // `session_creates` is bumped ONLY on the four local poll-descriptor
    // install paths (ForwardFlow / ReverseFlow / LocalMiss /
    // MissingNeighborSeed). Every synced-derived origin (SyncImport /
    // SharedMaterialize / WorkerLocalImport / SharedPromote) is never
    // create-counted, so counting its expiry drives session_expires past
    // session_creates, wrapping the unsigned Go subtraction to ~1.8e19.
    // count_local_session_expiries (exhaustive match, no wildcard) counts
    // only the create-counted locals so accounting is balanced on the
    // SAME node and the standby gauge stays 0.
    let local_expired = count_local_session_expiries(expired_entries.iter().map(|e| e.origin));
    retire_expired_missing_neighbor_seeds(
        &expired_entries,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
    );
    let deferred_conntrack_deletes = reap_expired_sessions(
        bindings,
        &expired_entries,
        forwarding,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        loop_now_ns,
        worker_id,
        shared_sessions,
    );
    sessions.defer_conntrack_deletes(deferred_conntrack_deletes);
    if local_expired > 0 {
        if let Some(binding) = bindings.first() {
            binding
                .live
                .session_expires
                .fetch_add(local_expired, Ordering::Relaxed);
        }
    }
    // #10419: expire the local row and its shared/conntrack teardown
    // before polling another packet. Otherwise a lookup can miss the
    // removed local row, rematerialize the still-published shared copy,
    // and forward one more packet on an expired session.
    // #10309: the expiry walk must remain all-in-one-call. A full ring
    // may have accepted the first Close deltas and returned the suffix
    // that did not fit on their `ExpiredSession` records. Drain the
    // pre-existing ring first (preserving Open -> Close order), then
    // flush the returned suffix in fixed-size chunks before processing
    // another packet or control event. No shared entry can remain
    // honoured merely because its Close missed the 4096-slot ring.
    // #19026 (cycle 2, Codex R15 P1#3 / R13 N2): an earlier tick's deferred
    // suffix is retired HERE, after the ring, never before it: the ring can
    // still hold an older Open/Update of the same session, and a Close must
    // not overtake its own session's older delta. Deltas RX queued since the
    // deferral also drain first; for the same session those are newer
    // deltas of a re-materialized same-id row (Close after them is the
    // correct order) or a new incarnation (id-fenced at flush).
    let mut expiry_overflow_deltas = std::mem::take(deferred_expiry_overflow_deltas);
    expiry_overflow_deltas.extend(
        expired_entries
            .into_iter()
            .filter_map(|entry| entry.overflow_close),
    );
    if drain_ring_bounded(
        sessions,
        bindings,
        binding_lookup,
        shared_recycles,
        shared_runtime,
        shared_sessions,
        shared_owner_rg_indexes,
        worker_lossless_wedged,
        close_barrier,
        worker_id,
        loop_now_ns,
        flush_deltas,
    ) {
        *deferred_expiry_overflow_deltas = expiry_overflow_deltas;
        return true;
    }
    while !expiry_overflow_deltas.is_empty() {
        let Some(rest) = flush_overflow_chunks(
            sessions,
            bindings,
            binding_lookup,
            shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            worker_lossless_wedged,
            flush_deltas,
            &expiry_overflow_deltas,
        ) else {
            break;
        };
        expiry_overflow_deltas = rest;
        match close_barrier.on_blocked(
            sessions,
            &mut expiry_overflow_deltas,
            BlockedAt::Overflow,
            worker_id,
            loop_now_ns,
        ) {
            BlockedVerdict::HoldRx => {
                *deferred_expiry_overflow_deltas = expiry_overflow_deltas;
                return true;
            }
            BlockedVerdict::Parked => {}
            BlockedVerdict::PollRx => {
                *deferred_expiry_overflow_deltas = expiry_overflow_deltas;
                break;
            }
        }
    }
    close_barrier.clear(sessions);
    false
}

/// #19026: drain the ring, a blocked head first. Inside the RX bound a
/// blocked Close holds the tick (`true`: skip RX, teardown first). Past it the
/// blocked Close is parked and the drain continues in this same tick, so every
/// delta behind it (including the other Closes, whose permits are free) is
/// retired before RX polls: only the parked Close itself waits.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
fn drain_ring_bounded(
    sessions: &mut crate::session::SessionTable,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    shared_runtime: &RuntimeViewReader,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_lossless_wedged: &mut bool,
    close_barrier: &mut ClosePermitBarrier,
    worker_id: u32,
    now_ns: u64,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
) -> bool {
    while sessions.has_pending_deltas() {
        let mut blocked = false;
        let _ = drain_and_flush_all_impl(
            &mut *sessions,
            &mut *bindings,
            binding_lookup,
            &mut *shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            &mut blocked,
            worker_lossless_wedged,
            &mut *flush_deltas,
        );
        if !blocked {
            return false;
        }
        match close_barrier.on_blocked(
            sessions,
            &mut Vec::new(),
            BlockedAt::Ring,
            worker_id,
            now_ns,
        ) {
            BlockedVerdict::HoldRx => return true,
            BlockedVerdict::Parked => {}
            BlockedVerdict::PollRx => return false,
        }
    }
    false
}

/// #10309 overflow suffix, in fixed-size chunks. Returns the unretired
/// suffix (its head is the blocked Close) when a Close cannot take its tuple
/// permit, `None` when everything retired.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
fn flush_overflow_chunks(
    sessions: &mut crate::session::SessionTable,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    shared_runtime: &RuntimeViewReader,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_lossless_wedged: &mut bool,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
    overflow: &[SessionDelta],
) -> Option<Vec<SessionDelta>> {
    let mut start = 0;
    while start < overflow.len() {
        let end = (start + 256).min(overflow.len());
        let deltas = &overflow[start..end];
        // #19026 (R13 F3): a blocked head moves nothing.
        if !close_permits_available(&deltas[0]) {
            return Some(overflow[start..].to_vec());
        }
        let handled = purge_queued_flows_for_closed_deltas(
            bindings,
            binding_lookup,
            shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            deltas,
            Some(&mut *sessions),
        );
        flush_deltas(sessions, bindings, worker_lossless_wedged, &deltas[..handled]);
        if handled < deltas.len() {
            return Some(overflow[start + handled..].to_vec());
        }
        start = end;
    }
    None
}

/// #19026 (R13 F1): retry every parked Close (oldest first). One whose
/// permit is free retires through the ordinary purge + flush. One the flush
/// requeued (it lost the permit race) goes back to the slot.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
fn retry_parked_closes(
    sessions: &mut crate::session::SessionTable,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    shared_runtime: &RuntimeViewReader,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_lossless_wedged: &mut bool,
    close_barrier: &mut ClosePermitBarrier,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
) {
    if close_barrier.parked.is_empty() {
        return;
    }
    let parked = std::mem::take(&mut close_barrier.parked);
    let mut still_parked = Vec::new();
    for delta in parked {
        if !close_permits_available(&delta) {
            still_parked.push(delta);
            continue;
        }
        let one = std::slice::from_ref(&delta);
        let handled = purge_queued_flows_for_closed_deltas(
            bindings,
            binding_lookup,
            shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            one,
            Some(&mut *sessions),
        );
        if handled == 0 {
            still_parked.push(delta);
            continue;
        }
        let queued_before = sessions.pending_delta_count();
        flush_deltas(sessions, bindings, worker_lossless_wedged, one);
        let requeued = sessions.pending_delta_count() > queued_before
            && sessions.front_pending_delta().is_some_and(|front| {
                front.kind == delta.kind && front.key == delta.key && front.session_id == delta.session_id
            });
        if requeued {
            if let Some(back) = sessions.pop_front_delta() {
                still_parked.push(back);
            }
        }
    }
    close_barrier.parked = still_parked;
}

// #13075: the loop's `drain_and_flush_all!` macro as a fn (shared with
// the export slice via the loop's closure). See the macro in mod.rs for
// the #2669 unconditional-flush rationale.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(super) fn drain_and_flush_all_impl(
    sessions: &mut crate::session::SessionTable,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    shared_runtime: &RuntimeViewReader,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    deferred_delta_cleanup: &mut bool,
    worker_lossless_wedged: &mut bool,
    flush_deltas: &mut dyn FnMut(
        &mut crate::session::SessionTable,
        &mut [BindingWorker],
        &mut bool,
        &[SessionDelta],
    ),
) -> bool {
    while sessions.has_pending_deltas() {
        // #19026 (R13 F3): a head Close already known to be blocked is
        // re-tested with one permit try; it moves nothing while blocked.
        if front_close_still_blocked(sessions) {
            *deferred_delta_cleanup = true;
            break;
        }
        let queued_before = sessions.pending_delta_count();
        let deltas = sessions.drain_deltas(256);
        let handled = purge_queued_flows_for_closed_deltas(
            bindings,
            binding_lookup,
            shared_recycles,
            shared_runtime,
            shared_sessions,
            shared_owner_rg_indexes,
            &deltas,
            Some(&mut *sessions),
        );
        if handled < deltas.len() {
            flush_deltas(
                sessions,
                bindings,
                worker_lossless_wedged,
                &deltas[..handled],
            );
            sessions.requeue_deltas_front(&deltas[handled..]);
            sessions.set_close_head_blocked(true);
            *deferred_delta_cleanup = true;
            break;
        }
        // #2669: flush UNCONDITIONALLY (see mod.rs macro for rationale).
        flush_deltas(sessions, bindings, worker_lossless_wedged, &deltas);
        // #19026: the flush takes the close permits again and, when one is
        // busy, requeues the suffix it could not retire. A pass that left the
        // queue no shorter made no progress: yield to the caller's bounded
        // barrier instead of re-draining the same busy close in this loop,
        // which spun with neither RX nor a heartbeat until the permit freed.
        if sessions.pending_delta_count() >= queued_before {
            sessions.set_close_head_blocked(true);
            *deferred_delta_cleanup = true;
            break;
        }
    }
    !*deferred_delta_cleanup
}
