use super::*;

pub(in crate::afxdp) fn should_teardown_tcp_rst(meta: UserspaceDpMeta, _flow: Option<&SessionFlow>) -> bool {
    should_teardown_tcp_rst_with(meta, false)
}

/// #15753: knob-driven variant. Default (knob off) retains the HA
/// stray-RST rationale below: do NOT immediately delete. When
/// `rst_invalidate_session` is set, an observed RST tears down.
pub(in crate::afxdp) fn should_teardown_tcp_rst_with(_meta: UserspaceDpMeta, rst_invalidate: bool) -> bool {
    // Do not immediately delete live sessions on an observed TCP RST
    // unless the operator configured rst-invalidate-session.
    //
    // On the current HA userspace dataplane, stray or misclassified reply-side
    // RSTs can appear while the real flow is still active. Immediate teardown
    // removes the pinned live-session keys from USERSPACE_SESSIONS, which then
    // causes userspace-xdp to stop redirecting valid reply traffic and the
    // kernel to emit follow-on RSTs that collapse the connection entirely.
    // That hazard is why the default stays false and the knob is opt-in,
    // diverging from Junos default-on explicitly per #15753 acceptance.
    //
    // The session table already marks TCP entries as closing when FIN/RST is
    // seen and ages them on the shorter TCP_CLOSING timeout.
    rst_invalidate && crate::tcp_flags::has_rst(_meta.tcp_flags)
}

pub(in crate::afxdp) fn teardown_tcp_rst_flow(left: &mut [BindingWorker],
current: &mut BindingWorker,
right: &mut [BindingWorker],
sessions: &mut SessionTable,
shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
forward_key: &SessionKey,
nat: NatDecision,
pending_forwards: &mut Vec<PendingForwardRequest>,
shared_recycles: &mut Vec<(u32, u64)>,
keep_triggers: &[(SessionKey, u64)],
// #15947 (H29-01): the calling worker's id + the forwarding snapshot,
// threaded so the teardown can release this worker's NAT holds exactly
// as every other pair teardown does. `worker_commands_by_id` is the
// repairing-delete queue the pair helper replicates through.
forwarding: &ForwardingState,
worker_commands_by_id: &WorkerCommandQueues,
worker_id: u32,
now_ns: u64,) {
    let reverse_key = reverse_session_key(forward_key, nat);
    // #15947 (H29-01): pair-aware teardown. The pre-fix body deleted
    // both session rows but released NO source-NAT / NAT64 allocation
    // and emitted NO close delta, so an rst-invalidate teardown leaked
    // the SNAT/NAT64 pool port until idle expiry and left the HA peer
    // holding the flow with no Close. `delete_terminal_half` (via
    // `delete_terminal_filtered_session`) releases each half's
    // allocation exactly once (self-gated on `is_reverse`), drops the
    // BPF/conntrack/shared rows, replicates the delete, and emits the
    // single forward Close — the same contract the idle reap and the
    // terminal-filter revocation already honour. The decision/metadata
    // are read from the live entries so a reverse-direction trigger
    // still tears down the forward half under its own decision.
    let hit = sessions
        .entry_with_origin(forward_key)
        .or_else(|| sessions.entry_with_origin(&reverse_key));
    if let Some((decision, metadata, origin)) = hit {
        delete_terminal_filtered_session(
            sessions,
            current.bpf_maps.session_map.handle(),
            SharedSessionRefs {
                sessions: shared_sessions,
                nat_sessions: shared_nat_sessions,
                forward_wire_sessions: shared_forward_wire_sessions,
                owner_rg_indexes: shared_owner_rg_indexes,
                peer_worker_commands,
                worker_commands_by_id,
                conntrack: ConntrackFds {
                    v4: current.bpf_maps.conntrack_v4_fd,
                    v6: current.bpf_maps.conntrack_v6_fd,
                },
                tick: Tick { ns: now_ns, secs: 0 },
            },
            forwarding,
            forward_key,
            decision,
            &metadata,
            origin,
            worker_id,
        );
    } else {
        // No live entry on either half (already reaped this tick):
        // still drop any stale BPF rows so the steering map cannot
        // outlive the table.
        delete_live_session_entry(
            current.bpf_maps.session_map.handle(),
            forward_key,
            nat,
            false,
        );
        delete_live_session_entry(
            current.bpf_maps.session_map.handle(),
            &reverse_key,
            nat,
            true,
        );
    }
    // #15947 (H29-01): cancel every pending forward for this flow EXCEPT
    // the triggering RST's own request (identified by flow key + desc
    // addr) — the pre-fix cancel recycled the RST itself, so with
    // rst-invalidate-session on, the RST that tore the session down
    // never reached the wire.
    cancel_pending_forwards_except(
        current,
        pending_forwards,
        forward_key,
        &reverse_key,
        keep_triggers,
    );
    cancel_queued_flow(
        left,
        current,
        right,
        forward_key,
        &reverse_key,
        shared_recycles,
    );
}

pub(in crate::afxdp) fn cancel_queued_flow(left: &mut [BindingWorker],
current: &mut BindingWorker,
right: &mut [BindingWorker],
forward_key: &SessionKey,
reverse_key: &SessionKey,
shared_recycles: &mut Vec<(u32, u64)>,) {
    for binding in left.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key, Some(shared_recycles));
    }
    cancel_queued_flow_on_binding(current, forward_key, reverse_key, Some(shared_recycles));
    for binding in right.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key, Some(shared_recycles));
    }
    route_cancelled_shared_recycles(left, current, right, shared_recycles);
}

pub(super) fn route_cancelled_shared_recycles(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if shared_recycles.is_empty() {
        return;
    }
    // F-149 (#9904): same single-region backstop as the dispatch paths, with
    // the same bounded one-line-per-drain logging (this site previously logged
    // per drop inside the loop — a spam vector on a stale-slot flood).
    let backstop = split_is_single_region(left, current, right);
    let mut dropped = 0u64;
    let mut rescued = 0u64;
    let mut first_drop = None;
    let mut first_rescue = None;
    for (slot, offset) in shared_recycles.drain(..) {
        if let Some(binding) = left
            .iter_mut()
            .chain(core::iter::once(&mut *current))
            .chain(right.iter_mut())
            .find(|binding| binding.slot == slot)
        {
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
        } else if backstop {
            // Same-region per the premise on `split_is_single_region`:
            // kernel-masked, bounds-checked, growth-bounded. See note.
            current.tx_pipeline.pending_fill_frames.push_back(offset);
            first_rescue.get_or_insert((slot, offset));
            rescued = rescued.saturating_add(1);
        } else {
            first_drop.get_or_insert((slot, offset));
            dropped = dropped.saturating_add(1);
        }
    }
    log_shared_recycle_unknown_slot_drops(dropped, first_drop);
    log_shared_recycle_unknown_slot_rescues(rescued, first_rescue);
    record_shared_recycle_unknown_slot_drops(Some(&current.live), dropped);
    record_shared_recycle_unknown_slot_rescues(Some(&current.live), rescued);
}

pub(in crate::afxdp) fn cancel_queued_flow_on_binding(binding: &mut BindingWorker,
forward_key: &SessionKey,
reverse_key: &SessionKey,
shared_recycles: Option<&mut Vec<(u32, u64)>>,) {
    let mut shared_recycles = shared_recycles;
    let mut kept_local = VecDeque::with_capacity(binding.tx_pipeline.pending_tx_local.len());
    while let Some(req) = binding.tx_pipeline.pending_tx_local.pop_front() {
        if tx_request_matches_flow(&req, forward_key, reverse_key) {
            continue;
        }
        kept_local.push_back(req);
    }
    binding.tx_pipeline.pending_tx_local = kept_local;

    let mut kept_prepared = VecDeque::with_capacity(binding.tx_pipeline.pending_tx_prepared.len());
    while let Some(req) = binding.tx_pipeline.pending_tx_prepared.pop_front() {
        if prepared_request_matches_flow(&req, forward_key, reverse_key) {
            recycle_cancelled_prepared(binding, &req, shared_recycles.as_deref_mut());
            continue;
        }
        kept_prepared.push_back(req);
    }
    binding.tx_pipeline.pending_tx_prepared = kept_prepared;

    // #706: the cross-worker redirect inbox (`binding.live.pending_tx`) is
    // now a lock-free MPSC ring (`MpscInbox`). In-place filtering from an
    // arbitrary thread is not safe on that structure — only the owner
    // worker may drain it. We accept that packets already sitting in the
    // redirect inbox for a now-canceled flow will drain out on the next
    // owner poll and hit the wire; the peer already saw a RST, so the
    // extra late packets are ignored (or provoke a benign RST-for-RST
    // response) rather than causing protocol harm. The worker-owned
    // `pending_tx_local` and `pending_tx_prepared` queues above are still
    // filtered because they are never touched by another thread.

    update_binding_debug_state(binding);
}

pub(in crate::afxdp) fn cancel_pending_forwards(binding: &mut BindingWorker,
pending_forwards: &mut Vec<PendingForwardRequest>,
forward_key: &SessionKey,
reverse_key: &SessionKey,) {
    cancel_pending_forwards_except(binding, pending_forwards, forward_key, reverse_key, &[]);
}

/// #15947 (H29-01): like `cancel_pending_forwards`, but requests
/// identified by `keeps` ((flow key, desc.addr) of this batch's
/// triggering RSTs) are retained so they still reach TX after the
/// teardown. This scans in place instead of allocating a fresh kept
/// vector for every reset drain.
pub(in crate::afxdp) fn cancel_pending_forwards_except(
    binding: &mut BindingWorker,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
    keeps: &[(SessionKey, u64)],
) {
    let mut index = 0;
    while index < pending_forwards.len() {
        let req = &pending_forwards[index];
        let is_trigger = keeps.iter().any(|(key, addr)| {
            req.flow_key.as_ref() == Some(key) && req.desc.addr == *addr
        });
        if pending_forward_matches_flow(req, forward_key, reverse_key) && !is_trigger {
            let req = pending_forwards.remove(index);
            binding
                .tx_pipeline
                .pending_fill_frames
                .push_back(req.desc.addr);
        } else {
            index += 1;
        }
    }
}

pub(in crate::afxdp) fn recycle_cancelled_prepared(binding: &mut BindingWorker,
req: &PreparedTxRequest,
shared_recycles: Option<&mut Vec<(u32, u64)>>,) {
    recycle_cancelled_prepared_offset_with_shared(
        &mut binding.tx_pipeline.free_tx_frames,
        &mut binding.tx_pipeline.pending_fill_frames,
        shared_recycles,
        binding.slot,
        req.recycle,
        req.offset,
    );
}

pub(in crate::afxdp) fn tx_request_matches_flow(req: &TxRequest,
forward_key: &SessionKey,
reverse_key: &SessionKey,) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

pub(in crate::afxdp) fn prepared_request_matches_flow(req: &PreparedTxRequest,
forward_key: &SessionKey,
reverse_key: &SessionKey,) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

pub(in crate::afxdp) fn pending_forward_matches_flow(req: &PendingForwardRequest,
forward_key: &SessionKey,
reverse_key: &SessionKey,) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

