use super::*;

pub(in crate::afxdp) fn should_teardown_tcp_rst(_meta: UserspaceDpMeta, _flow: Option<&SessionFlow>) -> bool {
    // Do not immediately delete live sessions on an observed TCP RST.
    //
    // On the current HA userspace dataplane, stray or misclassified reply-side
    // RSTs can appear while the real flow is still active. Immediate teardown
    // removes the pinned live-session keys from USERSPACE_SESSIONS, which then
    // causes userspace-xdp to stop redirecting valid reply traffic and the
    // kernel to emit follow-on RSTs that collapse the connection entirely.
    //
    // The session table already marks TCP entries as closing when FIN/RST is
    // seen and ages them on the shorter TCP_CLOSING timeout. Rely on that
    // path for now until RST provenance is made trustworthy again.
    false
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
shared_recycles: &mut Vec<(u32, u64)>,) {
    let reverse_key = reverse_session_key(forward_key, nat);
    sessions.delete(forward_key);
    sessions.delete(&reverse_key);
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
    delete_bpf_conntrack_entry(
        current.bpf_maps.conntrack_v4_fd,
        current.bpf_maps.conntrack_v6_fd,
        forward_key,
    );
    delete_bpf_conntrack_entry(
        current.bpf_maps.conntrack_v4_fd,
        current.bpf_maps.conntrack_v6_fd,
        &reverse_key,
    );
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        forward_key,
    );
    // #9560 round 3: release the coordinator's claim with the shared authority it
    // stood for.
    release_coordinator_session_rows(current.bpf_maps.session_map.handle(), forward_key);
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        &reverse_key,
    );
    // #9560 round 3: and for the reverse half's own shared entry.
    release_coordinator_session_rows(current.bpf_maps.session_map.handle(), &reverse_key);
    replicate_session_delete(peer_worker_commands, forward_key);
    replicate_session_delete(peer_worker_commands, &reverse_key);
    cancel_pending_forwards(current, pending_forwards, forward_key, &reverse_key);
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
    let mut kept = Vec::with_capacity(pending_forwards.len());
    for req in pending_forwards.drain(..) {
        if pending_forward_matches_flow(&req, forward_key, reverse_key) {
            binding
                .tx_pipeline
                .pending_fill_frames
                .push_back(req.desc.addr);
            continue;
        }
        kept.push(req);
    }
    *pending_forwards = kept;
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

