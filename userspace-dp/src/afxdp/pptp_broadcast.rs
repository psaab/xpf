// PPTP ALG control-channel association broadcast (#7699), extracted
// from worker_queue.rs (#13076, source finding D4-15).
//
// The generic worker command queue (worker_queue.rs) owns bounded
// enqueue/drain and the HA/session-import debt state machines. The
// PPTP broadcast/inbox subsystem only borrows its primitives
// (`lock_recover`, `push_bounded`) - it accesses no private debt
// internals - so it lives here as a sibling module. Pure code motion:
// no logic changed. worker_queue.rs re-exports the entry points so
// every existing `crate::afxdp::worker_queue::{broadcast_pptp_*,
// drain_pptp_control_inbox*}` call site resolves unchanged.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use super::super::types::WorkerCommand;
use super::super::worker_queue::{lock_recover, push_bounded};

/// #7699: broadcast a PPTP association install to EVERY worker.
///
/// The control channel (TCP/1723) and the GRE data channel are not reliably
/// co-located — RSS hashes the flow tuple, so they share a worker only by
/// chance — which is why this is a broadcast rather than a send to one worker.
///
/// Returns the number of queues that ACCEPTED the command and the identities of
/// queues that refused it. The control inbox retries refused recipients on a
/// later drain. A short count is not an error but it is not nothing either: a
/// worker that missed the install resolves that call's packets as UNASSOCIATED
/// until it is re-published, which is the forward-and-count path rather than a
/// drop.
pub(in crate::afxdp) fn broadcast_pptp_install(
    queues: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    call: crate::session::pptp::PptpCall,
    control: crate::session::pptp::ControlChannelId,
    learned_ns: u64,
) -> (usize, Vec<usize>) {
    let mut accepted = 0;
    let mut unsent_queue_ids = Vec::new();
    for q in queues {
        let mut pending = lock_recover(q);
        if push_bounded(
            &mut pending,
            WorkerCommand::InstallPptpCall {
                call,
                control,
                learned_ns,
            },
        ) {
            accepted += 1;
        } else {
            unsent_queue_ids.push(Arc::as_ptr(q) as usize);
        }
    }
    (accepted, unsent_queue_ids)
}

fn retry_pending_pptp_call_installs(
    inbox: &crate::session::pptp_control::PptpControlInbox,
    sessions: &mut crate::session::SessionTable,
    self_worker_commands: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    now_ns: u64,
) {
    let self_worker_queue_id = self_worker_commands.map(|queue| Arc::as_ptr(queue) as usize);
    for retry in inbox.take_call_install_retries(now_ns) {
        // A worker's peer list excludes itself. If it was the refused
        // recipient, preserve its queue's FIFO just as for peers: an empty
        // queue permits a local install; otherwise append behind its backlog.
        if let Some(queue) = self_worker_commands
            && let Some(queue_id) = self_worker_queue_id
            && retry.unsent_queue_ids.contains(&queue_id)
        {
            let mut pending = lock_recover(queue);
            if pending.is_empty() {
                match sessions
                    .pptp_mut()
                    .install(retry.call, retry.control, retry.learned_ns)
                {
                    Ok(_) => inbox.mark_call_install_sent(
                        retry.call,
                        retry.control,
                        retry.learned_ns,
                        queue_id,
                    ),
                    Err(e) => {
                        // The install error does not distinguish a permanent
                        // handle collision from an alias held until an older
                        // teardown arrives. Retain the retry for the next
                        // interval on any error rather than lose a transient
                        // AllocatorCollision.
                        debug_log!("PPTP association refused; retaining retry: {:?}", e);
                    }
                }
            } else if push_bounded(
                &mut pending,
                WorkerCommand::InstallPptpCall {
                    call: retry.call,
                    control: retry.control,
                    learned_ns: retry.learned_ns,
                },
            ) {
                inbox.mark_call_install_sent(retry.call, retry.control, retry.learned_ns, queue_id);
            }
        }
        for queue in peer_worker_commands {
            let queue_id = Arc::as_ptr(queue) as usize;
            if Some(queue_id) == self_worker_queue_id || !retry.unsent_queue_ids.contains(&queue_id)
            {
                continue;
            }
            let mut pending = lock_recover(queue);
            if push_bounded(
                &mut pending,
                WorkerCommand::InstallPptpCall {
                    call: retry.call,
                    control: retry.control,
                    learned_ns: retry.learned_ns,
                },
            ) {
                inbox.mark_call_install_sent(retry.call, retry.control, retry.learned_ns, queue_id);
            }
        }
    }
}

fn retry_pending_pptp_control_forgets(
    inbox: &crate::session::pptp_control::PptpControlInbox,
    sessions: &mut crate::session::SessionTable,
    self_worker_commands: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    now_ns: u64,
) {
    let self_worker_queue_id = self_worker_commands.map(|queue| Arc::as_ptr(queue) as usize);
    for retry in inbox.take_channel_forget_retries(now_ns) {
        if let Some(queue) = self_worker_commands
            && let Some(queue_id) = self_worker_queue_id
            && retry.unsent_queue_ids.contains(&queue_id)
        {
            let mut pending = lock_recover(queue);
            if pending.is_empty() {
                sessions
                    .pptp_mut()
                    .forget_control_channel_learned_by(retry.control, retry.closed_ns);
                inbox.mark_channel_forget_sent(retry.control, retry.closed_ns, queue_id);
            } else if push_bounded(
                &mut pending,
                WorkerCommand::ForgetPptpControlChannel {
                    control: retry.control,
                    closed_ns: retry.closed_ns,
                },
            ) {
                inbox.mark_channel_forget_sent(retry.control, retry.closed_ns, queue_id);
            }
        }
        for queue in peer_worker_commands {
            let queue_id = Arc::as_ptr(queue) as usize;
            if Some(queue_id) == self_worker_queue_id || !retry.unsent_queue_ids.contains(&queue_id)
            {
                continue;
            }
            let mut pending = lock_recover(queue);
            if push_bounded(
                &mut pending,
                WorkerCommand::ForgetPptpControlChannel {
                    control: retry.control,
                    closed_ns: retry.closed_ns,
                },
            ) {
                inbox.mark_channel_forget_sent(retry.control, retry.closed_ns, queue_id);
            }
        }
    }
    for retry in inbox.take_call_forget_retries(now_ns) {
        if let Some(queue) = self_worker_commands
            && let Some(queue_id) = self_worker_queue_id
            && retry.unsent_queue_ids.contains(&queue_id)
        {
            let mut pending = lock_recover(queue);
            if pending.is_empty() {
                sessions
                    .pptp_mut()
                    .forget_call_disconnected_by(retry.disconnect);
                inbox.mark_call_forget_sent(retry.disconnect, queue_id);
            } else if push_bounded(
                &mut pending,
                WorkerCommand::ForgetPptpCallByControl(retry.disconnect),
            ) {
                inbox.mark_call_forget_sent(retry.disconnect, queue_id);
            }
        }
        for queue in peer_worker_commands {
            let queue_id = Arc::as_ptr(queue) as usize;
            if Some(queue_id) == self_worker_queue_id || !retry.unsent_queue_ids.contains(&queue_id)
            {
                continue;
            }
            let mut pending = lock_recover(queue);
            if push_bounded(
                &mut pending,
                WorkerCommand::ForgetPptpCallByControl(retry.disconnect),
            ) {
                inbox.mark_call_forget_sent(retry.disconnect, queue_id);
            }
        }
    }
}

#[cfg(test)]
pub(in crate::afxdp) fn drain_pptp_control_inbox(
    inbox: &crate::session::pptp_control::PptpControlInbox,
    sessions: &mut crate::session::SessionTable,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    now_ns: u64,
) -> usize {
    drain_pptp_control_inbox_for_worker(inbox, sessions, None, peer_worker_commands, now_ns)
}

/// #7699: drain the PPTP control inbox — parse, install locally, publish.
///
/// Returns how many associations were learned on this pass.
///
/// **This is the production join.** Every other piece of #7699 works in
/// isolation: the parser parses, the table resolves, the broadcast fans out,
/// the drain applies. Until this function existed nothing chained them, and
/// each end's cells stayed green against a build where the middle was missing.
///
/// # It is safe to call every poll iteration, and that is a property of the
/// callee
///
/// The interval gate lives inside [`PptpControlInbox::take_pending`], not here
/// and not at the call site. The caller is the worker poll loop, which runs at
/// packet rate; a gate written at the call site would be one edit away from
/// running per-poll — the defect that shipped in #8399, where the association
/// expiry landed ABOVE `expire_stale_entries_ha`'s gc-interval gate and scanned
/// the whole map on every call.
///
/// # Why it installs locally AND broadcasts
///
/// `peer_worker_commands` EXCLUDES this worker (built with a
/// `filter(|(id, _)| **id != worker_id)` at the coordinator's bring-up). A
/// broadcast alone would therefore teach every worker but the one that saw the
/// segment — and since RSS does not co-locate the control and data channels,
/// that worker is as likely as any to be the one the call's GRE data lands on.
/// A refused retry for this worker uses its own queue when present, preserving
/// command order behind an existing backlog. Only an empty queue permits a
/// direct local install.
pub(in crate::afxdp) fn drain_pptp_control_inbox_for_worker(
    inbox: &crate::session::pptp_control::PptpControlInbox,
    sessions: &mut crate::session::SessionTable,
    self_worker_commands: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    now_ns: u64,
) -> usize {
    // Deliver older teardown retries before replacement installs. The retry
    // gate snapshots are separate, but this order makes a single drainer's
    // accepted commands preserve the old-call -> replacement-call sequence.
    retry_pending_pptp_control_forgets(
        inbox,
        sessions,
        self_worker_commands,
        peer_worker_commands,
        now_ns,
    );
    retry_pending_pptp_call_installs(
        inbox,
        sessions,
        self_worker_commands,
        peer_worker_commands,
        now_ns,
    );
    let mut learned = 0;
    for (routing_domain, seg) in inbox.take_pending_in_domain(now_ns) {
        let parsed = crate::session::pptp_control::parse_control_segment(&seg.payload);
        let control = crate::session::pptp::ControlChannelId::new_in_domain(
            routing_domain,
            seg.src,
            seg.src_port,
            seg.dst,
            seg.dst_port,
        );
        match parsed {
            crate::session::pptp_control::ControlParse::CallReply {
                call_id,
                peer_call_id,
            } => {
                let call = crate::session::pptp::PptpCall::new_in_domain(
                    routing_domain,
                    seg.src,
                    call_id,
                    seg.dst,
                    peer_call_id,
                );
                let local_install = sessions.pptp_mut().install(call, control, seg.captured_ns);
                let local_install_failed = local_install.is_err();
                if let Err(e) = &local_install {
                    debug_log!(
                        "PPTP association refused on the local worker; \
                         broadcasting and recording retry: {:?}",
                        e
                    );
                }
                let (accepted, mut unsent) =
                    broadcast_pptp_install(peer_worker_commands, call, control, seg.captured_ns);
                if local_install_failed {
                    if let Some(queue) = self_worker_commands {
                        let self_queue_id = Arc::as_ptr(queue) as usize;
                        if !unsent.contains(&self_queue_id) {
                            unsent.push(self_queue_id);
                        }
                    } else {
                        // No self queue identity to retry against (test-only
                        // drain without a self queue): record a sentinel that
                        // no real queue matches so the retry is retained but
                        // never misdelivered; production always passes Some.
                        // Use usize::MAX which cannot be an Arc pointer.
                        if !unsent.contains(&usize::MAX) {
                            unsent.push(usize::MAX);
                        }
                    }
                }
                if !local_install_failed && accepted == peer_worker_commands.len() {
                    inbox.complete_call_install_broadcast(call, control, seg.captured_ns);
                } else {
                    inbox.record_call_install(call, control, seg.captured_ns, unsent);
                }
                if !local_install_failed {
                    learned += 1;
                }
            }
            crate::session::pptp_control::ControlParse::CallDisconnect { call_id } => {
                let disconnect = crate::session::pptp::PptpCallDisconnect {
                    allocator: seg.src,
                    call_id,
                    control,
                    disconnected_ns: seg.captured_ns,
                };
                // Serialize this worker's own time-fenced forget with its
                // queued installs. Applying it directly while an earlier
                // install is queued would let that install resurrect the call.
                let self_worker_queue_id =
                    self_worker_commands.map(|queue| Arc::as_ptr(queue) as usize);
                let mut unsent_self = Vec::new();
                if let Some(queue) = self_worker_commands {
                    let queue_id = self_worker_queue_id.expect("queue id");
                    let mut pending = lock_recover(queue);
                    if pending.is_empty() {
                        let _ = sessions.pptp_mut().forget_call_disconnected_by(disconnect);
                    } else if !push_bounded(
                        &mut pending,
                        WorkerCommand::ForgetPptpCallByControl(disconnect),
                    ) {
                        unsent_self.push(queue_id);
                    }
                } else {
                    let _ = sessions.pptp_mut().forget_call_disconnected_by(disconnect);
                }
                inbox.forget_call_installs_for_disconnect(disconnect);
                let mut unsent = broadcast_pptp_call_forget(peer_worker_commands, disconnect);
                unsent.extend(unsent_self);
                inbox.record_call_forget(disconnect, unsent);
            }
            crate::session::pptp_control::ControlParse::Ignored
            | crate::session::pptp_control::ControlParse::Truncated
            | crate::session::pptp_control::ControlParse::NotControl => {}
        }
    }
    learned
}

/// #7699: broadcast a PPTP association teardown to every worker.
///
/// Same broadcast reasoning as the install, and a stronger reason to notice a
/// shortfall: a worker that misses a teardown keeps a stale association, and
/// PPTP call IDs are 16-bit and REUSED — so a later call can pair onto the dead
/// handle. That is a mis-attribution, not a leak, which is why the association
/// must also expire on its own rather than relying on this reaching everyone.
pub(in crate::afxdp) fn broadcast_pptp_forget(
    queues: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    handle: u32,
) -> usize {
    let mut accepted = 0;
    for q in queues {
        let mut pending = lock_recover(q);
        if push_bounded(&mut pending, WorkerCommand::ForgetPptpCall(handle)) {
            accepted += 1;
        }
    }
    accepted
}

/// Broadcast a per-call CDN. Return only queues that refused it so the shared
/// inbox can retry those recipients without duplicating accepted commands.
pub(in crate::afxdp) fn broadcast_pptp_call_forget(
    queues: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    disconnect: crate::session::pptp::PptpCallDisconnect,
) -> Vec<usize> {
    let mut unsent = Vec::new();
    for queue in queues {
        let queue_id = Arc::as_ptr(queue) as usize;
        let mut pending = lock_recover(queue);
        if !push_bounded(
            &mut pending,
            WorkerCommand::ForgetPptpCallByControl(disconnect),
        ) {
            unsent.push(queue_id);
        }
    }
    unsent
}

#[cfg(test)]
pub(in crate::afxdp) fn retry_pending_pptp_call_installs_for_test(
    inbox: &crate::session::pptp_control::PptpControlInbox,
    sessions: &mut crate::session::SessionTable,
    self_worker_commands: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    now_ns: u64,
) {
    retry_pending_pptp_call_installs(
        inbox,
        sessions,
        self_worker_commands,
        peer_worker_commands,
        now_ns,
    )
}
