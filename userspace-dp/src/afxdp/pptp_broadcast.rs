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
use super::super::worker_queue::{lock_recover, push_bounded, try_lock_recover};

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

/// #16609: retain a self-retry after a failed DIRECT local install
/// only while its refusal is transient. Transient iff a queued or
/// pending forget (per-call CDN / channel close, in the inbox or as
/// a not-yet-applied worker command) will retire the colliding
/// association, or the owner was learned strictly before the retry
/// (a replacement whose freeing CDN is in flight — the
/// #15251/#12133 shape). When the owner is already gone with no
/// pending forget, or none of the above holds, the collision is
/// permanent: drop the retry. The inbox hard cap + TTL
/// (association idle timeout) bound every retained retry, and the
/// retry walk probes without counting so a retained refusal is
/// never re-counted per tick.
fn install_collision_is_transient(
    sessions: &crate::session::SessionTable,
    inbox: &crate::session::pptp_control::PptpControlInbox,
    retry: &crate::session::pptp_control::PendingCallInstall,
    self_worker_commands: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
) -> bool {
    use crate::session::pptp::PptpInstallError;
    let err = match sessions.pptp().install_error_for(retry.call) {
        Some(e) => e,
        None => return true,
    };
    let owner_still_present = match err {
        PptpInstallError::AllocatorCollision { owner, .. } => {
            sessions.pptp().has_handle(owner)
        }
        PptpInstallError::HandleCollision { handle, .. } => {
            sessions.pptp().has_handle(handle)
        }
    };
    if !owner_still_present {
        return inbox.has_pending_forget_touching(retry);
    }
    if inbox.has_pending_forget_touching(retry) {
        return true;
    }
    let owner_alias_pending = match err {
        PptpInstallError::AllocatorCollision { allocator, call_id, .. } => {
            inbox.has_pending_forget_for_alias(retry.control, allocator, call_id)
        }
        PptpInstallError::HandleCollision { .. } => false,
    };
    if owner_alias_pending {
        return true;
    }
    let owner_learned_before_retry = match err {
        PptpInstallError::AllocatorCollision { owner, .. } => sessions
            .pptp()
            .learned_ns_for_handle(owner)
            .is_some_and(|ns| ns < retry.learned_ns),
        PptpInstallError::HandleCollision { handle, .. } => sessions
            .pptp()
            .learned_ns_for_handle(handle)
            .is_some_and(|ns| ns < retry.learned_ns),
    };
    if owner_learned_before_retry {
        return true;
    }
    let mut queues: Vec<&Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    if let Some(q) = self_worker_commands {
        queues.push(q);
    }
    queues.extend(peer_worker_commands.iter());
    // Non-blocking: the retry walk may hold the self queue.
    queues.iter().any(|q| {
        let Some(guard) = try_lock_recover(q) else {
            return false;
        };
        guard.iter().any(|cmd| match cmd {
            WorkerCommand::ForgetPptpCallByControl(d) => {
                d.control == retry.control
                    && retry.call.has_alias(d.allocator, d.call_id)
            }
            WorkerCommand::ForgetPptpControlChannel { control, .. } => {
                *control == retry.control
            }
            WorkerCommand::ForgetPptpCall(handle) => {
                match err {
                    PptpInstallError::AllocatorCollision { owner, .. } => *handle == owner,
                    PptpInstallError::HandleCollision { handle: h, .. } => *handle == h,
                }
            }
            _ => false,
        })
    })
}

fn retry_pending_pptp_call_installs(
    inbox: &crate::session::pptp_control::PptpControlInbox,
    sessions: &mut crate::session::SessionTable,
    self_worker_commands: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    now_ns: u64,
    current_epoch: u64,
) {
    let self_worker_queue_id = self_worker_commands.map(|queue| Arc::as_ptr(queue) as usize);
    for retry in inbox.take_call_install_retries_at(now_ns, current_epoch) {
        if let Some(queue) = self_worker_commands
            && let Some(queue_id) = self_worker_queue_id
            && retry.unsent_queue_ids.contains(&queue_id)
        {
            let mut pending = lock_recover(queue);
            if pending.is_empty() {
                // #16609: probe WITHOUT counting; only call the
                // counting install when the alias has actually freed.
                if sessions.pptp().install_error_for(retry.call).is_some() {
                    if install_collision_is_transient(sessions, inbox, &retry, self_worker_commands, peer_worker_commands) {
                        debug_log!("PPTP association still refused; retaining retry");
                    } else {
                        debug_log!("PPTP association permanently refused; dropping retry");
                        inbox.drop_call_install(retry.call, retry.control, retry.learned_ns);
                    }
                } else {
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
                            if install_collision_is_transient(sessions, inbox, &retry, self_worker_commands, peer_worker_commands) {
                                debug_log!("PPTP association refused; retaining retry: {:?}", e);
                            } else {
                                inbox.drop_call_install(retry.call, retry.control, retry.learned_ns);
                            }
                        }
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
    drain_pptp_control_inbox_at_epoch(inbox, sessions, self_worker_commands, peer_worker_commands, now_ns, 0)
}
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn drain_pptp_control_inbox_at_epoch(
    inbox: &crate::session::pptp_control::PptpControlInbox,
    sessions: &mut crate::session::SessionTable,
    self_worker_commands: Option<&Arc<Mutex<VecDeque<WorkerCommand>>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    now_ns: u64,
    current_epoch: u64,
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
        current_epoch,
    );
    let mut learned = 0;
    for (routing_domain, seg) in inbox.take_pending_in_domain(now_ns, current_epoch) {
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
                    // #16609: permanent first-learn refusals are
                    // broadcast to peers but do NOT retain a
                    // self-retry; transient ones keep it below.
                    let probe = crate::session::pptp_control::PendingCallInstall {
                        call,
                        control,
                        learned_ns: seg.captured_ns,
                        epoch: seg.epoch,
                        unsent_queue_ids: Vec::new(),
                    };
                    let permanent = !install_collision_is_transient(sessions, inbox, &probe, self_worker_commands, peer_worker_commands);
                    if !permanent {
                        if let Some(queue) = self_worker_commands {
                            let self_queue_id = Arc::as_ptr(queue) as usize;
                            if !unsent.contains(&self_queue_id) {
                                unsent.push(self_queue_id);
                            }
                        } else {
                            // No self queue identity (test-only drain):
                            // sentinel no real queue matches.
                            if !unsent.contains(&usize::MAX) {
                                unsent.push(usize::MAX);
                            }
                        }
                    }
                }
                if !local_install_failed && accepted == peer_worker_commands.len() {
                    inbox.complete_call_install_broadcast(call, control, seg.captured_ns);
                } else if !unsent.is_empty() {
                    inbox.record_call_install_at(call, control, seg.captured_ns, seg.epoch, unsent);
                } else {
                    inbox.complete_call_install_broadcast(call, control, seg.captured_ns);
                }
                if !local_install_failed {
                    learned += 1;
                }
            }
            crate::session::pptp_control::ControlParse::CallDisconnect { call_id }
            | crate::session::pptp_control::ControlParse::CallClear { call_id } => {
                let disconnect = crate::session::pptp::PptpCallDisconnect {
                    allocator: seg.src,
                    call_id,
                    control,
                    disconnected_ns: seg.captured_ns,
                };
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
            crate::session::pptp_control::ControlParse::StopControl => {
                // #15950: Stop-Control tears down every call on this channel,
                // reusing the channel-forget machinery (local + broadcast +
                // buffered-segment purge via forget_pptp_control_channel's
                // inbox half is not reachable here, so purge directly).
                inbox.forget_channel(control);
                inbox.forget_call_installs_for_channel(control, seg.captured_ns);
                let _ = sessions.pptp_mut().forget_control_channel_learned_by(control, seg.captured_ns);
                let mut unsent: Vec<usize> = Vec::new();
                for queue in peer_worker_commands {
                    let mut pending = lock_recover(queue);
                    if !push_bounded(
                        &mut pending,
                        WorkerCommand::ForgetPptpControlChannel {
                            control,
                            closed_ns: seg.captured_ns,
                        },
                    ) {
                        unsent.push(Arc::as_ptr(queue) as usize);
                    }
                }
                if let Some(queue) = self_worker_commands {
                    let mut pending = lock_recover(queue);
                    if !pending.is_empty()
                        && !push_bounded(
                            &mut pending,
                            WorkerCommand::ForgetPptpControlChannel {
                                control,
                                closed_ns: seg.captured_ns,
                            },
                        )
                    {
                        unsent.push(Arc::as_ptr(queue) as usize);
                    }
                }
                if !unsent.is_empty() {
                    inbox.record_channel_forget(control, seg.captured_ns, unsent);
                }
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
        0,
    )
}
