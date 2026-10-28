use super::super::*;
use super::worker_command_dispatch::WorkerCommandDispatchContext;
use super::{
    DeleteOrigin, handle_delete_synced_conditional, handle_delete_synced_with_guard,
    handle_demote_owner_rgs, handle_refresh_owner_rgs, handle_upsert_synced,
};

/// Keep the terminal-transition purge side effect beside the delegated
/// demote handler rather than in the dispatcher match arm.
pub(in crate::afxdp::session_glue) fn handle_demote_owner_rgs_command(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    owner_rgs: Vec<i32>,
) {
    if handle_demote_owner_rgs(
        ctx.sessions,
        ctx.session_map,
        ctx.conntrack_v4_fd,
        ctx.conntrack_v6_fd,
        ctx.forwarding,
        ctx.ha_state,
        ctx.dynamic_neighbors,
        owner_rgs,
        ctx.now_ns,
        ctx.now_secs,
        ctx.cancelled_keys,
        ctx.cancelled_keys_seen,
    ) {
        flag_install_table_purge(ctx.worker_id);
    }
}

/// Keep the terminal-transition purge side effect beside the delegated
/// refresh handler rather than in the dispatcher match arm.
pub(in crate::afxdp::session_glue) fn handle_refresh_owner_rgs_command(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    owner_rgs: Vec<i32>,
) {
    if handle_refresh_owner_rgs(
        ctx.sessions,
        ctx.session_map,
        ctx.forwarding,
        ctx.ha_state,
        ctx.dynamic_neighbors,
        owner_rgs,
        ctx.now_ns,
        ctx.now_secs,
    ) {
        flag_install_table_purge(ctx.worker_id);
    }
}

/// Apply the existing stale-replay fence before delegating a synced upsert.
pub(in crate::afxdp::session_glue) fn handle_upsert_synced_command(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    entry: SyncedSessionEntry,
) {
    if synced_entry_is_stale_replay(entry.origin, &entry.metadata, ctx.forwarding) {
        note_stale_replay_fence_drop();
        ctx.stale_replay_dropped_keys.push(entry.key);
    } else {
        handle_upsert_synced(
            ctx.sessions,
            ctx.session_map,
            ctx.forwarding,
            ctx.ha_state,
            ctx.dynamic_neighbors,
            entry,
            ctx.now_ns,
            ctx.now_secs,
            ctx.worker_id,
        );
    }
}

/// Apply the existing locally initiated clear through the shared delete helper.
pub(in crate::afxdp::session_glue) fn handle_delete_local_control_command(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    key: SessionKey,
) {
    handle_delete_synced_with_guard(
        ctx.sessions,
        ctx.session_map,
        ctx.forwarding,
        ctx.ha_state,
        key,
        ctx.now_ns,
        ctx.now_secs,
        ctx.deleted_synced_keys,
        ctx.worker_id,
        DeleteOrigin::LocalClear,
        &mut Vec::new(),
        0,
        None,
    );
}

/// Apply the existing identity-scoped synced-delete command.
pub(in crate::afxdp::session_glue) fn handle_delete_synced_conditional_command(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    key: SessionKey,
    expected_id: u64,
    companion: Option<SessionKey>,
    companion_expected_id: u64,
) {
    handle_delete_synced_conditional(
        ctx.sessions,
        ctx.session_map,
        ctx.forwarding,
        ctx.ha_state,
        key,
        expected_id,
        ctx.now_ns,
        ctx.now_secs,
        ctx.deleted_synced_keys,
        ctx.worker_id,
        companion,
        companion_expected_id,
    );
}
/// Keep policy-batch teardown arguments scoped to the worker command context.
pub(in crate::afxdp::session_glue) fn handle_delete_policy_batch_command(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    items: Vec<PolicyDeleteItem>,
    applied: Arc<Mutex<Vec<bool>>>,
    pending: &std::sync::atomic::AtomicUsize,
    report: Arc<Mutex<PolicyDeleteBatchReport>>,
    intents: Arc<Mutex<Vec<DeferredRedirectDelete>>>,
) {
    super::handle_delete_policy_batch(
        ctx.sessions,
        ctx.session_map,
        ctx.forwarding,
        ctx.ha_state,
        items,
        applied,
        pending,
        report,
        intents,
        ctx.now_ns,
        ctx.now_secs,
        ctx.deleted_synced_keys,
        ctx.worker_id,
        ctx.deleted_pptp_control_channels,
    );
}

/// Apply an imported PPTP association only when the ALG is currently enabled.
pub(in crate::afxdp::session_glue) fn handle_install_pptp_association(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    call: crate::session::pptp::PptpCall,
) {
    if ctx.forwarding.pptp_enabled() {
        let _ = ctx.sessions.pptp_mut().install_synced_association(call, ctx.now_ns);
    }
}

/// Learn a PPTP call on this worker, preserving the existing refusal log.
pub(in crate::afxdp::session_glue) fn handle_install_pptp_call(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    call: crate::session::pptp::PptpCall,
    control: crate::session::pptp::ControlChannelId,
    learned_ns: u64,
) {
    if ctx.forwarding.pptp_enabled() {
        if let Err(e) = ctx
            .sessions
            .pptp_mut()
            .install(call, control, learned_ns)
        {
            debug_log!("PPTP association refused: {:?}", e);
        }
    }
}
