use super::super::*;
pub(in crate::afxdp::session_glue) struct WorkerCommandDispatchContext<'a> {
    pub(in crate::afxdp::session_glue) sessions: &'a mut SessionTable,
    pub(in crate::afxdp::session_glue) session_map: SteeringMap<'a>,
    pub(in crate::afxdp::session_glue) conntrack_v4_fd: c_int,
    pub(in crate::afxdp::session_glue) conntrack_v6_fd: c_int,
    pub(in crate::afxdp::session_glue) forwarding: &'a ForwardingState,
    pub(in crate::afxdp::session_glue) ha_state: &'a BTreeMap<i32, HAGroupRuntime>,
    pub(in crate::afxdp::session_glue) dynamic_neighbors: &'a Arc<ShardedNeighborMap>,
    pub(in crate::afxdp::session_glue) worker_id: u32,
    pub(in crate::afxdp::session_glue) now_ns: u64,
    pub(in crate::afxdp::session_glue) now_secs: u64,
    pub(in crate::afxdp::session_glue) cancelled_keys: &'a mut Vec<SessionKey>,
    pub(in crate::afxdp::session_glue) cancelled_keys_seen:
        &'a mut rustc_hash::FxHashSet<SessionKey>,
    pub(in crate::afxdp::session_glue) exported_sequences: &'a mut Vec<u64>,
    pub(in crate::afxdp::session_glue) export_window_sequences: &'a mut Vec<u64>,
    pub(in crate::afxdp::session_glue) export_owner_rgs: &'a mut Vec<i32>,
    pub(in crate::afxdp::session_glue) export_kick_epoch: &'a mut Option<u64>,
    pub(in crate::afxdp::session_glue) stale_replay_dropped_keys: &'a mut Vec<SessionKey>,
    pub(in crate::afxdp::session_glue) deleted_synced_keys: &'a mut Vec<SessionKey>,
    pub(in crate::afxdp::session_glue) deleted_pptp_control_channels:
        &'a mut Vec<crate::session::pptp::ControlChannelId>,
    pub(in crate::afxdp::session_glue) shaped_tx_requests: &'a mut Vec<TxRequest>,
    pub(in crate::afxdp::session_glue) vacate_all_shared_exact_slots: &'a mut bool,
}
pub(in crate::afxdp::session_glue) fn dispatch_worker_commands(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    scratch: &mut VecDeque<WorkerCommand>,
) {
    for cmd in scratch.drain(..) {
        match cmd {
            WorkerCommand::DemoteOwnerRGS { owner_rgs } => {
                // #9752: a terminal demote arms the purge walk (D8).
                super::handle_demote_owner_rgs_command(ctx, owner_rgs);
            }
            WorkerCommand::RefreshOwnerRGS { owner_rgs } => {
                // #9752: a terminal refresh arms the purge walk (D8).
                super::handle_refresh_owner_rgs_command(ctx, owner_rgs);
            }
            WorkerCommand::ExportOwnerRGSessions {
                sequence,
                owner_rgs,
            } => {
                super::handle_export_owner_rg_sessions(
                    ctx.sessions,
                    ctx.exported_sequences,
                    ctx.export_window_sequences,
                    ctx.export_owner_rgs,
                    ctx.export_kick_epoch,
                    sequence,
                    owner_rgs,
                );
            }
            WorkerCommand::QuerySessionCounters {
                sequence,
                key,
                reply,
            } => {
                super::handle_query_session_counters(ctx.sessions, sequence, key, &reply);
            }
            WorkerCommand::ListSessionsByPolicy {
                request, collected, overflow, errors, pending,
            } => {
                super::handle_list_sessions_by_policy(
                    ctx.sessions, ctx.forwarding, request, collected, overflow, errors, &pending,
                );
            }
            WorkerCommand::InstallPptpAssociation(call) => {
                super::handle_install_pptp_association(ctx, call);
            }
            WorkerCommand::UpsertSynced(entry) => {
                super::handle_upsert_synced_command(ctx, entry);
            }
            WorkerCommand::UpsertLocal(entry) => {
                super::handle_upsert_local(ctx.sessions, entry, ctx.now_ns);
            }
            WorkerCommand::DeleteSynced(key) => {
                super::handle_delete_synced(
                    ctx.sessions,
                    ctx.session_map,
                    ctx.forwarding,
                    ctx.ha_state,
                    key,
                    ctx.now_ns,
                    ctx.now_secs,
                    ctx.deleted_synced_keys,
                    ctx.worker_id,
                );
            }
            WorkerCommand::DeleteLocalControl(key) => {
                super::handle_delete_local_control_command(ctx, key);
            }
            WorkerCommand::DeleteSyncedConditional {
                key,
                expected_id,
                companion,
                companion_expected_id,
            } => {
                super::handle_delete_synced_conditional_command(
                    ctx,
                    key,
                    expected_id,
                    companion,
                    companion_expected_id,
                );
            }
            WorkerCommand::DeletePolicyBatch { items, applied, pending, report, intents } => {
                super::handle_delete_policy_batch_command(
                    ctx, items, applied, &pending, report, intents,
                );
            }
            WorkerCommand::ProbePolicyBatch {
                bares,
                found,
                pending,
            } => {
                super::handle_probe_policy_tuples(ctx.sessions, &bares, found.as_ref());
                pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
            WorkerCommand::DeleteSyncedIfTableUnknown { key, domain, check } => {
                super::handle_delete_synced_if_table_unknown(
                    ctx.sessions,
                    ctx.session_map,
                    ctx.forwarding,
                    ctx.ha_state,
                    key,
                    domain,
                    check,
                    ctx.now_ns,
                    ctx.now_secs,
                    ctx.deleted_synced_keys,
                    ctx.worker_id,
                );
            }
            WorkerCommand::EnqueueShapedLocal(req) => ctx.shaped_tx_requests.push(req), // Inline push into the tick results.
            WorkerCommand::InstallPptpCall {
                call,
                control,
                learned_ns,
            } => {
                super::handle_install_pptp_call(ctx, call, control, learned_ns);
            }
            // #7699: a stale association re-pairs a REUSED 16-bit call id
            // onto a dead handle, so teardown must land on every worker.
            WorkerCommand::ForgetPptpCall(handle) => {
                ctx.sessions.pptp_mut().remove(handle);
            }
            WorkerCommand::ForgetPptpCallByControl(disconnect) => {
                ctx.sessions.pptp_mut().forget_call_disconnected_by(disconnect);
            }
            // #11053: tear down only the PPTP associations. The control
            // TCP session may still be owned by this worker.
            WorkerCommand::ForgetPptpControlChannel { control, closed_ns } => {
                ctx.sessions
                    .pptp_mut()
                    .forget_control_channel_learned_by(control, closed_ns);
            }
            // Inline flag set into the tick results.
            // #941 Work item C: signal the outer poll loop to vacate
            // all shared_exact slots (we don't have BindingWorker
            // access here, so we set the flag and let
            // `worker.rs:818-822` dispatch).
            WorkerCommand::VacateAllSharedExactSlots => {
                *ctx.vacate_all_shared_exact_slots = true;
            }
        }
    }
}
