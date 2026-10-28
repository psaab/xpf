use super::super::*;
use super::handle_remove_policy_item;

/// Apply `WorkerCommand::DeletePolicyBatch`: run the abort-fenced
/// per-item teardown for one policy-delete batch (phase 1, table work
/// only; BPF redirect deletes are deferred as intents).
///
/// Extracted verbatim from the `apply_worker_commands` dispatcher
/// (#18144); no behaviour change.
#[expect(
    clippy::too_many_arguments,
    reason = "#17200: wide dataplane signature; census in docs/log/17200.md"
)]
pub(in crate::afxdp::session_glue) fn handle_delete_policy_batch(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    items: Vec<PolicyDeleteItem>,
    applied: Arc<Mutex<Vec<bool>>>,
    pending: &std::sync::atomic::AtomicUsize,
    report: Arc<Mutex<PolicyDeleteBatchReport>>,
    intents: Arc<Mutex<Vec<DeferredRedirectDelete>>>,
    now_ns: u64,
    now_secs: u64,
    deleted_synced_keys: &mut Vec<SessionKey>,
    worker_id: u32,
    deleted_pptp_control_channels: &mut Vec<crate::session::pptp::ControlChannelId>,
) {
    // Abort fence, phase 1 (table work ONLY): hold the report
    // mutex across cancel-check and the per-item teardown loop, so
    // cancel validation is atomic with the table mutations (see
    // PolicyDeleteBatchReport). Microsecond, syscall-free, and
    // tree-standard to hold — BPF redirect deletes are collected
    // as intents and stashed into the shared handoff INSIDE this
    // scope (table-side metadata only): holding syscalls would let
    // a slow worker wedge the coordinator's abort indefinitely,
    // and post-fence worker BPF would break abort-quiescence.
    // The coordinator drains + executes after phase-1 acks, under
    // the batch lease. Lock order fence -> applied slot / intents,
    // never reversed: the coordinator reads slots and drains
    // intents without the fence (after all acks) and takes the
    // fence touching neither (on abort).
    {
        let mut guard = report
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !guard.cancelled {
            let mut applied_slot = applied
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut deferred = Vec::new();
            for (index, item) in items.iter().enumerate() {
                // #15966r: forget broadcast PPTP associations only
                // AFTER the identity-conditional policy delete
                // applies. A stale captured session-id (or a
                // companion refusal) returns false and must leave
                // a replacement channel's calls and buffered
                // segments untouched.
                let local_id_before = sessions.session_id_for(&item.key);
                let applied = handle_remove_policy_item(
                    sessions,
                    session_map,
                    forwarding,
                    ha_state,
                    item,
                    &mut *guard,
                    index,
                    now_ns,
                    now_secs,
                    deleted_synced_keys,
                    worker_id,
                    &mut deferred,
                );
                // Genuine delete = applied here, or this worker
                // never held the incarnation (absent): broadcast
                // associations must still be purged. A present
                // session with a different id is a replacement
                // incarnation and is protected.
                // Trade-off (explicit, #15966r4): the absent arm
                // cannot discriminate a stale batch (captured
                // before a replacement was learned on THIS
                // worker, which holds no local row to check)
                // from a genuine delete on a non-owning worker.
                // It chooses purge: leaving broadcast calls
                // after a genuine delete resurrects a revoked
                // channel, while a stale purge is bounded by
                // call re-learning on the live control channel
                // and association idle expiry. The present-row
                // arm IS incarnation-scoped above.
                let genuine = applied || local_id_before == 0;
                if applied {
                    applied_slot[index] = true;
                }
                if genuine {
                    if let Some(ch) =
                        crate::session::SessionTable::pptp_control_channel_for_key(&item.key)
                    {
                        sessions.pptp_mut().forget_control_channel(ch);
                        if !deleted_pptp_control_channels.contains(&ch) {
                            deleted_pptp_control_channels.push(ch);
                        }
                    }
                }
            }
            intents
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend(deferred);
        }
    }
    pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
}
