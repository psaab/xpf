use super::super::*;
use super::handle_delete_synced;

/// Apply `WorkerCommand::DeleteSyncedIfTableUnknown`: conditionally
/// purge this worker's entry when it still carries the captured
/// install-table stamp and that stamp is unresolvable now.
///
/// Extracted verbatim from the `apply_worker_commands` dispatcher
/// (#18144); no behaviour change.
#[expect(
    clippy::too_many_arguments,
    reason = "#17200: wide dataplane signature; census in docs/log/17200.md"
)]
pub(in crate::afxdp::session_glue) fn handle_delete_synced_if_table_unknown(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    key: SessionKey,
    domain: u32,
    check: u32,
    now_ns: u64,
    now_secs: u64,
    deleted_synced_keys: &mut Vec<SessionKey>,
    worker_id: u32,
) {
    // #9752: conditional purge delete — decline (no-op, not even
    // `deleted_keys`: the entry survives so its flow-cache permit
    // stays backed, the #9048 reasoning) unless OUR entry still
    // carries this stamp AND is unresolvable under CURRENT
    // registry. Lagging senders, re-added tables, and
    // Companions are not replicated: they converge locally
    // (age/evict; default-scoped and validation-gated).
    let purgeable = sessions
        .entry_with_origin(&key)
        .is_some_and(|(decision, metadata, _)| {
            !metadata.is_reverse
                && decision.install_table_domain == domain
                && decision.install_table_check == check
                && install_table_purge::install_table_purge_predicate(forwarding, &key, &decision)
        });
    if purgeable {
        handle_delete_synced(
            sessions,
            session_map,
            forwarding,
            ha_state,
            key,
            now_ns,
            now_secs,
            deleted_synced_keys,
            worker_id,
        );
    }
}
