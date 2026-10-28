use super::super::*;

/// Apply `WorkerCommand::UpsertLocal`: install a coordinator-authoritative
/// local-tunnel replica entry in this worker's table.
///
/// Extracted verbatim from the `apply_worker_commands` dispatcher
/// (#18144); no behaviour change.
pub(in crate::afxdp::session_glue) fn handle_upsert_local(
    sessions: &mut SessionTable,
    entry: SyncedSessionEntry,
    now_ns: u64,
) {
    // This logic was inline in the dispatcher (with no `commands/` handler);
    // the debug_assert contract below remains tied to this command arm.
    // #1870: local-tunnel pair entries are coordinator-
    // authoritative replicas of state ALREADY published to
    // the shared maps (the tunnel.rs publish precedes the
    // enqueue). Routing them through the capped
    // install_with_protocol_with_origin let max_sessions
    // refuse the worker-table copy while the reactive
    // shared-hit materialization
    // (materialize_shared_session_hit) reinstalls the
    // reverse entry uncapped on the next reply packet — a
    // futile cap that only polluted create_drops and
    // delayed/voided the prewarm. Use the uncapped
    // sync-family install these SyncImport-origin entries
    // belong to. allow_replace_local=true preserves the
    // pre-#1870 replace semantics (the capped install
    // clobbered any same-key entry below cap); the data is
    // locally generated — the producer only runs when the
    // tunnel resolution is ForwardCandidate
    // (build_local_origin_tunnel_tx_request) — so the
    // "don't let peer data clobber local sessions" guard
    // does not apply.
    debug_assert!(
        entry.origin.is_peer_synced(),
        "UpsertLocal entries must carry a sync-family origin; a \
         local origin would have pushed an HA delta on the old \
         install path"
    );
    // #5212 / #9412: the shared mapping preserves the entry's id (a
    // local-tunnel replica carries 0 => fresh local alloc) and its
    // close class.
    let installed = sessions.upsert_synced_with_origin(
        entry.into_session_install(now_ns),
        /* allow_replace_local = */ true,
    );
    // The only false exit is the local-clobber guard, which
    // allow_replace_local=true bypasses — infallible by
    // construction (#1855 contract: assert in debug, inert
    // in release).
    debug_assert!(
        installed,
        "upsert_synced_with_origin(_, true) is infallible"
    );
    let _ = installed;
}
