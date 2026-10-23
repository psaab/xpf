use super::super::*;

/// Apply `WorkerCommand::ExportOwnerRGSessions`: record the requested owner
/// RGs for a chunked, drain-as-you-export re-emit by the worker loop, and
/// push the command sequence onto the exported-sequences accumulator so the
/// `session_export_ack` advances once the export has shipped.
///
/// #2653: this handler used to call `export_forward_sessions_for_owner_rgs`
/// inline, which pushed the ENTIRE owned-session set (up to
/// `DEFAULT_MAX_SESSIONS` = 131072 = 32x the 4096-slot delta ring) into the
/// ring in one shot. With no interleaved drain, the ring overflowed at delta
/// 4097 and `push_delta` silently dropped sessions 4097..N, so the HA peer
/// received an INCOMPLETE bulk snapshot on rejoin / RG transition.
///
/// `apply_worker_commands` has no `BindingWorker`/flush access, so it cannot
/// drain the ring to the peer mid-export. The fix mirrors the #2442
/// loss-of-sync resync: the handler only RECORDS the owner RGs here; the
/// worker loop (`worker::loop_body`), which holds the binding + flush
/// machinery, drives a resumable multi-pass cursor over the table
/// (budgeted slices: direct-convert into the export buffer + paced
/// ring/echo + drain between slices, #9856) so the complete snapshot
/// ships without ever overflowing the ring. The sequence is acked
/// only after the final slice completes.
/// #15950 (H39-02 arm 2): a batched export window must name exactly
/// ONE kicked command — the last one. `apply_worker_commands` drains
/// up to `WORKER_COMMAND_DRAIN_BUDGET` commands per tick, so two
/// `ExportOwnerRGSessions` commands with different owner-RG sets can
/// be co-resident in one drain: typically a timed-out window's queued
/// command and its retry's command. The coordinator's
/// global-single-export BUSY gate serialises kicks, but it cannot
/// prevent both being legitimately queued when the worker next
/// drains. Unioning their RG sets (the pre-fix behaviour) exports the
/// union under the newest command's sequence token: sessions owned
/// solely by the superseded command's RGs ship inside a window that
/// command never scoped, and the superseded sequence is acked by a
/// walk it did not ask for. Last-command-wins matches the worker
/// loop's single-window adopt (`worker_export` is overwritten by the
/// newest adopt with `purge_foreign`), which already assumes one
/// window per tick-batch.
///
/// Returns `true` when this accept superseded an earlier export
/// command in the same drain.
pub(in crate::afxdp::session_glue) fn handle_export_owner_rg_sessions(
    sessions: &mut SessionTable,
    exported_sequences: &mut Vec<u64>,
    export_owner_rgs: &mut Vec<i32>,
    export_kick_epoch: &mut Option<u64>,
    sequence: u64,
    owner_rgs: Vec<i32>,
) -> bool {
    let superseded = !exported_sequences.is_empty();
    if superseded {
        exported_sequences.clear();
        export_owner_rgs.clear();
        *export_kick_epoch = None;
    }
    // #9856: capture the kick epoch at accept (first command of the
    // window wins; no installs run during dispatch, so every accept in
    // one window would read the same value). The worker loop exports
    // entries with install_epoch <= kick.
    if export_kick_epoch.is_none() {
        // Drop removals that predate this fresh window. They have no matching
        // open in the export and could close a reused key on the peer.
        sessions.discard_tombstones_for_export();
        *export_kick_epoch = Some(sessions.current_epoch());
    }

    for rg in owner_rgs {
        if !export_owner_rgs.contains(&rg) {
            export_owner_rgs.push(rg);
        }
    }
    exported_sequences.push(sequence);
    superseded
}
