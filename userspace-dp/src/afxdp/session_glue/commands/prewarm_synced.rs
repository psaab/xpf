use super::super::*;
use super::worker_command_dispatch::WorkerCommandDispatchContext;

/// #19145: apply an RG-activation prewarm restore only while the shared map
/// still holds its incarnation (`WorkerCommand::PrewarmSynced`). The check
/// takes and releases the shared lock before the install. A delete that
/// removes the row after the check pushes its `DeleteSynced` behind this
/// command in the same queue, so the install it races is still removed.
pub(in crate::afxdp::session_glue) fn handle_prewarm_synced_command(
    ctx: &mut WorkerCommandDispatchContext<'_>,
    entry: SyncedSessionEntry,
    shared: &crate::afxdp::types::SharedSessionsHandle,
) {
    let still_shared = crate::afxdp::shared_ops::shared_holds_incarnation(
        &crate::afxdp::shared_ops::lock_shared_recover(&shared.0),
        &entry.key,
        entry.session_id,
    );
    if still_shared {
        super::handle_upsert_synced_command(ctx, entry);
    }
}
