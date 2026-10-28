use super::super::*;

/// Take the worker's bounded command prefix while preserving repair position
/// fences and queue-lock observations used by the post-dispatch debt step.
pub(in crate::afxdp::session_glue) fn take_worker_command_slice(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    worker_id: u32,
    scratch: &mut VecDeque<WorkerCommand>,
) -> (
    Vec<worker_queue::SessionImportRepair>,
    bool,
    bool,
    bool,
    usize,
) {
    // Hot path: try_lock avoids blocking when another thread holds the mutex
    // and avoids lock/unlock on empty queues during steady-state forwarding.
    // #1807: poisoned mutexes are recovered and processed as normal.
    // #7201: this takes a BOUNDED PREFIX, not the whole deque: the worker cannot
    // touch AF_XDP rings until the dispatch loop ends.
    // #9720: no early returns; debt must step on empty and contended paths.
    // Scratch enters empty by invariant; the delta remains correct for a
    // test-reused buffer.
    let (mut session_import_repairs, ready_remains_at_start, mut session_import_repair_pending) =
        worker_queue::take_ready_session_import_repairs(
            worker_id,
            worker_queue::SESSION_IMPORT_REPAIR_DRAIN_BUDGET,
        );
    let repair_due_at_start = !session_import_repairs.is_empty() || ready_remains_at_start;
    let scratch_len_before = scratch.len();
    let (commands_backlogged, queue_lock_acquired) = if repair_due_at_start {
        let backlogged = worker_queue::try_lock_recover(commands)
            .map(|pending| !pending.is_empty())
            .unwrap_or(false);
        (backlogged, false)
    } else {
        match worker_queue::try_lock_recover(commands) {
            Some(mut pending) => {
                let backlogged = if pending.is_empty() {
                    false
                } else {
                    // #11718: stop the budgeted slice at the nearest repair
                    // boundary; its later FIFO suffix stays queued until the
                    // shared-authority repair has been applied.
                    let drain_limit = if session_import_repair_pending {
                        worker_queue::session_import_repair_drain_limit(
                            worker_id,
                            worker_queue::WORKER_COMMAND_DRAIN_BUDGET,
                        )
                    } else {
                        worker_queue::WORKER_COMMAND_DRAIN_BUDGET
                    };
                    worker_queue::drain_bounded_into_with_limit(&mut pending, scratch, drain_limit)
                };
                let drained = scratch.len() - scratch_len_before;
                // Capture the drain under the same queue lock importers use to
                // assign repair positions.
                worker_queue::note_worker_commands_drained(worker_id, drained);
                let (ready, _, pending_repairs) = worker_queue::take_ready_session_import_repairs(
                    worker_id,
                    worker_queue::SESSION_IMPORT_REPAIR_DRAIN_BUDGET,
                );
                session_import_repairs = ready;
                session_import_repair_pending = pending_repairs;
                (backlogged, true)
            }
            None => {
                session_import_repair_pending =
                    worker_queue::has_session_import_repair_debt(worker_id);
                // The queue is not known to be empty — a producer holds it.
                (false, false)
            }
        }
    };
    let drained = scratch.len() - scratch_len_before;
    (
        session_import_repairs,
        session_import_repair_pending,
        commands_backlogged,
        queue_lock_acquired,
        drained,
    )
}
