use super::super::*;

/// Apply `WorkerCommand::QuerySessionCounters`: answer the READ-ONLY
/// counters query for one session key.
///
/// Extracted verbatim from the `apply_worker_commands` dispatcher
/// (#18144); no behaviour change.
pub(in crate::afxdp::session_glue) fn handle_query_session_counters(
    sessions: &mut SessionTable,
    sequence: u64,
    key: SessionKey,
    reply: &Arc<Mutex<Option<SessionCounterAnswer>>>,
) {
    // READ-ONLY. `counters_with_replica_flag` looks the key up
    // without touching the table; nothing here installs, refreshes
    // or expires anything. A diagnostic that perturbed the state it
    // reports would be worse than no diagnostic.
    let answer = match sessions.counters_with_replica_flag(&key) {
        Some((counters, replica)) => SessionCounterAnswer {
            sequence,
            found: true,
            replica,
            fwd_packets: counters.fwd_packets,
            fwd_bytes: counters.fwd_bytes,
            rev_packets: counters.rev_packets,
            rev_bytes: counters.rev_bytes,
        },
        None => SessionCounterAnswer {
            sequence,
            found: false,
            replica: false,
            fwd_packets: 0,
            fwd_bytes: 0,
            rev_packets: 0,
            rev_bytes: 0,
        },
    };
    *reply.lock().unwrap_or_else(|e| e.into_inner()) = Some(answer);
}
