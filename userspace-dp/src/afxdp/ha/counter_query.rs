//! #7919: the per-session counter QUERY — read-only, diagnostic, broadcast.
//!
//! WHAT IT ANSWERS, and why nothing else could. `show security flow session`
//! reports a session's volume from the shared BPF conntrack mirror. When a row
//! reads `Pkts: 0` for a flow that is demonstrably moving traffic, two
//! explanations survive and they need opposite fixes:
//!
//!   - the OWNING worker's table holds the volume and the mirror lost it, or
//!   - no worker's table holds it, and the mirror is faithfully reporting
//!     nothing that was ever accounted.
//!
//! Every worker holds a copy of every session (measured: `session_table_entries`
//! reads 6 on all six workers for three flows) but only the worker whose packets
//! land accounts for one, so the question is per-flow AND per-worker: for ONE
//! 5-tuple, what does EACH worker's own copy say. No existing surface answers
//! it. The shared session table cannot — `SyncedSessionEntry` has no counters
//! field. The per-worker `session_volume_high_water` cannot — it is monotonic
//! over the process lifetime, so a large value on a worker whose current flow
//! reads 0 may be residue from an earlier flow that worker owned. Axis and
//! attribution are different properties, and only this supplies the second.
//!
//! TWO-PHASE, mirroring `kick_owner_rg_export` (#2962): the kick runs under the
//! `ServerState` lock and returns immediately; the bounded wait runs lock-free
//! afterwards, so a slow or stalled worker cannot freeze the control plane.
//!
//! THE SEQUENCE IS THE ACK. A worker writes its answer fields and then its
//! sequence with Release; this side loads the sequence with Acquire and only
//! then reads the answers. There is no second completion flag that could
//! disagree with the sequence.
//!
//! NOT PERIODIC AND NOT ON THE HOT PATH. It is issued by an operator-driven
//! diagnostic, never by a poll. The control socket is shared with the status
//! poll, HA sync, session installs and snapshot sync; a caller above ~1 Hz
//! starves session installs during bulk sync.

use crate::afxdp::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Process-global request sequence. Only uniqueness matters — it is never
/// persisted, compared across restarts, or put on the wire.
static COUNTER_QUERY_SEQ: AtomicU64 = AtomicU64::new(0);

/// How long the lock-free wait gives the workers. A worker that does not answer
/// within this is reported as `answered: false` rather than waited on forever —
/// an unanswered worker is a fact about the reading, and silently dropping it
/// would turn a partial answer into one that looks complete.
const COUNTER_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// One worker's reply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WorkerSessionCounters {
    pub(crate) worker_id: u32,
    /// False when this worker did not answer before the deadline. Distinct from
    /// `found == false` (it answered: it does not hold the session).
    pub(crate) answered: bool,
    pub(crate) found: bool,
    pub(crate) replica: bool,
    pub(crate) fwd_packets: u64,
    pub(crate) fwd_bytes: u64,
    pub(crate) rev_packets: u64,
    pub(crate) rev_bytes: u64,
}

pub(crate) struct SessionCounterQueryWait {
    sequence: u64,
    slots: Vec<(u32, Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>)>,
    /// #9900 F-093: workers shed at kick time; the wait reports them as
    /// unanswered without eating the timeout.
    dead: Vec<u32>,
}

impl crate::afxdp::Coordinator {
    /// Locked phase: broadcast the query and capture the reply slots.
    pub(crate) fn kick_session_counter_query(
        &self,
        key: &crate::session::SessionKey,
    ) -> SessionCounterQueryWait {
        let sequence = COUNTER_QUERY_SEQ
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let mut slots = Vec::with_capacity(self.workers.records().len());
        let mut dead = Vec::new();
        for (worker_id, rec) in self.workers.records().iter() {
            let handle = &rec.handle;
            // #9900 F-093: shed dead workers (see `dead` on the wait struct).
            if rec.shed_if_dead(1) {
                dead.push(*worker_id);
                continue;
            }
            // Recover, never early-return: one worker's poisoned queue must not
            // deny the reading for every healthy worker. A worker that never
            // receives the command simply never answers, which the deadline
            // below already reports as `answered: false`.
            let mut pending = worker_queue::lock_recover(&handle.commands);
            worker_queue::push_bounded(
                &mut pending,
                WorkerCommand::QuerySessionCounters {
                    sequence,
                    key: key.clone(),
                },
            );
            drop(pending);
            slots.push((*worker_id, handle.runtime_atomics.clone()));
        }
        SessionCounterQueryWait {
            sequence,
            slots,
            dead,
        }
    }
}

impl SessionCounterQueryWait {
    /// Lock-free phase: wait (bounded) for each worker's sequence to reach ours,
    /// then read its answer. Run with the `ServerState` lock RELEASED.
    pub(crate) fn wait_and_collect(self) -> Vec<WorkerSessionCounters> {
        let deadline = Instant::now() + COUNTER_QUERY_TIMEOUT;
        let mut out = Vec::with_capacity(self.slots.len());
        for (worker_id, atomics) in self.slots {
            let mut answered = false;
            loop {
                // Acquire pairs with the worker's Release store of the sequence,
                // so every answer field written before it is visible here.
                if atomics.counter_query_seq.load(Ordering::Acquire) >= self.sequence {
                    answered = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if !answered {
                out.push(WorkerSessionCounters {
                    worker_id,
                    ..Default::default()
                });
                continue;
            }
            out.push(WorkerSessionCounters {
                worker_id,
                answered: true,
                found: atomics.counter_query_found.load(Ordering::Relaxed) != 0,
                replica: atomics.counter_query_replica.load(Ordering::Relaxed) != 0,
                fwd_packets: atomics.counter_query_fwd_packets.load(Ordering::Relaxed),
                fwd_bytes: atomics.counter_query_fwd_bytes.load(Ordering::Relaxed),
                rev_packets: atomics.counter_query_rev_packets.load(Ordering::Relaxed),
                rev_bytes: atomics.counter_query_rev_bytes.load(Ordering::Relaxed),
            });
        }
        // #9900 F-093: dead workers were shed at kick time; report them as
        // unanswered (never silently drop — a partial answer must not look
        // complete).
        for worker_id in self.dead {
            out.push(WorkerSessionCounters {
                worker_id,
                ..Default::default()
            });
        }
        out
    }
}
