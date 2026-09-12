// delete_drop_sweep.rs — the resumable, budgeted delete-drop reconcile (#9327).
//
// Split out of session_glue/mod.rs rather than recorded in
// docs/refactoring-audit-accepted.txt: adding the sweep there crossed the
// 2000-LOC modularity floor (1988 -> 2081), and an exemption is satisfiable by
// writing something plausible in a text file. The sweep is a self-contained
// state machine with one entry point, which is exactly the shape that should be
// its own file.

use super::*;

/// The most slab slots one delete-drop reconcile pass may examine (#9327).
///
/// SAME UNIT AND SAME JUSTIFICATION as [`WORKER_COMMAND_DRAIN_BUDGET`]: the
/// worker does not service its AF_XDP RX/TX rings while it sweeps, so the pass
/// size is wall-clock time the rings go unserviced. A 4096-slot RX ring fills
/// in ~1.97 ms at 25 Gbps with 1500 B frames, and the UNBUDGETED sweep measured
/// on this tree:
///
/// ```text
/// n=16384 finds-nothing  1.745 ms     <- already at the ring fill
/// n=60000 finds-nothing  6.466 ms     <- 3x the fill
/// n=60000 all-stale     39.148 ms     <- ~20x the fill
/// ```
///
/// with `DEFAULT_MAX_SESSIONS = 131072`, so 60k is not the ceiling. The epoch
/// gate upstream bounds how OFTEN this runs, not what one run costs — and one
/// refused cross-worker `DeleteSynced`, ordinary RG-activation churn, arms it.
///
/// 256 matches the command-drain budget so the worker keeps ONE batch
/// granularity rather than two.
pub(in crate::afxdp) const DELETE_DROP_SWEEP_BUDGET: usize = 256;

/// Resumable state for the delete-drop reconcile (#9327).
///
/// The sweep is spread across worker-loop passes instead of running to
/// completion in one. `stale` is retained between passes so a steady state
/// performs NO allocation: it is cleared, not dropped, and its capacity
/// converges on the per-pass high-water mark (at most the budget).
#[derive(Default)]
pub(in crate::afxdp) struct DeleteDropSweep {
    cursor: usize,
    running: bool,
    stale: Vec<SessionKey>,
}

impl DeleteDropSweep {
    /// Restart the sweep from the top. Called on an epoch bump.
    ///
    /// Restarting an in-flight sweep rather than queueing is deliberate: the
    /// epoch says the shared map changed, so slots already visited under the
    /// OLD map have to be re-examined anyway. Queueing would defer that.
    pub(in crate::afxdp) fn arm(&mut self) {
        self.cursor = 0;
        self.running = true;
    }

    pub(in crate::afxdp) fn is_running(&self) -> bool {
        self.running
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn stale_capacity_for_test(&self) -> usize {
        self.stale.capacity()
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn cursor_for_test(&self) -> usize {
        self.cursor
    }

    /// Examine at most [`DELETE_DROP_SWEEP_BUDGET`] slab slots, deleting the
    /// peer-synced sessions the shared authority no longer holds. Returns the
    /// number swept THIS pass.
    pub(in crate::afxdp) fn step(
        &mut self,
        sessions: &mut SessionTable,
        shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        session_map: SteeringMap<'_>,
        evicted_keys: &mut Vec<SessionKey>,
    ) -> usize {
        if !self.running {
            return 0;
        }
        self.stale.clear();
        let next = {
            // One lock acquisition per PASS rather than per sweep. The pass is
            // bounded, so the hold time is bounded with it — which the whole-
            // table version could not say.
            let shared = lock_shared_recover(shared_sessions);
            let stale = &mut self.stale;
            sessions.iter_with_origin_budgeted(
                self.cursor,
                DELETE_DROP_SWEEP_BUDGET,
                |key, origin| {
                    if origin.is_peer_synced() && !shared.contains_key(key) {
                        stale.push(key.clone());
                    }
                },
            )
        };
        for key in &self.stale {
            // #9560 round 3: give up this worker's steering claims BEFORE the table
            // entry goes. The sweep deletes the entry directly, so nothing downstream
            // can derive the rows it published; its holdings and the fixed-size BPF
            // rows would survive with no entry left to reap them, and unique-key churn
            // would grow both until publishes failed.
            release_all_session_rows(session_map, key);
            sessions.delete(key);
            evicted_keys.push(key.clone());
        }
        self.cursor = next;
        if next == 0 {
            // iter_with_origin_budgeted wraps to 0 on cycle completion.
            self.running = false;
        }
        self.stale.len()
    }
}
