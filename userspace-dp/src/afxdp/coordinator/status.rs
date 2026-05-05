use super::*;

/// Operator-status surface split out of `coordinator/mod.rs` to keep
/// the gRPC / HTTP status methods in one place. Most are pure-read
/// snapshots (e.g. `cos_statuses` loads ArcSwap values and aggregates
/// them); the one exception is `drain_session_deltas`, which mutates
/// per-binding state by popping entries off `pending_session_deltas`
/// and bumping `session_delta_drained`. Coordinator lifecycle
/// (worker spawn / shutdown / reconcile) and HA reconciliation state
/// stay in mod.rs and ha.rs.
impl super::Coordinator {
    pub fn dynamic_neighbor_status(&self) -> (usize, u64) {
        let entries = self.neighbors.dynamic.len();
        let generation = self.neighbors.generation.load(Ordering::Relaxed);
        (entries, generation)
    }

    /// #710: sum of `no_owner_binding_drops` across every binding's
    /// `BindingLiveState`. The per-binding increment site lives in
    /// `apply_worker_shaped_tx_requests` and mechanically lands on
    /// `bindings.first_mut()` (there is no binding to attribute to —
    /// the whole point of the counter is that the request's egress
    /// has no binding on this worker). Summing across every binding's
    /// live state gives the cluster-wide total regardless of which
    /// worker's "first binding" the increments landed on. This is the
    /// only operator-facing surface for this counter.
    pub fn cos_no_owner_binding_drops_total(&self) -> u64 {
        self.workers.live
            .values()
            .map(|live| live.no_owner_binding_drops.load(Ordering::Relaxed))
            .sum()
    }

    pub fn recent_exceptions(&self) -> Vec<ExceptionStatus> {
        self.recent_exceptions
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn recent_session_deltas(&self) -> Vec<SessionDeltaInfo> {
        self.recent_session_deltas
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn last_resolution(&self) -> Option<PacketResolution> {
        self.last_resolution
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    pub fn slow_path_status(&self) -> SlowPathStatus {
        self.slow_path
            .as_ref()
            .map(|slow| slow.status())
            .unwrap_or_else(|| self.last_slow_path_status.clone())
    }

    pub fn cos_statuses(&self) -> Vec<crate::protocol::CoSInterfaceStatus> {
        let snapshots: Vec<Vec<_>> = self
            .workers
            .handles
            .values()
            .map(|worker| worker.cos_status.load().iter().cloned().collect())
            .collect();
        aggregate_cos_statuses_across_workers(&snapshots, &self.cos_owner_worker_by_queue)
    }

    pub fn filter_term_counters(&self) -> Vec<crate::protocol::FirewallFilterTermCounterStatus> {
        let mut filter_keys = self
            .forwarding
            .filter_state
            .filters
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        filter_keys.sort();
        let mut out = Vec::new();
        for key in filter_keys {
            let Some(filter) = self.forwarding.filter_state.filters.get(&key) else {
                continue;
            };
            for term in &filter.terms {
                out.push(crate::protocol::FirewallFilterTermCounterStatus {
                    family: filter.family.clone(),
                    filter_name: filter.name.clone(),
                    term_name: term.name.clone(),
                    packets: term.counter.packets.load(Ordering::Relaxed),
                    bytes: term.counter.bytes.load(Ordering::Relaxed),
                });
            }
        }
        out
    }

    pub fn drain_session_deltas(&self, max: usize) -> Vec<SessionDeltaInfo> {
        let mut remaining = max.max(1);
        let mut out = Vec::new();
        for live in self.workers.live.values() {
            if remaining == 0 {
                break;
            }
            let drained = live.drain_session_deltas(remaining);
            remaining = remaining.saturating_sub(drained.len());
            out.extend(drained);
        }
        out
    }

    pub fn worker_heartbeats(&self) -> Vec<chrono::DateTime<Utc>> {
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        self.workers.handles
            .iter()
            .map(|(_, handle)| {
                monotonic_timestamp_to_datetime(
                    handle.heartbeat.load(Ordering::Relaxed),
                    now_mono,
                    now_wall,
                )
                .unwrap_or(now_wall)
            })
            .collect()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.handles.len()
    }

    /// #869: snapshot per-worker busy/idle runtime counters.  Each row is
    /// the current `WorkerRuntimeAtomics` publish, most recently written
    /// on the worker's ~1s publish cadence.
    /// #925: also surfaces `dead` (one-shot AtomicBool set when the
    /// supervisor catches a worker_loop panic) and the rendered panic
    /// payload from the per-worker slot in `worker_panics`.
    pub fn worker_runtime_snapshots(&self) -> Vec<crate::protocol::WorkerRuntimeStatus> {
        self.workers.handles
            .iter()
            .map(|(worker_id, handle)| {
                let s = handle.runtime_atomics.snapshot();
                let dead = handle
                    .runtime_atomics
                    .dead
                    .load(std::sync::atomic::Ordering::Relaxed);
                let panic_message = if dead {
                    self.worker_panics
                        .get(worker_id)
                        .and_then(|slot| match slot.lock() {
                            Ok(g) => g.clone(),
                            Err(poisoned) => poisoned.into_inner().clone(),
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                crate::protocol::WorkerRuntimeStatus {
                    worker_id: *worker_id,
                    tid: handle.runtime_atomics.tid(),
                    wall_ns: s.wall_ns,
                    active_ns: s.active_ns,
                    idle_spin_ns: s.idle_spin_ns,
                    idle_block_ns: s.idle_block_ns,
                    thread_cpu_ns: s.thread_cpu_ns,
                    work_loops: s.work_loops,
                    idle_loops: s.idle_loops,
                    dead,
                    panic_message,
                }
            })
            .collect()
    }

    pub fn identity_count(&self) -> usize {
        self.workers.identities.len()
    }

    pub fn live_count(&self) -> usize {
        self.workers.live.len()
    }

    pub fn planned_counts(&self) -> (usize, usize) {
        (self.workers.last_planned_workers(), self.workers.last_planned_bindings())
    }

    pub fn reconcile_debug(&self) -> (u64, String) {
        (self.reconcile_calls, self.last_reconcile_stage.clone())
    }
}
