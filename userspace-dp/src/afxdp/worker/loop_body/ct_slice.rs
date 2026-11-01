// #13075 (D4-12) — conntrack-refresh slice + fabric/WG control drains,
// extracted from `worker_loop` in loop_body/mod.rs (pure code motion; see
// housekeeping.rs for the shared rationale).
//
// Per tick, immediately before the binding poll: drive one budgeted
// BPF-conntrack `last_seen` refresh slice (#5287/#333, folding the
// slice's volume high-water #7919), adopt coordinator fabric-link
// updates into the forwarding Arc, and drain the control->worker WG
// queue (#10597). The fabric adoption reassigns the caller's
// `forwarding` Arc — the caller's variable arrives as `&mut Arc<..>` so
// the reassignment is the loop's own. `#[inline(never)]`.
//
// `use super::*;` chains through loop_body/mod.rs to worker/mod.rs.

use super::slice_pacing::{CT_REFRESH_SLICE_BUDGET, CT_REFRESH_WINDOW_NS, CT_SLICE_INTERVAL_NS};
use super::*;

/// #16217 (FZDiag28, part b): packet-independent pending-neighbor retry.
///
/// `retry_pending_neigh` is otherwise reachable only from `poll_binding`:
/// a binding with a parked representative but no RX waits for the next
/// packet (up to the client's retransmit backoff) before the sweep can
/// notice the neighbor landing in the node map. This timer arm runs
/// the SAME sweep from the worker loop on the ct-slice cadence
/// (CT_SLICE_INTERVAL_NS, 100 ms), so a hop the warm pass or the kernel
/// monitor lands in `dynamic_neighbors` dispatches the parked frame
/// within one cadence even with zero RX on every binding.
///
/// Borrow shape: `retry_pending_neigh` takes one binding mutably plus
/// its siblings as `left`/`right`, so the bindings vec is split per
/// index exactly as `poll_binding` splits it. A binding with an empty
/// pending map costs one `is_empty` check (the sweep's own early-out
/// does the same); the timer gate below keeps that at 10 Hz per
/// binding, never per-packet.
pub(super) struct PendingNeighTimer {
    last_retry_ns: Option<u64>,
    counters: BatchCounters,
    dbg: DebugPollCounters,
    shared_recycles: Vec<(u32, u64)>,
}

impl PendingNeighTimer {
    pub(super) fn new() -> Self {
        Self {
            last_retry_ns: None,
            counters: BatchCounters::default(),
            dbg: DebugPollCounters::default(),
            shared_recycles: Vec::new(),
        }
    }

    /// True when the 100 ms cadence has elapsed since the last retry
    /// pass. Split out as a pure predicate so the cadence itself is
    /// unit-pinned without bindings: a pass at +99 ms must not fire,
    /// a pass at +100 ms must. `None` (never fired) is due only when
    /// a caller explicitly primes it — the test fixtures prime via
    /// `prime_for_test`; production primes on the first pass below.
    pub(super) fn due(&self, now_ns: u64) -> bool {
        match self.last_retry_ns {
            Some(last) => now_ns.saturating_sub(last) >= CT_SLICE_INTERVAL_NS,
            None => false,
        }
    }

    #[cfg(test)]
    pub(super) fn prime_for_test(&mut self, now_ns: u64) {
        self.last_retry_ns = Some(now_ns);
    }
}

/// Drive one timer pending-neighbor retry pass over every binding.
/// Returns true when the cadence fired (the caller may count it as
/// work for idle regulation); false when gated off.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(super) fn run_pending_neigh_timer(
    timer: &mut PendingNeighTimer,
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    mirror_targets: &MirrorTargetMap,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    neighbor_resolver: Option<&Arc<NeighborResolver>>,
    now_ns: u64,
    event_stream: Option<&crate::event_stream::EventStreamWorkerHandle>,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) -> bool {
    if timer.last_retry_ns.is_none() {
        timer.last_retry_ns = Some(now_ns);
        return false;
    }
    if !timer.due(now_ns) {
        return false;
    }
    timer.last_retry_ns = Some(now_ns);
    if bindings.iter().all(|b| b.pending_neigh.is_empty()) {
        return true;
    }
    for idx in 0..bindings.len() {
        if bindings[idx].pending_neigh.is_empty() {
            continue;
        }
        // Mint the UMEM handle before the mutable split, exactly as
        // `poll_binding` does: the handle keeps the area alive while
        // `binding` is handed out mutably.
        let area = UmemAreaHandle::from_umem(&bindings[idx].umem);
        let (left, rest) = bindings.split_at_mut(idx);
        let Some((binding, right)) = rest.split_first_mut() else {
            continue;
        };
        retry_pending_neigh(
            binding,
            left,
            idx,
            right,
            binding_lookup,
            mirror_targets,
            forwarding,
            dynamic_neighbors,
            neighbor_resolver,
            now_ns,
            area.area(),
            &mut timer.shared_recycles,
            event_stream,
            &mut timer.counters,
            recent_exceptions,
            &mut timer.dbg,
        );
        timer.counters.flush(&binding.live);
    }
    true
}
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
#[inline(never)]
pub(super) fn run_ct_slice(
    sessions: &mut crate::session::SessionTable,
    forwarding: &mut Arc<ForwardingState>,
    loop_now_ns: u64,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    ct_refresh_cursor: &mut usize,
    ct_cycle_start_ns: &mut u64,
    last_ct_slice_ns: &mut u64,
    session_volume_high_water: &mut u64,
    shared_fabrics: &Arc<ArcSwap<Vec<FabricLink>>>,
    wg_uncovered_queues: &Arc<
        ArcSwap<
            std::collections::BTreeMap<
                u32,
                Arc<crate::afxdp::wg_uncovered_forward::WgUncoveredIngressQueue>,
            >,
        >,
    >,
    wg_uncovered_batch: &mut crate::afxdp::wg_uncovered_forward::WgUncoveredInjectedBatch,
    worker_id: u32,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    established_cursor: &mut usize,
) {
    // Incrementally refresh last_seen in BPF conntrack entries so Go-side
    // callers of IterateSessions (CLI, gRPC, Prometheus) see accurate
    // session idle times.  Issue #333; budgeted/resumable per #5287.
    //
    // #5287: drive at most one budgeted slice per CT_SLICE_INTERVAL_NS.
    // `should_slice` is true while a cycle is in flight (cursor != 0, keep
    // draining the table) OR once the freshness window has elapsed since the
    // last cycle started (time to begin a fresh cycle). The `&&` short-
    // circuits on the cheap cursor compare in the common between-cycles idle
    // case, so the per-tick cost stays one integer compare plus one u64
    // subtract — no allocation, no regression to the empty/idle table.
    let should_slice = *ct_refresh_cursor != 0
        || loop_now_ns.saturating_sub(*ct_cycle_start_ns) >= CT_REFRESH_WINDOW_NS;
    if should_slice && loop_now_ns.saturating_sub(*last_ct_slice_ns) >= CT_SLICE_INTERVAL_NS {
        *last_ct_slice_ns = loop_now_ns;
        // Stamp the cycle start on the FIRST slice of a cycle (cursor at the
        // top) so successive cycles are paced to the freshness window.
        if *ct_refresh_cursor == 0 {
            *ct_cycle_start_ns = loop_now_ns;
        }
        let ct_outcome = refresh_bpf_conntrack_last_seen(
            conntrack_v4_fd,
            conntrack_v6_fd,
            &sessions,
            // #3395: re-resolve each live row's policy_id against the
            // current rule table from the session's bound rule handle.
            &forwarding.policy,
            loop_now_ns,
            *ct_refresh_cursor,
            CT_REFRESH_SLICE_BUDGET,
        );
        *ct_refresh_cursor = ct_outcome.cursor;
        // #7919: fold this slice's largest observed per-session volume into
        // the worker's monotonic high-water. The walk is budgeted, so a
        // single slice may miss a busy session; taking the max ACROSS
        // slices is what makes a reading of 0 mean "this worker's table has
        // never held a session with traffic" rather than "not in this
        // slice".
        *session_volume_high_water =
            (*session_volume_high_water).max(ct_outcome.max_session_volume);
        // #16223: on the same cadence, advance the shared synced
        // entries for this worker's completed pairs to the
        // Established wire. The expiry retention and replica
        // completion on sibling workers consult that wire as
        // node-level proof; without this maintenance it only ever
        // carried the install-time Opening/Pending state, so replicas
        // reaped at 20 s despite a promoted serving pair. Full-table
        // walk each slice: per-worker tables are small next to the
        // 2048-slot conntrack budget above, and a completed pair must
        // advance within one GC interval of its completion, not after
        // a multi-second cursor rotation.
        let mut established: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
        *established_cursor =
            sessions.established_forward_slice(*established_cursor, usize::MAX, &mut established);
        // #16217/#16223: assemble completion evidence NODE-WIDE (the
        // shared maps are visible here): (a) any worker's local row
        // Established, (b) reverse traffic for the canonical key in
        // the shared synced/replica maps, or (c) #16223
        // cache_hit_handshake_progress completion — folded via the
        // counter stamps in `node_served_evidence`. Shared
        // Established is OUTPUT only (the restamp below), never an
        // input, so there is no chicken-and-egg.
        let shared_evidence = |key: &SessionKey| {
            crate::afxdp::shared_ops::shared_completion_evidence(
                shared_sessions,
                shared_forward_wire_sessions,
                key,
            )
        };
        // #16217 (fw1 rev=0 leg): stamp EVERY forward pair this
        // worker's table holds -- any origin incl. `SyncImport`
        // replicas, any stage -- with its OWN live counters BEFORE
        // the evidence read below. Pre-fix only `established` pairs
        // were stamped, and `established_forward_slice` requires
        // `established && !handshake_pending && rev>0`, so a pending
        // `SyncImport` replica on fw1 that DOES serve reverse traffic
        // (its local counters move where packets land -- fabric
        // pre-FO / post-FO replies) never stamped: its shared row
        // kept the import-time rev=0 forever and no evidence arm
        // could ever fire for it. `restamp_*` take the max, so a
        // zero-count replica never regresses a served count.
        for (key, nat) in sessions.ct_slice_forward_pairs() {
            let fwd = sessions.fwd_packets_for(&key);
            let rev = sessions.rev_packets_for(&key);
            if fwd > 0 || rev > 0 {
                crate::afxdp::shared_ops::restamp_shared_packet_counts(
                    shared_sessions,
                    shared_forward_wire_sessions,
                    &key,
                    nat,
                    fwd,
                    rev,
                );
            }
        }
        let mut node_served: Vec<(SessionKey, crate::nat::NatDecision)> = Vec::new();
        sessions.node_served_forward_slice(0, usize::MAX, &shared_evidence, &mut node_served);
        // `collected` = strict-established pairs PLUS node-served
        // (evidence-collected) pairs: the stage/count/alias restamps
        // below target exactly this union.
        let mut collected = established.clone();
        for pair in node_served {
            if !collected.contains(&pair) {
                collected.push(pair);
            }
        }
        let canonical_transitioned =
            crate::afxdp::shared_ops::restamp_shared_handshakes_established(
                shared_sessions,
                &collected,
            );
        // #16217: the collected pairs' ACTUAL fwd+rev counts (folded
        // by their serving workers; the promotion above only moved
        // the stage) must ride onto the shared rows, or the peer's
        // scoped adoption arm keeps reading the import-time counts.
        // (Pairs only in `ct_slice_forward_pairs` were already
        // stamped above; re-stamping the collected subset is a
        // max-idempotent no-cost overlap.)
        for (key, nat) in &collected {
            let fwd = sessions.fwd_packets_for(key);
            let rev = sessions.rev_packets_for(key);
            if fwd > 0 || rev > 0 {
                crate::afxdp::shared_ops::restamp_shared_packet_counts(
                    shared_sessions,
                    shared_forward_wire_sessions,
                    key,
                    *nat,
                    fwd,
                    rev,
                );
            }
        }
        // #16217: advance the forward-wire KEY ALIAS slot beside the
        // canonical restamp so a completed fabric pair reads
        // Established under the NAT'd tuple too.
        let alias_transitioned = crate::afxdp::shared_ops::restamp_shared_forward_wire_established(
            shared_sessions,
            shared_forward_wire_sessions,
            &collected,
        );
        // #16217 (ct-slice HA emit): the restamps above advanced
        // THIS node's shared rows, but no HA delta carries that
        // evidence — emission is transition-only and fw0's split
        // forward half never locally transitions, so fw1's imported
        // rows kept the Open-time stage/counts forever (FZDiag20/23:
        // fw0 shared rev=103505, fw1 rev=0, no delta in 60 s). Queue
        // a stage/count Update for each collected forward row whose
        // shared stage transitioned to Established, or whose counts
        // first show rev>0, reusing the shared-evidence Update
        // vehicle. Rate-limited per row inside
        // `emit_ct_slice_state_update` (once per stage transition
        // per node; the restamp's transition list is the detector,
        // and already-at-wire=4 rows are not re-detected, so
        // steady-state slices stay silent). Counts are read AFTER
        // the restamps so the Update carries wire=4 + rev counts;
        // the alias-transitioned rows are already canonical-
        // transitioned or alias-only, so the union is drained once.
        {
            let mut emit_keys: Vec<(SessionKey, crate::nat::NatDecision)> =
                canonical_transitioned.clone();
            for pair in &alias_transitioned {
                if !emit_keys.contains(pair) {
                    emit_keys.push(pair.clone());
                }
            }
            // Rows that did not transition stage may still have
            // crossed rev>0 for the first time on the count stamps
            // above; the per-row mark inside the emit is the gate,
            // so offer every collected row and let it decide.
            for pair in &collected {
                if !emit_keys.contains(pair) {
                    emit_keys.push(pair.clone());
                }
            }
            for (key, nat) in &emit_keys {
                let (stage, fwd, rev) =
                    crate::afxdp::shared_ops::shared_row_stage_and_counts(
                        shared_sessions,
                        shared_forward_wire_sessions,
                        key,
                        *nat,
                    );
                sessions.emit_ct_slice_state_update(key, stage, rev, fwd);
            }
        }
    }
    // Check if fabric links were updated by the coordinator (e.g. after
    // RG failover when peer MAC was resolved). If so, rebuild the
    // forwarding Arc with the new fabric links so fabric redirect works.
    {
        let live_fabrics = shared_fabrics.load();
        if !live_fabrics.is_empty() && live_fabrics.as_ref() != &forwarding.fabrics {
            let mut updated = (**forwarding).clone();
            updated.fabrics = live_fabrics.as_ref().clone();
            // #18534 fold: different contents, so not the published
            // snapshot's identity — per-flow memos key on it.
            updated.restamp_local_derivation();
            *forwarding = Arc::new(updated);
        }
    }
    // #10597: drain the control→worker WG queue independently of native
    // RX availability. The batch stays live across binding calls/ticks;
    // a worker with no AF_XDP traffic must still adjudicate uncovered
    // host-inbound records.
    if wg_uncovered_batch.is_empty() {
        let live_wg_queues = wg_uncovered_queues.load();
        if let Some(queue) = live_wg_queues.get(&worker_id) {
            wg_uncovered_batch.drain_from(queue);
        }
    }
}
