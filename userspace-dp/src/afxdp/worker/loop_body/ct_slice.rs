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

use super::*;

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn run_ct_slice(
    sessions: &crate::session::SessionTable,
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
) {
    const CT_REFRESH_WINDOW_NS: u64 = 10_000_000_000;
    const CT_SLICE_INTERVAL_NS: u64 = 100_000_000;
    const CT_REFRESH_SLICE_BUDGET: usize = 2048;
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
    }
    // Check if fabric links were updated by the coordinator (e.g. after
    // RG failover when peer MAC was resolved). If so, rebuild the
    // forwarding Arc with the new fabric links so fabric redirect works.
    {
        let live_fabrics = shared_fabrics.load();
        if !live_fabrics.is_empty() && live_fabrics.as_ref() != &forwarding.fabrics {
            let mut updated = (**forwarding).clone();
            updated.fabrics = live_fabrics.as_ref().clone();
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
