// CoS TX-selection resolve + COS fast-path enqueue helpers for the
// dispatch loop (#1443).
//
// Pure code motion from `dispatch/mod.rs`. All helpers are per-
// request hot path; the orchestrator calls them once per
// `pending_forwards` iteration. `#[inline]` on each helper — one
// caller, release-build inlining is reliable.
//
// `enqueue_local_request_to_target_or_owner` is the COS-shared
// fast-path enqueue that may either keep the request on the
// local TX queue or hand it off to the owner binding's MPSC
// channel via `owner_live.enqueue_tx_owned(req)`. Cross-worker
// ordering (HA session-sync) depends on this happening in the
// same per-request sequence the master code uses — no batching,
// no reordering, no hoisting upstream of the loop.

use super::*;

#[inline]
pub(super) fn cos_queue_fast_path_for_request<'a>(
    cos_fast_interfaces: &'a FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<&'a WorkerCoSQueueFastPath> {
    let iface = cos_fast_interfaces.get(&egress_ifindex)?;
    iface.queue_fast_path(requested_queue_id)
}

#[inline]
pub(super) fn cos_owner_live_for_request<'a>(
    cos_fast_interfaces: &'a FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> Option<&'a Arc<BindingLiveState>> {
    // #4972: return a borrow of the map-owned owner `Arc`, not a
    // per-request clone. Both callers only need a reference — a
    // pointer-eq (`Arc::ptr_eq`) and `enqueue_tx_owned(&self)` — so an
    // owned `Arc` was a needless per-eligible-packet refcount bump on a
    // cross-worker-shared atomic.
    cos_queue_fast_path_for_request(cos_fast_interfaces, egress_ifindex, requested_queue_id)
        .and_then(|queue_fast| queue_fast.owner_live.as_ref())
}

/// #1598 (secondary fix): does this request target a queue that runs
/// under the shared multi-worker drain policy?
///
/// This is the routing-level "stay local — don't funnel to one owner"
/// signal. It distinguishes three queue regimes:
///
/// - Exact + high-rate queues: `shared_exact = true` AND
///   `shared_queue_lease = Some(...)` (lease holds the per-queue rate
///   cap). Returns `true`.
/// - Non-exact + high-rate queues (e.g. Junos `priority low` uncapped
///   class with effective rate at the iface shaping rate): `shared_exact
///   = true` but `shared_queue_lease = None` (no per-queue rate cap to
///   serve, see `coordinator/mod.rs:1058`). Returns `true`.
/// - Low-rate queues (exact or non-exact): `shared_exact = false`.
///   Returns `false`; the request funnels to `owner_worker_id`.
///
/// The previous implementation of this gate consulted
/// `shared_queue_lease.is_some()` as a proxy for the routing policy.
/// That worked before #1598 (the two were coextensive on the production
/// queue set, exact queues only), but diverged once non-exact uncapped
/// queues were admitted to `shared_exact` — they have no lease, so the
/// proxy mis-classified them as "single-owner, route to owner",
/// recreating the cross-worker funnel that the routing-side
/// `queue_uses_shared_exact_service` fix at `worker/cos/mod.rs:126-131`
/// was supposed to break (#1598 primary smoke regression).
///
/// Lease-bookkeeping consumers (`token_bucket.rs`, `tx_completion.rs`)
/// inspect `queue_fast.shared_queue_lease.as_ref()` directly via
/// `if let Some(lease)`; they have never used a helper for the
/// "is there a lease?" question, so no separate helper is needed.
#[inline]
pub(super) fn request_runs_under_shared_exact_policy(
    cos_fast_interfaces: &FastMap<i32, WorkerCoSInterfaceFastPath>,
    egress_ifindex: i32,
    requested_queue_id: Option<u8>,
) -> bool {
    cos_queue_fast_path_for_request(cos_fast_interfaces, egress_ifindex, requested_queue_id)
        .is_some_and(|queue_fast| queue_fast.shared_exact)
}

// #2208: test-only fault injection for the enqueue-failure control flow.
// The owner-path `enqueue_tx_owned` swallows overflow today (it records a
// redirect-inbox drop but returns Ok), so the `is_err()` arms in the
// dispatch copy paths are not reachable from pure production inputs. They
// ARE on the hot path (the function returns `Result<(), TxRequest>` and
// the Err arm is compiled), and a future backpressure change would make
// them live. This thread-local lets the dispatch tests drive the Err arm
// deterministically to prove it recycles the ingress descriptor and runs
// the slow-path fallback. It is `#[cfg(test)]` only — the production build
// never sees the branch, so the hot path is unchanged.
#[cfg(test)]
thread_local! {
    pub(super) static FORCE_ENQUEUE_ERR: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[inline]
pub(super) fn enqueue_local_request_to_target_or_owner(
    target_binding: &mut BindingWorker,
    req: TxRequest,
) -> Result<(), TxRequest> {
    #[cfg(test)]
    if FORCE_ENQUEUE_ERR.with(|c| c.get()) {
        return Err(req);
    }
    // #1598 secondary fix: gate on the routing-level `shared_exact`
    // flag rather than on `shared_queue_lease.is_some()`. The lease is
    // an exact-queue-only marker — non-exact uncapped queues run under
    // shared_exact but have no per-queue lease, so the lease-only gate
    // here was funneling them to a single owner_worker_id (rebuilding
    // the cross-binding funnel the worker/cos/mod.rs:126-131 primary
    // fix was supposed to break).
    if request_runs_under_shared_exact_policy(
        &target_binding.cos.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    ) {
        target_binding.tx_pipeline.pending_tx_local.push_back(req);
        bound_pending_tx_local(target_binding);
        return Ok(());
    }
    let owner_live = cos_owner_live_for_request(
        &target_binding.cos.cos_fast_interfaces,
        req.egress_ifindex,
        req.cos_queue_id,
    );
    if let Some(owner_live) = owner_live {
        if !Arc::ptr_eq(owner_live, &target_binding.live) {
            // Triple-review fold: use the admission-reporting inbox API.
            // `enqueue_tx_owned` deliberately returns Ok even when its
            // bounded MPSC inbox drops the newest request; treating that
            // as acceptance let multi-fragment callers fire WireGuard
            // commits for frames that never entered TX. `try_` preserves
            // the same counters on refusal and returns the request.
            return owner_live.try_enqueue_tx_owned(req);
        }
    }
    bound_pending_tx_local(target_binding);
    Ok(())
}

// #hb166 T-7: the deferred forward-request CoS-TX-selection helpers
// (`resolve_pending_forward_cos_tx_selection` +
// `pending_forward_needs_cos_tx_selection`) were removed as dead code.
// Every PendingForwardRequest is built with `cos_tx_selection_resolved =
// true`, so the dispatch loop never deferred CoS selection to them. The
// live resolution path uses `resolve_cos_tx_selection_at` directly at
// build time (forward_request.rs / icmp.rs / poll_descriptor).
