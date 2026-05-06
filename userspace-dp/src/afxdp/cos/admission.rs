// Per-flow admission gates (share/buffer caps, ECN CE-marking) +
// flow-fair (SFQ) queue promotion. `COS_MIN_BURST_BYTES` is
// imported via `super::COS_MIN_BURST_BYTES` (cos/mod.rs re-export)
// so admission stays agnostic to which sibling module owns the
// constant.

use crate::afxdp::types::{
    CoSInterfaceRuntime, CoSPendingTxItem, CoSQueueRuntime, WorkerCoSQueueFastPath,
};
use crate::afxdp::umem::MmapArea;

use super::ecn::{maybe_mark_ecn_ce, maybe_mark_ecn_ce_prepared};
use super::flow_hash::{cos_flow_hash_seed_from_os, cos_queue_prospective_active_flows};
use super::COS_MIN_BURST_BYTES;

/// Minimum per-flow admission share. Sized so TCP fast-retransmit can
/// trigger reliably on a single-packet drop:
/// - 3 dupacks to trigger fast-retransmit (Linux `tcp_reordering = 3`)
/// - headroom for in-flight reordering up to ~13 MTU-sized packets
/// - 16 MTU-sized (1500 B) packets total = 24 KB
/// Below this, a single drop produces < 3 dupacks before cwnd is drained,
/// forcing an RTO with cwnd reset to 1 MSS and starting the oscillation
/// observed in #704 / #707 at high flow counts on low-rate exact queues.
/// 1500 matches the default MTU and is a conservative proxy for TCP
/// payload size; actual MSS (1460 v4 / 1440 v6) is smaller, so 16 × 1500
/// is a safe over-count of the "packets needed for fast-retransmit".
pub(in crate::afxdp) const COS_FLOW_FAIR_MIN_SHARE_BYTES: u64 = 16 * 1500;

// Compile-time pin so the floor cannot silently drift below the
// fast-retransmit-safe threshold on a rebase/refactor. Parallels the
// `const _: () = assert!` invariants in `types/mod.rs`. Lives here (at the
// constant) rather than in `tests/` so `cargo build` enforces it, not
// just `cargo test`.
const _: () = assert!(COS_FLOW_FAIR_MIN_SHARE_BYTES >= 16 * 1500);

/// Hard upper bound on per-flow fair queue residence time. Without
/// this, `cos_flow_aware_buffer_limit` can scale the aggregate cap
/// to `COS_FLOW_FAIR_BUCKETS × COS_FLOW_FAIR_MIN_SHARE_BYTES`
/// (~24 MB at max), which on a 1 Gbps queue is ~190 ms of queueing
/// — far outside the scheduler's predictable regime. 5 ms is ~5×
/// BDP at 1 Gbps cluster RTT and keeps the tail bounded while
/// leaving generous room for bulk TCP. Tracked in #717.
pub(in crate::afxdp) const COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS: u64 = 5_000_000;

// Compile-time sanity: must be at least 1 ms. Below that TCP has
// no room to grow cwnd past a handful of packets.
const _: () = assert!(COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS >= 1_000_000);

/// ECN CE-marking threshold as a fraction of the relevant cap.
/// Applied to both the aggregate `buffer_limit` and the per-flow
/// `share_cap` in `apply_cos_admission_ecn_policy`.
///
/// History:
///   1/2 (initial) — marks never fired under the 16-flow / 1 Gbps
///     workload; per-flow buckets averaged ~36% of share_cap.
///   1/5 (#728)    — one-order-of-magnitude earlier marking to give
///     ECN-negotiated TCP room to halve cwnd smoothly.
///   1/3 (#754)    — 1/5 over-marked on a single-flow / low-rate
///     exact queue. Live trace on loss:xpf-userspace-fw0:
///       * 1 Gbps queue: 971K ECN marks vs. 1766 flow_share drops
///       * single iperf3 -P 1 -t 30: bimodal 1.44 Gbps spikes and
///         hard stalls to 0 bps, 78K retrans, avg 820 Mbps
///     Raising to 1/3 backs the marker off to 33% of share_cap so
///     TCP cubic has more headroom before mark pressure collapses
///     cwnd. Still fires before hard-drop, still lets ECN do its
///     job on elephant flows.
///
/// This is a tuning knob against live counter telemetry, not a
/// first-principles derivation. If `admission_ecn_marked` stays
/// pathologically low under load despite ECT traffic, lower further;
/// if marks fire so often that throughput drops (ECN double-backoff),
/// raise. Observe via `show class-of-service interface`. Longer-term
/// a rate-aware threshold (#747) replaces this single ratio with a
/// signal that scales with configured drain rate rather than buffer
/// depth alone.
pub(in crate::afxdp) const COS_ECN_MARK_THRESHOLD_NUM: u64 = 1;
pub(in crate::afxdp) const COS_ECN_MARK_THRESHOLD_DEN: u64 = 3;

// Guard against a refactor flipping the fraction. A threshold >= 1
// would never fire (queue is capped at buffer_limit) and a zero
// denominator would divide-by-zero at admission time.
const _: () = assert!(COS_ECN_MARK_THRESHOLD_NUM < COS_ECN_MARK_THRESHOLD_DEN);
const _: () = assert!(COS_ECN_MARK_THRESHOLD_DEN > 0);

/// Per-flow BDP-equivalent floor used by `cos_queue_flow_share_limit`
/// on `shared_exact` queues (#914). Computed against the cluster's
/// post-shaper RTT envelope; intentionally larger than the
/// `cos_flow_aware_buffer_limit`'s 5 ms `delay_cap` because they
/// serve different purposes — the aggregate buffer ceiling targets
/// queue-residence latency, the per-flow floor targets TCP cwnd
/// build-up at queue rate. Project memory: cluster RTT 5-7 ms
/// post-shaper; 10 ms gives ~1.5× headroom.
const RTT_TARGET_NS: u64 = 10_000_000;

/// Burst headroom multiplier applied to the per-flow `fair_share`
/// inside `cos_queue_flow_share_limit` for shared_exact queues. Set
/// to 2 to admit short bursts up to 2× the steady-state per-flow
/// allocation without tail-drops. Only binding in the moderate-N
/// regime where it exceeds `bdp_floor` and is below `buffer_limit`;
/// at high N `bdp_floor` dominates and at low N `buffer_limit` clamps.
const SHARED_EXACT_BURST_HEADROOM: u64 = 2;

/// Per-flow BDP at the queue's rate divided across `active_flows`.
/// Used as a floor in the shared_exact rate-aware cap — TCP cwnd
/// must reach approximately one BDP for the per-flow rate to fit
/// the queue's transmit rate without tail-drops.
///
/// Truncation: result truncates to 0 when `per_flow_rate <
/// 1e9 / RTT_TARGET_NS = 100 bytes/sec`. At cluster-scale rates
/// (≥ 1 Gbps queues with ≤ 4096 flows → ≥ 122 KB/s/flow) this is
/// far from the truncation floor. On user-configured low-rate
/// queues (e.g., 64 kbps WAN class with 100+ flows) the BDP floor
/// silently degenerates to 0 and the `MIN_SHARE` (24 KB) clamp
/// becomes the effective floor. Acceptable because the MIN_SHARE
/// floor still keeps TCP recoverable via fast-retransmit.
#[inline]
pub(in crate::afxdp) fn bdp_floor_bytes(transmit_rate_bytes: u64, active_flows: u64) -> u64 {
    let per_flow_rate = transmit_rate_bytes / active_flows.max(1);
    per_flow_rate.saturating_mul(RTT_TARGET_NS) / 1_000_000_000
}

#[inline]
pub(in crate::afxdp) fn cos_queue_flow_share_limit(
    queue: &CoSQueueRuntime,
    buffer_limit: u64,
    flow_bucket: usize,
) -> u64 {
    if !queue.flow_fair {
        return buffer_limit;
    }
    // #914 (post-#785 Phase 3): shared_exact queues now enforce a
    // RATE-AWARE per-flow cap rather than passing through buffer_limit
    // unchanged. The previous unconditional return was correct as far
    // as it preserved TCP cwnd build-up (Attempt A had regressed
    // 22.3 → 16.3 Gbps + 25k retrans because the rate-unaware
    // `COS_FLOW_FAIR_MIN_SHARE_BYTES` floor of 24 KB was used as the
    // cap), but it allowed a single elephant to occupy the entire
    // queue buffer, starving mice in the same shared_exact class.
    //
    // The new cap = `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)`:
    //
    //   - `fair_share*2` = aggregate buffer split N ways with 2×
    //     headroom for transient bursts.
    //   - `bdp_floor` = per-flow BDP at queue rate / N flows; ensures
    //     TCP cwnd can build to one BDP without tail-drops.
    //   - Clamped above by `buffer_limit` so the per-flow allocation
    //     never exceeds the aggregate; clamped below by MIN_SHARE
    //     (24 KB) for the existing guarantee.
    //
    // Behavior at low N (where bdp_floor > buffer_limit): the cap
    // clamps to buffer_limit, i.e. the formula degenerates to today's
    // behavior. This is intentional — at low N the buffer_limit
    // ceiling is the binding constraint anyway, and forcing a tighter
    // cap would regress TCP cwnd. The cap actively splits the buffer
    // only at moderate-to-high N (around N ≈ 23 flows on a 10 G
    // shared_exact queue).
    //
    // Owner-local-exact queues (low-rate, #784 workload) keep the
    // legacy aggregate/N share cap — at 1 Gbps / 12 flows the
    // 24 KB MIN floor matches TCP cwnd at 77 Mbps/flow.
    if queue.shared_exact {
        let prospective = cos_queue_prospective_active_flows(queue, flow_bucket);
        // Copilot C.2: use `div_ceil` to match the legacy owner-local
        // path below. Truncating division systematically undersizes
        // the per-flow cap by up to (prospective - 1) bytes when
        // `buffer_limit` is not divisible by `prospective`, increasing
        // boundary-condition tail-drops. The legacy path picked
        // div_ceil for that reason; shared_exact should follow.
        let fair_share = buffer_limit.div_ceil(prospective.max(1));
        let bdp = bdp_floor_bytes(queue.transmit_rate_bytes, prospective);
        return fair_share
            .saturating_mul(SHARED_EXACT_BURST_HEADROOM)
            .max(bdp)
            .clamp(COS_FLOW_FAIR_MIN_SHARE_BYTES, buffer_limit);
    }
    let prospective_active = cos_queue_prospective_active_flows(queue, flow_bucket);
    buffer_limit
        .div_ceil(prospective_active)
        .clamp(COS_FLOW_FAIR_MIN_SHARE_BYTES, buffer_limit)
}

/// Effective buffer cap for the admission check. Grows with the
/// *prospective* distinct-flow count — same denominator that
/// `cos_queue_flow_share_limit` uses — so the aggregate admission
/// threshold never drops below `prospective_active ×
/// COS_FLOW_FAIR_MIN_SHARE_BYTES`.
///
/// Why "prospective" and not current `active_flow_buckets`: the per-
/// flow clamp already adds `+1` when the target bucket is empty, so it
/// reserves headroom for a newly arriving flow. If the aggregate cap
/// uses the *current* count it asymmetrically excludes that same new
/// flow and the first packet of every new flow can get rejected right
/// at the boundary even though the per-flow path was trying to admit
/// it. Matching the two denominators removes that off-by-one window.
///
/// Non-flow-fair queues (e.g. best-effort or pure rate-limited) bypass
/// this scaling; their admission is buffer-bound by the operator's
/// configured `buffer-size` alone.
///
/// This is a logical threshold only. The backing `VecDeque` storage is
/// dynamic, so raising the cap costs nothing until traffic actually
/// fills it.
///
/// #717 latency-envelope clamp: the flow-aware expansion is bounded
/// on the high side by `delay_cap = transmit_rate_bytes ×
/// COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS / 1e9`, i.e. the number of bytes
/// the queue can drain in the max tolerated residence time. Without
/// this, at 4096 active buckets the cap reaches ~24 MB, which on a
/// 1 Gbps queue is ~190 ms of queueing — far outside the scheduler's
/// predictable regime. The clamp is applied as
/// `.min(delay_cap.max(base))`: it never shrinks below the operator's
/// explicit `buffer-size`, so an operator who asked for a deeper
/// buffer still gets it. Adds one u128 multiply + divide per admission
/// decision, not per packet.
#[inline]
pub(in crate::afxdp) fn cos_flow_aware_buffer_limit(queue: &CoSQueueRuntime, flow_bucket: usize) -> u64 {
    let base = queue.buffer_bytes.max(COS_MIN_BURST_BYTES);
    if !queue.flow_fair {
        return base;
    }
    let prospective_active = cos_queue_prospective_active_flows(queue, flow_bucket);
    // u128 to keep the intermediate product safe at 10 Gbps × 5 ms
    // (plus any plausible operator-configured rate inflation).
    let delay_cap = ((queue.transmit_rate_bytes as u128)
        * (COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS as u128)
        / 1_000_000_000u128) as u64;
    base.max(prospective_active.saturating_mul(COS_FLOW_FAIR_MIN_SHARE_BYTES))
        .min(delay_cap.max(base))
}

/// Core ECN admission decision, factored out so tests can drive it
/// without spinning up a full `BindingWorker` while still exercising
/// the exact code path that `enqueue_cos_item` uses. Mutates both the
/// item (CE bits + incremental IP checksum) and the queue's
/// `admission_ecn_marked` counter.
///
/// Returns whether the packet was marked. The caller is still
/// responsible for the subsequent drop-vs-admit decision: a
/// marked packet is ALSO admitted; a non-ECT packet above threshold
/// falls through unchanged and drops via the existing buffer/share
/// caps.
///
/// Two thresholds fire the mark, whichever trips first:
///
///   * **Aggregate**: `queue.queued_bytes > buffer_limit × NUM/DEN`.
///     This is the #718 arm — it signals congestion once the entire
///     queue is past the mark fraction of its operator-configured
///     buffer, independent of per-flow accounting.
///   * **Per-flow**: `queue.flow_bucket_bytes[flow_bucket] >
///     share_cap × NUM/DEN`, where `share_cap` is the current
///     per-flow cap from `cos_queue_flow_share_limit`. This is the
///     #722 arm. On the 16-flow / 1 Gbps exact-queue live workload
///     the aggregate queue sat at ~31% utilisation — the #718 50%
///     threshold never tripped — while per-flow buckets routinely
///     hit the 24 KB share cap and drops fired via
///     `flow_share_exceeded`. Marking off the per-flow bucket lets
///     ECN-negotiated TCP halve cwnd via ECE before the per-flow
///     cap trips the drop.
///
/// Both arms use the same `NUM/DEN` fraction. If an operator wants
/// the fraction tuned it must move in lockstep across both arms —
/// see the `admission_ecn_per_flow_threshold_matches_share_cap_denominator`
/// test for the regression pin.
///
/// Non-flow-fair queues degenerate safely:
/// `cos_queue_flow_share_limit` returns `buffer_limit` unchanged when
/// `queue.flow_fair` is false, so the per-flow threshold collapses
/// onto the aggregate one. No behaviour change on best-effort or
/// pure-rate-limited queues.
#[inline]
pub(in crate::afxdp) fn apply_cos_admission_ecn_policy(
    queue: &mut CoSQueueRuntime,
    buffer_limit: u64,
    flow_bucket: usize,
    flow_share_exceeded: bool,
    buffer_exceeded: bool,
    item: &mut CoSPendingTxItem,
    umem: &MmapArea,
) -> bool {
    // #784: ECN mark policy differs by queue kind:
    //
    // - **Flow-fair queues** (SFQ active): mark ONLY on the
    //   per-flow threshold. An aggregate-queue mark penalises
    //   every flow that happens to enqueue during a
    //   high-aggregate window — regardless of whether THAT flow
    //   is contributing to the congestion. With N flows actively
    //   sharing a queue at its rate cap, the aggregate sits above
    //   1/3 the buffer almost permanently, so the aggregate clause
    //   used to mark effectively every packet. The per-flow cwnd
    //   collapse from the marks concentrated on flows that hadn't
    //   yet filled their bucket (because their current cwnd was
    //   smaller) — a positive feedback loop producing the observed
    //   3-winner / 9-loser bimodal rate distribution on
    //   iperf3 -P 12 to a 1 Gbps cap.
    //
    // - **Non-flow-fair queues**: the aggregate IS the right
    //   signal — there's no per-flow isolation, so aggregate
    //   saturation is the only congestion indicator available.
    //
    // Adversarial review posture (required by campaign #775 /
    // issue #784): if the flow_fair branch ever grows back to
    // include the aggregate queued_bytes check, the fairness
    // regression observed in #784 (iperf3 -P 12 returning 3
    // flows at 145 Mbps with 0 retrans and 9 flows at 50-75 Mbps
    // with thousands of retrans) WILL come back.
    //
    // #722: per-flow threshold derived from the same share cap
    // the admission gate uses. `cos_queue_flow_share_limit` is
    // pure and inlined: ~5 ns on the legacy owner-local path
    // (saturating_add + max + div_ceil + clamp); ~8 ns on the
    // post-#914 shared_exact path (adds one division + multiply
    // for `bdp_floor_bytes`).
    let aggregate_ecn_threshold = buffer_limit
        .saturating_mul(COS_ECN_MARK_THRESHOLD_NUM)
        / COS_ECN_MARK_THRESHOLD_DEN.max(1);
    let share_cap = cos_queue_flow_share_limit(queue, buffer_limit, flow_bucket);
    let flow_ecn_threshold = share_cap
        .saturating_mul(COS_ECN_MARK_THRESHOLD_NUM)
        / COS_ECN_MARK_THRESHOLD_DEN.max(1);

    let flow_above = queue.flow_bucket_bytes[flow_bucket] > flow_ecn_threshold;
    let aggregate_above = queue.queued_bytes > aggregate_ecn_threshold;
    // Three classes:
    //   * flow_fair && !shared_exact — owner-local-exact (#784).
    //     Per-flow arm only; #784's fairness fix on 1 Gbps iperf-a
    //     depends on NOT marking on aggregate.
    //   * flow_fair && shared_exact — high-rate shared_exact
    //     (#785 Phase 3). Aggregate arm only; per-flow fairness is
    //     enforced by MQFQ virtual-finish-time ordering in the
    //     dequeue path, and per-flow ECN on top of that would
    //     double-signal on the same flow (MQFQ already depthens
    //     throttled flows' drain position; marking them too would
    //     collapse their cwnd twice).
    //   * !flow_fair — legacy best-effort / rate-limited queues.
    //     Aggregate arm; there is no per-flow accounting on that
    //     path.
    let should_mark = if queue.flow_fair && !queue.shared_exact {
        flow_above
    } else {
        aggregate_above
    };

    if !should_mark || flow_share_exceeded || buffer_exceeded {
        return false;
    }
    // Both variants share a single `admission_ecn_marked` counter: the
    // CoS counter surfaced in `show class-of-service interface` tracks
    // how often the admission policy marked a packet, independent of
    // whether that packet is Local-owned bytes or a zero-copy UMEM
    // frame. Split subcounters can be introduced later if operators
    // ask for Local-vs-Prepared attribution.
    let marked = match item {
        CoSPendingTxItem::Local(req) => maybe_mark_ecn_ce(req),
        CoSPendingTxItem::Prepared(req) => maybe_mark_ecn_ce_prepared(req, umem),
    };
    if marked {
        queue.drop_counters.admission_ecn_marked = queue
            .drop_counters
            .admission_ecn_marked
            .wrapping_add(1);
    }
    marked
}

/// Promote every queue on a freshly-built `CoSInterfaceRuntime` onto
/// (or off) the SFQ (flow-fair) path, using the per-queue
/// `WorkerCoSQueueFastPath.shared_exact` signal as the gate. This is
/// the whole-runtime entry point — `ensure_cos_interface_runtime`
/// calls it exactly once after `build_cos_interface_runtime`. The
/// zip alignment between `runtime.queues` and
/// `iface_fast.queue_fast_path` is load-bearing: both vectors are
/// built by iterating the same `CoSInterfaceConfig.queues` slice in
/// order (`build_cos_interface_runtime` → `CoSQueueRuntime`,
/// `build_worker_cos_fast_interfaces` → `WorkerCoSQueueFastPath`),
/// so position N in one always corresponds to position N in the
/// other.  Passing both vectors through this helper — rather than
/// inlining the `zip` at the call site — lets the integration test
/// drive the exact production promotion path with hand-authored
/// fast-path state, pinning the zip + per-queue gate end-to-end.
///
/// See `promote_cos_queue_flow_fair` below for the per-queue policy
/// rationale, and the `#785` test block for the pins that guard this
/// surface against silent regressions.
#[inline]
pub(in crate::afxdp) fn apply_cos_queue_flow_fair_promotion(
    runtime: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    worker_id: u32,
) {
    for (queue, queue_fast) in runtime.queues.iter_mut().zip(queue_fast_path) {
        promote_cos_queue_flow_fair(queue, queue_fast, worker_id);
    }
}

/// Promote a freshly-built queue runtime onto the SFQ (flow-fair)
/// path when its configuration warrants it, and cache the
/// `shared_exact` signal onto the runtime so future work on this
/// surface can branch on it without another iface_fast lookup.
///
/// **Current policy (post-#785 Phase 3, post-#914):** `flow_fair =
/// queue.exact` for both owner-local-exact AND shared_exact. The
/// dequeue-ordering mechanism is MQFQ virtual-finish-time (#913 fixed
/// the snapshot-rollback bug). The admission-side per-flow cap on
/// shared_exact is RATE-AWARE (#914): `cos_queue_flow_share_limit`
/// returns `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)`
/// rather than the rate-unaware MIN floor that regressed throughput
/// in the historical attempts described below.
///
/// **Historical retrospective (issue #785):** two earlier attempts
/// to enable SFQ on shared_exact were rolled back:
///
/// 1. Naïve flip (flow_fair=queue.exact, no admission change).
///    iperf3 -P 12 on the 25 Gbps iperf-c cap regressed from
///    22.3 Gbps / 0 retrans to 16.3 Gbps / 25 k+ retrans. Root
///    cause: the per-flow share cap (`cos_queue_flow_share_limit`
///    → floor `COS_FLOW_FAIR_MIN_SHARE_BYTES` = 24 KB) and the
///    per-flow ECN arm (`apply_cos_admission_ecn_policy`) were
///    rate-unaware; on a 25 Gbps queue with 12 flows the per-flow
///    cap collapsed to ~24 KB, far below the ~5 MB BDP a
///    2 Gbps / 20 ms TCP flow needs, so admission drops and ECN
///    marks fired on nearly every packet. **#914 fixes this** by
///    making the cap rate-aware via `bdp_floor_bytes`.
///
/// 2. SFQ + aggregate-only admission (flow_fair=queue.exact;
///    `cos_queue_flow_share_limit` returns `buffer_limit` on
///    shared_exact). Throughput preserved (22-23 Gbps) but per-flow
///    CoV went UP from ~33 % to ~40-51 % over three runs because
///    per-worker SFQ DRR cannot equalise flows that are distributed
///    unevenly across workers by NIC RSS — the dominant imbalance
///    source at P=12 / 8 workers. The DRR primitive was replaced
///    with MQFQ (#913) which uses byte-rate fairness, the
///    architecturally correct primitive for TCP under pacing.
///
/// **Contract shape:** `queue_fast: &WorkerCoSQueueFastPath` is the
/// live classifier output from `build_worker_cos_fast_interfaces`,
/// i.e. the exact same field the service path (`drain_shaped_tx`,
/// `try_drain_shared_exact`, etc.) consults. Taking the reference
/// directly rather than a loose `bool` pins the contract to the
/// same struct shape production uses: tests exercise the same
/// `WorkerCoSQueueFastPath` contract rather than an unrelated
/// standalone flag, so any future addition of fields to the
/// fast-path struct (e.g. a `min_local_flow_count` guarantee for
/// the cross-worker DRR work) is automatically visible here.
///
/// **Adversarial review posture (post-#914):** the historical
/// `!shared_exact` gate is no longer in policy — `flow_fair =
/// queue.exact` for both shared_exact and owner-local-exact. The
/// `shared_exact` shadow cached onto `CoSQueueRuntime` is now the
/// branch point used by `cos_queue_flow_share_limit` to apply the
/// rate-aware admission cap (`max(fair_share*2, bdp_floor)`)
/// instead of the legacy aggregate/N share cap. Reviewers should
/// reject PRs that re-introduce the rate-unaware MIN-floor cap on
/// shared_exact without also re-validating iperf-c P=12 ≥ 22 Gbps
/// and the same-class iperf-b mouse-latency p99 (the regressions
/// historical Attempts A and B hit).
///
/// The SFQ salt is drawn only for queues that actually use the
/// flow-fair path — non-flow-fair queues never consult the seed
/// (`exact_cos_flow_bucket` is only called from the flow-fair
/// callers). Keeping them at seed=0 also preserves byte-identical
/// legacy behavior on that path.
fn promote_cos_queue_flow_fair(
    queue: &mut CoSQueueRuntime,
    queue_fast: &WorkerCoSQueueFastPath,
    worker_id: u32,
) {
    queue.shared_exact = queue_fast.shared_exact;
    // #917: pull V_min coordination Arc from the fast-path
    // struct. Only allocated on shared_exact queues (per
    // `build_shared_cos_queue_vtime_floors_reusing_existing`
    // in coordinator.rs). The runtime caches it so hot-path
    // pop/push_front helpers can publish without an
    // iface_fast lookup. `worker_id` is the local thread's
    // 0-based id — used to index `vtime_floor.slots` for
    // self-publish and to skip self in V_min reads.
    queue.vtime_floor = queue_fast.vtime_floor.clone();
    queue.worker_id = worker_id;
    // #785 Phase 3 — flow-fair is enabled on EVERY exact queue,
    // including shared_exact. The dequeue-ordering mechanism is
    // MQFQ virtual-finish-time (byte-rate fair), not DRR round-robin
    // (packet-count fair) — which is the architecturally correct
    // primitive for per-flow fairness under TCP pacing. See
    // `docs/785-cross-worker-drr-retrospective.md` §4 for the
    // retrospective analysis, and `docs/785-perf-fairness-plan.md`
    // for the phased plan.
    //
    // Admission gates: `cos_queue_flow_share_limit` is RATE-AWARE
    // on shared_exact post-#914 — it returns
    // `max(fair_share*2, bdp_floor).clamp(MIN, buffer_limit)` so the
    // per-flow cap follows BDP at queue rate / N flows rather than
    // collapsing to the rate-unaware 24 KB MIN floor that caused the
    // Attempt A regression (22.3 → 16.3 Gbps).
    // `apply_cos_admission_ecn_policy` still uses the aggregate arm
    // on shared_exact (per-flow ECN remains rate-unaware).
    queue.flow_fair = queue.exact;
    if queue.flow_fair {
        queue.flow_hash_seed = cos_flow_hash_seed_from_os();
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
