---
status: REVISED v3 — addresses Codex round-2 (task-mow38bom, PLAN-NEEDS-MAJOR with 5 findings) AND Gemini round-2 (task-mow3904l, PLAN-KILL on the narrow-but-valid observed_bps-via-flow_cache point + concrete v3 alternative). Both reviewers converged on the same fix: rate-tracking belongs in FlowFairState.flow_bucket_bytes (verified at types/cos.rs:563), aggregator belongs in CoSQueueConfigState, denominator is per-(egress_ifindex,queue_id) not binding-wide.
issue: #1229
phase: design proposal — per-worker local max-min using existing FlowFair buckets + CoSQueueConfigState placement
prerequisites:
  - PR #1217 contract ✓
  - PR #1220 harness ✓
  - PR #1228 ✓ (sym key + daemon pin merged)
  - #1211 archived
---

## v3 — adopt both reviewers' constructive feedback

Round-2 reviewers converged. Codex: PLAN-NEEDS-MAJOR (right direction,
wiring gaps). Gemini: PLAN-KILL on the specific `observed_bps` via
flow_cache path (would re-introduce cross-worker write contention)
plus concrete v3 alternative.

Both reviewers' grounds verified against the code:
- `flow_bucket_bytes: [u64; COS_FLOW_FAIR_BUCKETS]` already exists on
  `FlowFairState` at `userspace-dp/src/afxdp/types/cos.rs:563` —
  exactly the field Gemini named.
- `CoSQueueConfigState` at `cos.rs:450` is per-(egress_ifindex,queue_id)
  shared state — exactly where `PerClassFairnessState` belongs.
- Active flow count today is binding-wide (Codex finding #1), per
  `umem/mod.rs:232` and `flow_cache.rs:365`. Need a per-queue derivation.

User mandate ("gemini can be wrong a lot"): calibration applied.
This Gemini PLAN-KILL is the substantive case — narrow, code-cited,
with a concrete fix proposed. Adopted, not capitulated to.

## v3 design — per-worker rate tracking via existing FlowFair buckets

### 1. State placement (Codex finding #1, #5; Gemini Q-F)

```rust
// userspace-dp/src/afxdp/types/cos.rs — extend CoSQueueConfigState
pub(in crate::afxdp) struct PerClassFairnessState {
    /// Per-worker active flow count for this (egress_ifindex, queue_id).
    /// Each worker writes its own slot at the ~65ms tick (single-writer
    /// per slot); other workers read for sum.
    per_worker_active_flows: [AtomicU32; MAX_WORKERS],
    /// Cached sum, recomputed at the same tick. Read by hot path.
    total_active_flows: AtomicU32,
}

pub(in crate::afxdp) struct CoSQueueConfigState {
    // ... existing fields ...
    /// New: cross-worker per-queue fairness state. Arc so workers
    /// share. Written only at ~65ms tick.
    pub(in crate::afxdp) fairness: Arc<PerClassFairnessState>,
}
```

### 2. Per-flow rate tracking — no flow_cache touch (Gemini PLAN-KILL fix)

```rust
// FlowFairState already has flow_bucket_bytes at cos.rs:563
// Track per-bucket rate via difference + local timestamp.
//
// On TX enqueue (existing path): bucket_bytes += pkt_size  (already done)
// On periodic local tick (per worker, per queue):
fn refresh_bucket_rates(&mut self, now_ns: u64) {
    let dt_ns = now_ns - self.last_rate_sample_ns;
    if dt_ns < MIN_RATE_SAMPLE_NS { return; }  // 10ms minimum
    for b in 0..COS_FLOW_FAIR_BUCKETS {
        let cur_bytes = self.flow_bucket_bytes[b];
        let dbytes = cur_bytes - self.last_rate_sample_bytes[b];
        self.bucket_observed_bps[b] = (dbytes * 8 * 1_000_000_000) / dt_ns;
        self.last_rate_sample_bytes[b] = cur_bytes;
    }
    self.last_rate_sample_ns = now_ns;
}
```

This adds `bucket_observed_bps: [u64; COS_FLOW_FAIR_BUCKETS]` and
`last_rate_sample_bytes: [u64; COS_FLOW_FAIR_BUCKETS]` plus
`last_rate_sample_ns: u64` to FlowFairState. All single-writer per
worker. No cross-worker state.

### 3. Cap-aware MQFQ selector (Codex finding #2)

```rust
// userspace-dp/src/afxdp/cos/queue_service/drain.rs
// Replace the simple cos_queue_front + pop with eligible-bucket scan.

fn next_eligible_bucket(state: &mut FlowFairState, target_bps: u64) -> Option<usize> {
    // Scan active buckets in finish-time order (existing MQFQ semantics);
    // skip buckets where bucket_observed_bps > target_bps.
    // O(COS_FLOW_FAIR_BUCKETS) which is small (typ. 32-64).
    let mut min_finish = u64::MAX;
    let mut chosen = None;
    for b in 0..COS_FLOW_FAIR_BUCKETS {
        if state.flow_bucket_bytes[b] == 0 { continue; }  // empty
        if state.bucket_observed_bps[b] > target_bps { continue; }  // capped
        if state.bucket_finish[b] < min_finish {
            min_finish = state.bucket_finish[b];
            chosen = Some(b);
        }
    }
    chosen
}
```

If all buckets are over-cap (rare but possible during transient
overshoot), fall back to the lowest-finish-time bucket regardless
of cap to avoid stall.

### 4. Per-queue active_flow_count (Codex finding #1)

The existing `count_active_flows()` at `flow_cache.rs:365` scans the
binding-wide flow cache. To get per-queue counts:

Option A: extend `count_active_flows()` to return a per-queue
breakdown, computed from each entry's `egress_queue_id` field.
flow_cache entries should already have this for routing.

Option B: maintain a per-(queue_id) active flow count incrementally
on lookup hit / eviction.

**v3 picks A** — single-writer extension of an existing scan, no
new write paths.

### 5. class_rate definition (Codex finding #5)

`class_rate` for the cap = the queue's effective transmit rate
under the SharedCoSQueueLease, considering surplus-sharing phase:

```rust
fn class_rate_for_cap(queue: &CoSQueueConfigState) -> u64 {
    if queue.surplus_phase_active() {
        // Exact-rate queue in surplus phase: cap at root_shaping_rate
        // share, not exact rate.
        queue.root_shaping_rate * queue.shared_lease.local_share()
    } else {
        // Exact phase: each worker's share is queue.transmit_rate / N_workers
        queue.transmit_rate / queue.shared_lease.n_active_workers()
    }
}
```

This explicitly distinguishes surplus vs exact phase — addresses
Codex's PR #915 surplus-sharing concern.

### 6. SharedCoSQueueLease nonempty-queue token retention (Codex finding #4)

Codex correctly noted that `SharedCoSQueueLease` doesn't auto-free
held tokens while a worker's queue is nonempty. v3 mitigation:

When the cap-aware selector skips ALL buckets in the local queue
(all over-cap) for `EXACT_QUEUE_FORCE_RELEASE_TICKS` (e.g. 10
consecutive batches ≈ 1 ms), invoke
`shared_lease.release_local_tokens()` to return tokens to the pool
explicitly. Existing helper at `tx_completion.rs:403`.

This is a CONDITIONAL early-release, not unconditional. Avoids
gratuitous lease churning during normal operation.

## 7. v3 acceptance criteria (unchanged from v2)

- Workload: `iperf3 -c <target> -P 12 -t 90 -p 5205 -R` (no `--cport`,
  no `-b`).
- Pre-mechanism baseline: per-flow CoV ≥ 0.50.
- Post-mechanism: per-flow CoV ≤ Cstruct + 0.10.
- No aggregate regression > 5%.

## 8. v3 risks (revised)

| Risk | Mitigation |
|------|------------|
| Cap-aware selector skips all buckets → stall | §3 fall-through to lowest-finish unconditional |
| Bucket-rate sample period (10ms) too coarse for fast cwnd ramp | §2 EWMA smoothing or per-batch increment alongside the periodic refresh |
| Per-queue active_flow_count computation cost (Codex finding #1 Option A) | §4 acceptable: existing `count_active_flows` is owner-only periodic scan, ~63K loads/sec/worker. Extension is one extra pass. |
| `class_rate` definition rare-corner-case (transmit-rate not configured, etc.) | §5: when shaper is unconfigured, fall back to no-cap (preserves baseline behavior) |
| Per-bucket rate state grows FlowFairState size | each [u64; COS_FLOW_FAIR_BUCKETS] adds 256-512 bytes per queue. Small. |

## 9. What v3 DOESN'T do (intentionally)

- ❌ No flow_cache modification (Gemini Q-C fatal flaw avoided).
- ❌ No cross-worker writes per packet (only ~65ms tick + opt-in token
  release).
- ❌ No RWND, no RTT, no ECN.
- ❌ No new TCP-level mechanisms.

## 10. Implementation outline (revised)

1. **Add `PerClassFairnessState` to `CoSQueueConfigState`**.
   Single field; init at queue creation.
2. **Extend FlowFairState with rate-sample fields**.
   `bucket_observed_bps` + `last_rate_sample_bytes` + `last_rate_sample_ns`.
3. **Add `refresh_bucket_rates` invocation** in the existing per-worker
   tick path (alongside `update_binding_debug_state`).
4. **Replace simple front-check with `next_eligible_bucket`** in
   `cos/queue_service/drain.rs:161`.
5. **Per-queue active_flow_count derivation** in `count_active_flows`.
6. **Aggregator update** at the ~65ms tick: each worker writes own
   slot to `PerClassFairnessState.per_worker_active_flows[worker_id]`,
   sum recomputed.
7. **`class_rate_for_cap` helper** integrating SharedCoSQueueLease state.
8. **Conditional token release** when locally-capped for N batches.

## 11. Methodology

- v3 plan committed.
- Re-dispatch Codex + Gemini round-3 with explicit answers to each
  prior finding.
- If Gemini round-3 PLAN-KILLs again: per operator calibration
  ("gemini can be wrong a lot"), evaluate the NEW grounds carefully.
  If they're empirically valid → iterate. If they're a re-issue of
  prior already-addressed points or generic → flag as bad-faith and
  override.
- Implement on PLAN-READY consensus or operator override.
