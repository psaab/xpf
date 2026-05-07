---
status: REVISED v4 — addresses Codex round-3 (task-mow3ndit, PLAN-NEEDS-MAJOR with 6 findings) AND Gemini round-3 (task-mow3nz4o, PLAN-KILL on convergent fatal underflow finding). Both reviewers caught the same fatal: `flow_bucket_bytes` is a backlog gauge (decremented on dequeue at cos/queue_ops/accounting.rs:109), not monotonic — v3's diff math would underflow. v4 introduces a NEW monotonic per-bucket TX counter and reuses the existing active-ring scan pattern (cos_queue_min_finish_bucket at queue_ops/mod.rs:82). Convergent reviewer agreement on fix.
issue: #1229
phase: design proposal — v4 addresses all v3 wiring gaps
prerequisites:
  - PR #1217 contract ✓
  - PR #1220 harness ✓
  - PR #1228 (sym key + daemon pin) ✓
  - #1211 archived
---

## v4 — convergent reviewer fix

Both round-3 reviewers caught the same FATAL flaw with v3:

> `flow_bucket_bytes` is incremented on enqueue AND decremented on
> dequeue (verified `cos/queue_ops/accounting.rs:34, 82`). v3's
> `let dbytes = cur_bytes - last_rate_sample_bytes` would underflow
> when a bucket drains between sample ticks. **Deterministic crash
> bug.**

Convergent code-cited finding from Codex (MAJOR #1) AND Gemini
(PLAN-KILL fatal). They are right.

Plus Codex round-3 raised 5 more concrete wiring issues (all
verified):

1. `flow_bucket_bytes` underflow — covered above.
2. Cap-aware selector must wire through both `cos_queue_front()` AND
   `cos_queue_pop_front()` selection sites; otherwise pop can take a
   different bucket than was selected (queue_ops/mod.rs:109,
   queue_ops/pop.rs:58).
3. **`COS_FLOW_FAIR_BUCKETS = 4096`** (verified at types/cos.rs:105),
   not 32-64. v3's "scan all buckets" is unacceptable.
4. **`CoSQueueConfigState` is per-worker local** (built per worker at
   cos/builders.rs:96), NOT magically Arc-shared. Cross-worker
   `PerClassFairnessState` must be plumbed through coordinator and
   `WorkerCoSQueueFastPath` like queue leases at worker/cos.rs:132.
5. No `release_local_tokens()` helper exists — only `release_unused()`
   at tx_completion.rs:406 for empty-queue. Need new owner-local
   token-drain path.
6. No `local_share()` / `n_active_workers()` methods on
   `SharedCoSQueueLease`. Derive from new fairness state, not from
   static `active_shards`.

Plus Gemini's sawtooth concern (round-3 C):
> 10ms periodic sample creates burst-stall sawtooth. Backed-off TCP
> flows pass cap unconditionally for 10ms (stale 0 bps), inject
> burst, then stall on next tick.

User mandate ("gemini can be wrong a lot"): this round-3 PLAN-KILL is
the substantive case again — narrow, code-cited, with a concrete v4
direction implicit in their findings. Adopted.

## v4 design — monotonic per-bucket TX counter + event-driven rate + active-ring scan

### 1. Monotonic per-bucket TX counter (replaces v3's broken diff)

```rust
// userspace-dp/src/afxdp/types/cos.rs — add to FlowFairState
pub(in crate::afxdp) struct FlowFairState {
    // ... existing fields ...

    /// MONOTONIC per-bucket TX bytes. Updated only at dequeue (TX
    /// commit), never decremented. Wraps at u64::MAX (≈ 5×10^9 sec
    /// at 100 Gbps — practically unreachable).
    pub(in crate::afxdp) flow_bucket_tx_bytes: [u64; COS_FLOW_FAIR_BUCKETS],

    /// Per-bucket EWMA-smoothed rate, updated on every dequeue (event-
    /// driven, no sample window). Eliminates Gemini's sawtooth concern.
    pub(in crate::afxdp) flow_bucket_observed_bps: [u32; COS_FLOW_FAIR_BUCKETS],

    /// Last dequeue timestamp per bucket — for EWMA dt computation.
    pub(in crate::afxdp) flow_bucket_last_tx_ns: [u64; COS_FLOW_FAIR_BUCKETS],
}

// On dequeue (at cos/queue_ops/pop.rs - pop commit path):
fn account_flow_bucket_tx(state: &mut FlowFairState, bucket: u16, bytes: u64, now_ns: u64) {
    let b = bucket as usize;
    state.flow_bucket_tx_bytes[b] = state.flow_bucket_tx_bytes[b].wrapping_add(bytes);
    let last_ns = state.flow_bucket_last_tx_ns[b];
    state.flow_bucket_last_tx_ns[b] = now_ns;
    if last_ns != 0 {
        let dt_ns = now_ns.saturating_sub(last_ns).max(1);
        // bps = bytes * 8 * 1e9 / dt_ns; use u128 intermediate per Codex.
        let inst_bps = ((bytes as u128) * 8 * 1_000_000_000 / dt_ns as u128) as u64;
        // EWMA: smoothed = (smoothed * 7 + inst) / 8; alpha = 1/8.
        let smoothed = state.flow_bucket_observed_bps[b] as u64;
        state.flow_bucket_observed_bps[b] =
            (((smoothed * 7) + inst_bps) / 8) as u32;
    }
}
```

Event-driven rate (updated on every dequeue) eliminates the 10ms
sample-window sawtooth entirely.

### 2. Cap-aware selector reusing the existing active-ring scan pattern

`cos_queue_min_finish_bucket` at `queue_ops/mod.rs:82` already does
linear scan over `flow_rr_buckets` (the active ring, typ. 2-16
entries). Extend it to skip over-cap buckets:

```rust
// New: cap-aware variant. Same scan, two outputs.
fn cos_queue_min_eligible_bucket(
    ff: &FlowFairState,
    target_bps: u64,
) -> (Option<u16>, Option<u16>) {
    // Returns (eligible_min, fallback_min). If eligible_min is None,
    // caller uses fallback_min unconditionally.
    let mut eligible: Option<u16> = None;
    let mut eligible_finish = u64::MAX;
    let mut fallback: Option<u16> = None;
    let mut fallback_finish = u64::MAX;
    for bucket in ff.flow_rr_buckets.iter() {
        let b = usize::from(bucket);
        let finish = ff.flow_bucket_head_finish_bytes[b];
        let observed = ff.flow_bucket_observed_bps[b] as u64;
        if finish < fallback_finish {
            fallback_finish = finish;
            fallback = Some(bucket);
        }
        if observed <= target_bps && finish < eligible_finish {
            eligible_finish = finish;
            eligible = Some(bucket);
        }
    }
    (eligible, fallback)
}
```

O(active_ring) — typically 2-16 entries on iperf3-sized workloads,
matching the existing scan cost (~20 ns per pop).

### 3. Wired through both `cos_queue_front` and `cos_queue_pop_front`

Both helpers (queue_ops/mod.rs:109 and queue_ops/pop.rs:58)
independently call `cos_queue_min_finish_bucket`. v4 replaces both
with `cos_queue_min_eligible_bucket` invocations. The selected
bucket is passed through the existing `front`/`len`/`snapshot`/
`accounting` pipeline as a `u16` argument, so both selection sites
agree.

### 4. Plumbing `Arc<PerClassFairnessState>` through coordinator + worker

```rust
// userspace-dp/src/afxdp/coordinator/cos_state.rs — alongside queue_leases
pub(crate) per_queue_fairness:
    Arc<ArcSwap<BTreeMap<(i32, u8), Arc<PerClassFairnessState>>>>,

// userspace-dp/src/afxdp/types/cos.rs — extend CoSQueueConfigState
pub(in crate::afxdp) struct CoSQueueConfigState {
    // ... existing ...
    pub(in crate::afxdp) shared_fairness: Option<Arc<PerClassFairnessState>>,
}

// userspace-dp/src/afxdp/cos/builders.rs — at queue creation, look up
// shared_fairness from coordinator's per_queue_fairness map and clone
// the Arc. Same pattern as shared_queue_lease at line 132 of worker/cos.rs.
```

PerClassFairnessState lifetime: created at coordinator's
`build_cos_state`, populated/updated at the existing ~65ms
`update_binding_debug_state` tick on each worker.

### 5. Per-queue active_flow_count derivation (Codex finding #1, answer #3)

Existing flow_cache entries already have `descriptor.egress_ifindex`
and `tx_selection.queue_id` (verified at `flow_cache.rs:47`).
`count_active_flows` extension:

```rust
// userspace-dp/src/afxdp/flow_cache.rs — extend existing scan
pub(super) fn count_active_flows_per_queue(
    &self
) -> BTreeMap<(i32, u8), u32> {
    let mut counts = BTreeMap::new();
    let now = self.current_epoch;
    for slot in self.entries.iter() {
        if let Some(entry) = slot {
            if entry.last_used_epoch == 0 { continue; }
            let age = now.wrapping_sub(entry.last_used_epoch);
            if age >= ACTIVE_WINDOW_EPOCHS { continue; }
            let key = (
                entry.descriptor.egress_ifindex,
                entry.descriptor.tx_selection.queue_id.unwrap_or(0),
            );
            *counts.entry(key).or_insert(0) += 1;
        }
    }
    counts
}
```

Single owner-only periodic scan extension. No new write paths. ~63K
loads/sec/worker per #1219, +1 BTreeMap insert per active entry.

### 6. `class_rate_for_cap` concrete (Codex finding #5)

```rust
// On the per-queue fairness state's published target_rate_bps:
fn target_rate_bps(
    fairness: &PerClassFairnessState,
    queue: &CoSQueueConfigState,
    surplus_phase: bool,
) -> u64 {
    let total_flows = fairness.total_active_flows.load(Relaxed);
    if total_flows == 0 { return u64::MAX; }
    let class_rate = if surplus_phase {
        // root_shaping_rate × this_queue's surplus share. Derive
        // from queue.surplus_phase config (existing #915 plumbing).
        queue.root_shaping_rate * queue.surplus_share() / 100
    } else {
        queue.transmit_rate_bps()
    };
    class_rate / total_flows as u64
}
```

`queue.transmit_rate_bps()`, `queue.root_shaping_rate`,
`queue.surplus_share()` — all reference existing fields on
`CoSQueueConfigState` that were added by #915 and prior work.

### 7. Conditional token release (Codex finding #4)

New helper `release_local_tokens_when_capped()` extends the existing
`release_unused()` at tx_completion.rs:406. Triggered when:
- Queue is non-empty (otherwise `release_unused` already handles it).
- Selector returns `eligible=None` (all over-cap) for ≥10 consecutive
  poll-batches.

Releases up to `local_tokens` to shared pool via existing CAS path
(`shared_lease.return_tokens`). Bounded by token-bucket invariants.

## 8. Sawtooth analysis (Gemini round-3 C)

v3 sample-window sawtooth eliminated by v4's event-driven update
(every dequeue). Per-bucket EWMA with α=1/8 smooths bursts within
~8 packets. For 1500-byte packets at 1 Gbps, that's 100 µs of
smoothing — well below TCP cwnd-cycle scale.

Worst-case post-backoff: TCP comes out of backoff with cwnd=1 packet.
First dequeue updates EWMA from old (high) to new (1500/8/RTT) bytes/
(short_dt). EWMA drops slowly over next 8 packets. During those 8
packets, cap-check uses old-rate; flow may re-burst slightly. Then
EWMA settles. Burst bounded by 8 × MSS = 12 KB. Acceptable.

## 9. Performance budget (revised)

| Item | Cost |
|---|---|
| TX commit per packet (dequeue): bucket bytes + EWMA update | ~10 ns (was ~5 ns; EWMA arithmetic is the increase) |
| Cap-aware selector: O(active_ring) ≈ O(12) for iperf3 -P 12 | ~25 ns per pop (was ~20 ns) |
| ~65ms tick: per-queue active_flow_count derivation | +~5 µs/sec/worker (one extra pass through flow_cache) |
| Cross-worker read of total_active_flows | 1 atomic_load per batch (~2 ns) |

Total hot-path overhead: ~12 ns/packet. Acceptable.

## 10. Acceptance criteria

(Unchanged from v2/v3.)

- Workload: `iperf3 -c <target> -P 12 -t 90 -p 5205 -R` (no
  `--cport`, no `-b`).
- Pre-mechanism: per-flow CoV ≥ 0.50.
- Post-mechanism: per-flow CoV ≤ Cstruct + 0.10.
- No aggregate regression > 5%.
- Bucket collision impact: with 12 flows in 4096 buckets, P(any
  collision) ≈ 1.6%. For workload validation this is fine.
  Document as bucket-cap (not strict per-flow cap) per Codex MAJOR #5.

## 11. Implementation outline

1. Add `flow_bucket_tx_bytes`, `flow_bucket_observed_bps`,
   `flow_bucket_last_tx_ns` to FlowFairState.
2. Add `account_flow_bucket_tx` helper, called from existing
   dequeue commit path in `cos/queue_ops/pop.rs`.
3. Add `PerClassFairnessState` struct + Arc plumbing through
   coordinator/cos_state.rs and worker/cos.rs.
4. Implement `cos_queue_min_eligible_bucket` and replace both
   selection sites in queue_ops/mod.rs:109 and pop.rs:58.
5. Implement `count_active_flows_per_queue`; wire into ~65ms tick
   alongside existing `count_active_flows`.
6. Implement `target_rate_bps` with surplus-phase distinction.
7. Implement `release_local_tokens_when_capped` extending
   `release_unused`.
8. Cargo build + test (no regression).
9. Smoke matrix: v4/v6 × push/reverse × CoS-on/off, 30 measurements
   per project standard.
10. Validate on user's exact iperf3 -P 12 -t 90 -p 5205 -R command.

## 12. Risks (revised)

- **Bucket collision at scale**: 4096 buckets, but at 100K flows
  collisions are guaranteed. Per-bucket cap then under-serves
  collided flows. Documented as known limitation; production
  workload testing required to validate at scale.
- **EWMA tuning**: α=1/8 picked heuristically. May need adjustment.
- **Surplus-phase target_rate divergence**: if surplus phase
  activates mid-flow, target_rate jumps. Cap-check is observational
  only (deferral, not drop), so flows naturally re-converge.

## 13. Methodology

- v4 plan committed.
- Re-dispatch round-4 with: "convergent fatal flaw fixed, all 6
  Codex MAJOR + Gemini PLAN-KILL grounds addressed via
  monotonic counter + event-driven EWMA + active-ring scan +
  Arc plumbing through coordinator".
- If round-4 verdicts converge to PLAN-READY → implementation.
- If still PLAN-NEEDS-MAJOR with NEW substantive grounds →
  iterate.
- If PLAN-KILL on a re-issue of already-addressed points →
  override per operator mandate.
