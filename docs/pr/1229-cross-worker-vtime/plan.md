---
status: REVISED v7 — Codex round-6 returned **PLAN-READY**; Gemini round-6 returned PLAN-NEEDS-MAJOR with 2 substantive plan-text issues now fixed: (1) §1.1/§1.3 contradiction — monotonic_nanos sampled ONCE per batch commit at the apply-cos-* call site, NOT per packet inside the loop (would have been syscall/VDSO per packet); (2) CoSPendingTxItem is an enum, not struct — sidecar built as Vec<(u16, u64)> in submit_cos_batch BEFORE transmit_batch, sliced by returned sent_packets count.
issue: #1229
phase: design proposal — v6 final-pass; both reviewers explicitly said this fix → PLAN-READY
prerequisites:
  - PR #1217 contract ✓
  - PR #1220 harness ✓
  - PR #1228 ✓
  - #1211 archived
---

## v6 — convergent reviewer fix on F3 (the elegant solution)

Both round-5 reviewers caught the SAME flaw in v5 §F3 and proposed
the SAME fix. Convergent:

**v5's F3 was wrong**: `flow_bucket_flow_count[u16; 4096]` was supposed
to track "how many distinct flows live in this bucket", multiplied
into the cap. But the dataplane has NO per-flow state to distinguish
"first packet of new flow" from "next packet of existing flow".
Increment-on-bucket-empty-to-nonempty would only toggle 0/1.
Multiplicity would never reach 25; bucket cap stuck at 1× per_flow.
At 100K-flow scale → 4096 × (Queue_BW/100K) = **4% utilization**
crash.

**v6 fix (both reviewers)**: drop `flow_bucket_flow_count` entirely.
Use the existing `active_flow_buckets` field (at
`cos/queue_ops/accounting.rs:23/81`, owner-only single-writer that
already correctly tracks bucket-active count via the same
nonempty-transition mechanism) as the cap denominator.

```rust
// v6: cap denominator from existing state. NO new fields needed.
fn bucket_target_bps(queue: &CoSQueueRuntime, fairness: &PerClassFairnessState) -> u64 {
    let queue_bw = queue.config.transmit_rate_bps()
        .max(queue.config.surplus_share_bps());
    let active_buckets = queue.flow_fair_state.active_flow_buckets.max(1);
    queue_bw / active_buckets as u64
}

// In the cap-aware selector:
fn bucket_eligible(state: &FlowFairState, bucket: u16, target_bps: u64) -> bool {
    let b = bucket as usize;
    state.flow_bucket_observed_bps[b] <= target_bps  // direct compare, no multiplicity
}
```

**Math at all scales**:
- 12 flows in 4096 buckets: ~12 active buckets, each gets
  Queue_BW/12. Per-flow ≈ Queue_BW/12 (no collision).
- 100K flows in 4096 buckets: ~4096 active buckets (saturated),
  each gets Queue_BW/4096. Per-flow ≈ Queue_BW/100K via TCP
  cwnd-fairness within buckets (statistical multiplexing).
- 1 flow: 1 active bucket gets full Queue_BW. Work-conserving.

100% utilization at all scales. No 4% crash.

## 1. Codex round-5 minor findings, addressed

### C-MINOR-1: commit-boundary audit (incomplete in v5)

v5 listed `service.rs:320` and `tx_completion.rs:440`. Codex round-5
found more, and Gemini round-6 confirmed the function signatures.
The 4 flow-fair commit paths are:
- `service.rs:320` (Local exact flow-fair direct path)
- `service.rs:658` (Prepared peer commit path)
- `tx_completion.rs:440` (`apply_cos_send_result` — surplus/shared
  batch settle)
- `tx_completion.rs:508` (`apply_cos_prepared_result`)

The FIFO direct paths at `service.rs:160`/`:492` also commit but
have NO bucket state (non-flow-fair). The backup `tx/transmit.rs`
paths are NOT CoS commit boundaries.

**Sidecar mechanism (v7 — Gemini round-6 correction)**:

`CoSPendingTxItem` is an **enum** wrapping `TxRequest` and
`PreparedTxRequest`, not a struct. We can't add `flow_bucket`
directly. v7 picks the cleaner path: **build a `Vec<(u16, u64)>`
sidecar (bucket, bytes) BEFORE `transmit_batch`** in
`submit_cos_batch`, then slice by returned `sent_packets` after the
transmit consumes items in-place.

```rust
// In submit_cos_batch (or its flow-fair equivalent):
let pending_sidecar: Vec<(u16, u64)> = batch.iter()
    .map(|item| (item.flow_bucket(), item.bytes()))
    .collect();

let (sent_packets, sent_bytes) = transmit_batch(/* ... */);

// Apply only the prefix that actually committed.
let now_ns = monotonic_nanos();  // ONCE per batch
let committed = &pending_sidecar[..sent_packets];
for &(bucket, bytes) in committed {
    account_flow_bucket_tx(state, bucket, bytes, now_ns);
}
```

`item.flow_bucket()` lives on the underlying `TxRequest` /
`PreparedTxRequest` (added there as a `u16` field), or computed
on-the-fly from `flow_key` via existing bucket-hash. Either works;
implementation chooses based on per-packet hot-path cost.

(Demote, teardown, restore, retry paths are NOT commit boundaries —
they correctly bypass `settle_*` and skip accounting.)

### C-MINOR-2: flow_bucket_flow_count drop (both reviewers)

v6 drops this field entirely. See above.

### C-MINOR-3: fresh monotonic_nanos sampled ONCE per batch (v7 — Gemini round-6 correction)

v5's `now_ns` came from caller and was re-used across drain loops —
`dt_ns` could stay below threshold across multiple real commit
batches. v6 first proposed sampling `monotonic_nanos()` *inside*
`account_flow_bucket_tx`, but Gemini round-6 caught that this would
be a syscall/VDSO read per packet (millions/sec) — unacceptable
hot-path cost.

**v7 fix**: sample `monotonic_nanos()` **ONCE per batch commit** at
the apply-cos-* call site (just before iterating the committed
sidecar), pass the timestamp into `account_flow_bucket_tx` as an
arg.

```rust
// Per batch commit:
let now_ns = monotonic_nanos();  // sampled ONCE
let committed = &pending_sidecar[..sent_packets];
for &(bucket, bytes) in committed {
    account_flow_bucket_tx(state, bucket, bytes, now_ns);
}

// account_flow_bucket_tx takes now_ns by argument (NOT sampled inside):
fn account_flow_bucket_tx(
    state: &mut FlowFairState,
    bucket: u16,
    bytes: u64,
    now_ns: u64,  // arg, not sampled inside
) {
    // ... EWMA logic from v5 §1.2 ...
}
```

This invariant — "sample time once per batch commit, not per
packet" — must be preserved by reviewers and implementation.

### C-MINOR-4: capped-batch reset contract expanded

```rust
// In addition to v5's reset triggers (eligible service, queue
// empty, config reset, target absent), also reset on:
fn reset_consecutive_capped_batches(queue: &mut CoSQueueRuntime) {
    queue.hot.consecutive_capped_batches = 0;
}

// Triggers:
// - eligible service
// - queue empty / drained
// - config reset
// - target absent (no PerClassFairnessState)
// - NEW v6: target generation/value change (fairness state Arc replaced)
// - NEW v6: shared lease Arc replacement
// - NEW v6: token starvation (lease.acquire fails)
// - NEW v6: V_min throttle activation (existing v_min_suspended)
// - NEW v6: TX-ring no-progress (existing dbg_tx_ring_full counter ticks)
// - NEW v6: build/drop error
```

These additional resets prevent the counter from accumulating
during transient non-cap interruptions, avoiding spurious
release_unused calls.

### C-MINOR-5: EWMA first-packet ramp

Codex flagged that `observed=0` ramps slowly from first sample.
v6 fix: initialize `flow_bucket_observed_bps[b] = inst_bps`
(skip EWMA mix) on the first non-zero sample after creation:

```rust
if smoothed == 0 {
    state.flow_bucket_observed_bps[b] = inst_bps;
} else {
    state.flow_bucket_observed_bps[b] = (smoothed * 7 + inst_bps) / 8;
}
```

## 2. Final v6 design summary

### 2.1 New per-bucket fields on FlowFairState (3, was 5 in v5)

```rust
pub(in crate::afxdp) struct FlowFairState {
    // ... existing ...

    // v6: per-bucket TX accounting (owner-only).
    pub(in crate::afxdp) flow_bucket_tx_bytes: [u64; COS_FLOW_FAIR_BUCKETS],     // monotonic
    pub(in crate::afxdp) flow_bucket_observed_bps: [u64; COS_FLOW_FAIR_BUCKETS], // EWMA
    pub(in crate::afxdp) flow_bucket_last_tx_ns: [u64; COS_FLOW_FAIR_BUCKETS],   // EWMA dt
    pub(in crate::afxdp) flow_bucket_pending_bytes: [u32; COS_FLOW_FAIR_BUCKETS], // sub-100us
    // NOTE: flow_bucket_flow_count DROPPED (v6 reviewer convergence)
}
```

Memory: 4096 × (8+8+8+4) = 112 KB per FlowFairState × ~7 classes
= ~780 KB total (down from v5's 860 KB).

### 2.2 Cap denominator from existing active_flow_buckets

No new shared cross-worker state needed for the per-bucket cap —
each worker reads its OWN `active_flow_buckets` (already
single-writer at accounting.rs:23/81) and divides Queue_BW by it.

The `PerClassFairnessState` cross-worker aggregator (per-worker
active_flow_count array) is still useful for COORDINATION-LEVEL
work (e.g. SharedCoSQueueLease reading total flow counts). v6 keeps
this for the lease's own accounting but does NOT use it for the
per-bucket cap. The per-bucket cap is purely local-worker.

This actually SIMPLIFIES v6 — the cap mechanism is now fully
local-worker, no cross-worker coordination per packet.

### 2.3 Cap-aware selector (v5 §1.4 simplified)

```rust
let target_bps = bucket_target_bps(queue, fairness);  // local read
let (eligible, fallback) = cos_queue_min_eligible_bucket(ff, target_bps);
let selected = eligible.or(fallback);
```

### 2.4 Wire account_flow_bucket_tx to all 4 commit paths

- `service.rs:320` (Local exact flow-fair direct path)
- `service.rs:658` (Prepared peer commit path)
- `tx_completion.rs:440` (`apply_cos_send_result`)
- `tx_completion.rs:508` (`apply_cos_prepared_result`)

Each path collects `Vec<(u16, u64)>` (bucket, bytes) from settle
and iterates inside the post-transmit confirm region.

## 3. Acceptance criteria (unchanged)

- Workload: `iperf3 -c <target> -P 12 -t 90 -p 5205 -R` (no
  `--cport`, no `-b`).
- Pre-mechanism: per-flow CoV ≥ 0.50.
- Post-mechanism: per-flow CoV ≤ Cstruct + 0.10.
- No aggregate regression > 5%.
- 100% utilization at all flow scales (verified by both reviewers'
  proposed math).

## 4. Implementation outline (final)

1. Add 4 new fields to FlowFairState (was 5 in v5; flow_bucket_flow_count dropped).
2. Add `account_flow_bucket_tx` with fresh-sampled monotonic_nanos.
3. Wire into 4 commit paths (audit list above).
4. Cap-aware selector with `bucket_target_bps` from existing
   `active_flow_buckets`.
5. consecutive_capped_batches with expanded reset contract.
6. Conditional release_unused on threshold.
7. cargo build + test.
8. Smoke matrix.
9. Validate on user's iperf3 -P 12 -t 90 -p 5205 -R command.

## 5. v6 risks (consolidated)

- Within-bucket fairness (1 hot + N quiet flows in same bucket)
  relies on TCP cwnd statistical multiplexing. Documented; not a
  structural fix in this iteration.
- EWMA tuning (α=1/8, threshold=100µs) heuristic. Validated by
  smoke; tuned post-hoc if needed.
- Commit-path audit must be COMPLETE; missed path → undercounted
  bytes → cap permissive. v6 §1 enumerates all 4 known paths;
  implementation must verify no others exist.

## 6. Methodology

- v6 plan committed.
- Round-6 dispatch.
- BOTH reviewers explicitly said v6 with this F3 fix → PLAN-READY.
  If they hold to that, implementation begins on round-6.
- If new substantive grounds emerge → address.
- If re-issue of already-addressed → override per operator mandate.
