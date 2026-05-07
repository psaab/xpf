---
status: REVISED v5 — addresses Codex round-4 (task-mow42hmc, PLAN-NEEDS-MAJOR with 6 findings) AND Gemini round-4 (task-mow432be, PLAN-KILL convergent on the same 3 fatals: pop.rs commit-path mistake, u32 truncation, bucket collision at scale). Each round finds new real bugs and gets closer; v5 incorporates all v4 round-4 feedback.
issue: #1229
phase: design proposal
prerequisites:
  - PR #1217 contract ✓
  - PR #1220 harness ✓
  - PR #1228 ✓
  - #1211 archived
---

## v5 — round-4 fixes (convergent reviewer findings)

Both round-4 reviewers caught three convergent fatal bugs:

### F1 (FATAL): pop.rs is NOT the TX commit boundary

`cos_queue_pop_front` at queue_ops/pop.rs:58 is the SPECULATIVE
batch-build path. If the AF_XDP TX ring rejects the batch (full),
unsubmitted packets restore via `push_front`. v4's monotonic counter
update at pop would double-count restored items.

**v5 fix**: move `account_flow_bucket_tx` to the `settle_*` paths
(specifically `settle_exact_local_scratch_submission_flow_fair` and
its peers — verified in `cos/queue_service/service.rs:320` and
`cos/tx_completion.rs:440`). These run AFTER the TX ring confirms
the prefix accepted; restored items are not accounted.

```rust
// v5: account at the actual commit path
fn settle_flow_fair_submission(/* ... */) {
    // ... existing settle logic ...
    for (bucket, sent_bytes, now_ns) in actually_sent_iter {
        account_flow_bucket_tx(state, bucket, sent_bytes, now_ns);
    }
}
```

### F2 (FATAL): u32 observed_bps truncates above 4.29 Gbps

This cluster has 25 Gbps shaped (iperf-c) and the project supports
100 Gbps NICs. A single hot flow exceeds 4.3 Gbps trivially.

**v5 fix**: `flow_bucket_observed_bps: [u64; COS_FLOW_FAIR_BUCKETS]`.
EWMA arithmetic uses `u128` intermediate.

### F3 (FATAL): bucket collisions at production scale

4096 buckets / 100K flows = ~24 flows per bucket. Per-bucket cap
divided by total_active_flows would permanently throttle every
bucket since each bucket aggregates 24 flows.

**v5 fix**: track per-bucket flow count and scale target
proportionally:

```rust
// New: per-bucket flow count, owner-only.
pub(in crate::afxdp) flow_bucket_flow_count: [u16; COS_FLOW_FAIR_BUCKETS],

// Update on flow-bucket-membership change (existing mechanism in
// flow_fair admission has add/remove). Already tracked elsewhere?
// If not, add an increment on first packet to a bucket and
// decrement on bucket emptying.

// In the cap-aware selector:
fn bucket_eligible(state: &FlowFairState, bucket: u16, target_bps: u64) -> bool {
    let b = bucket as usize;
    let multiplicity = state.flow_bucket_flow_count[b].max(1) as u64;
    let bucket_target = target_bps.saturating_mul(multiplicity);
    state.flow_bucket_observed_bps[b] <= bucket_target
}
```

A bucket holding `k` flows is allowed `k × target_bps` aggregate
throughput. With 4096 buckets and 12 flows, multiplicity ≈ 1
(occasional 2). With 100K flows and 4096 buckets, multiplicity
~25 → bucket gets 25× per-flow share. **Mathematically equivalent
to per-flow fairness when the bucket-internal flows are
fairness-equal**, which is the property we want at saturation.

(Within-bucket fairness — when one flow is hot and 23 are quiet —
isn't perfectly enforced by this scheme. Documented as known
limitation; in practice TCP cwnd-fairness within a bucket works
because all flows share the same vtime.)

### Round-4 minor findings, addressed in §1-§5 below

C-MINOR-3 (target snapshot through batch): pass single target_rate
read at batch-build start through the loop, not re-read.

C-MINOR-4 (Arc plumbing path): use worker_loop arg pattern from
V_min floors at worker/cos.rs:113 + admission.rs:490, not direct
from builders.rs.

C-MINOR-5 (skip None queue_id): `tx_selection.queue_id` is
`Option<u8>`. Skip None entries when computing per-queue count.

C-MINOR-6 (capped-batch counter): explicit home in
`CoSQueueHotState`, single-writer (owner). Reset on: successful
eligible service, queue empty, config reset, target absent.

G-MINOR-EWMA (timestamp microspike): when `dt_ns` < some threshold
(e.g. 100 µs), accumulate into a pending bucket; only roll EWMA
when dt_ns crosses threshold. Prevents back-to-back packet bursts
from injecting 100+ Gbps spikes.

## 1. Final design summary (v5 consolidated)

### 1.1 New per-bucket fields on FlowFairState

```rust
pub(in crate::afxdp) struct FlowFairState {
    // ... existing ...

    // v5: per-bucket TX accounting (owner-only, cache line aligned).
    pub(in crate::afxdp) flow_bucket_tx_bytes: [u64; COS_FLOW_FAIR_BUCKETS],     // monotonic
    pub(in crate::afxdp) flow_bucket_observed_bps: [u64; COS_FLOW_FAIR_BUCKETS], // EWMA
    pub(in crate::afxdp) flow_bucket_last_tx_ns: [u64; COS_FLOW_FAIR_BUCKETS],   // last commit ts
    pub(in crate::afxdp) flow_bucket_pending_bytes: [u32; COS_FLOW_FAIR_BUCKETS], // sub-100us accumulator
    pub(in crate::afxdp) flow_bucket_flow_count: [u16; COS_FLOW_FAIR_BUCKETS],   // multiplicity
}
```

Memory: 4096 × (8+8+8+4+2) = 122 KB per FlowFairState. Allocated
per per-(egress_ifindex, queue_id) FlowFair, which is per-CoS-class.
For typical 7-class config, total ~860 KB. Acceptable.

### 1.2 Threshold-gated EWMA at settle (v5 F1+F2+G-MINOR-EWMA)

```rust
const EWMA_MIN_DT_NS: u64 = 100_000;  // 100 µs minimum for rate sample

fn account_flow_bucket_tx(
    state: &mut FlowFairState,
    bucket: u16,
    bytes: u64,
    now_ns: u64,
) {
    let b = bucket as usize;
    state.flow_bucket_tx_bytes[b] = state.flow_bucket_tx_bytes[b]
        .wrapping_add(bytes);
    let last_ns = state.flow_bucket_last_tx_ns[b];
    let pending = state.flow_bucket_pending_bytes[b] as u64;
    let total = pending + bytes;

    if last_ns == 0 {
        // First packet, just stamp.
        state.flow_bucket_last_tx_ns[b] = now_ns;
        state.flow_bucket_pending_bytes[b] = 0;
        return;
    }

    let dt_ns = now_ns.saturating_sub(last_ns);
    if dt_ns < EWMA_MIN_DT_NS {
        // Accumulate, defer EWMA roll.
        state.flow_bucket_pending_bytes[b] = total as u32;
        return;
    }

    let inst_bps = ((total as u128) * 8 * 1_000_000_000 / dt_ns as u128) as u64;
    let smoothed = state.flow_bucket_observed_bps[b];
    state.flow_bucket_observed_bps[b] = (smoothed * 7 + inst_bps) / 8;
    state.flow_bucket_last_tx_ns[b] = now_ns;
    state.flow_bucket_pending_bytes[b] = 0;
}
```

### 1.3 Collision-aware cap (v5 F3)

`bucket_eligible` (above) multiplies target by bucket flow count.
A bucket with 25 flows gets 25× per-flow target — correctly scaling
the cap with the aggregation level.

`flow_bucket_flow_count[b]` is incremented when a flow is first
inserted into bucket b (i.e. on first-packet-in-bucket via the
existing flow-fair admission path) and decremented on bucket
emptying. Single-writer, owner only.

### 1.4 Cap-aware selector with batch-stable target (v5 C-MINOR-3)

```rust
// At the start of each batch-build, snapshot the target.
let target_bps = compute_target_bps_from_per_class_fairness(...);

// Front and pop both call:
let (eligible, fallback) = cos_queue_min_eligible_bucket_with_target(ff, target_bps);
let selected = eligible.or(fallback);
```

Single read of fairness state per batch. Both selector calls use
the same target_bps. No race.

### 1.5 Arc<PerClassFairnessState> plumbing (v5 C-MINOR-4)

Following V_min floor pattern at admission.rs:490:

```
coordinator/cos_state.rs (Arc + ArcSwap map)
  → worker_loop arg (in BindingWorker.run)
    → build_worker_cos_fast_interfaces (worker/cos.rs:113)
      → WorkerCoSQueueFastPath.shared_fairness
        → at queue admission (cos/admission.rs:490): copy Arc
          into runtime CoSQueueConfigState.shared_fairness
```

### 1.6 Per-queue active flow count, skipping None (v5 C-MINOR-5)

```rust
pub(super) fn count_active_flows_per_queue(&self) -> BTreeMap<(i32, u8), u32> {
    let mut counts = BTreeMap::new();
    let now = self.current_epoch;
    for slot in self.entries.iter() {
        if let Some(entry) = slot {
            if entry.last_used_epoch == 0 { continue; }
            let age = now.wrapping_sub(entry.last_used_epoch);
            if age >= ACTIVE_WINDOW_EPOCHS { continue; }
            let queue_id = match entry.descriptor.tx_selection.queue_id {
                Some(q) => q,
                None => continue,  // non-CoS egress, no per-queue
            };
            *counts.entry((entry.descriptor.egress_ifindex, queue_id))
                .or_insert(0) += 1;
        }
    }
    counts
}
```

### 1.7 Capped-batch counter and conditional release (v5 C-MINOR-6)

```rust
pub(in crate::afxdp) struct CoSQueueHotState {
    // ... existing ...
    /// v5: counter of consecutive batches where eligible=None
    /// (all buckets over-cap). Used to trigger conditional
    /// release_local_tokens. Owner-only, single-writer, race-free.
    pub(in crate::afxdp) consecutive_capped_batches: u32,
}

// At end of each pop attempt:
if eligible.is_none() && !queue_empty {
    queue.hot.consecutive_capped_batches = queue.hot
        .consecutive_capped_batches.saturating_add(1);
    if queue.hot.consecutive_capped_batches >= CAPPED_RELEASE_THRESHOLD {
        // Use existing release_unused mechanism
        queue.hot.consecutive_capped_batches = 0;
        shared_lease.release_unused(local_tokens_to_drain);
    }
} else {
    queue.hot.consecutive_capped_batches = 0;
}
```

`CAPPED_RELEASE_THRESHOLD = 10` batches ≈ 1 ms at typical poll
rate. Tunable.

## 2. Acceptance criteria (unchanged)

- Workload: `iperf3 -c <target> -P 12 -t 90 -p 5205 -R` (no `--cport`,
  no `-b`).
- Pre-mechanism: per-flow CoV ≥ 0.50.
- Post-mechanism: per-flow CoV ≤ Cstruct + 0.10.
- No aggregate regression > 5%.
- Per-bucket flow count tracking: at iperf3 -P 12 scale, multiplicity
  ≈ 1 (occasional 2). At 100K-flow scale, multiplicity ~25, scheme
  delivers per-flow-equal-aggregate fairness.

## 3. v5 risks (consolidated)

| Risk | Mitigation |
|------|------------|
| settle_* path coverage incomplete (e.g. demote/teardown skip accounting) | Audit all callers; verify monotonic counter only updates on actual TX commit |
| flow_bucket_pending_bytes overflow (u32 = 4 GB) at ultra-high rates | EWMA_MIN_DT_NS = 100 µs caps pending growth at ~100 µs × 25 Gbps = 312 KB. Safe. |
| per-bucket flow_count tracking adds maintenance burden | Single-writer extension to existing flow-fair admission path |
| Within-bucket fairness asymmetry (1 hot + 23 quiet flows in same bucket) | Documented; TCP cwnd usually equalizes |

## 4. v5 implementation outline

1. Add 5 new fields to FlowFairState (122 KB / instance).
2. Add account_flow_bucket_tx with threshold-gated EWMA.
3. Wire account_flow_bucket_tx into all settle_* commit paths
   (audit list TBD during implementation).
4. Add PerClassFairnessState; plumb via V_min pattern.
5. count_active_flows_per_queue extension with None skip.
6. Cap-aware selector with batch-stable target.
7. consecutive_capped_batches counter in CoSQueueHotState.
8. Conditional release_unused on threshold.
9. Cargo build + test.
10. Smoke matrix.

## 5. Methodology

- v5 plan committed.
- Round-5 dispatch.
- If both PLAN-READY → implementation.
- If MINOR → iterate v6 quickly.
- If a NEW substantive PLAN-KILL ground emerges → address.
- If PLAN-KILL on re-issued already-addressed points → override.
