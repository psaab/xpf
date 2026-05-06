---
status: DRAFT v1 — pending adversarial plan review
issue: #1215
phase: design route + race-safety analysis; no code
prerequisites:
  - #1206 (CoSQueueRuntime split) merged as a1688792 — DONE
---

## 1. Issue framing

User mandate (this session, verbatim):

> Each TCP flow = `(dip, dport, sip, sport, proto)`. Each one of these
> flows which may happen to fall on **distinct RSS queues** or even
> **multiple flows on the same RSS queue** — each flow does not consume
> more than any other flow.

User accepts aggregate throughput regression on degenerate RSS
distributions (1+3 example: aggregate may drop ~33%).

Today's measurement (this session): **47% per-flow CoV on iperf-c P=12
t=10 -R**. #789 gate: ≤20%. The gap is structural per Codex
retrospective: "structural limit of per-worker fair queueing under
RSS-skewed flow placement". V_min sweep (this session) showed knob
tuning is dispositive-negative; current defaults near-optimal at 25-29%
floor. New mechanism needed.

## 2. Honest scope/value framing

**Architectural change.** Adds cross-worker shared per-flow state and a
scheduler-stall mechanism. The aggregate regression is NOT a bug — it's
the explicit price of equalizing per-flow rates across RSS-skewed
worker placement.

Value: closes the #789 gate for TCP traffic, achieves the user's
explicit per-5-tuple fairness goal.

Cost:
- ~33% aggregate regression on degenerate RSS distributions like
  {6,0,0,0,0,6} (1 worker has 6 flows, another has 6 flows, others
  have 0)
- Hot-path adds 1 atomic load + 1 atomic store per pop on shared_exact
  queues
- ~32 KB per shared_exact queue × #queues × ifaces (across workers'
  per-bucket slots — bounded)

**If reviewers conclude the per-flow fairness goal cannot be met
without unacceptable race exposure (the #836/#838 trap), PLAN-KILL is
acceptable. Path 2 (#937 ingress XDP_REDIRECT) and Path 3
(workload-aware gate) remain as alternatives.**

## 3. Prior-art digest (read first)

This plan WILL FAIL plan-review if it proposes patterns already
PLAN-KILLed. Three prior attempts in this codebase, summarized in
the tracker:

- **#836** shared MQFQ HOL-finish-time array — PLAN-KILLed because
  HOL-finish-time is non-commutative under concurrent writers
  (per-packet timestamp; rollback needs snapshot).
- **#838** AFD-lite per-flow bytes-served counter — 5 plan rounds,
  4 race surfaces uncovered: period reset coherence, fair-share
  denominator staleness, rollback semantics, batch-latency
  (selector per-packet, accounting per-batch-settle).
- **#840** RSS rebalance from per-binding RX signal — IMPLEMENTED
  AND REVERTED. Made fairness WORSE: CoV 37.7% with vs 18.5%
  baseline.

This plan must NOT replicate #836 (no shared HOL-finish-time write).
Must NOT replicate #840 (no RSS-hash steering). Must explicitly
answer each of #838's 4 race surfaces.

## 4. Design

### 4.1 Mechanism: per-worker per-bucket served-bytes table + cross-worker stall

Add a per-shared-exact-queue Arc:

```rust
// userspace-dp/src/afxdp/cos/shared_flow_table.rs (new file)
#[repr(C, align(64))] // cache-line aligned per slot
pub(in crate::afxdp) struct SharedFlowSlot {
    // Single-writer (the worker owning this slot). Cross-worker
    // readers via Relaxed loads. Each slot is its own cache line
    // to avoid false sharing.
    served_bytes: AtomicU64,
    _pad: [u8; 56],
}

pub(in crate::afxdp) struct SharedFlowTable {
    /// Per-(worker, flow_bucket) served-bytes counter.
    /// Layout: slots[worker_id * COS_FLOW_FAIR_BUCKETS + bucket].
    /// Single-writer per slot (the worker owning that worker_id),
    /// many cross-worker readers via `peer_served_bytes` query.
    pub(in crate::afxdp) slots: Box<[SharedFlowSlot]>,
    /// Number of workers participating in this queue. Set at
    /// construction; immutable.
    pub(in crate::afxdp) num_workers: u32,
    /// Cross-worker shared `flow_hash_seed`. Set once at queue
    /// construction by coordinator (NOT per-runtime — that was
    /// the bug that killed #936 v1). All workers servicing this
    /// queue use the same seed so the same 5-tuple maps to the
    /// same bucket on every worker.
    pub(in crate::afxdp) shared_flow_hash_seed: u64,
}
```

Hook into `FlowFairState`:

```rust
pub(in crate::afxdp) struct FlowFairState {
    // ... (existing fields)
    /// #1215 — Arc to the queue's cross-worker per-flow served-bytes
    /// table. None on owner-local queues; Some on shared_exact.
    /// Single Arc owned by every worker servicing this queue;
    /// allocated by coordinator at queue construction time alongside
    /// `vtime_floor`.
    pub(in crate::afxdp) shared_flow_table: Option<Arc<SharedFlowTable>>,
}
```

Replace `flow_hash_seed: u64` field on FlowFairState with a method
that pulls from `shared_flow_table.shared_flow_hash_seed` if
shared_exact, else uses a per-runtime seed.

### 4.2 Hot path: write own slot on pop

In `cos_queue_pop_front_inner` after the existing `served_finish` /
`queue_vtime` advance:

```rust
if let Some(table) = ff.shared_flow_table.as_ref() {
    let bucket = bucket_u16 as usize;
    let slot_idx = (queue.v_min.worker_id as usize) * COS_FLOW_FAIR_BUCKETS + bucket;
    let slot = &table.slots[slot_idx];
    // Single-writer: this worker owns this slot. fetch_add is
    // ABA-safe (monotonic counter), commutative under
    // single-writer (we're the only writer to this slot).
    slot.served_bytes.fetch_add(item_len_u64, Ordering::Relaxed);
}
```

The `fetch_add` is the **commutative quantity** — a per-(worker, bucket)
served-bytes counter that monotonically increases. Reorderings within
a single writer are irrelevant; cross-worker reads see eventually-
consistent values. **No rollback** because the bytes were actually
served (push_front on submit failure means the bytes were attempted to
send; for AFD purposes, "attempted to send" is the right signal —
TCP-level retransmits fall out of the receiver-side loss).

### 4.3 Hot path: read peers + decide stall

In `cos_queue_v_min_continue` (the existing throttle decision), extend
to also consider **per-flow** lag:

```rust
fn cos_queue_v_min_continue_per_flow(queue: &CoSQueueRuntime, bucket: u16) -> bool {
    let Some(ff) = queue.flow_fair_state.as_ref() else {
        return true;
    };
    let Some(table) = ff.shared_flow_table.as_ref() else {
        return true;  // no shared table → no per-flow stall (owner-local)
    };
    let my_worker = queue.v_min.worker_id as usize;
    let bucket = bucket as usize;
    let my_slot_idx = my_worker * COS_FLOW_FAIR_BUCKETS + bucket;
    let my_served = table.slots[my_slot_idx].served_bytes.load(Ordering::Relaxed);

    // Compute slowest peer's served-bytes for this same bucket.
    // Snapshot semantics: each load is independent; we accept
    // skew across slots (same tolerance as participating_v_min_snapshot).
    let mut min_peer = u64::MAX;
    let mut peer_count = 0u32;
    for w in 0..table.num_workers as usize {
        if w == my_worker { continue; }
        let slot_idx = w * COS_FLOW_FAIR_BUCKETS + bucket;
        let peer = table.slots[slot_idx].served_bytes.load(Ordering::Relaxed);
        // Skip peers with 0 bytes served on this bucket (they don't
        // have this flow / haven't yet seen it). NOT a peer for
        // fairness purposes.
        if peer == 0 { continue; }
        peer_count += 1;
        if peer < min_peer { min_peer = peer; }
    }
    if peer_count == 0 {
        return true;  // no peers serving this flow → owner-local-fair
    }

    // Per-flow lag threshold: same construction as V_min lag
    // (per_worker_rate × 1ms), tunable via const.
    const PER_FLOW_LAG_NS: u64 = 1_000_000;
    let per_worker_rate = queue.transmit_rate_bytes() / table.num_workers as u64;
    let lag_threshold_bytes = (per_worker_rate.saturating_mul(PER_FLOW_LAG_NS)) / 1_000_000_000;

    // If we're more than `lag_threshold_bytes` ahead of the slowest
    // peer on this bucket, stall — let peers catch up so this flow's
    // total send rate (sum across workers) stays equal to other flows.
    my_served.saturating_sub(min_peer) <= lag_threshold_bytes
}
```

### 4.4 Race-safety analysis (addresses #838's 4 surfaces)

**Surface 1 — period reset coherence.** This plan has NO PERIOD
RESET. Counters are monotonic across the runtime lifetime; on HA
failover the queue is torn down and rebuilt with fresh counters.
**Resolved by design**: there is no period.

**Surface 2 — fair-share denominator staleness.** This plan does NOT
USE A FAIR-SHARE DENOMINATOR. The decision is binary per-flow
(stall if lag > threshold, else proceed). No `fair_share = bandwidth
/ N` computation; no N variable. **Resolved by design**.

**Surface 3 — rollback semantics.** push_front on submit failure
DOES NOT roll back the served-bytes counter. Rationale: the bytes
WERE attempted to send (frames went into UMEM, may have hit NIC
already). For AFD/fairness purposes, "served" is the right signal
because peer workers are also using "served". TCP-level loss
(actual not-on-wire) feeds back via retransmits naturally. **The
counter is monotonic AT THE WORKER, period.**

This is the critical departure from #838. #838 wanted byte-
counters that could roll back on rejection; that's where the race
came in. We accept that submit-failure bytes are still counted —
this is fine because all workers do it the same way.

**Surface 4 — batch-latency mismatch.** The selector decision
(`cos_queue_v_min_continue_per_flow`) runs per-pop, not per-batch-
settle. The fetch_add is also per-pop. **Both are per-packet, so
no latency mismatch**. The only batching is at the TX-ring submit
level, which doesn't change the served-bytes accounting (per
Surface 3).

### 4.5 HA failover

On role flip (primary → secondary or vice versa):

- The local worker drops its CoSQueueRuntime; the new role's worker
  builds a fresh one with `served_bytes = 0` on every slot.
- No `saturating_sub` underflow risk (per the PR #1203 Phase 2
  retro that killed that approach) because we never compute
  byte-rate diffs from old vs new values; we only compute
  `my_served - min_peer` for stall, and on a fresh queue both are
  zero so the diff is zero (no stall).
- The shared Arc is dropped when the queue is torn down; new role
  allocates a new SharedFlowTable.

### 4.6 Cross-worker hash seed

This is the v1 of #936 lesson learned. **The shared seed is
allocated by the coordinator at queue-construction time and stored
in `SharedFlowTable.shared_flow_hash_seed`**, NOT in per-runtime
FlowFairState. All workers servicing the queue read from the same
Arc, so the same 5-tuple maps to the same bucket on every worker.

The existing per-runtime `flow_hash_seed` field on FlowFairState is
preserved for owner-local queues (where there's no cross-worker
fairness need). On shared_exact queues, FlowFairState's seed is
replaced by table-side delegation:

```rust
impl FlowFairState {
    pub(in crate::afxdp) fn flow_hash_seed(&self) -> u64 {
        match self.shared_flow_table.as_ref() {
            Some(table) => table.shared_flow_hash_seed,
            None => self.local_flow_hash_seed,
        }
    }
}
```

### 4.7 Memory layout

8 workers × 4096 buckets × 64 bytes (cache-line padded slot) =
**2 MB per shared_exact queue**. With 8 queues × 2 ifaces ≈ 32 MB
total per cluster node for the shared tables. This is on top of the
per-queue FlowFairState (~232 KB). Acceptable on production hosts.

If 32 MB is judged too high, alternative: drop padding (1 atomic per
slot = 8 bytes), accept false-sharing risk. 8 × 4096 × 8 = 256 KB
per queue, 4 MB total. PLAN-REVIEW question: is the false-sharing
cost worse than the memory cost?

## 5. Public API preservation

- `CoSQueueRuntime` shape preserved (post-#1206).
- New `SharedFlowTable` type (private to `cos::shared_flow_table`).
- Change to `FlowFairState`: add `shared_flow_table:
  Option<Arc<SharedFlowTable>>`. The existing `flow_hash_seed: u64`
  field stays on FlowFairState (now `local_flow_hash_seed`); a new
  helper method `flow_hash_seed(&self)` delegates to the table when
  present.

## 6. Hidden invariants the change must preserve

- MQFQ vtime semantics on owner-local queues (unchanged path).
- V_min cross-worker queue_vtime sync (#917) — orthogonal to this
  plan; no change.
- HA failover saturating_sub discipline — see §4.5.
- The flow_fair() ↔ flow_fair_state.is_some() invariant from #1206
  — preserved; this plan only adds an optional Arc field on
  FlowFairState.
- shared_exact() ↔ vtime_floor.is_some() ↔
  shared_flow_table.is_some() — three-way invariant. Allocated
  together at promotion; guarded by the same `if shared_exact`
  branch.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression on FIFO / owner-local queues | NONE | Code path unchanged for those queues |
| Behavioral regression on shared_exact aggregate | EXPECTED | The trade-off the user accepted |
| Hot-path perf cost | MED | 1 atomic load + 1 atomic store per pop on shared_exact; per-bucket peer scan in v_min_continue |
| Race-safety on shared atomics | LOW | Single-writer slots, monotonic fetch_add, no rollback, no period reset |
| HA failover semantics | LOW | Fresh SharedFlowTable on role flip; no carry-over arithmetic |
| Memory pressure (32 MB) | MED | May need to drop cache-line padding for budget reasons |

## 8. Test plan

- `cargo build --release` clean
- `cargo test --release` passes existing 977
- New unit tests for SharedFlowTable construction + slot writes +
  cross-worker reads
- New behavior test: `iperf3 -P 12 -t 60 -R` on iperf-c, simulate
  RSS-skewed placement (single-source iperf concentrates on one
  worker via 5-tuple → RSS hash → single binding). Measure per-flow
  CoV.
- 5×flake on `cos::shared_flow_table::tests::*`
- Smoke matrix on loss userspace cluster:
  - Pass A (CoS off) — connectivity + 12-stream `-R` line rate
  - Pass B (CoS on) — 24 cells per-class
  - **Acceptance**: iperf-c P=12 t=120 -R 5-rep mean per-flow CoV
    ≤20% (the #789 gate)
  - **Aggregate gate**: iperf-c aggregate ≥18 Gbps (allowed
    regression from 22-23 to 18 = ~22% under pessimistic skew).
    iperf-d (non-saturated) within ±2pp of pre-PR.
- `make test-failover` — clean

## 9. Out of scope

- ECN-overlay (AFD/CSFQ) marking — separate effort #1211. This plan
  uses STALL not ECN. ECN is a complement to (not replacement for)
  per-flow fairness work; it requires sender response.
- Ingress XDP_REDIRECT (#937) — orthogonal architectural lever.
- Per-flow telemetry (operator-facing per-bucket stall counters,
  CoV gauge) — follow-up; #1209 telemetry double-buffer is a
  natural surface to thread it through.
- Owner-local queues — unchanged.

## 10. Open questions for adversarial review

1. **Surface 5: snapshot skew.** §4.3's peer-scan reads each
   `served_bytes` slot independently with `Relaxed`. A worker may
   read peer A's value at time T, peer B's at T + Δ. The decision
   uses the minimum across peers. Worst-case: all peers were
   simultaneously updating, and the read sees a stale-low value
   for one peer → over-estimates lag → over-stalls this worker.
   Bounded by the lag_threshold cushion. Is this acceptable?

2. **Surface 6: starvation under asymmetric peer drain rates.**
   If peer A is genuinely slower (NIC-side issue, kernel preemption),
   `min_peer` will track A's slow rate. This worker stalls to match,
   even though A's slowness is environmental, not fairness-induced.
   Result: this flow's aggregate suffers because of an unrelated
   problem on a peer worker. Is this acceptable, or do we need a
   "active peer" gate (only stall against peers that are actively
   draining)?

3. **Memory budget.** Is 32 MB per cluster node acceptable, or do
   we need to drop the cache-line padding (4 MB total but with
   false-sharing risk)?

4. **Per-flow lag threshold tuning.** §4.3's `PER_FLOW_LAG_NS =
   1_000_000` is the same as V_min's threshold. Is this correct
   for per-flow signals, or does per-flow want a different
   constant?

5. **Saturated-vs-not behavior.** The disposition doc shows
   non-saturated workloads (iperf-d) already pass at 16% CoV.
   The stall mechanism activates only on per-flow lag > threshold,
   which non-saturated workloads should rarely hit. But if it
   activates spuriously due to TCP cwnd jitter, we add latency for
   no fairness benefit. Mitigation: check `peer_count > 0` before
   stalling — done. Is there a need for a saturation-detect gate?

6. **Test fixture for RSS-skewed measurement.** Single iperf3
   instance hashes to one worker. To force the 1+3 case we need
   either source-port-varying iperf or an artificial workload
   generator. PLAN-REVIEW question: how do we measure cross-worker
   per-flow fairness reproducibly without controlling RSS hash?

## 11. Verdict request

PLAN-READY → execute (single PR, single feature commit + tests).
PLAN-NEEDS-MINOR → tighten field names / lag threshold / memory
layout choice.
PLAN-NEEDS-MAJOR → rework on a different design route (e.g.,
message-passing through coordinator instead of cross-worker shared
table; or pivot to ECN-overlay).
PLAN-KILL → prior-art constraints make this approach unworkable.
Acceptable verdicts: this plan has structural risks (Surfaces 5+6);
PLAN-KILL is reasonable if reviewers conclude they can't be bounded.
