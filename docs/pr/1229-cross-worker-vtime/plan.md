---
status: REVISED v2 — adopts Gemini round-1 alternative (per-worker local max-min using existing SharedCoSQueueLease + per-worker active_flow_count from #1219) AFTER verifying Gemini's three architectural claims against xpf code. v1's RWND/ArcSwap/single-writer design was wrong; v2 is a cleaner mechanism that leverages existing infrastructure.
issue: #1229 (filed)
phase: design proposal — substantive cross-worker fairness via per-worker max-min + existing shared CoS lease propagation
prerequisites:
  - PR #1217 contract ✓
  - PR #1220 harness ✓ (provides active_flow_count gauge per binding)
  - PR #1228 ✓ (sym key + daemon pin merged on master)
  - #1211 archived (PLAN-KILL)
---

## v2 — adoption of Gemini PLAN-KILL alternative

Gemini round-1 (task-mow2x47y) PLAN-KILL of v1 with three substantive
findings, each verified against the codebase:

1. **Bidirectional flow ≠ single-writer.** `enqueue_tx_owned` at
   `userspace-dp/src/afxdp/tx/dispatch.rs:52` is the cross-binding
   TX handoff. For a TCP flow, data and ACKs traverse different
   bindings → different workers. v1's "single-writer per-flow vtime"
   claim was empirically wrong.
2. **RFC 1122 §4.2.2.16** prohibits mid-stream window shrinkage. F5/A10
   industry technique is SYN-time RWND clamping (window-scale
   negotiation), NOT mid-stream rewriting. v1 cited the wrong RFCs.
3. **ArcSwap<FxHashMap<FiveTuple, …>> O(N) clone-on-insert.**
   At 1M flows × 10K inserts/sec → 400 GB/s memory bandwidth on
   cloning alone. Catastrophic.

Codex round-1 (task-mow2wczw) PLAN-NEEDS-MAJOR converged on the same
fixes plus 5 additional findings: ArcSwap insert race, RTT-from-
conntrack false premise, BindingPlan vs RSS asymmetry, RWND control
sawtooth, window-scale shift-vs-divide bug.

**Operator mandate**: "keep pushing even when others give kill
feedback, they could also be wrong." Both reviewers' grounds checked
against `userspace-dp/src/afxdp/coordinator/cos_state.rs:7,13`,
`tx/dispatch.rs:52`, and RFC 1122 §4.2.2.16. **They are right.** v2
adopts the better alternative.

## 1. v2 design — per-worker local max-min + cross-worker share via existing CoS lease

### 1.1 What's already in xpf (verified)

- **Per-worker active flow count** (PR #1219, master):
  `xpf_userspace_binding_active_flow_count` gauge, refreshed every
  ~65ms at the umem debug-publish tick. Read directly from
  flow_cache state by the owning worker (single-reader, single-
  writer pattern that does work).
- **SharedCoSQueueLease** at
  `userspace-dp/src/afxdp/coordinator/cos_state.rs:7`: per-worker
  per-class lease that enforces total class throughput across
  workers (V_min throttle infrastructure, hardened by #915 #940
  #944).
- **VMinQueueState** at
  `userspace-dp/src/afxdp/cos/builders.rs:142`: per-worker
  per-queue state tracking `consecutive_v_min_skips`,
  `v_min_suspended_remaining`, etc.
- **Per-worker MQFQ** in `tx.rs` with PR #928's
  `max(vtime, served_finish)` semantics — already correct
  byte-fairness within a worker.

### 1.2 The gap

Per-worker MQFQ gives equal BYTES per flow over time within a
worker. At saturation, each flow on Worker A (with 4 flows) gets
worker_capacity / 4. Worker B (with 1 flow) gives that flow
worker_capacity / 1 = 4× more.

To even out, Worker B's flow must be throttled to match Worker A's
per-flow rate. Currently nothing does this.

### 1.3 The fix

**Per-worker max-min cap from a global per-flow target**, computed
from per-worker active flow counts. No ArcSwap map, no RWND, no
RTT estimation, no cross-worker per-packet writes.

```rust
// userspace-dp/src/afxdp/cos/queue_service/service.rs
// (extension to existing MQFQ in the per-class queue service)

// Read by all workers; written by each worker for its own slot.
struct PerClassFairnessState {
    // 6 entries × 4 bytes = 24 bytes = 1 cache line read per batch
    per_worker_active_flows: [AtomicU32; MAX_WORKERS],
    // Sum of all per_worker_active_flows, recomputed at each
    // ~65ms publish tick. No cross-worker writes per packet.
    total_active_flows: AtomicU32,
}

// Each worker, in its TX dispatch hot path:
fn target_per_flow_bps(&self) -> u64 {
    let class_rate = self.shared_cos_lease.current_rate_bps();
    let total_flows = self.fairness.total_active_flows.load(Relaxed);
    if total_flows == 0 { return u64::MAX; }
    class_rate / total_flows as u64
}

// In the MQFQ scheduler when picking the next flow to send:
fn next_flow_under_cap(&self, candidate_flow: FlowKey) -> bool {
    let observed = candidate_flow.observed_bps();  // existing flow-cache state
    observed < self.target_per_flow_bps()
}
```

**Throttle mechanism**: when a flow exceeds the target rate, the MQFQ
scheduler defers it (not drops; not ECN-marks; not RWND). Other
flows on the same worker get scheduled instead. If no other local
flows are eligible, the worker's TX ring gets shorter. The class's
SharedCoSQueueLease redistributes: if Worker B's lonely flow is
throttled, Worker B uses fewer tokens, freeing tokens for Worker A.

This is **work-conserving in the local sense** (Worker B never goes
idle while it has a packet to send below cap) and **non-work-
conserving in the global sense** (the system intentionally caps
total throughput to enforce per-flow fairness).

### 1.4 Cross-worker coordination cost

Per packet (hot path):
- 1 atomic_load of `total_active_flows` (cached, batchable per batch).
- 1 read of own flow's `observed_bps` from local flow_cache state.
- 0 cross-worker writes.

Per ~65ms tick (slow path, owner only):
- For each of 6 workers: store own active flow count to per-class array.
- 1 sum across 6 entries → store to total_active_flows.

Total hot-path cost: ~5 ns per packet for the cap check. No memory
bandwidth concerns. No QPI saturation.

## 2. Acceptance criteria

Same as v1 (and operator mandate):

- **Workload**: `iperf3 -c <target> -P 12 -t 90 -p 5205 -R` (no
  `--cport`, no `-b`).
- **Pre-mechanism baseline**: per-flow CoV ≥ 0.50.
- **Post-mechanism**: per-flow CoV ≤ Cstruct + 0.10.
- **No aggregate regression** > 5% (per the existing fairness contract).
- **Pathological case explicit guard**: when `n_active_workers == 1`
  (single fat flow, others idle), the cap is `class_rate / 1 = full`
  → no throttle. Work-conserving in the single-flow case.

## 3. What v2 does NOT do (compared to v1)

- ❌ No ArcSwap<FxHashMap<FiveTuple, …>> — single fixed-size 24-byte
  cross-worker array.
- ❌ No RWND manipulation — pure dataplane scheduling, no TCP header
  rewrites.
- ❌ No RTT estimation — class_rate / total_flows is enough.
- ❌ No window-scale arithmetic — RWND is gone.
- ❌ No cross-worker shared mutable state per packet — only the
  fixed-size flat array.

## 4. Risks (revised)

- **Convergence speed**: per-worker active_flow_count is sampled at
  ~65ms ticks. New flows take up to 65ms to reflect in the global
  cap. Existing flows are throttled within 1 batch (~10 µs).
  Acceptable.
- **Pathological case: fat flow on idle worker**: Codex/Gemini's
  shared finding. v2 mitigates via the explicit
  `n_active_workers == 1` guard above. If the lonely flow's
  worker has 1 active flow but other workers have multiple, the
  flow is still throttled (intentional — that's the fairness
  goal). The user accepted this trade in the standing mandate
  ("user accepts aggregate regression on degenerate RSS
  distributions").
- **Codex finding #5 — window-scale**: N/A in v2; no RWND.
- **Codex finding #4 — RWND sawtooth**: N/A.
- **Codex finding #2 — RTT premise false**: N/A.
- **Codex finding #1 — ArcSwap insert race**: N/A; no map.

## 5. Why this addresses the operator's hard requirement

- ✓ No `--cport` workload-side knob required.
- ✓ Applies to all flows, all 5-tuples, all RSS distributions.
- ✓ Convergence in ~65ms after flow-table change.
- ✓ Built on existing infrastructure (PR #1219 + SharedCoSQueueLease).
- ✓ No new TCP-level mechanisms; no RFC compliance concerns.
- ✓ No QPI saturation; no clone-on-write storms.

## 6. Implementation outline

Stages:
1. **`PerClassFairnessState` struct** added to per-class state.
   Per-worker active_flow_count slots already exist via #1219;
   wire them into a per-class aggregator.
2. **Cap check in MQFQ scheduler**: extend the per-class queue
   service in `cos/queue_service/service.rs` to defer flows
   exceeding the target rate.
3. **Per-flow observed_bps tracking**: leverage existing flow_cache
   state. Add a field `observed_bps: u64` updated by the owner
   worker on TX completion (single-writer, no contention).
4. **65ms publish tick extension**: at the existing
   `update_binding_debug_state` call site, also update the
   per-class total_active_flows.
5. **Test**: harness validation against the user's exact command.
6. **Smoke**: full CoS-on/off + push/reverse + v4/v6 matrix per
   project standard.

## 7. Open questions for adversarial review (v2)

1. Is `class_rate / total_flows` the right target, or should it be
   `worker_capacity / per_worker_flow_count` (per-worker fair
   share)? The latter is what V_min already enforces; the former
   is what we want for global per-flow fairness. Subtle but
   important.
2. Does the per-class aggregator need to be per (egress_ifindex,
   queue_id) or just per (forwarding_class)? CoS queues can be
   shared across interfaces.
3. What's the right behavior when `class_rate` is configured as
   "transmit-rate exact" vs "transmit-rate"? The exact flag
   changes whether unused tokens are surplus-sharable.
4. How does this interact with PR #1206 / #1216's
   CoSQueueRuntime split? Specifically, the FairnessState would
   live in the ColdState (cross-worker visibility) or the FlowFair
   sub-struct?

## 8. Methodology (v2)

- v2 plan committed.
- Re-dispatch Codex + Gemini with explicit "addresses your prior
  PLAN-KILL/PLAN-NEEDS-MAJOR via the per-worker local max-min
  alternative you yourself suggested".
- If Codex + Gemini both PLAN-READY → implementation phase.
- If Gemini PLAN-KILLs again on grounds we haven't engaged with →
  evaluate; per operator mandate may override.
- v2 incorporates substantive feedback; this is "we listened" not
  "we capitulated". The mandate is to push past WRONG kill verdicts,
  not all kill verdicts.
