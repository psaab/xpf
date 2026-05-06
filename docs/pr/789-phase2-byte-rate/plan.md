---
status: DRAFT v1 — pending adversarial plan review
issue: #789 (parent), Phase 2 of mlx5 ntuple closed-loop steering
phase: layered on top of Phase 1 (PR #1203 draft); adds byte-rate-aware candidate selection
---

## 1. Issue framing

Phase 1 (PR #1203, branch `refactor/789-fairness-via-ntuple`) shipped
the closed-loop mechanism: 1 Hz reconcile, mlx5 detection, sticky
placement, ntuple install/eviction, 23 unit tests, 6 Prometheus
counters, CLI knob + show command. Empirical result on iperf-c P=12
t=30 -R: **55% mean CoV** (master 62.5%, gate ≤ 20%) and on
iperf-d P=12 t=30 push: **49% CoV**. Mechanism flattens the per-queue
*flow count* but doesn't drive per-flow CoV down to gate.

Plan v6 §4.3 explicitly deferred byte-rate-aware candidate selection
to Phase 2 because the obvious implementation adds a per-packet
cache-line write to the worker hot path. This plan addresses that
deferral.

## 2. Honest scope/value framing

The remaining gap is structural. With 12 long-lived TCP flows over
6 NIC queues, the controller correctly drives each queue to 2 flows.
But:

- TCP fairness on a shared queue is bounded by cwnd convergence speed.
  A 30-second test averages over the cwnd-equalization window, which
  is meaningfully different from the per-flow steady state.
- Sticky placement means a "heavy" flow that lands on a queue with
  another heavy flow stays there. The controller has no signal to
  prefer migrating elephants over mice.
- iperf-d (port 5204) shape rate 13 Gb/s, ideal per-flow 1.083 Gb/s.
  Observed range: 0.55-1.90 Gb/s (3.5× spread). If we knew which
  flows were the elephants we could put exactly one elephant per
  queue; the rest would split each queue's residual bandwidth.

**If reviewers conclude the per-packet cache-line write isn't worth
the residual CoV improvement, PLAN-KILL is an acceptable verdict.**

## 3. What's already shipped

Phase 1 (commit `979482df` on `refactor/789-fairness-via-ntuple`):

- `SessionEntry { installed_on_binding_slot, installed_at_ns }`
- `SessionTable.current_binding_slot` ambient state
- `SessionTable::ingress_active_flows_for_binding(slot, now_ns,
  recency_window_ns) -> ActiveFlowInventory`
- `BindingLiveState { active_ingress_flows_count,
  active_ingress_flows_sample }` with 1 Hz publish gate at
  `worker/mod.rs` (sibling to the `COS_STATUS_INTERVAL_NS` gate)
- `BindingStatus { active_ingress_flows_count,
  active_ingress_flows_sample: Vec<ActiveFlowSampleStatus> }`
- `ActiveFlowSampleStatus { wire_5tuple, install_age_secs,
  last_seen_age_ms }`
- Go controller in `pkg/dataplane/userspace/flow_steering.go`:
  - sticky placement
  - 30-tick stale-rule eviction
  - K=4 per tick
  - bottom-K destination round-robin
  - tcp4 + tcp6 install, auto-allocated rule slot
- 23 unit tests (closed-loop bug regression + selection + parsing)

## 4. Concrete design

### 4.1 Per-session byte counter (Rust hot path)

Add to `SessionEntry`:

```rust
pub(crate) struct SessionEntry {
    // existing fields ...
    installed_at_ns: u64,
    installed_on_binding_slot: u32,
    // Phase 2: per-flow byte counter for elephant detection.
    // Incremented on every packet by the worker poll path
    // (xdp_conntrack tail-call equivalent in userspace-dp).
    // u64 wraparound at line rate ~37 years; safe.
    bytes_total: u64,
}
```

Write site: in the worker poll path where `last_seen_ns` is updated.
Search points by issue plan-review: `session/mod.rs` lookup paths
already touch the entry for `last_seen_ns` refresh — the cache line
is hot. Adding `entry.bytes_total += packet_len` is one extra
write to the same cache line.

**Cost analysis:**
- Same cache line as `last_seen_ns` (hot path already pays for it).
- One additional u64 write per packet.
- At 14.8M pps (line rate) the additional cost is ~3 cycles/packet
  (single store buffered). Total CPU: ~3 cycles × 14.8M = 44M cy/sec
  per worker = ~1.5% of one core at 3 GHz. Per-worker cost; on a
  6-worker setup the aggregate is ~9% of one core's worth.
- **This is the cost the deferral was about.** Reviewers must weigh
  it against the residual CoV improvement Phase 2 delivers.

### 4.2 Byte-rate computation in `ingress_active_flows_for_binding`

Currently the method returns count + sample with `(install_age_secs,
last_seen_age_ms)`. Phase 2 extends `ActiveFlowSample` with:

```rust
pub(crate) struct ActiveFlowSample {
    pub(crate) key: SessionKey,
    pub(crate) installed_at_ns: u64,
    pub(crate) last_seen_ns: u64,
    // Phase 2:
    pub(crate) bytes_total: u64,
}
```

The worker publishes the snapshot at 1 Hz. The controller computes
byte rate by diffing successive snapshots:

```
rate_bps_t = (bytes_total_t - bytes_total_{t-1}) * 8 / dt_ns * 1e9
```

This is computed in the Go controller, NOT the worker — keeps the
hot-path cost to one u64 write. Diffing happens on the 1 Hz reconcile
tick, no impact on packet path.

### 4.3 Controller changes

Extend `ActiveFlowSampleStatus`:

```go
type ActiveFlowSampleStatus struct {
    Wire5Tuple     string
    InstallAgeSecs uint32
    LastSeenAgeMs  uint32
    BytesTotal     uint64  // Phase 2
}
```

Controller maintains `prevBytesByFlow map[flowKey]uint64` and
computes per-flow byte rate at each tick. Selection algorithm:

```go
// Phase 2 candidate selection: prefer elephants.
// 1. Filter by stable-flow gate (install_age >= 3s, last_seen < 1s)
// 2. Filter out already-steered (sticky placement)
// 3. Sort by byte_rate DESC (elephants first)
// 4. Pick top-K
```

Heuristic: an "elephant" is a flow whose byte rate over the previous
1 Hz window exceeds `mean_rate × elephantThreshold` where
elephantThreshold defaults to 1.5. Configurable via CLI knob:

```
set system services userspace-dp flow-steering elephant-threshold 1.5
```

### 4.4 Destination selection refinement

Current Phase 1 picks bottom-K least-loaded queues by COUNT. Phase 2
extends to pick bottom-K by BYTE RATE so we don't pile a new elephant
onto a queue that already has a quiet elephant.

```go
// Per-queue byte rate (sum of all flows on that queue from sample).
// Pick bottom-K queues by byte rate.
```

### 4.5 Risk: rule-table churn

Phase 1 sticky placement was the right call for stability. Phase 2
keeps it sticky. The byte-rate change is read-only on the steering
side; we still don't move a flow once it has a rule. The signal
just helps us pick the right flow to install in the first place.

### 4.6 Observability

Extend `show class-of-service flow-steering` with per-flow byte rates
on the rules table:

```
Recent re-steer events:
  HH:MM:SS  iface=ge-0-0-1  loc=1023  q=3  flow="tcp ..." rate=1.85Gb/s reason=elephant
```

New Prometheus counters:
- `xpf_userspace_flow_steering_elephant_count` — number of flows
  currently classified as elephants
- `xpf_userspace_flow_steering_elephant_threshold_breaches_total`
  — counter incremented each tick a flow crosses the threshold

## 5. Public API preservation

- New optional CLI knob (default 1.5).
- Extended `ActiveFlowSampleStatus` field (additive, JSON `omitempty`).
- New Prometheus counters.
- No breaking changes.

## 6. Hidden invariants the change must preserve

- **Worker hot path correctness.** `entry.bytes_total += pkt_len`
  must not introduce a race. Workers are single-threaded per session
  table; no atomicity required.
- **Snapshot consistency.** When the worker takes the 1 Hz snapshot,
  bytes_total may be observed mid-update. Acceptable: byte rate is a
  rate, single-packet skew is noise.
- **HA portability.** SessionEntry is replicated via session sync.
  bytes_total in the synced entry will diverge across nodes (each
  worker counts its own); HA semantics need this NOT to break the
  reconciliation. Cleanest: don't sync bytes_total; recreate as 0
  on activation.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Hot-path cost | **MED** | 1 u64 write/packet on already-hot cache line; 3 cy/pkt × 14.8M pps × N workers. Need to measure on the loss cluster |
| Architectural mismatch | LOW | Layered on top of working Phase 1; no new closed-loop logic |
| Snapshot skew at high rate | LOW | Rate computed over 1 Hz, sub-packet skew rounds out |
| HA reconciliation | LOW-MED | bytes_total divergence across cluster; requires "recreate as 0 on activation" handling |
| Operator misconfig | LOW | elephantThreshold knob is bounded `[1.1, 10.0]`; default sensible |
| Empirical: clears ≤20% gate | UNKNOWN | Concept is sound; measurement on loss cluster will tell |

## 8. Test plan

- `cargo build --release` clean
- `cargo test --release` 977+ pass
- New cargo tests:
  - `bytes_total_increments_on_packet`
  - `ingress_active_flows_for_binding_includes_bytes_total`
- New Go controller tests (extending `flow_steering_test.go`):
  - `TestSelectStableCandidates_prefersHighRateFlows`
  - `TestSelectDestinationQueues_picksLowByteRateQueues`
  - `TestReconcile_byteRateDiffAcrossTicks`
- Smoke matrix on loss userspace cluster, default off
- **Per-flow CoV gate measurement (the actual point of Phase 2):**
  - iperf-c P=12 t=60 -R, 5 reps. Gate: ≤20% mean CoV
  - iperf-d P=12 t=60 push, 5 reps. Gate: ≤20% mean CoV
  - iperf-b P=12 t=60 -R, 5 reps. Gate: ≤20% mean CoV
- **Hot-path measurement:**
  - perf stat -e cache-misses,L1-dcache-load-misses on a 14.8M pps
    workload before and after the bytes_total write
  - Aggregate throughput before/after — must not regress >2%
- 5×flake on the most-affected named test

## 9. Out of scope

- ice/i40e driver portability (still mlx5_core only)
- UDP / fragmented-packet steering
- NAT-aware wire-tuple extraction (Phase 1 limitation persists)
- Per-class enable/disable knobs

## 10. Open questions for adversarial review

1. **Hot-path cost worth the CoV win?** 1.5% of one core per worker
   for residual ~30 percentage points of CoV reduction. PLAN-KILL is
   reasonable if the deployment doesn't care about the 30 points.

2. **bytes_total race-free?** Single-threaded per worker, but is the
   session-table re-entry path a path that could expose a partial
   write? Need code-level confirmation.

3. **HA bytes_total divergence.** Should the cluster-sync code touch
   this field at all, or just zero it on activation? Either is safe;
   pick the simpler.

4. **elephantThreshold default.** 1.5× mean. Should it be configured
   per-class, or global? Phase 1 keeps it global for simplicity.

5. **Snapshot interval still 1Hz?** With byte-rate diffing, a faster
   tick (5 Hz) gives finer rate signal. But it stresses the publish
   path. Phase 1 chose 1 Hz; should Phase 2 reconsider?

6. **Should bytes_total be exposed in the show command for
   operator triage?** Adds one column to the re-steer events table.

## 11. Verdict request

PLAN-READY → execute Phase 2 (additive on Phase 1).
PLAN-NEEDS-MINOR → tweak (threshold tuning, snapshot cadence).
PLAN-NEEDS-MAJOR → revise (different elephant detection, different
write site, different selection algorithm).
PLAN-KILL → hot-path cost not worth the residual CoV win; ship
Phase 1 as-is or close #789 with the achieved improvement.
