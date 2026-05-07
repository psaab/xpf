---
status: DRAFT v1 — pending adversarial plan-review
issue: #1219
phase: implementation plan; multi-step PR (Rust crate + Go collector + harness script + smoke fixture)
prerequisites:
  - PR #1217 (fairness-regimes contract) MERGED as e1ec6b90 ✓
  - PR #1216 (CoSQueueRuntime split) MERGED as a1688792 ✓
---

## 1. Issue framing

Implement the harness work that the fairness-regimes contract
(`docs/fairness-regimes.md`) requires. Without this, the contract
is enforced only by hand and we cannot answer the immediate
operational question: **is today's 47% iperf-c P=12 -R CoV at the
structural ceiling for the observed RSS distribution, or is it Δ
above ceiling indicating a scheduler bug?**

## 2. Honest scope/value framing

**Mid-sized implementation PR.** Touches:
- New Rust `pure-fn` module for `compute_cstruct` /
  `compute_observed_cov` / `starved_flow_count` /
  `is_saturated` (~150 LOC, fully unit-tested against contract's
  worked-example table)
- New per-binding `distinct_flow_count` signal — bounded LRU set
  on each worker (~80 LOC + integration into existing
  flow_cache hit path)
- New Prometheus exports in `pkg/api/` collector — 4 gauges/counters
- New test harness script `test/incus/fairness-harness.sh` —
  runs iperf3 fixture, reads counters, computes gates, reports
- New smoke fixture for the deterministic RSS-skew distributions
  Codex Path 0 demands ({1+3, 0/2/2/2/3/3, balanced})

Estimated diff: ~600 LOC new code + ~150 LOC tests + ~100 LOC
harness scripting.

**Value:** the immediate operational measurement that tells us
whether scheduler work is needed at all. If `observed_CoV ≈
Cstruct`, fairness is solved structurally; the only remaining
lever is RSS distribution (out of scope for this PR).

**If reviewers conclude the implementation cost isn't justified
(e.g. the harness logic is too complex), PLAN-NEEDS-MAJOR or
PLAN-KILL is reasonable. The contract requires this work eventually
but it could be deferred.**

## 3. Concrete design

### 3.1 Rust pure-fn module: `userspace-dp/src/fairness/mod.rs` (new)

```rust
//! Fairness regime computations per docs/fairness-regimes.md.
//!
//! These are pure functions (no I/O, no global state) so they can
//! be unit-tested against the worked-example table in the contract.
//! They are called by:
//! - the production Prometheus collector (Go side, via gRPC)
//! - the test harness (test/incus/fairness-harness.sh)

/// Compute the structural CoV ceiling Cstruct for the observed
/// per-worker active-flow distribution.
///
/// `distribution[i]` = active flow count on worker i. Idle workers
/// (a_i == 0) are excluded from the per-flow set per the contract:
/// "the idle worker is excluded from the per-flow set (it has zero
/// flows), not 'compensating' for anything".
///
/// Returns the population CoV: stddev / mean across the per-flow
/// shares {1/a_i : repeated a_i times for each active worker i}.
/// The S/N_v scaling factor cancels because CoV is dimensionless.
pub fn compute_cstruct(distribution: &[u32]) -> f64 {
    let mut shares: Vec<f64> = Vec::new();
    for &a_i in distribution {
        if a_i == 0 {
            continue;
        }
        let share = 1.0_f64 / (a_i as f64);
        for _ in 0..a_i {
            shares.push(share);
        }
    }
    if shares.is_empty() {
        return 0.0;
    }
    let mean = shares.iter().sum::<f64>() / (shares.len() as f64);
    if mean == 0.0 {
        return 0.0;
    }
    let var = shares.iter()
        .map(|s| (*s - mean).powi(2))
        .sum::<f64>() / (shares.len() as f64);
    var.sqrt() / mean
}

/// Compute observed CoV across the per-flow throughput vector
/// from the steady-state window.
pub fn compute_observed_cov(per_flow_throughputs: &[u64]) -> f64 {
    if per_flow_throughputs.is_empty() {
        return 0.0;
    }
    let mean = per_flow_throughputs.iter().map(|&x| x as f64).sum::<f64>()
        / (per_flow_throughputs.len() as f64);
    if mean == 0.0 {
        return 0.0;
    }
    let var = per_flow_throughputs.iter()
        .map(|&x| (x as f64 - mean).powi(2))
        .sum::<f64>() / (per_flow_throughputs.len() as f64);
    var.sqrt() / mean
}

/// Count flows whose throughput stayed < 1% of mean per-flow
/// throughput for the ENTIRE steady-state window. Per the contract:
/// "A flow that drops below 1% transiently but recovers does not
/// count."
///
/// `per_flow_buckets` is indexed by flow, then by 1-second bucket.
pub fn starved_flow_count(per_flow_buckets: &[Vec<u64>]) -> u32 {
    if per_flow_buckets.is_empty() {
        return 0;
    }
    // Compute mean across all (flow, bucket) cells in the window.
    let total_cells: u64 = per_flow_buckets.iter().map(|v| v.len() as u64).sum();
    let total_bytes: u64 = per_flow_buckets.iter()
        .flat_map(|v| v.iter().copied())
        .sum();
    if total_cells == 0 || total_bytes == 0 {
        return 0;
    }
    let mean_per_cell = total_bytes as f64 / total_cells as f64;
    let starved_threshold = 0.01_f64 * mean_per_cell;
    let mut starved = 0u32;
    for flow_buckets in per_flow_buckets {
        let always_below = flow_buckets.iter()
            .all(|&b| (b as f64) < starved_threshold);
        if always_below {
            starved += 1;
        }
    }
    starved
}

/// Determine saturation per the contract: aggregate >= 95% of
/// (N_a / N_v) * shaper_rate for >= 80% of 1-second buckets.
pub fn is_saturated(
    aggregate_buckets_bps: &[u64],
    structural_cap_bps: u64,
) -> bool {
    if aggregate_buckets_bps.is_empty() || structural_cap_bps == 0 {
        return false;
    }
    let threshold = (structural_cap_bps as f64 * 0.95) as u64;
    let above_count = aggregate_buckets_bps.iter()
        .filter(|&&b| b >= threshold)
        .count();
    let ratio = above_count as f64 / aggregate_buckets_bps.len() as f64;
    ratio >= 0.80
}
```

Unit tests against the contract's worked-example table:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool { (a - b).abs() < 0.005 }

    #[test]
    fn cstruct_balanced() {
        assert!(close(compute_cstruct(&[2,2,2,2,2,2]), 0.00));
    }
    #[test]
    fn cstruct_mild_skew() {
        assert!(close(compute_cstruct(&[1,1,2,2,3,3]), 0.47));
    }
    #[test]
    fn cstruct_one_idle() {
        assert!(close(compute_cstruct(&[0,2,2,2,3,3]), 0.20));
    }
    #[test]
    fn cstruct_severe_skew() {
        assert!(close(compute_cstruct(&[1,3,0,0,0,0]), 0.58));
    }
    #[test]
    fn cstruct_degenerate() {
        assert!(close(compute_cstruct(&[6,0,0,0,0,6]), 0.00));
    }
    // ... plus tests for compute_observed_cov, starved_flow_count,
    // is_saturated edge cases
}
```

### 3.2 Per-binding distinct-flow-count signal

Add to the binding live state:

```rust
// userspace-dp/src/afxdp/types/runtime.rs (extend BindingLiveState)
pub(in crate::afxdp) distinct_flow_tracker: DistinctFlowTracker,
```

```rust
// userspace-dp/src/afxdp/binding/distinct_flow.rs (new file)
use std::collections::HashMap;

const FLOW_AGE_OUT_NS: u64 = 1_000_000_000;  // 1 second
const MAX_TRACKED_FLOWS: usize = 1024;       // cap to bound memory

/// Bounded LRU-ish set tracking distinct flow_keys seen on this
/// binding within the last FLOW_AGE_OUT_NS. Single-writer (the
/// owner worker thread); snapshot reads via atomic count.
pub(in crate::afxdp) struct DistinctFlowTracker {
    map: HashMap<FlowKey, u64>,  // flow_key -> last_seen_ns
    /// Atomic snapshot of `map.len()` after the most recent
    /// age-out pass. Read by the gRPC status path; written only
    /// by the owner.
    pub(in crate::afxdp) distinct_count: AtomicU32,
}

impl DistinctFlowTracker {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            map: HashMap::with_capacity(MAX_TRACKED_FLOWS),
            distinct_count: AtomicU32::new(0),
        }
    }

    /// Called from the flow-cache hit path. Single-writer;
    /// no atomic on the map.
    pub(in crate::afxdp) fn record(&mut self, flow_key: FlowKey, now_ns: u64) {
        if self.map.len() >= MAX_TRACKED_FLOWS {
            // Cap reached; only update existing entries. New
            // flows are dropped from tracking until age-out
            // frees a slot. Bounded memory > full coverage.
            if let Some(slot) = self.map.get_mut(&flow_key) {
                *slot = now_ns;
            }
            return;
        }
        self.map.insert(flow_key, now_ns);
    }

    /// Called periodically (every 100ms) from the worker tick.
    /// Ages out flows that haven't been seen in FLOW_AGE_OUT_NS
    /// and updates the atomic snapshot count.
    pub(in crate::afxdp) fn age_out(&mut self, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(FLOW_AGE_OUT_NS);
        self.map.retain(|_, &mut last_seen| last_seen >= cutoff);
        self.distinct_count.store(self.map.len() as u32, Ordering::Relaxed);
    }
}
```

Wired into the existing flow-cache lookup path
(`userspace-dp/src/afxdp/flow_cache.rs`-ish — exact site identified
during implementation): on hit OR miss we `record(flow_key,
now_ns)`. The age-out runs from the existing per-worker tick.

### 3.3 Prometheus exports (Go side, `pkg/api/`)

Add to the existing collector:

```go
// pkg/api/fairness_collector.go (new file)
var (
    fairnessCstruct = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "xpf_fairness_cstruct",
            Help: "Structural CoV ceiling computed from per-worker active-flow distribution",
        },
        []string{"queue"},
    )
    fairnessObservedCoV = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "xpf_fairness_observed_cov",
            Help: "Rolling 30-second observed per-flow CoV",
        },
        []string{"queue"},
    )
    fairnessStarvedFlows = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "xpf_fairness_starved_flows",
            Help: "Lifetime count of flows that fell below the starved threshold",
        },
        []string{"queue"},
    )
    fairnessSaturated = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "xpf_fairness_saturated",
            Help: "1 if the queue is in saturated regime per the structural cap, 0 otherwise",
        },
        []string{"queue"},
    )
)
```

The collector reads the per-binding distinct-flow-count via the
existing gRPC status call (extended with a new field), computes
Cstruct + observed CoV + saturation per the Rust pure-fns (mirror
the formulas in Go), and updates the gauges every 1Hz.

**Open question for adversarial review**: should the formulas live
in a single source of truth (Rust crate exposed to Go via CGo or
re-implemented in Go from the same spec)? Re-implementing in Go
risks drift; CGo adds build complexity. For v1, recommend
**re-implementing in Go with a shared test-vector file** that both
Rust and Go test against, so any drift is caught by CI.

### 3.4 Test harness `test/incus/fairness-harness.sh`

```bash
#!/usr/bin/env bash
# Run an iperf3 fixture, collect per-flow + per-binding metrics,
# compute the contract gates, report pass/fail with regime label.
#
# Usage: ./fairness-harness.sh <port> <streams> <duration>
# Example: ./fairness-harness.sh 5203 12 120

set -euo pipefail
PORT=${1:-5203}
N=${2:-12}
T=${3:-120}

# 1. Start iperf3 with JSON output, parse per-stream rates over
#    1-second buckets in the steady-state window (5s..T-1s)
# 2. Read per-binding distinct_flow_count from Prometheus or gRPC
#    at the same 1-second cadence
# 3. Compute aggregate by summing per-stream rates
# 4. Pass per-flow buckets, distinct_flow_count snapshots, and
#    aggregate buckets to a small Go helper that calls the
#    fairness pure-fns and reports:
#    - {a_i} distribution observed
#    - Cstruct
#    - observed_CoV
#    - gap (observed - Cstruct)
#    - saturated/non-saturated label
#    - starved_flow_count
#    - PASS/FAIL per the contract gates
```

The Go helper is a thin wrapper around the Prometheus-collector's
fairness functions — no new logic, just a CLI surface for them.

### 3.5 Smoke fixture (deferred to follow-up issue per Codex Path 0)

Deterministic RSS-skew (controlled 5-tuples that produce known
distributions) is its own issue. This PR only ships the harness;
the fixture comes next.

For initial validation, this PR uses iperf3's natural RSS hashing
on a 12-stream test against ports 5203 / 5204 — recording the
distribution observed without trying to control it.

## 4. Public API preservation

- gRPC: 1 new field added to per-binding status response
  (`distinct_flow_count: u32`). Backward-compatible (proto field
  number reserved).
- HTTP REST: unchanged.
- Prometheus: 4 new metrics. Additive only.
- CLI: optional new `show class-of-service fairness` command (or
  fold into existing `show class-of-service queues`); defer to
  v1.5 if scope is too broad.

## 5. Hidden invariants the change must preserve

- The flow-cache hit path is on the hot path. Adding `record()`
  must not regress per-pop budget. `HashMap::insert` is ~30 ns
  amortized; if measured high, fall back to a `LinearProbeMap`
  with bounded probe length.
- `distinct_count.store()` happens on the periodic tick (100ms
  cadence), NOT on every record. No atomic-write storm on hot
  path.
- HA failover: `DistinctFlowTracker` is reset on role flip
  (fresh `BindingLiveState`).
- The Rust + Go formula re-implementation must agree to ≤
  1e-3 absolute on all worked examples (CI-pinned).

## 6. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression on FIFO/owner-local | NONE | Code path unchanged |
| Behavioral regression on shared_exact | NONE | Data plane only adds a tracker write per flow-cache lookup |
| Hot-path perf cost | LOW-MED | ~30 ns HashMap amortized; verify on smoke |
| Rust/Go formula drift | LOW | Shared test-vector file enforced by CI |
| HA failover | LOW | Tracker is per-binding fresh state |
| Memory pressure | LOW | MAX_TRACKED_FLOWS=1024; ~64 KB per binding |

## 7. Test plan

- `cargo build --release` clean
- `cargo test --release`: 977/977 + new fairness pure-fn tests pass
- 5×flake on `fairness::tests::*`
- `go test ./...`: clean + new collector tests pass
- Smoke matrix on loss userspace cluster:
  - **Pass A (CoS off)**: harness reports observed_CoV, Cstruct,
    saturation for the standard iperf-c P=12 -R workload.
    First-time measurement of "is 47% at structural ceiling".
  - **Pass B (CoS on)**: 24 cells per-class harness output; verify
    Cstruct and observed_CoV are computed correctly per queue.
- `make test-failover` clean — tracker fresh on role flip

## 8. Out of scope

- AFD ECN overlay (#1211) — separate research effort
- Deterministic RSS-skew fixture (Codex Path 0) — separate
  follow-up issue
- Shared formula library (Rust + CGo) — v1 re-implements in Go
  with shared test vectors; consolidation deferred
- New CLI commands beyond Prometheus — deferred

## 9. Open questions for adversarial review

1. **Distinct-flow-count cap.** MAX_TRACKED_FLOWS=1024 is bounded
   memory but caps observed `aᵢ` at 1024. For high-fan-in
   workloads (#788 P=128 × multiple sources) this could miscount.
   Is 1024 the right cap, or is uncapped + bounded-memory a
   different LRU strategy needed?

2. **Hash collisions in DistinctFlowTracker.** The HashMap key is
   `FlowKey` (5-tuple). What's the collision rate at 1024 flows?
   If high, the count is overstated.

3. **Rust↔Go formula parity.** Re-implementing in Go invites drift.
   Is the shared test-vector approach sufficient, or should we go
   to CGo / WASM / a single source of truth?

4. **HA failover timing.** Tracker reset on role flip means the
   secondary observes 0 distinct flows immediately after takeover
   for ~1 second. The Cstruct compute therefore can't run during
   that window. Is this acceptable, or do we need cross-node
   tracker sync?

5. **Steady-state window detection.** The harness needs to identify
   warmup (5s) and final-burst (1s) precisely. iperf3 JSON output
   includes per-stream timestamps; is that reliable enough, or do
   we need server-side gating?

6. **Prometheus cadence.** 1Hz collector is the existing default.
   Is 1Hz Cstruct compute fast enough for production observability?
   At 0.1Hz (10s) we'd see lower compute cost but slower regime
   transitions in the dashboard.

7. **Smoke matrix for the harness itself.** Does the harness need
   a self-test that runs deterministic synthetic data through the
   pure-fns and asserts the contract's worked-example numbers?
   (Yes — included in §7 cargo tests + new go test.)

## 10. Verdict request

PLAN-READY → execute (single PR with Rust + Go + harness script
delivery, in that dependency order).
PLAN-NEEDS-MINOR → tighten module boundaries / cap values / cadence.
PLAN-NEEDS-MAJOR → restructure (e.g., shared formula library;
different distinct-flow tracking strategy; defer Prometheus to
follow-up).
PLAN-KILL → harness logic too complex for the value; defer or
simplify drastically.
