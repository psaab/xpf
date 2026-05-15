# #1304 Equal-Flow Rate-Suppression Estimator

## Goal

Add the first measurement-only slice for issue #1304: quantify how much
throughput an exact shaped CoS queue would have to suppress to make the
currently sampled flows converge to one per-flow rate under RSS skew.

This PR does not change packet scheduling, queue admission, AF_XDP
binding, or CoS token allocation. It only exposes telemetry for review
and live measurement.

## Background

The existing structural fairness contract is work-conserving. With a
skewed RSS distribution, perfect worker-local fairness still leaves
flows on lightly-loaded workers faster than flows on heavily-loaded
workers. That is the `Cstruct` floor.

The only remaining way to drive absolute per-flow spread below that
floor without moving packets between AF_XDP queues is to deliberately
give up work conservation inside a shaped exact CoS queue. The
suppressor would cap each worker's aggregate queue service to:

```text
cap_worker_bps = target_per_flow_bps * active_flows_on_worker
```

where `target_per_flow_bps` is the slowest sampled worker's observed
per-flow rate.

## Phase 0 Design

Reuse the existing Go-side rolling 30-second fairness throughput window:

- `FlowWorkerMap` supplies cumulative per-flow byte counters and worker
  ownership.
- `CoSActiveFlowCounts` supplies the per-CoS queue active-flow count per
  worker.
- The collector already advances wall-clock time on healthy scrapes and
  resets on truncated flow-worker snapshots.

For each egress CoS queue, keep an additional rolling byte total per
worker alongside the existing byte total per flow. On each summary:

1. Convert per-worker bytes to `observed_bps`.
2. Divide by the current active-flow count to get observed
   `per_flow_bps` for each sampled active worker.
3. Pick the minimum sampled `per_flow_bps` as the strict equal-flow
   target.
4. Compute each worker's hypothetical cap and suppressed throughput.
5. Export the queue-level and worker-level values as Prometheus gauges.

The estimate is valid only when:

- the flow-worker snapshot is not truncated,
- the CoS active-flow snapshot is not truncated,
- at least two active workers have non-zero rolling byte samples.

## Invariants

- No new hot-path atomics or packet-path branches.
- No scheduler path reads the estimator.
- Truncated source data fails closed by suppressing estimator output or
  marking the estimate invalid.
- Worker IDs are bounded with the same `boundedFairnessRSSWorkerSlots`
  cap used by the production RSS-structure gauges, so malformed status
  rows cannot create unbounded estimator state or Prometheus labels.
- The existing `observed_cov <= Cstruct + 0.05` contract remains the
  pass/fail contract. Equal-flow telemetry is an advisory model for a
  later non-work-conserving mode.
- Prometheus labels stay bounded to `{ifindex,queue_id}` and
  `{ifindex,queue_id,worker_id}`.

## Non-Goals

- Phase 0 had no Rust dataplane enforcement. The follow-on enforcement
  slice is explicit opt-in via
  `class-of-service schedulers <name> equal-flow-enforcement` and lives
  inside the shared v8 exact queue lease, not in the Go rolling estimator.
- No Go collector feedback loop into the scheduler. The Go estimator remains
  measurement-only; Rust enforcement uses prior-epoch shared-lease grant
  samples with fail-open guards.
- No CLI command for the rolling estimator; the CLI status path is
  stateless across invocations, while the estimator needs a daemon-owned
  rolling window.
- No claim that the target distinguishes CPU-bound demand from
  naturally quiet flows. Phase 0 intentionally measures the strict
  equalize-to-slowest-sampled outcome so reviewers can quantify its
  throughput cost first.

## Enforcement Slice

The opt-in Rust slice deliberately trades throughput for lower absolute
per-flow spread under RSS skew:

- only positive `transmit-rate exact` schedulers may enable it;
- queue-lease acquire remains O(1), loading a cap published by the existing
  200 us v8 rotation;
- rotation samples workers that were active, demanded lease credit, and
  received prior-epoch grants;
- every active sampled worker must have consumed a material fraction of its
  prior fair share, so a merely low-traffic worker cannot become the global
  equal-flow target;
- any active unsampled worker, zero target, stale epoch, or insufficient valid
  streak fails open to the default v8 behavior; a low-demand sampled worker
  fails open for the same reason;
- when active, bypass/surplus cannot grant beyond the equal-flow cap, because
  that would defeat suppression;
- status and Prometheus distinguish configured mode, actively enforced epochs,
  target, cap-hit events, suppressed grant bytes, and the bounded fail-open
  reason.

## Validation

- Unit test the estimator math on a skewed worker distribution:
  worker 0 has 3 active flows and 9.6 Kbps observed, worker 1 has
  1 active flow and 6.4 Kbps observed. Target is 3.2 Kbps/flow, capped
  aggregate is 12.8 Kbps, suppression is 3.2 Kbps.
- Unit test invalidation when CoS active-flow counts are truncated.
- Unit test Prometheus descriptor emission for queue-level and
  worker-level estimator gauges.
- Run focused Go tests:

```bash
go test ./pkg/dataplane/userspace ./pkg/api
```
