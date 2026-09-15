# pkg/natpoolalarm — NAT source pool-utilization-alarm monitor (#2079)

Runtime consumer for the Junos
`set security nat source pool-utilization-alarm raise-threshold/clear-threshold`
stanza. Before #2079 the stanza was parsed and stored
(`config.NATConfig.PoolUtilizationAlarm`) but had **no consumer** — an operator
who configured it got a silent no-op. vSRX raises a `show security alarms` entry
and emits a NAT syslog event when a source pool's port utilization crosses the
raise threshold, and clears below the clear threshold; this package implements
that behaviour entirely in the Go control plane.

## What it does

A slow (10s) daemon-resident loop (`Monitor.run`) samples the helper's
LAST-APPLIED NAT pool snapshot and, for each rule-referenced non-deterministic
source pool, computes utilization as the max of the ports leg
`UsedPorts * 100 / (AddressCount * (PortHigh - PortLow + 1))` and the
tracked-flow leg `LiveFlows * 100 / MaxTrackedFlows` (#9896 — the cap that
actually refuses new flows; address-only pools evaluate the flow leg alone),
and applies hysteresis:

- **RAISE** when utilization `>= raise-threshold` (record an active alarm).
- **CLEAR** when it drops `< clear-threshold` (strict less-than).
- **HOLD** in the band `[clear, raise)` — no transition, no emission.

On each raise/clear transition (and only on a transition — never per tick) the
monitor:

1. updates the in-memory active-alarm set surfaced by `ActiveAlarms()`, rendered
   at BOTH `show security alarms` sites (gRPC `Server.showSecurityAlarms`, local
   CLI `CLI.showSecurityAlarms`) via the shared `RenderAlarms` helper; and
2. emits ONE structured `RT_NAT NAT_POOL_UTILIZATION_ALARM_RAISED` /
   `..._CLEARED` syslog line via the injected `Emitter`
   (daemon → `logging.EventReader.ForwardLogMsg`).

## Generation coherency (the r10 fixed point)

The monitor must evaluate a single generation-coherent `(config, counters)`
pair. The sampler reads `dp.AppliedNATView()`
(`pkg/dataplane/userspace`), whose `Config` and `Pools` both belong to the
helper's LAST-APPLIED generation — the generation the helper echoes as
`status.LastSnapshotGeneration`, captured in `m.appliedSnapshot` only at the
successful full-`apply_snapshot` sites (`markAppliedSnapshotLocked`). This is the
provable fixed point between two wrong sources:

- `m.publishedSnapshot` is too LOOSE (advances on content-dedup no-op publishes
  and on the neighbor-regen `update_neighbors` path, which the helper records
  only as `last_fib_generation`).
- `m.lastSnapshot.Generation` is too STRICT (`BumpFIBGeneration` /
  `RegenerateNeighborSnapshot` bump it WITHOUT a full apply, so it permanently
  exceeds the helper's `last_snapshot_generation` → the alarm would never fire).

When the view is `!Available` (helper down) or `!HelperCoherent` (mid-apply,
status gen != applied gen), the monitor HOLDs ALL alarms — no clear — because no
data is not a decision to clear. Config-derived clears (rule un-reference, pool
removal, deterministic-convert, feature-disabled, nil-config) DO fire once a
coherent applied config is available.

## Constraints honoured

- **No Rust / wire change** — reuses the existing 1 Hz `SourceNATPoolStatus`
  counters and `last_snapshot_generation`.
- **No new control-socket request** — the sampler reads the manager's CACHED
  status + applied snapshot, no socket I/O (CLAUDE.md control-socket-contention
  rule).
- **No per-tick logging** — the syslog emit is gated entirely behind a raise/
  clear transition.

## Dedup / deterministic / persistent / address-only

- Rules sharing a pool share one `Arc<PortAllocatorShared>` and report identical
  `UsedPorts`; `AppliedNATView` deduplicates by pool name and takes one entry —
  never sums (summing would double/triple-count → false alarms).
- Deterministic pools are SKIPPED in this release (`UsedPorts` is not the right
  numerator for block-based allocation; block-based utilization is a follow-up).
- Persistent-NAT pools use raw `UsedPorts` for the ports leg; the tracked-flow
  leg (#9896) covers their divergence (many live flows per translated tuple).
- Address-only (`port no-translation`) pools have no ports leg (`UsedPorts` is
  permanently 0) but raise/clear on the tracked-flow leg; with no flow-cap
  data the pool is recorded inapplicable (#7361, narrowed by #9896).

## Commit-time validation

`compileNAT` (`pkg/config/compiler_nat.go`) hard-rejects thresholds outside
`0 < clear < raise <= 100` at commit (a bare `pool-utilization-alarm;` →
raise=0/clear=0 is an always-firing alarm). See `docs/config-schema.md` #2079.

## Tests

- `natpoolalarm_test.go` — raise-once, clear-once, hysteresis no-flap, boundary
  comparators, registry populate/clear, rule-referenced eligibility +
  prune-on-unreference, eligible-but-absent HOLD, transient-uncomputable HOLD,
  deterministic skip + det-convert clear, no-double-count, nil-config / feature-
  disabled clear-all, unavailable / not-coherent HOLD-all, updatePct-no-syslog,
  syslog severity/shape, start/stop. Mutation-verified non-tautological.
- `natpoolalarm_tracked_flows_9896_test.go` — at-cap fixture raises, dual-leg
  crossing emits one line, `MaxTrackedFlows==0` falls back to ports-only,
  flow-leg clear + hysteresis-band hold.
- `render_test.go` — shared `show security alarms` render (detail/summary/empty,
  numbering continuation).
- `../dataplane/userspace/applied_nat_view_test.go` — coherency, the FIB-bump
  fixed point, dedup, unavailable-before-apply.
- `../config/compiler_nat_pool_alarm_test.go` — commit-time threshold validation.
