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
LAST-APPLIED NAT pool snapshot and, for each rule-referenced source pool,
computes utilization as the max of the ports leg
`UsedPorts * 100 / (AddressCount * (PortHigh - PortLow + 1))` and the
tracked-flow leg `max(LiveFlows, PersistentLeases) * 100 / MaxTrackedFlows`
(#9896 — the cap that actually refuses new flows; deterministic and
address-only pools evaluate the flow leg alone), and applies hysteresis:

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
removal, feature-disabled, nil-config — plus a convert to a class whose legs
are unmeasurable) DO fire once a coherent applied config is available.

## Constraints honoured

- **No new control-socket request** — the sampler reads the manager's CACHED
  status + applied snapshot, no socket I/O (CLAUDE.md control-socket-contention
  rule).
- **No per-tick logging** — the syslog emit is gated entirely behind a raise/
  clear transition.
- The utilization half reuses the existing 1 Hz `SourceNATPoolStatus`
  counters and `last_snapshot_generation` with no Rust change (#2079); the
  exhaustion half adds one additive `allocator_id` u64 to the pool row
  (#9902 F-026), defaulted on both planes so mixed-version pairs degrade to
  the documented legacy-0 residual instead of failing a decode.

## Dedup / deterministic / persistent / address-only

- Rules sharing a pool share one `Arc<PortAllocatorShared>` and report identical
  `UsedPorts`; `AppliedNATView` deduplicates by pool name and takes one entry —
  never sums (summing would double/triple-count → false alarms). Among
  same-name rows the CONSTRUCTED allocator wins (`MaxTrackedFlows>0`, tie →
  first): a poisoned rule (#9874) keeps its pool_mode but builds no allocator,
  and its `MaxTrackedFlows==0` row must not shadow the live one (#9902 F-026).
- Deterministic pools evaluate the flow leg alone: their arms enforce the same
  tracked-flow cap (`allocator.rs:2930,3088,3731` — a deterministic pool at the
  cap refuses while port utilization reads healthy), so the flow leg is
  evaluated independently of deterministic classification. The ports leg stays
  excluded (aggregate utilization cannot predict per-block exhaustion); with no
  flow-cap data the pool is recorded inapplicable. Commit time warns the
  narrowed partial-signal claim. Allocator-reported exhaustion events ARE
  watched for every class (see below).
- Persistent-NAT pools use raw `UsedPorts` for the ports leg; the tracked-flow
  leg (#9896) covers both their divergence (many live flows per translated
  tuple) and their idle-lease accumulation (fresh-lease admission refuses at
  the same cap — the leg is `max(live, leases)`).
- Address-only (`port no-translation`) pools have no ports leg (`UsedPorts` is
  permanently 0) but raise/clear on the tracked-flow leg; with no flow-cap
  data the pool is recorded inapplicable (#7361, narrowed by #9896).

Utilization cannot see every exhaustion mode (per-subscriber block fullness,
reverse-identity collision), so the same monitor also watches the
allocator's cumulative `exhaustion_total` per pool — "allocator-REPORTED
exhaustion events" (block/pool/cap fullness, deterministic bounds,
address-only collision; config-error/drift refusals reusing the reason string
are deliberately uncounted). Any positive delta on a comparable baseline
raises `NAT_POOL_EXHAUSTION_ALARM_RAISED` (syslog `events=<delta>`); 3 fresh
clean ticks clear it. "Clear" means "no recently observed exhaustion", not
"capacity recovered".

Comparability is keyed on instance identity, not the counter value: each pool
row carries the reporting allocator's instance id (`allocator_id`, minted per
`PortAllocatorShared` construction) and the sample carries the helper
incarnation (`procGen`). A change in EITHER means the counter instance was
replaced (rebuild or helper restart) and the tick rebases SILENTLY — no
evaluation, no clear, no false hysteresis credit. Freshness comes from the
manager's status-publication sequence: a repeated sequence means the sampler
re-read the same cached sample, so the exhaustion pass skips the tick
entirely. Watches every rule-referenced pool class (PAT, deterministic,
address-only); still gated on the same stanza (feature-disabled / nil-config
clears and retires baselines).

Two stated residuals. (1) Legacy `allocator_id` 0 ALWAYS rebases — a legacy
same-process rebuild is invisible (0→0), and evaluating the delta would
false-raise on a fast re-exhaustion past the old count — so legacy helpers
fail silent (never raise) for the skewed-upgrade window. (2) Rebase loses the
inter-tick delta: events between the last tick and a rebuild are unobservable
at the 1 Hz poll cadence, and a rebase neither counts nor clears them.

## Commit-time validation

`compileNAT` (`pkg/config/compiler_nat.go`) hard-rejects thresholds outside
`0 < clear < raise <= 100` at commit (a bare `pool-utilization-alarm;` →
raise=0/clear=0 is an always-firing alarm). See `docs/config-schema.md` #2079.

## Tests

- `natpoolalarm_test.go` — raise-once, clear-once, hysteresis no-flap, boundary
  comparators, registry populate/clear, rule-referenced eligibility +
  prune-on-unreference, eligible-but-absent HOLD, transient-uncomputable HOLD,
  deterministic flow-leg (ports exclusion preserved) + det-convert clear,
  no-double-count, nil-config / feature-disabled clear-all, unavailable /
  not-coherent HOLD-all, updatePct-no-syslog, syslog severity/shape, start/stop.
  Mutation-verified non-tautological.
- `natpoolalarm_exhaustion_9902_test.go` — exhaustion first-sight silence,
  raise/refresh/clear-3, id×{below,equal,above} + procGen×{below,equal,above}
  silent rebase, same-key below/equal/above, rebase-no-clear-credit,
  same-seq HOLD, absent HOLD, removal retire + re-add silence,
  baseline-only prune, deterministic + address-only watched, det-convert
  1-clear, class-change continuity, disable/nil-config clear,
  unavailable/incoherent HOLD, severity/shape.
- `natpoolalarm_tracked_flows_9896_test.go` — at-cap fixture raises, dual-leg
  crossing emits one line, `MaxTrackedFlows==0` falls back to ports-only,
  flow-leg clear + hysteresis-band hold, address-only flow-leg cells,
  deterministic flow-leg raise / ports-exclusion / healthy / recovery /
  no-cap cells, lease-leg raise + defer-to-live.
- `render_test.go` — shared `show security alarms` render (detail/summary/empty,
  numbering continuation), utilization + exhaustion.
- `../dataplane/userspace/applied_nat_view_test.go` — coherency, the FIB-bump
  fixed point, dedup, unavailable-before-apply.
- `../dataplane/userspace/applied_nat_view_9902_test.go` — constructed-first
  selection (both orders, import-only vs poisoned, identical dedup),
  exhaustion-identity + flow-leg projection, allocator_id and flow-cap wire
  lockstep, status-sequence publish/fail/clear semantics.
- `../daemon/natpoolalarm_projection_9902_test.go` — sampler field projection.
- `../config/compiler_nat_pool_alarm_test.go` — commit-time threshold validation.
- `../config/natpoolalarm_inapplicable_7361_test.go` — address-only advisory +
  deterministic sentence (narrowed to the partial-signal claim, #9896).
- `../../api/metrics_test.go` — `max_tracked_flows` denominator emission.
