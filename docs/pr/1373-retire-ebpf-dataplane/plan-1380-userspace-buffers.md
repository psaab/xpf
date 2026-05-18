# #1380 Userspace Buffer and Status Parity Plan

## Goal

Keep operational buffer/status visibility intact after the eBPF dataplane is
retired. `show system buffers`, gRPC `ShowText`, and related status/metrics
must expose userspace AF_XDP ring capacity, fill/comp pressure, and active
session summaries with the same operator utility as the legacy path.

## Dependencies

- #1381 should land first so status and telemetry live behind the abstract
  runtime domains instead of depending on the embedded eBPF manager.
- #1386 restores the immediate userspace `show system buffers` parity gaps:
  active-session footer, detail/non-detail distinction, and fallback from sparse
  per-binding capacity gauges to binding-level status.
- Follow-up implementation after #1386 widens the shared formatter to include
  all bounded buffer surfaces already present on the helper status wire: AF_XDP
  UMEM/TX rings plus class-of-service queued-byte capacity. It also adds an
  unbounded status-counter section for neighbor entries, active flow-cache
  counts, flow-cache collision evictions, fill/TX ring saturation, pending-TX
  gauges, and worker queue overflow/drop attribution.

## Design

Treat buffer visibility as runtime telemetry, not config state. The userspace
helper publishes per-binding/ring capacity, available fill frames, completion
backlog, RX/TX ring occupancy, and drop/error counters. Go formatting keeps a
stable aggregate view for `show system buffers` and only emits per-binding rows
for `show system buffers detail`.

If mixed-version helpers omit a newer capacity surface, Go must fall back to the
older binding fields or clearly mark the row unavailable. It must not display
zero capacity for a live binding unless the helper explicitly reported zero.

The current helper status does not publish capacity denominators for the
session table, dynamic neighbor cache, or per-worker flow cache. `show system
buffers` therefore reports active sessions through the existing footer and
renders neighbor/flow-cache pressure as counts/counters, not fill percentages.
Adding true fill rows for those structures requires new optional helper fields
such as `session_table_entries/max_sessions`, `flow_cache_capacity`, and
`neighbor_cache_capacity`; Go must not hard-code Rust private constants to infer
those denominators.

## Hot-Path Invariants

- Telemetry sampling must not touch AF_XDP rings with contended atomics in the
  packet path.
- Formatters must tolerate mixed-version JSON with missing optional fields.
- Detail output may be verbose; non-detail output remains aggregate and stable.
- Counter/gauge types must stay stable for Prometheus consumers.

## State and HA Behavior

- Buffer telemetry is local per node and not HA-synchronized.
- Active-session footer uses the same session source as other userspace status
  commands so failover and helper restart do not report contradictory totals.
- Mixed-version cluster peers must still render useful local status.

## Risks

- False-zero capacity: missing fields rendered as zero can hide a compatibility
  problem and send operators chasing nonexistent ring exhaustion.
- False fill percentages: session, flow-cache, or neighbor-cache counts without
  matching denominators must remain counters until the helper publishes bounded
  capacity fields.
- Status drift: CLI, gRPC, and REST/metrics can diverge if they format different
  DTOs. Tests should use the same fixture through every output path.
- Sampling cost: overly frequent ring introspection can perturb the hot path;
  publish cadence and helper snapshots need bounded overhead.
- Schema churn: adding/removing fields without nil-aware fallbacks breaks
  mixed-version upgrades.

## Exact Tests

- Go: aggregate formatter omits per-binding rows, detail formatter includes
  them, and both preserve the active-session footer.
- Go: mixed-version status with sparse per-binding capacity falls back to
  binding-level capacity instead of rendering false zeroes.
- Go: gRPC `ShowText` and local CLI use the same userspace buffer fixture and
  produce equivalent text.
- Go: formatter covers CoS queued-byte capacity plus existing helper pressure
  counters without turning unbounded counts into utilization percentages.
- Integration: userspace cluster under forwarding load shows nonzero AF_XDP
  capacities, stable active sessions, and no status command hang.

## Non-Goals

- Do not change AF_XDP ring sizing policy in this PR.
- Do not make buffer telemetry HA state.
- Do not remove eBPF source as part of #1380.
