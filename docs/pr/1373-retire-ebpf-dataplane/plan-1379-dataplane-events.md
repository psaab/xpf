# #1379 Userspace Dataplane Events Plan

## Goal

Emit userspace-dp per-flow `PolicyDeny`, `ScreenDrop`, and `FilterLog` events
with eBPF syslog parity so removing the eBPF ring buffer does not regress
security visibility or audit logging.

## Dependencies

- #1381 must land first or in the same stack. Daemon event-source selection and
  userspace manager ownership are tightly coupled to the DataPlane interface
  split.
- #1378-style policy/rule identity plumbing is useful for high-fidelity policy
  event fields; coordinate identity shape across both PRs.

## Design

Add frame types to `userspace-dp/src/event_stream/codec.rs`:

- `MSG_POLICY_DENY = 11`
- `MSG_SCREEN_DROP = 12`
- `MSG_FILTER_LOG = 13`

Keep existing message values stable and add golden codec tests for old and new
frames.

The frame layout must fit the existing fixed-size event budget and carry the
fields needed to reproduce eBPF `dataplane.Event` semantics, including source
and destination tuple, ingress ifindex/interface name path, zone data,
policy/rule/application identity, reason, NAT-rewritten tuple when applicable,
and timestamp.

Current implementation status after #1394 and this infrastructure slice:

- Frame types 11/12/13 are reserved and covered by Rust golden tests.
- Rust encodes and decodes fixed-size 136-byte RT_FLOW payloads for policy
  deny, screen drop, and filter log records.
- Go decodes and dispatches these frames through the existing logging path and
  exposes daemon-side event/drop counters.
- Rust helper producer infrastructure now provides
  `try_emit_dataplane_event_at()` with fixed-size non-blocking queueing,
  per-event/per-ingress-zone rate limiting, generic producer sent/dropped
  counters, and per-event loss reason accounting.

Emission points:

- policy deny path in `userspace-dp/src/policy.rs`
- screen drop path in `userspace-dp/src/screen.rs`
- filter log term path in `userspace-dp/src/filter/engine.rs`

FilterLog matches BPF semantics: emit only for `then log` / `then syslog`, not
plain `then count`.

Go adds a userspace logging `EventSource` adapter that converts these frames
into the same `dataplane.Event` records consumed by `pkg/logging/ringbuf.go`.
During the overlap phases before BPF removal, use either a composite fan-in
source or explicit dataplane-mode event source selection. The daemon must not
silently keep reading only the legacy eBPF ring buffer while userspace owns the
forwarding decision.

## Hot-Path Invariants

- Event emission is fixed-size, no heap, copy-by-value, and non-blocking.
- Use `try_emit_dataplane_event_at()`; a full event queue drops the event and
  increments both the generic producer drop counter and per-event queue-full
  accounting.
- Per-source-zone/per-event token-bucket-equivalent rate limiting must run
  before sequence allocation to prevent deny storms from starving session
  open/close/update events without creating sequence gaps for limiter drops.
- Event frames stay within the existing 256-byte-ish event budget unless the
  codec is explicitly resized and tested.
- Policy evaluation returns enough rule/policy/app metadata for event creation;
  no post-hoc heap lookup on the worker hot path.

## State and HA Behavior

- Event stream is operational telemetry, not synchronized HA state.
- Dropped-event counters are local per node and exposed in userspace status,
  CLI, and Prometheus.
- On failover, the new active node emits events for decisions it owns; no event
  replay is required.
- Fan-in/source selection must avoid duplicate syslog records when both legacy
  eBPF and userspace event sources are present during migration.

## Risks

- Duplicate/lost syslog events: overlap mode must select exactly one source for
  a decision or explicitly de-duplicate fan-in records.
- Deny storms: policy or screen drops can arrive at Mpps rates. Rate limiting
  and non-blocking queue behavior must prevent event emission from becoming a
  forwarding bottleneck.
- Metadata fidelity: policy/rule/application identity must be available at the
  decision point; reconstructing it later from mutable config risks wrong audit
  records after commits.
- Codec compatibility: adding event types must not renumber existing session
  frames or mixed-version readers will decode the wrong event kind.

## Exact Tests

- Cargo: codec encode/decode round-trip for `MSG_POLICY_DENY`.
- Cargo: codec encode/decode round-trip for `MSG_SCREEN_DROP`.
- Cargo: codec encode/decode round-trip for `MSG_FILTER_LOG`.
- Cargo: golden codec tests for existing session frame type values.
- Cargo: policy deny path emits a fixed-size event with correct metadata.
- Cargo: screen drop path emits a rate-limited event and accounts drops when
  the limiter is empty.
- Cargo: filter log emits only for log/syslog terms, not count-only terms.
- Cargo: producer API queues admitted RT_FLOW events without blocking and
  accounts per-event sent counts.
- Cargo: rate limiting is per event kind and ingress zone, and limiter drops do
  not allocate sequence numbers.
- Cargo: event queue full and disconnected paths use non-blocking
  drop-and-count behavior with per-event loss reason accounting.
- Go: userspace `EventSource` adapter converts each new frame into the expected
  `dataplane.Event`.
- Go: `pkg/logging/ringbuf_test.go` or equivalent verifies identical
  `RT_FLOW_SESSION_DENY`, screen-drop, and filter-log syslog output for eBPF
  and userspace events.
- Go: daemon dispatch test covers userspace source selection or fan-in without
  duplicate records.
- Integration: userspace cluster with deny policy, screen drop, and filter log
  term; generated traffic produces matching syslog records with no session
  event starvation under a deny storm.

## Remaining Gaps

- Wire policy deny, screen drop, and filter log runtime producer call sites to
  the Rust producer API without colliding with #1374/#1375/#1378 workstreams.
- Surface the helper-side per-event loss reason counters in status JSON,
  CLI/status formatting, and Prometheus if the follow-up wants operator-visible
  attribution beyond the existing aggregate `event_stream_dropped` producer
  counter.
- Run end-to-end userspace syslog validation for deny policy, screen drop, and
  filter log traffic, including a deny-storm case that proves session event
  delivery is not starved.

## Non-Goals

- Do not replace the HA session-sync event stream with this logging adapter.
- Do not emit FilterLog for count-only filter terms.
- Do not make event delivery reliable at Mpps flood rates; rate-limited loss
  with counters is acceptable.
- Do not remove eBPF source as part of #1379.
