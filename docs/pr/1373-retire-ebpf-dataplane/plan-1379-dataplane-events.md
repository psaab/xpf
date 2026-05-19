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

Current implementation status after the 2026-05-19 closeout slice:

- Frame types 11/12/13 are reserved and covered by Rust golden tests.
- Rust encodes and decodes fixed-size 136-byte RT_FLOW payloads for policy
  deny, screen drop, and filter log records.
- Go decodes and dispatches these frames through the existing logging path and
  exposes daemon-side event/drop counters.
- Rust helper producer infrastructure now provides
  `try_emit_dataplane_event_at()` with fixed-size non-blocking queueing,
  per-event/per-ingress-zone rate limiting, generic producer sent/dropped
  counters, and per-event loss reason accounting.
- Runtime producers cover userspace policy deny, screen drop, logged PBR
  filter hits, non-PBR input filter logs, live and cached output filter logs,
  and lo0/local-delivery filter logs. Non-PBR input filter-log matching runs
  only on the slow path after a flow-cache miss. Non-PBR input filter
  `discard`/`reject` actions are terminal before route lookup and policy
  evaluation; logged terminal actions emit `source=input` with deny/reject RT_FLOW
  action. If the first permitted packet installs a flow-cache entry, the matched
  input log term and ingress-zone ID are stored in that entry and cached hits
  re-emit `source=input` without rescanning filter terms.
- Policy deny records carry the userspace snapshot's numeric policy ID. Filter
  log records carry the compiled filter ID, term ID, action, and source
  (`pbr`, `input`, `output`, `cached-output`, or `lo0`). These IDs are
  deterministic inside the compiled snapshot and intentionally avoid invented
  names or unstable runtime-only identifiers.
- The `lo0` source label means a userspace local-delivery packet matched the
  configured lo0 log term. It does not claim that kernel/nft lo0 ingress
  enforcement moved into the AF_XDP helper.
- The event-stream wire format is a helper/daemon lockstep contract. For
  `MSG_FILTER_LOG`, the RT_FLOW reason byte carries the source label above;
  close events continue to interpret the same byte as a close reason. This is
  event-stream semantics, not a config-snapshot protocol field.
- `pkg/dataplane/userspace/eventstream_test.go` includes a deterministic UDP
  syslog harness that feeds raw userspace policy-deny, screen-drop, and
  filter-log frames through the Go event-stream callback, `EventReader`, and
  syslog fanout path.

Emission points:

- policy deny path in `userspace-dp/src/afxdp/poll_descriptor.rs`
- screen drop path in `userspace-dp/src/afxdp/poll_stages.rs`
- logged PBR filter-hit path in `userspace-dp/src/afxdp/forwarding/mod.rs`
- non-PBR input and lo0/local-delivery filter-log helpers in
  `userspace-dp/src/afxdp/poll_descriptor.rs`
- live output filter-log path in `userspace-dp/src/afxdp/forward_request.rs`
  and cached output filter-log path in the flow-cache hit path in
  `userspace-dp/src/afxdp/poll_descriptor.rs`

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
- Dataplane telemetry must not monopolize the shared event-stream queue:
  in-flight telemetry is capped to a bounded share of the channel, and each
  event kind has its own cap so one storm leaves capacity for session/control
  frames and other telemetry kinds.
- Per-source-zone/per-event token-bucket-equivalent rate limiting must run
  before sequence allocation to prevent deny storms from starving session
  open/close/update events without creating sequence gaps for limiter drops.
- Event frames stay within the existing 256-byte-ish event budget unless the
  codec is explicitly resized and tested.
- Policy evaluation returns enough rule/policy metadata for event creation; no
  post-hoc heap lookup on the worker hot path. Application-specific numeric
  identity remains limited to the compiled policy slot until the snapshot schema
  carries stable per-expansion application identity.

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
- Cargo: non-PBR input filter-log helper returns compiled filter/term/action
  identity and skips routing-instance terms so PBR logs are not double-emitted.
- Cargo: output filter-log forwarding emits a fixed-size event with correct
  zone and filter identity.
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
- Go: raw userspace policy-deny, screen-drop, and filter-log frames feed
  through the event-stream callback, `EventReader.ProcessRawEvent`, and UDP
  syslog fanout with per-event counters intact. FILTER_LOG syslog includes the
  source label so operators can distinguish PBR and non-PBR hits without
  reverse-engineering compiled term IDs.
- Go: daemon dispatch test covers userspace source selection or fan-in without
  duplicate records.
- Integration: userspace cluster with deny policy, screen drop, and filter log
  term; generated traffic produces matching syslog records with no session
  event starvation under a deny storm.

## Remaining Gaps

- Run live userspace-cluster syslog validation for deny policy, screen drop,
  PBR filter log, non-PBR input/output filter log, and lo0/local-delivery filter
  log traffic. The local UDP syslog harness proves the Go decode/fanout path,
  but it is not operator evidence from a real cluster.
- Run a live deny-storm validation that proves policy/screen/filter telemetry
  does not starve session event delivery and that per-event loss counters remain
  auditable under backpressure.
- Carry stable per-expanded-application identity in the userspace snapshot if
  audit parity requires distinguishing multiple application expansions within a
  single configured policy rule. The current numeric policy ID is stable for the
  compiled policy slot and avoids inventing unstable IDs.

## Non-Goals

- Do not replace the HA session-sync event stream with this logging adapter.
- Do not emit FilterLog for count-only filter terms.
- Do not make event delivery reliable at Mpps flood rates; rate-limited loss
  with counters is acceptable.
- Do not remove eBPF source as part of #1379.
