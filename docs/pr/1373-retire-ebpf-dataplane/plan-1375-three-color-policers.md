# #1375 Userspace Three-Color Policer Plan

## Goal

Add userspace support for Junos three-color policers so configs under
`firewall three-color-policer` no longer require the eBPF dataplane.

## Current Status

The bounded runtime slice is implemented after #1395:

- Rust compiles three-color policer snapshots into stable name-sorted runtime
  IDs and links filter terms to shared runtime handles.
- Live forwarding-path TX selection meters srTCM/trTCM policers, applies red
  drops for `then discard`, and records green/yellow/red/drop packet and byte
  counters.
- Flow-cache hits carry cached policer handles and meter them before cached
  forwarding.
- Rust status, Go protocol, status formatting, and Prometheus expose
  per-color/drop counters.
- `deriveUserspaceCapabilities()` admits the current color-blind `then
  discard` runtime slice for `firewall three-color-policer` configs.
- Rust snapshot parsing now also fails closed for bypassed or malformed
  three-color snapshots that request color-aware mode, non-`discard`
  actions, unknown modes, or invalid token parameters. Matching traffic is
  metered by an explicit unsupported runtime that returns red/drop, rather
  than silently unlinking the policer.
- Equivalent snapshot refreshes preserve token buckets and per-color counters
  by reusing the same runtime handle when the name-derived runtime ID and shape
  are unchanged. A changed mode, color mode, rate, burst, or treatment creates
  a fresh runtime.

Remaining #1375 work is validation and hardening rather than admission:

- Color-aware inherited-color handling remains fail-closed until packet
  metadata carries trusted incoming color end-to-end. This avoids silently
  promoting yellow/red traffic to green.
- Replace the per-policer mutex runtime with the approved sharded or packed
  atomic state if throughput testing shows contention.
- Decide whether #1373 needs HA/process-restart token continuity. Current
  continuity is local to compatible in-process snapshot refreshes.
- Wire non-drop per-color actions, especially loss-priority propagation, into
  the downstream forwarding/CoS path. Until then, non-`discard` three-color
  actions remain fail-closed.
- Run integration traffic, failover, and performance evidence for
  green/yellow/red classification and red drops.

## Dependencies

- #1381 should land first so userspace capability removal and snapshot delivery
  are owned by the userspace manager, not BPF-shaped map writers.
- Do not inherit the DPDK srTCM overflow bug; the Rust implementation must use
  the RFC contract below as the source of truth.

## Design

Extend the userspace policer snapshot and Rust types with srTCM, trTCM,
`color_blind`, color-aware input handling, and per-color actions for DSCP
rewrite plus red drop/count behavior. The current runtime enables only the
subset with enforceable semantics: color-blind metering and red drop/count
for `then discard`.

Use `u128` token refill math with `monotonic_nanos`. Reject invalid config at
compile/commit time: zero rate, zero burst, `PIR < CIR`, `PBS < CBS`, and
missing required three-color fields.

srTCM: C fills at CIR; E fills only when C is full and EBS remains; green
requires C tokens, yellow requires E tokens, red otherwise.

trTCM: C fills independently at CIR; P fills independently at PIR; green
requires both C and P tokens, yellow requires only P tokens, red otherwise.

Color-aware mode must respect incoming color and never promote packets above
their incoming color. Color-blind mode evaluates each packet without inherited
color. Until inherited color is carried in trusted packet metadata, userspace
must reject color-aware three-color policers rather than defaulting every
packet to green.

## Hot-Path Invariants

- Flow-cache hits still execute the policer before forwarding.
- No `f64` token math in the dataplane.
- No `FxHashMap<String, PolicerState>` mutable hot-path lookup. The current
  runtime uses stable name-sorted IDs with shared handles; sharded or packed
  atomic state remains the scaling follow-up.
- Per-color DSCP rewrite and red drop decisions happen in the same forwarding
  decision that accounts tokens.
- Per-color counters are attached to the stable policer runtime. The current
  counters use relaxed atomics per logical policer/color.
- Unsupported snapshot shapes that bypass Go admission must fail closed in
  Rust: terms still link a runtime handle, and every matching packet receives
  a red/drop decision.

## State and HA Behavior

- Policer token state is local runtime state. Compatible in-process snapshot
  refreshes preserve token and counter state by reusing the same runtime handle
  for the name-derived policer ID; failover or process restart may restart
  token buckets from configured burst values unless a broader HA state-sync PR
  explicitly adds token sync.
- Config snapshots carry stable policer/rule identity so counters survive
  compatible snapshot rebuilds where practical.
- Status exposes green/yellow/red packet and byte counters plus red drops
  through Rust status, Go protocol, CLI, and Prometheus.

## Risks

- Token overflow/math: refill uses rates, bursts, and elapsed time supplied by
  config and monotonic clocks. All multiplication must stay in `u128` or
  explicitly saturate before conversion to packet-size units.
- Atomicity: packed/sharded state must avoid cross-worker false sharing while
  preserving one logical bucket per configured policer identity.
- Color semantics: color-aware mode must never promote incoming yellow/red
  traffic; one wrong branch turns a security control into a bandwidth grant.
- Counter attribution: green/yellow/red/drop counters are stable inside a
  compiled runtime and across compatible in-process snapshot refreshes. Changed
  runtime shapes intentionally reset counters with the new rate/burst contract;
  failover/restart continuity remains out of scope until userspace owns a
  broader HA state-sync surface.

## Exact Tests

- Cargo: `policer::srTCM_green_yellow_red_at_thresholds`.
- Cargo: `policer::srTCM_c_overflow_refills_e_bucket`.
- Cargo: `policer::trTCM_independent_CIR_PIR`.
- Cargo: `policer::color_aware_never_promotes_incoming_yellow_or_red`.
- Cargo: `policer::color_blind_ignores_incoming_color`.
- Cargo: `policer::u128_bucket_math_boundary_inputs`.
- Cargo: `policer::three_color_dscp_rewrite`.
- Cargo: `filter::tests::three_color_runtime_ids_and_miss_path_counters_are_stable`.
- Cargo: `filter::tests::flow_cache_hits_run_three_color_policer`.
- Cargo: `filter::tests::unsupported_three_color_snapshots_fail_closed_in_rust_compiler`.
- Cargo: `filter::tests::three_color_empty_then_action_uses_default_discard`.
- Cargo: `filter::tests::equivalent_snapshot_refresh_preserves_three_color_state_and_counters`.
- Cargo: `filter::tests::changed_snapshot_shape_resets_three_color_runtime_state`.
- Go: userspace snapshot round-trip for three-color policer fields, per-color
  actions, and `ColorBlind`.
- Go: compiler validation rejects zero rates/bursts, `PIR < CIR`, and
  `PBS < CBS`.
- Go: `deriveUserspaceCapabilities()` admits three-color policer configs after
  the userspace snapshot and Rust runtime support are wired.
- Go: ProcessStatus, status formatting, and Prometheus tests cover
  three-color per-color/drop counters.
- Integration: controlled-rate traffic against userspace cluster verifies
  green/yellow/red classification, DSCP rewrite, red drop behavior, and
  per-color counters.

## Non-Goals

- Do not fix the separate DPDK srTCM dead-overflow bug in this PR.
- Do not redesign CoS shaping or scheduler behavior.
- Do not remove eBPF source as part of #1375.
