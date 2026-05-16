# #1375 Userspace Three-Color Policer Plan

## Goal

Add userspace support for Junos three-color policers so configs under
`firewall three-color-policer` no longer require the eBPF dataplane.

## Dependencies

- #1381 should land first so userspace capability removal and snapshot delivery
  are owned by the userspace manager, not BPF-shaped map writers.
- Do not inherit the DPDK srTCM overflow bug; the Rust implementation must use
  the RFC contract below as the source of truth.

## Design

Extend the userspace policer snapshot and Rust types with srTCM, trTCM,
`color_blind`, color-aware input handling, and per-color actions for DSCP
rewrite plus red drop/count behavior.

Use `u128` token refill math with `monotonic_nanos`. Reject invalid config at
compile/commit time: zero rate, zero burst, `PIR < CIR`, `PBS < CBS`, and
missing required three-color fields.

srTCM: C fills at CIR; E fills only when C is full and EBS remains; green
requires C tokens, yellow requires E tokens, red otherwise.

trTCM: C fills independently at CIR; P fills independently at PIR; green
requires both C and P tokens, yellow requires only P tokens, red otherwise.

Color-aware mode must respect incoming color and never promote packets above
their incoming color. Color-blind mode evaluates each packet without inherited
color.

## Hot-Path Invariants

- Flow-cache hits still execute the policer before forwarding.
- No `f64` token math in the dataplane.
- No `FxHashMap<String, PolicerState>` mutable hot-path lookup as the final
  production model; use stable rule IDs with sharded or packed atomic state.
- Per-color DSCP rewrite and red drop decisions happen in the same forwarding
  decision that accounts tokens.
- Per-color counters are updated without central hot atomics.

## State and HA Behavior

- Policer token state is local runtime state; failover may restart token buckets
  from configured burst values unless a broader HA state-sync PR explicitly
  adds token sync.
- Config snapshots carry stable policer/rule identity so counters can survive
  snapshot rebuilds where practical.
- Status exposes green/yellow/red packet and byte counters, DSCP rewrites, and
  red drops through Rust status, Go protocol, CLI, and Prometheus.

## Risks

- Token overflow/math: refill uses rates, bursts, and elapsed time supplied by
  config and monotonic clocks. All multiplication must stay in `u128` or
  explicitly saturate before conversion to packet-size units.
- Atomicity: packed/sharded state must avoid cross-worker false sharing while
  preserving one logical bucket per configured policer identity.
- Color semantics: color-aware mode must never promote incoming yellow/red
  traffic; one wrong branch turns a security control into a bandwidth grant.
- Counter attribution: green/yellow/red/drop counters must survive snapshot
  rebuilds by stable identity, or operators cannot audit policer behavior after
  commits.

## Exact Tests

- Cargo: `policer::srTCM_green_yellow_red_at_thresholds`.
- Cargo: `policer::srTCM_c_overflow_refills_e_bucket`.
- Cargo: `policer::trTCM_independent_CIR_PIR`.
- Cargo: `policer::color_aware_never_promotes_incoming_yellow_or_red`.
- Cargo: `policer::color_blind_ignores_incoming_color`.
- Cargo: `policer::u128_bucket_math_boundary_inputs`.
- Cargo: `policer::three_color_dscp_rewrite`.
- Cargo: `policer::flow_cache_hits_run_policer`.
- Go: userspace snapshot round-trip for three-color policer fields, per-color
  actions, and `ColorBlind`.
- Go: compiler validation rejects zero rates/bursts, `PIR < CIR`, and
  `PBS < CBS`.
- Go: `deriveUserspaceCapabilities()` admits three-color policer configs only
  after the userspace snapshot and Rust runtime support are wired, and rejects
  them before that point.
- Integration: controlled-rate traffic against userspace cluster verifies
  green/yellow/red classification, DSCP rewrite, red drop behavior, and
  per-color counters.

## Non-Goals

- Do not fix the separate DPDK srTCM dead-overflow bug in this PR.
- Do not redesign CoS shaping or scheduler behavior.
- Do not remove eBPF source as part of #1375.
