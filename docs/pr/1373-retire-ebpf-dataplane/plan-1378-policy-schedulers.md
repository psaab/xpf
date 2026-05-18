# #1378 Userspace Policy Scheduler Plan

## Goal

Propagate Junos `schedulers { ... }` state into userspace policy evaluation so
scheduled policy rules activate and deactivate correctly without the eBPF
`policy_rules` map.

## Dependencies

- The safe slice no longer waits on #1381. The userspace manager now shadows
  `UpdatePolicyScheduleState` and republishes a userspace snapshot instead of
  falling through to the embedded eBPF manager.

## Design

Add `SchedulerName string`, `Inactive bool`, and a stable rule identity to
`PolicyRuleSnapshot` and `userspace-dp/src/policy.rs::PolicyRule`. The stable
identity must not depend on transient array position alone; use a config-driven
UUID if available or `(policy_set_id, policy_name, rule_name)`/equivalent
compiled identity.

Safe #1378 slice status: this change wires `rule_id`, `scheduler_name`, and
`inactive` through userspace policy snapshots and Rust policy evaluation. The
daemon reconciles the scheduler lifecycle on every committed config while
holding the apply semaphore; userspace snapshot rebuilds are seeded with that
same active-state map, and runtime scheduler ticks acquire the same semaphore
before publishing one coherent snapshot delta. Missing scheduler references are
compile errors.

Closeout update, 2026-05-17: the strict missing-scheduler validator now runs
inside `CompileConfig`, so zone and global policies that reference undefined
schedulers fail commit instead of entering the warning-only path. Rust policy
hit counters are stored behind stable rule-id keyed atomics, so active/inactive
scheduler snapshot rebuilds reuse the existing counter when the rule identity
is unchanged. The remaining #1378 blocker is integration/HA failover evidence:
show that the new active node recomputes scheduler state and publishes the full
policy snapshot before admitting scheduled-policy traffic.

Closeout update, 2026-05-18: `test/incus/policy_scheduler_validate.py` now
defines the deterministic evidence contract for that remaining lab gate. It
requires helper/control-socket status from the userspace runtime, protocol
version >= 2, `forwarding_supported=true`, `forwarding_armed=true`, policy
rule counters that advance while the scheduler is active, survive a full
snapshot rebuild, stay unchanged while the scheduler is inactive, advance again
after RG failover on the new userspace owner, and a captured commit failure for
an undefined scheduler. `pkg/daemon/policy_scheduler_apply_test.go` also pins
the non-eBPF apply path: scheduler state is seeded before userspace compile and
the initial userspace apply does not fall back to `UpdatePolicyScheduleState`
legacy map updates.

On scheduler state changes, publish one atomic userspace snapshot delta that
contains the updated inactive bits for all affected rules. Do not issue
per-rule fast-path toggles because first-match ordering requires same-instant
activate/deactivate semantics.

`evaluate_policy` skips inactive rules before address/application matching.
This is on the new-flow/session-miss path; flow-cache hits keep forwarding
existing sessions unless a separate `policy-rematch` feature is implemented.
That matches Junos default behavior: schedulers block new lookups, not existing
sessions.

Scheduler granularity is 60 seconds. The wall clock is used only by the Go
control-plane scheduler to decide the next active-state map; workers receive
booleans in the snapshot and never evaluate wall-clock time in the packet path.
The scheduler compares wall elapsed time with Go's monotonic elapsed time at
each evaluation. Backward wall-clock steps or drift beyond tolerance fail
closed for that evaluation by publishing all scheduler bits inactive.
Tests and docs must use deterministic scheduler inputs or windows that span
multiple evaluator ticks; the earlier 30-second integration target is invalid.

Missing scheduler references fail closed as commit errors. Do not copy the
existing eBPF behavior that can default missing scheduler state to active.

## Hot-Path Invariants

- One inactive-branch per rule on miss path is acceptable; no scheduler clock
  evaluation occurs in the packet worker.
- Snapshot publication is ArcSwap-atomic across all rule inactive bits.
- Snapshots carrying scheduler inactive bits require protocol version 2; the
  Rust control server rejects older/unknown snapshot versions instead of
  silently ignoring scheduling fields, and status exposes the helper's supported
  snapshot protocol so new Go refuses to publish scheduled-policy snapshots to
  an old helper before the fail-open path can occur. The refusal actively
  disarms helper forwarding with `set_forwarding_state armed=false`; recording
  a compile error while leaving the old helper armed is not fail-closed.
- Hit counters are keyed by stable rule identity outside rebuilt rule structs;
  rebuilt policy snapshots share the same per-rule atomic while a rule identity
  remains present in the snapshot, so counters survive scheduler active/inactive
  flips and same-process policy rebuilds.
- Do not copy the existing eBPF indexing bug in
  `UpdatePolicyScheduleState`; userspace updates must target stable identities.

## State and HA Behavior

- Scheduler active state is control-plane derived from config and daemon clock;
  it is republished after config load, daemon restart, and scheduler state
  change.
- Existing sessions continue until normal timeout unless policy-rematch is
  explicitly configured in a later feature.
- Counters persist across active/inactive flips and snapshot rebuilds.
- HA failover recomputes scheduler state on the new active node and publishes a
  complete policy snapshot before admitting scheduled-policy traffic.

## Risks

- Scheduler atomicity: first-match policy ordering requires affected inactive
  bits to publish as one coherent snapshot. Per-rule toggles can expose an
  impossible mixed policy state.
- Clock drift: scheduler state is daemon-clock derived. The scheduler must
  fail closed on wall-clock discontinuity, and HA peers must recompute after
  failover rather than trusting stale peer-local state.
- Counter continuity: stable rule identity is mandatory because inactive flips
  and snapshot rebuilds must not reset operator-visible hit counters.
- Missing scheduler references: fail-open behavior admits traffic outside the
  intended time window; userspace must reject these commits explicitly.

## Exact Tests

- Cargo: `policy::evaluate_policy_skips_inactive_rules`.
- Cargo: `policy::inactive_rule_falls_through_to_next_match`.
- Cargo: `policy::hit_counters_survive_scheduler_snapshot_rebuild`.
- Cargo: `policy::hit_counters_reset_after_rule_absent_then_readded`.
- Go: userspace snapshot round-trip for `SchedulerName`, `Inactive`, and stable
  rule identity.
- Go: deterministic scheduler clock tests for active/inactive windows at
  60-second granularity.
- Go: `UpdatePolicyScheduleState` in userspace mode republishes one snapshot
  delta with updated inactive bits.
- Go: userspace apply seed test proves initial scheduled-policy snapshots are
  built from daemon-computed active state without invoking legacy eBPF policy
  map updates.
- Go: missing scheduler reference is a commit error.
- Python: `test/incus/policy_scheduler_validate.py` validates the live artifact
  set for active, rebuild, inactive, failover, and missing-scheduler rejection.
- Integration: scheduler window spanning multiple 60-second ticks with a policy
  referencing it; new connections pass only during active windows, while
  established sessions retain Junos-default behavior.

## Integration Evidence Harness

The #1378 live evidence directory must contain:

- `active-status.json`: helper `{"type":"status"}` response after active
  scheduled-policy traffic increments the stable rule counter.
- `rebuild-status.json`: helper status after a full snapshot rebuild with the
  same rule identity; the counter must not go backward.
- `inactive-status.json`: helper status after the scheduler is inactive and a
  new connection attempt was made; the scheduled rule counter must remain equal
  to `rebuild-status.json`.
- `failover-status.json`: helper status from the new RG owner after failover
  and post-failover scheduled-policy traffic; the counter must advance.
- `missing-scheduler-commit.txt`: `commit check` or `commit` output for a
  policy referencing an undefined scheduler; it must contain the strict
  undefined-scheduler rejection and no commit-success text.

Validate the directory from the repo root:

```bash
python3 test/incus/policy_scheduler_validate.py \
  <artifact-dir> \
  --rule-id 'trust->untrust/scheduled-allow'
```

The validator intentionally fails if the artifacts show `ebpf_only`, missing
protocol v2 support, unarmed/unsupported userspace forwarding, counter reset on
rebuild, counter growth while inactive, no post-failover counter growth, or a
successful missing-scheduler commit.

Validated in the 2026-05-17 closeout slice:

- `go test ./pkg/config`
- `go test ./pkg/dataplane/userspace -run 'Test(BuildPolicySnapshots|UpdatePolicyScheduleState)'`
- `cargo test policy:: -- --nocapture`

Validated in the 2026-05-18 closeout slice:

- `go test ./pkg/daemon -run 'TestPolicyScheduler|TestApplyConfig.*Scheduler|TestApplyConfig.*Protocol'`
- `python3 test/incus/policy_scheduler_validate_test.py`

## Non-Goals

- Do not implement multi-scheduler-per-rule; current config supports one.
- Do not implement policy-rematch/session flush in this PR.
- Do not remove eBPF source as part of #1378.
