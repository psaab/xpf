---
status: PLAN-READY v3 — Codex round-2 PLAN-NEEDS-MINOR addressed (CLI file path, CoSQueueConfig step, validation-rule citation, end-to-end test tightening); Gemini Pro 3 round-2 PLAN-READY ✅
issue: https://github.com/psaab/xpf/issues/915
phase: Add `surplus-sharing` opt-in for exact CoS queues
---

## Changelog v3

Codex round-2 (`task-morzhmoo-pobdx3`) returned PLAN-NEEDS-MINOR
with 4 trivial findings; Gemini Pro 3 round-2 (`task-morzi1xz-rqwsd8`)
returned PLAN-READY ✅ with no findings.

Codex round-2 v3 fixes:

- **MINOR — §4.7 stale CLI file path**: `pkg/cli/cli_show_cos.go`
  does not exist; actual path is `pkg/cli/cli_show_services.go`
  which delegates to `pkg/dataplane/userspace/cosfmt.go`.
  Updated §4.7 to point only at `cosfmt.go` (no separate CLI
  mirror needed).

- **MINOR — §4.3 missing intermediate `CoSQueueConfig` step**:
  v2 went straight from snapshot → `CoSQueueRuntime`. Actual
  flow is snapshot scheduler → `CoSQueueConfig`
  (userspace-dp/src/afxdp/types/cos.rs:50) → `build_cos_runtime`
  (userspace-dp/src/afxdp/cos/builders.rs:90) →
  `CoSQueueRuntime`. v3 §4.3 names both copy sites explicitly.

- **MINOR — §4.9 contradicts §4.2 on validation location**:
  v2 §4.9 said `compiler_class_of_service.go` emits the
  warning; v2 §4.2 correctly puts it in
  `pkg/config/compiler.go:ValidateConfig` (which runs after
  typed CoS compilation and has access to
  `cfg.ClassOfService.Schedulers`). v3 removes §4.9's
  duplicate; §4.2 is the canonical statement.

- **MINOR — §8 end-to-end test too loose**: Codex flagged
  that a test which only calls `select_cos_surplus_batch` does
  not prove the no-park branch was crossed. v3 §8 keeps the
  isolation tests AND adds an explicit production-order test
  that drives `drain_shaped_tx` (or sequentially calls
  `select_exact_cos_guarantee_queue_with_fast_path` then
  `select_cos_surplus_batch`) so the parking blocker can't
  reappear outside the surplus selector unit test.

Gemini PASS confirmed all v2 round-2 mechanics: no-park
branch, phase-gated lease, opt-in default, strict-priority,
DRR fairness, validation strip semantics, smoke contention
scenario, no new MAJOR.

## Changelog v2

Codex round-1 (`task-morz4uac-7srr47`) returned PLAN-NEEDS-MAJOR
with 4 blockers; Gemini Pro 3 round-1 (`task-morz59nh-p9hebp`)
returned PLAN-NEEDS-MINOR with 2 (both subsumed by Codex):

- **MAJOR — park-on-starvation race (Codex 1)**: An exact queue
  whose `queue.tokens < head_len` is parked (`queue.runnable =
  false`) by `select_exact_cos_guarantee_queue_with_fast_path`
  before the surplus phase runs. Once parked, surplus skips it
  via `!queue.runnable` at queue_service/mod.rs:572. v1's
  one-line surplus-skip removal would never trigger. **Fix
  (§4.4)**: in the exact-guarantee selector, when
  `queue.exact && queue.surplus_sharing && queue.tokens <
  head_len`, do NOT park — just `continue` so the queue stays
  runnable and falls through to `select_cos_surplus_batch` on
  the same drain pass.

- **MAJOR — `shared_queue_lease` consumption on surplus (Codex
  2)**: Exact queues unconditionally debit `shared_queue_lease`
  in `apply_cos_send_result` (tx_completion.rs:449-458) and
  `apply_cos_prepared_result` (tx_completion.rs:515-524), based
  solely on `queue.exact`. Surplus-sharing bytes would also
  debit the per-queue lease, violating the "surplus consumes
  only root tokens" claim. **Fix (§4.5)**: phase-gate the lease
  consumption — only consume `shared_queue_lease` when `phase ==
  CoSServicePhase::Guarantee`. Safe today because non-surplus-
  sharing exact queues never reach Surplus phase, so this
  changes no current behavior.

- **MAJOR — Rust JSON reader missing serde default (Codex 3 +
  Gemini #7)**: `userspace-dp/src/protocol.rs:CoSSchedulerSnapshot`
  needs `#[serde(default)] pub surplus_sharing: bool`. Go
  `omitempty` covers the writer side; the Rust reader needs
  `default` so older snapshots (without the field) decode safely.
  **Fix (§4.2)**: add to the snapshot schema list.

- **MAJOR — Config schema target wrong/incomplete (Codex 4)**:
  Parser acceptance lives in `pkg/config/ast.go`, not just
  `pkg/cmdtree/tree.go`. Validation belongs in `ValidateConfig`
  in `pkg/config/compiler.go`, not only
  `compiler_class_of_service.go`. **Fix (§4.2)**: add the leaf
  to `ast.go`'s `class-of-service schedulers <name>` block;
  put the warn-and-strip rule in `ValidateConfig`.

- **MINOR — CLI exposure (Gemini #8 + Codex non-blocking)**:
  Add `surplus-sharing` to per-queue CLI output via
  `pkg/dataplane/userspace/cosfmt.go`. **Fix (§4.6)**.

- **MINOR — stale `select_combined_cos_batch` reference**:
  That symbol does not exist; the actual entry point is
  `drain_shaped_tx → service_exact_guarantee_queue_direct_with_info
  → build_nonexact_cos_batch → select_nonexact_cos_guarantee_batch
  || select_cos_surplus_batch`. **Fix throughout §4-§6**:
  reference correct symbols.

Plan v1's other points (opt-in default correct, strict-priority
preserved, DRR fairness OK, surplus phase already excludes
`queue.tokens` consumption) all confirmed by both reviewers.

## 1. Issue framing

`exact` CoS queues are non-work-conserving: even when the root
shaper has slack and other queues are idle, an `exact 1G` queue
sitting on a 100 G interface shaped to 10 G stays at 1 G forever.
This matches Junos `exact` strict semantics (hard-cap), but
operators have asked for a way to opt an `exact` queue into
surplus participation while keeping its guarantee floor.

Issue #915 proposes:

1. Remove the hard `queue.exact` skip in
   `select_cos_surplus_batch`.
2. Introduce a config attribute (e.g. `surplus-sharing`)
   to control this behavior, **or** allow it by default if
   `surplus_weight` is non-zero.

## 2. Honest scope/value framing

This is a **non-Junos extension**, not a bug fix. Junos
`transmit-rate <r> exact` is by design a hard cap — the whole
point of the `exact` qualifier. The proposal adds a
`surplus-sharing` qualifier on the scheduler that, when set on
an `exact` queue, lifts the surplus skip and lets the queue
draw from root surplus tokens once its own guarantee phase has
finished.

Concrete operator value: an `iperf-a 1 Gbps exact` queue on a
10 Gbps interface can burst into the spare 9 Gbps when no other
class is hungry, then drop back to 1 Gbps when contention
returns.  Per #915's "100E100M" framing this is the canonical
high-utilization scenario.

If reviewers conclude the operator value is too small to
justify the config-schema + plumbing churn, PLAN-KILL is an
acceptable verdict.

## 3. What's already shipped / partially batched

- `TransmitRateExact bool` already plumbs through
  `pkg/config/types.go:359 → pkg/dataplane/userspace/protocol.go:179
  → userspace-dp/src/afxdp/types/cos.rs:409 (queue.exact)`.
- `cos_surplus_weight` at `userspace-dp/src/afxdp/forwarding_build.rs:858`
  already computes a per-queue weight in [1, 16] proportional to
  configured rate / root rate. Every queue (including exact ones)
  already has a non-zero `surplus_weight` — that means the
  "default-on if `surplus_weight > 0`" form of the issue's
  proposed fix would silently flip every existing `exact` queue
  into work-conserving mode. **This is not what we want as the
  default**, because it breaks the Junos contract for every
  operator already running `transmit-rate <r> exact`. The plan
  picks the **explicit opt-in** form.
- `select_cos_surplus_batch` is at
  `userspace-dp/src/afxdp/cos/queue_service/mod.rs:561-615`. The
  guarantee phase already calls
  `select_exact_cos_guarantee_queue_with_fast_path` BEFORE the
  surplus phase, so the guarantee floor is preserved by the
  existing schedule order — no token-bucket changes needed in
  this plan.

## 4. Concrete design

### 4.1 Config syntax (Junos-style extension)

```
set class-of-service schedulers iperf-a transmit-rate 1g exact
set class-of-service schedulers iperf-a surplus-sharing
```

Both hierarchical (`schedulers iperf-a { surplus-sharing; }`)
and flat-set are supported by the existing parser. The flag is
a leaf node with no value; presence = true. Default =
absent = false.

The flag is **only meaningful on `exact` queues**. On
non-exact queues it has no effect (they already participate in
surplus). Validation emits a warning if `surplus-sharing` is
set without `transmit-rate <r> exact` so operators don't think
they've asked for new behavior they didn't get; doesn't reject
the config.

### 4.2 Go config plumbing

- `pkg/config/types.go:CoSScheduler`: add
  `SurplusSharing bool`.
- `pkg/config/ast.go`: add `surplus-sharing` as a leaf node in
  the `class-of-service schedulers <name>` block (per Codex
  round-1 MAJOR 4 — parser acceptance lives here, not in
  `cmdtree`). Mirror the existing `exact` leaf's shape on
  `transmit-rate`.
- `pkg/config/compiler_class_of_service.go`: extract
  `surplus-sharing` leaf inside the scheduler block. Sets
  `sched.SurplusSharing = true` on presence.
- `pkg/config/compiler.go:ValidateConfig`: per-scheduler post-
  parse rule (per Codex round-1 MAJOR 4) — when
  `sched.SurplusSharing && !sched.TransmitRateExact`, append a
  validation warning `"surplus-sharing on scheduler %q is
  meaningful only with transmit-rate exact; ignored"` and clear
  `sched.SurplusSharing` (warn-and-strip per #1183 lesson —
  effective state never carries the no-op flag).
- `pkg/dataplane/userspace/protocol.go:CoSSchedulerSnapshot`:
  add `SurplusSharing bool` JSON field (`omitempty`).
- `pkg/dataplane/userspace/snapshot.go`: copy
  `sched.SurplusSharing` into the snapshot per scheduler.
- `userspace-dp/src/protocol.rs:CoSSchedulerSnapshot`: add
  `#[serde(rename = "surplus_sharing", default)] pub
  surplus_sharing: bool` (per Codex round-1 MAJOR 3 + Gemini
  round-1 #7 — `default` is required so older snapshots without
  the field decode without panic).
- `pkg/cmdtree/tree.go`: add the new leaf under
  `class-of-service schedulers <name>` for tab-completion / `?`
  help on the CLI.

### 4.3 Rust runtime plumbing

The snapshot → runtime flow has THREE Rust struct layers
(per Codex round-2 MINOR 2): `CoSSchedulerSnapshot` (wire
format, src/protocol.rs) → `CoSQueueConfig` (intermediate,
src/afxdp/types/cos.rs:50) → `CoSQueueRuntime`
(hot-path, src/afxdp/types/cos.rs:405). `surplus_sharing`
must be added to all three with explicit copy steps.

- `userspace-dp/src/afxdp/types/cos.rs:CoSQueueConfig`: add
  `pub(in crate::afxdp) surplus_sharing: bool`. This is the
  intermediate config built from the snapshot before the
  runtime is materialized.
- `userspace-dp/src/afxdp/types/cos.rs:CoSQueueRuntime`: add
  `pub(in crate::afxdp) surplus_sharing: bool`. Doc-comment
  records: "Only meaningful when `exact == true`. When set,
  the queue (1) is NOT parked on `queue.tokens < head_len` in
  the exact-guarantee selector, and (2) participates in
  `select_cos_surplus_batch` as if it were non-exact. The
  combined effect is that the queue retains its strict-priority
  guarantee but can also draw from root surplus tokens once its
  own bucket is empty (#915)."
- `userspace-dp/src/afxdp/forwarding_build.rs`: populate
  `CoSQueueConfig.surplus_sharing` from
  `scheduler.surplus_sharing`, defaulting to `false`. Mirror
  the `exact` field's `.map(...).unwrap_or(false)` shape.
- `userspace-dp/src/afxdp/cos/builders.rs:build_cos_runtime`:
  copy `config.surplus_sharing` into
  `CoSQueueRuntime.surplus_sharing` alongside the existing
  `config.exact` copy. The builders test
  (`cos_queue_runtime_propagates_surplus_sharing` in §8)
  exercises this site.

### 4.4 Surplus-skip change in `select_cos_surplus_batch`

`userspace-dp/src/afxdp/cos/queue_service/mod.rs:572` —
change the surplus-phase skip from

```rust
if cos_queue_is_empty(queue) || !queue.runnable || queue.exact {
    continue;
}
```

to

```rust
if cos_queue_is_empty(queue) || !queue.runnable {
    continue;
}
if queue.exact && !queue.surplus_sharing {
    continue;
}
```

Two-stage gate keeps the empty/non-runnable fast skip unchanged
and the `exact && !surplus-sharing` skip explicit for
grep-ability.

### 4.5 No-park rule for surplus-sharing exact queues (Codex MAJOR 1)

`userspace-dp/src/afxdp/cos/queue_service/mod.rs:452-473` —
the `queue.tokens < head_len` branch in
`select_exact_cos_guarantee_queue_with_fast_path` parks the
queue so subsequent drain passes wait for refill. For
surplus-sharing exact queues we want the queue to stay
runnable so it falls through to surplus phase on the same
drain pass. Change:

```rust
if queue.tokens < head_len {
    queue.owner_profile.drain_park_queue_tokens
        .fetch_add(1, Ordering::Relaxed);
    if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
        root.tokens, root.shaping_rate_bytes,
        queue.tokens, queue.transmit_rate_bytes,
        head_len, now_ns, true,
    ) {
        count_park_reason(root, queue_idx,
            ParkReason::QueueTokenStarvation);
        park_cos_queue(root, queue_idx, wake_tick);
    }
    continue;
}
```

to

```rust
if queue.tokens < head_len {
    queue.owner_profile.drain_park_queue_tokens
        .fetch_add(1, Ordering::Relaxed);
    if queue.surplus_sharing {
        // #915: do NOT park. Stay runnable so
        // select_cos_surplus_batch can pick this queue up on
        // the same drain pass when root tokens exist.
        continue;
    }
    if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
        root.tokens, root.shaping_rate_bytes,
        queue.tokens, queue.transmit_rate_bytes,
        head_len, now_ns, true,
    ) {
        count_park_reason(root, queue_idx,
            ParkReason::QueueTokenStarvation);
        park_cos_queue(root, queue_idx, wake_tick);
    }
    continue;
}
```

Counter increment (`drain_park_queue_tokens`) is retained for
diagnostic parity — the queue's own bucket DID starve; the
fact that surplus picks up the slack later is separately
visible via the queue's `surplus_deficit` accounting.

### 4.6 Phase-gated `shared_queue_lease` consumption (Codex MAJOR 2)

`userspace-dp/src/afxdp/cos/tx_completion.rs:449-458` (in
`apply_cos_send_result`) and `:515-524` (in
`apply_cos_prepared_result`) — consume `shared_queue_lease`
unconditionally when `queue.exact`. Surplus-sharing bytes
would also debit the per-queue lease, which represents the
per-queue rate cap; this would cap surplus draws at the
configured rate and defeat the point.

Fix: gate the lease consumption on phase. Change

```rust
if let Some(queue_idx) = exact_queue_idx {
    if let Some(shared_queue_lease) = ... {
        shared_queue_lease.consume(sent_bytes);
    }
}
```

to

```rust
if let Some(queue_idx) = exact_queue_idx {
    if matches!(phase, CoSServicePhase::Guarantee) {
        if let Some(shared_queue_lease) = ... {
            shared_queue_lease.consume(sent_bytes);
        }
    }
}
```

Both apply functions already take `phase: CoSServicePhase` —
no signature change needed. Behavior parity for non-surplus-
sharing exact queues: those never reach the Surplus phase
(blocked by §4.4's surplus-skip), so the gate is a no-op for
them. Correct: surplus consumes only `root.tokens` +
`shared_root_lease` + `surplus_deficit`; the per-queue rate
cap stays a Guarantee-phase concept.

### 4.7 CLI exposure (Gemini MINOR 8)

`pkg/dataplane/userspace/cosfmt.go` — extend the per-queue
output of `show class-of-service interface <iface>` to print
a `Surplus sharing: yes/no` line for each queue. Operators
debugging an exact queue that exceeds its configured rate need
this visibility — without it, the bursting looks like a bug.

`pkg/cli/cli_show_services.go:100` already delegates to
`cosfmt.go` (per Codex round-2 MINOR 1), so the rendering
change in `cosfmt.go` is the only CLI write site. No separate
`pkg/cli/cli_show_cos.go` (that file does not exist).

Field is rendered only when `Exact == true` to avoid noise on
non-exact queues.

### 4.8 What NOT to change

- The order of phases in `drain_shaped_tx` —
  `service_exact_guarantee_queue_direct_with_info` →
  `build_nonexact_cos_batch` (which calls
  `select_nonexact_cos_guarantee_batch` then
  `select_cos_surplus_batch`) — is unchanged. Strict-priority
  exact-guarantee still runs first.
- `cos_surplus_quantum_bytes` is unchanged. The DRR per-queue
  quantum still applies — surplus-sharing exact queues
  participate fairly with non-exact queues at the same priority
  level, weighted by `surplus_weight`.
- `queue.tokens` is unchanged on the surplus path. Surplus
  consumes only `root.tokens`, same as for non-exact queues
  today. So an exact queue with surplus-sharing draws bytes
  from the root shaper, not from its own per-queue bucket
  (which has already been consumed during the guarantee phase).

### 4.9 Validation rule

(See §4.2 for the canonical statement — warn-and-strip in
`pkg/config/compiler.go:ValidateConfig`. v3 removes the
duplicate text that previously incorrectly cited
`compiler_class_of_service.go` as the validation site, per
Codex round-2 MINOR 3.)

## 5. Public API preservation

- `CoSScheduler` gains one new bool field. Existing `omitempty`
  JSON tags ensure forward-compat with older snapshots that
  lack the field — they decode to `false`, preserving today's
  behavior.
- `CoSQueueRuntime` gains one bool. No struct-size concern;
  Rust doesn't pin layout.
- No public-API method signatures change.

## 6. Hidden invariants the change must preserve

- **Strict-priority exact guarantee over surplus**: exact queues
  with surplus-sharing must still drain their guarantee budget
  via `select_exact_cos_guarantee_queue_with_fast_path` before
  hitting the surplus phase. The actual entry point is
  `drain_shaped_tx` (queue_service/mod.rs:128) which calls
  `service_exact_guarantee_queue_direct_with_info` first; only
  if that returns `None` does it call `build_nonexact_cos_batch`
  (which then runs `select_nonexact_cos_guarantee_batch` ||
  `select_cos_surplus_batch`). The order is preserved.
- **Per-queue token bucket as guarantee floor**: an exact
  queue's `queue.tokens` cap is enforced ONLY in Guarantee
  phase. `apply_cos_send_result` only debits `queue.tokens`
  when `phase == CoSServicePhase::Guarantee` (verified
  tx_completion.rs:422-429). After §4.6, `shared_queue_lease`
  is also Guarantee-phase only. So surplus-sharing does NOT
  let a 1 Gbps exact queue exceed 1 Gbps via its own token
  bucket — its surplus-phase bytes draw from `root.tokens` +
  `shared_root_lease` only.
- **No-park rule (NEW per §4.5)**: when
  `queue.exact && queue.surplus_sharing && queue.tokens <
  head_len`, the exact-guarantee selector must not park the
  queue. Otherwise `queue.runnable = false` and surplus skips
  it, defeating the point. The `drain_park_queue_tokens`
  counter still increments for diagnostic parity (the bucket
  DID starve), but no `park_cos_queue` call.
- **DRR fairness**: `surplus_deficit` accumulation is unchanged.
  An exact-with-surplus-sharing queue lands in the priority RR
  alongside non-exact queues at the same priority and DRR
  fairly via its existing `surplus_weight`.
- **Park accounting in surplus**: `count_park_reason(...,
  RootTokenStarvation)` / `park_cos_queue` paths in surplus
  already exist (queue_service/mod.rs:589). When a
  surplus-sharing exact queue runs out of root tokens during
  surplus phase, it gets parked there — correct.
- **#1183 useful-state gate**: exact queues with no
  surplus-sharing (the default) keep the same code path they
  have today (parked on queue-token starvation, skipped in
  surplus). The new branches fire only for opted-in queues.
  This is the post-build "useful CoS state" pattern — extra
  state only for queues that need it. Validation
  (warn-and-strip in `ValidateConfig`) ensures the flag is
  never set when it's a no-op.

## 7. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | **LOW** | Default = false. No change for existing operators. New behavior only when operator explicitly opts in. |
| Lifetime / borrow-checker | **LOW** | Plain bool field, no lifetime changes. |
| Performance regression | **LOW** | One extra `&& !queue.surplus_sharing` branch in surplus path. Predictable not-taken on the common case (most queues are non-exact). |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | **LOW** | Targeted fix at one specific call site. Not a refactor. The proposed surplus-sharing semantic maps cleanly to existing surplus mechanics; no new abstraction. |

## 8. Test plan

- `make generate` clean.
- `cargo build --release` clean.
- `cargo test --release` 962+ pass, plus new tests:
  - `pkg/config/parser_class_of_service_test.go`:
    `TestSchedulerSurplusSharingHierarchical` /
    `TestSchedulerSurplusSharingFlatSet` — both parse paths
    set `SurplusSharing = true` via the `ast.go` schema.
  - `pkg/config/compiler_security_test.go` (or
    `pkg/config/compiler_test.go`):
    `TestValidateConfigSurplusSharingWithoutExactStripsAndWarns`
    — `ValidateConfig` strips the no-op flag when set without
    `exact` and emits the warning verbatim.
  - `pkg/dataplane/userspace/manager_test.go` (mirroring
    existing `TestBuildClassOfServiceSnapshotIncludesTransmitRateExact`):
    `TestBuildClassOfServiceSnapshotIncludesSurplusSharing` —
    snapshot encoding round-trips the bool.
  - `userspace-dp/src/protocol_tests.rs` (or wherever the
    existing serde defaults are tested): a test that decodes
    a snapshot WITHOUT `surplus_sharing` and confirms
    `surplus_sharing == false` (covers the
    `#[serde(default)]` schema-migration path; addresses
    Codex MAJOR 3 + Gemini #7).
  - `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
    `surplus_sharing_exact_reaches_surplus_through_full_drain_pass`
    — **production-order end-to-end test (Codex round-2 MINOR
    4)**. Sets up an exact queue with `surplus_sharing=true`,
    `queue.tokens=0`, root with tokens, no other queues
    runnable. Calls `drain_shaped_tx` (the actual production
    entry point). Asserts the batch returned came from the
    surplus-sharing exact queue with `phase ==
    CoSServicePhase::Surplus`. This proves the full path:
    exact-guarantee selector hits the no-park branch
    (§4.5) → falls through to `build_nonexact_cos_batch` →
    `select_cos_surplus_batch` (§4.4) picks the queue. A
    surplus-selector-only test would not catch a parking
    regression elsewhere on the same drain pass.
  - `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
    `select_cos_surplus_batch_excludes_exact_without_surplus_sharing`
    — default-false preserves today's hard-cap behavior; the
    exact queue gets parked, surplus skips it. Direct unit
    on the surplus selector for fast regression detection.
  - `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
    `exact_with_surplus_sharing_not_parked_on_queue_token_starvation`
    — directly tests §4.5: after one exact-guarantee call
    that fails the queue-token gate, `queue.runnable` is
    still `true` (no `park_cos_queue` call). Failure here
    catches Codex MAJOR 1 in isolation.
  - `userspace-dp/src/afxdp/cos/tx_completion_tests.rs`:
    `surplus_phase_does_not_consume_shared_queue_lease` —
    drives `apply_cos_send_result` with
    `phase=CoSServicePhase::Surplus` on an exact queue and
    asserts the per-queue lease counter is unchanged.
    Failure here catches Codex MAJOR 2.
  - `userspace-dp/src/afxdp/cos/tx_completion_tests.rs`:
    `guarantee_phase_still_consumes_shared_queue_lease` —
    non-regression: the existing Guarantee-phase debit still
    fires, defending against an over-eager phase gate.
  - `userspace-dp/src/afxdp/cos/queue_service/tests.rs`:
    `exact_surplus_sharing_consumes_root_tokens_only` — verify
    `queue.tokens` and `shared_queue_lease` are unchanged
    after a Surplus-phase drain.
  - `userspace-dp/src/afxdp/cos/builders_tests.rs`:
    `cos_queue_runtime_propagates_surplus_sharing` — snapshot
    → runtime field copy works.
- Go test suite clean.
- Smoke matrix per `triple-review` SKILL.md Step 6: full
  Pass A + Pass B 30 measurements (CoS-disabled best-effort
  fast path + per-class CoS 5201-5206 v4+v6 push+reverse).
  Expected: zero throughput delta on default config (all
  classes default surplus-sharing=false).
- Smoke validation: configure
  `set class-of-service schedulers iperf-a surplus-sharing`,
  re-apply CoS, run `iperf3 -c 172.16.80.200 -p 5201 -P 12
  -t 30`. Expect throughput on 5201 to exceed 1 Gbps shape rate
  when other classes idle (target: ≥ 6 Gbps single-stream cap
  per the loss-cluster baseline).

## 9. Out of scope (explicitly)

- Default-true `surplus-sharing` semantics. Risk of breaking
  operators relying on Junos `exact` hard-cap is too high.
- Surplus-share weighting different from `surplus_weight`. The
  feature reuses the existing weight; a separate
  `surplus-sharing-weight <n>` knob can be a follow-up if
  operators ask.
- Glide-style per-flow rate signal (#747).
- HA sync of per-scheduler `surplus-sharing` config — config
  sync already covers all scheduler config including this
  field.
- DPDK pipeline parity. The DPDK manager mirrors scheduler
  config but the DPDK CoS scheduler doesn't yet match the
  Rust queue_service — separate scope.

## 10. Open questions for adversarial review

Resolved in v2 (kept for traceability):
- ~~Token-bucket interaction~~ — confirmed by both Codex and
  Gemini that surplus phase only touches `surplus_deficit` +
  `root.tokens`, never `queue.tokens`. The lease question
  (Codex MAJOR 2) is now phase-gated in §4.6.
- ~~Default semantics~~ — both reviewers confirmed opt-in
  default is correct (every queue has `surplus_weight >= 1`
  today, default-on would flip everything).
- ~~Strict-priority preservation~~ — confirmed via the
  `drain_shaped_tx` order; `select_combined_cos_batch` was a
  stale symbol reference in v1.
- ~~Schema migration~~ — addressed by `#[serde(default)]` in
  Rust (§4.2).
- ~~CLI exposure~~ — added in §4.7.

Open for round 2:
1. **Scope/value vs PLAN-KILL**: Codex round-1 explicitly
   ruled out PLAN-KILL ("the knob has real value if the
   operator wants to keep exact-queue guarantee
   ordering/direct exact semantics while allowing idle
   surplus"). Gemini also PASS on operator value. The plan
   stays unless round 2 raises new concerns.
2. **Validation rule**: v2 picks reject-via-strip — the
   warning fires AND the bool is cleared, so the runtime
   never sees the no-op flag. Reviewers may prefer hard
   reject (block the commit). Argument for strip: matches
   #1183 lesson and avoids breaking commits on benign
   misconfig.
3. **Smoke evidence**: the success criterion (≥ 6 Gbps
   single-stream on 5201 with surplus-sharing on) assumes
   no other CoS class is hungry. v2 §8 also adds a
   contention scenario suggestion: configure
   `surplus-sharing` on iperf-a (1 Gbps shape), run
   `iperf3 -P 12 -t 30 -p 5201` AND a hungry iperf-b
   (10 Gbps shape) at the same time, verify iperf-a settles
   to ≤ 1 Gbps when iperf-b is using its full share. This
   demonstrates the guarantee floor still holds under
   contention.
4. **DPDK parity**: still out of scope per §9. The plan
   doesn't yet add a follow-up issue. Reviewers may push for
   that — easy to add if requested.
