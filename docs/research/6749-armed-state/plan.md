# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v6 — pending adversarial plan review (round 5)**

- Issue: #6749 (opus-review-001 root R06, severity High)
- Research base: `ad9591177` (origin/master at worktree creation)
- Research branch: `research/6749-armed-state` (plan docs only — no
  production code in this branch)
- v1 @ `8c76670d6` (r1: all DEMAND-REVISION); v3 @ `bce10126c` (r2:
  all DEMAND-REVISION); v4 @ `f679a791a` (r3: all DEMAND-REVISION);
  v5 @ `0c0b9b677` (r4: Codex DEMAND-REVISION; AGY + SMR
  PLAN-READY-WITH-NITS); v6 folds round 4: tri-state
  `activation_state` provenance (Codex r4 B3), coherent-vector
  invariant replacing the plan gate (Codex r4 B2/M9), common-locus
  S4' + pending-aware retry predicate (Codex r4 B4), arm-verb
  rollback (Codex r4 B5 / AGY r4 n1), Go arm-sync defer gate
  (Codex r4 B6), `complete_deferred` rebind provenance (Codex r4 M7).

---

## 1. Status

DRAFT v6 — pending adversarial plan review round 5 (Codex + AGY + Claude
SMR). Convergence target: PLAN-READY (recommended path shipped to
`/engineer`) or PLAN-KILL. No production code is written under `/research`.

### Round verdict log

- **Round 1** (v1): all three DEMAND-REVISION. Deferred-activation is
  not a disarm; identity is not physical; E2; volatile-vs-control
  carry; queue-override lifetime; B dismissal overstated; unsafe-green
  tests; trigger/outage overstatement.
- **Round 2** (v3): all three DEMAND-REVISION, converging on durable
  provenance. The rebind completion path; full-leg defer completion;
  deferred CONTRACTION leaves all armed; arm-before-reconcile lie;
  full fan-out reverses operator disarms — scoped provenance REQUIRED;
  E2 flap; unsafe-green tests.
- **Round 3** (v4): all three DEMAND-REVISION. Hybrid-plan activation
  via unversioned marker; S3/S2 mark operator-owned slots (was-armed
  gates); one-bool provenance conflation (C3 scoped to registered);
  S4's scope (S4' global failure mark); toggle mid-defer (defer
  gate); arm fan-out reordered after Ok; planner never arms (AGY f1).
- **Round 4** (v5): Codex DEMAND-REVISION (6 BLOCKER + 3 MAJOR); AGY
  PLAN-READY-WITH-NITS (2 nits); SMR PLAN-READY-WITH-NITS (3 nits).
  Codex's round: name-only plan gate authorizes the WRONG PHYSICAL
  (same-name/new-ifindex) and INCOMPLETE retained plans (failed
  contraction arms `[b,c]` while A=`[a,b,c]` has no `a` worker) —
  gate by accepted-plan provenance or restore a coherent vector; the
  bool still conflates global-disarm with operator ownership (a
  global disarm creates `registered && !armed && !pending` with no
  operator claim, and a later flap strands it D-silent); S4' is
  full-apply-only (same-plan/rebind/toggle/forwarding failures
  uncovered) AND a retained-records retry deficit blocks same-plan
  recovery (planned==live==runnable with `last_error` set → deficit
  predicate false); arm-then-fail strands (no rollback, no production
  retry); the compile-time arm-sync bypasses the defer gate entirely
  (`syncDesiredForwardingStateLocked` has no defer check — VERIFIED
  manager_ha.go:601-607); verb-identity rebind is not completion
  provenance (the busy watchdog sends the same verb); the
  convergence replan rereads live sysfs (environment-sensitive
  authorization race); tests still green-capable.
- **Round-4 disposition table (per Codex r4 BLOCKER 1's audit):**

  | r4 finding | v6 disposition |
  |---|---|
  | Codex B2 wrong-physical / incomplete retained plan | CLOSED — coherent-vector invariant: the failure path replans from the restored snapshot; the plan gate is deleted as redundant (§5-C) |
  | Codex B3 global-disarm false operator-owned | CLOSED — tri-state `activation_state` (none/pending/operator) (§5-C) |
  | Codex B4 S4' locus + retry deficit | CLOSED — common typed S4' in `reconcile_status_bindings` + pending-aware deficit predicate (§5-C, §9 item 18) |
  | Codex B5 arm-then-fail, no retry | CLOSED — arm-verb rollback → the existing desired-loop retries (§5-C) |
  | Codex B6 arm-sync defer bypass | CLOSED — Go arm direction gated on `!m.deferWorkers` (§5-C) |
  | Codex M7 rebind verb ≠ provenance | CLOSED — `complete_deferred` field on the rebind request, set only by NotifyLinkCycle (§5-C) |
  | Codex M8 test holes | CLOSED — §9 items 12-18 rewritten |
  | Codex M9 sysfs authorization race | CLOSED — plan gate (and its replan-at-convergence) deleted with the coherent-vector invariant (§5-C) |
  | AGY r4 n1 (arm rollback) | CLOSED — promoted to required (§5-C) |
  | AGY r4 n2 (rebind log pending count) | CLOSED — §9 docs bullet |
  | SMR r4 N1/N2/N3 | CLOSED — N1 moot (gate deleted); N2 codified (§5-C C2); N3 §1 formatting |

### Round-1 detail log (kept for the record)

- Claude SMR r1: DEMAND-REVISION — SMR-1 B-rejection overstated, SMR-2
  missing observability-only Go leg, SMR-3 close Q2/Q5 from source,
  SMR-4 document identity semantics. Folded (v2).
- AGY r1: DEMAND-REVISION — finding 1 (MAJOR): `had_existing` /
  `last_change` interaction strands an interface transitioning
  `ifindex<=0 → >0`. Folded as edge case E2. Finding 2 (MINOR, zero
  volatile on carry): adopted in v3's R3 (control-only carry).
  Finding 3 (NIT, Go-side gate test): folded into §9.
- Codex r1: DEMAND-REVISION — BLOCKER 1 (the real deferred-activation
  path enters a plan-changing apply with `forwarding_armed=true`
  WITHOUT disarming; arming new slots there combines with the
  slot-keyed `refresh_bindings` stale-Ready alias to open ctrl with
  stale-identity rows). BLOCKER 2 (`(interface, queue_id)` is unique
  per plan but is not physical identity — real XSK identity is
  (ifindex, queue)). MAJOR 3 (E2 concurrence), MAJOR 4 (whole-record
  carry conflates control with slot-owned telemetry), MAJOR 5
  (queue-scoped override lifetime), MAJOR 6 (B rejection overstated —
  the deferred design forces an explicit activation step), MAJOR 7
  (unsafe-green tests), MINOR 8 (trigger/outage overstated; release
  note must require helper restart).

## 2. Issue framing

A full `apply_snapshot` that changes the AF_XDP binding plan while the
helper is armed leaves every newly-created binding slot `registered=true`
but `armed=false`. The helper then reports `enabled=false` (the enabled
gate requires EVERY binding registered+armed), the Go manager's
shim-control gate keeps `userspace_ctrl.Enabled=0`, and transit traffic
stays fail-closed — for the WHOLE dataplane, not just the new slots.
Go's desired-state reconciliation compares only the GLOBAL
`forwarding_armed` bit, sees it equal to the desired value, and returns
without acting, so nothing ever arms the new slots. The dataplane stays
down until an operator manually toggles forwarding state or restarts the
helper. Config-synced HA peers take the same code path and land in the
same state, so failover does not recover.

The issue asks us to decide (i) who owns the per-binding `armed` state —
global fan-out vs per-binding vs planner — and (ii) the correct
convergence model — slot-stable identity vs numeric slot;
initialize-from-global vs explicit per-binding reconcile — and to ship a
fix with an expansion-while-armed regression test.

## 3. Honest scope/value framing

This is an availability bug with a total-transit-outage blast radius,
not a performance issue. The win at absolute scale (corrected per Codex
r1 MINOR 8 — v1 overstated both the trigger frequency and the "zero
outage" claim):

- **Outage avoided per trigger:** indefinite (until human intervention)
  → the bounded interruption of a normal plan-changing apply. The fix
  does NOT make the outage zero: a plan-changing Compile already
  programs bootstrap ctrl disabled and clears binding rows
  (manager_compile.go:319, maps_sync.go:121) and the full reconcile
  tears down + recreates workers (reconcile/mod.rs:330) — that bounded
  replan interruption exists today and stays. What dies is the
  INDEFINITE tail that required an operator to notice and act.
- **Trigger frequency in production (precise):** commits whose new plan
  has MORE numeric slots than the old one — slot count is
  `min(rx_i) × candidate_count` (planning.rs:495), so: adding a
  candidate without lowering the min queue count; raising the min
  (removing the lowest-queue candidate, or `ethtool -L` raising the
  smallest channel count when the snapshot carries `rx_queues == 0` —
  the sysfs-resolved count is hashed per #3007, so the replan fires on
  an unrelated later commit and the outage correlates with the WRONG
  commit in post-incident analysis). Contractions, pure reorders, and
  replacements change the plan key WITHOUT new numeric slots and do not
  trigger it. Plan-key inputs (`update_snapshot_binding_plan_key`):
  candidate set, `vlan_id`/`parent_linux_name`/`parent_ifindex`,
  effective rx_queues, fabric parents, workers/ring/shared_umem.
  - **deferred-activation amplifier (v3, Codex r1 BLOCKER 1):** a
    commit that both changes the plan AND pends a RETH MAC
    (reth membership change on a healthy armed node) strands the new
    slots through the deferred bring-up too — same indefinite tail via
    a second door (the v4 marker lifecycle closes all three completion
    shapes of it: same-plan re-apply, full-leg re-apply, rebind).
  - **amplifier on the roadmap:** #6702/#6681 change the layout from
    `min(rx_i) × N` to `Σ min(rx_i, 16)`, which makes plan-shape changes
    (and therefore new-slot creation) far more common. Both issues were
    read in full; their scope is capacity/UMEM/heartbeat/worker
    consequences of the count change — neither touches arm
    initialization. No collision; this issue must land its own fix and
    not wait for them.
- **HA multiplier:** config sync replays the same commit on both nodes;
  both helpers strand the same new slots; an RG failover moves the
  outage rather than clearing it.
- **Recovery cost today:** operator must know to run a forwarding
  arm/disarm toggle (or restart the helper). Nothing in `show` output
  says "slot N is registered but unarmed because of a plan expansion" —
  the failure presents as a total transit blackout after a routine
  commit.

If reviewers conclude the fix's churn exceeds the value — e.g. that the
trigger set is too rare to justify touching the planner — PLAN-KILL is
an acceptable verdict. Our assessment going in: the trigger set is
"any interface-geometry commit on a live box", the failure mode is a
silent total outage with no self-heal, and the primary fix is ~one
function plus tests, so the value/churn ratio strongly favors fixing.

## 4. What's already shipped / partially batched

Verified mechanism chain (every link read at base `ad9591177`):

1. **Full-apply replan** — `userspace-dp/src/server/handlers/snapshot.rs:344-350`:
   the non-same-plan leg replaces `guard.snapshot`, calls
   `replan_queues(guard.snapshot.as_ref(), guard.status.workers, &existing_bindings)`,
   and assigns the result to `guard.status.bindings`. The apply path
   never touches `guard.status.forwarding_armed`.
2. **Numeric-slot state carry + default-false armed** —
   `userspace-dp/src/server/helpers/planning.rs:482-531`
   (`replan_bindings_from_candidates`): prior state is carried by
   NUMERIC slot (`existing_by_slot.remove(&slot)`). A slot with no
   predecessor (`had_existing == false`) and a valid ifindex gets
   `registered = true`; `armed` stays at the `BindingStatus::default()`
   value `false`. Slots WITH a predecessor keep their full prior record
   — including `armed=true` — even when the plan reshuffle means the
   slot now addresses a DIFFERENT (interface, queue) pair (slot index =
   `queue_id * n_interfaces + iface_idx`; inserting/removing a candidate
   shifts every later slot).
3. **Enabled gate** — `userspace-dp/src/server/helpers/status.rs:274-281`:
   `enabled = forwarding_armed && forwarding_supported &&
   !bindings.is_empty() && all(registered && armed)`. One unarmed slot
   forces `enabled=false` for the whole process.
4. **Go ctrl gate** — `pkg/dataplane/userspace/maps_sync.go:391-487`:
   `status.Enabled == false` skips the entire enable block, leaving
   `ctrl.Enabled = 0`; the shim then holds transit fail-closed. Two
   inner gates agree with the same predicate even if `enabled` were
   true: `probeBindingsReady` (maps_sync.go:438-450) requires every
   registered binding armed, and the per-row shim admission
   `bindingForwardingLive` (maps_sync.go:97-99, consumed at :695/:751)
   requires `Registered && Armed && Ready && !workerDead` before the
   (ifindex, queue) row is marked READY in `userspace_bindings`.
5. **No convergence** — `syncDesiredForwardingStateLocked`
   (`pkg/dataplane/userspace/manager_ha.go:601-607`) compares only
   `m.lastStatus.ForwardingArmed == desired` and returns nil. Its three
   call sites (post-compile `manager_compile.go:408`, HA path
   `manager_ha.go:66`, ~1s status poll `process_status.go:240`) all
   inherit the blind spot. Per-slot verbs exist
   (`SetBindingState`/`SetQueueState`, `manager_status.go:132-180`) but
   are operator-only (gRPC diag + CLI `request chassis …`).
6. **The coordinator does NOT consume `armed`** — worker bring-up
   filters on `registered && ifindex > 0`
   (`afxdp/coordinator/reconcile/bringup.rs:274`); `bound`,
   `xsk_registered`, `ready` are re-derived from live worker state by
   `refresh_bindings` during reconcile (#2794 tail). So after the
   expansion apply's own reconcile, the new slots' XSKs really are
   bound and forwarding-capable — ONLY the stale `armed=false` bit (and
   its three downstream gates) keeps traffic off them, and the
   all-or-nothing `enabled` gate extends that to the whole dataplane.
7. **The deferred-activation door (v3, Codex r1 BLOCKER 1 —
   verified):** the daemon pends `DeferWorkers` for RETH MAC
   programming WITHOUT disarming (daemon_apply_dataplane.go:45-71 →
   manager_compile.go:330-331; the pre-publish disarm at
   manager_ha.go:568-599 fires only for unsupported configs). A healthy
   armed helper can therefore take a plan-changing DEFERRED apply:
   replan runs (new slots registered, unarmed), reconcile is SKIPPED
   (snapshot.rs:351-354), and `refresh_status` →
   `afxdp.refresh_bindings` (status.rs:23) maps still-live OLD workers
   into the NEW binding vector by NUMERIC SLOT
   (refresh_bindings.rs:25-32). Two consequences: (i) master strands
   the deferred new slots the same way (armed=false, later bound by the
   bring-up's reconcile, never converged — same indefinite tail); (ii)
   any fix that arms new slots on a no-reconcile apply would combine
   with the slot-keyed refresh to report stale-identity `ready`, open
   ctrl, and steer the new (ifindex, queue) onto an XSK bound to a
   DIFFERENT physical binding — worse than the outage. **The deferred
   CONTRACTION shape (Codex r2 BLOCKER 5) is already live on master
   through door (ii):** `[a,b,c] → [b,c]` deferred introduces no new
   slot, so every survivor stays armed, `enabled=true`, ctrl stays
   open, and the slot-keyed refresh attaches shifted stale `ready`
   state to the new identities — today's only mitigation is that
   deferring commits are rare. Any credible fix must gate the WHOLE
   vector, not just new slots (§5-C S3).
8. **The completion path is `rebind`, not `apply_snapshot` (v4, Codex
   r2 BLOCKER 3 — verified):** after MAC programming cycles the link,
   `NotifyLinkCycle` fires and Go sends `ControlRequest{Type:
   "rebind"}` (process_linkcycle.go:219; the daemon clears
   `m.deferWorkers` before it). The rebind handler reconciles and
   refreshes but never touches `armed` (rebind.rs:42-76). Any
   activation model scoped to `apply_snapshot` legs (v3's R2) misses
   the normal completion path entirely — the convergence must live
   inside `reconcile_status_bindings`, which rebind shares
   (rebind.rs:64).
9. **Partial survival on failed bring-up (v4, Codex r2 BLOCKER 2 —
   verified):** a post-teardown `WorkerSpawn` failure returns WITHOUT
   `stop_inner` — already-launched workers KEEP their records
   (bringup.rs:172-183) — and the reconcile refreshes actual partial
   state before returning `Err` (reconcile/mod.rs:391). An
  arm-at-replan model therefore reports `enabled=true` against a
   partially-dead worker set (the #869 gate ignores `ready`/`bound`),
   and Go can publish READY rows for the surviving subset. Activation
   must follow reconcile SUCCESS (or be reverted on failure) — §5-C S4.
10. **Volatile state ownership (v3, Codex r1 MAJOR 4 — verified):**
    every successful reconcile clears per-binding volatile fields
    (`reset_binding_counters`, reconcile/reset.rs:9-15) and
    `refresh_bindings` repopulates them from live workers by slot. So
    counters/`last_error`/`ready` carried across a replan are dead
    weight on the normal path and alias-prone in the defer window — the
    carry must move CONTROL fields only (§5-C R3).

Adjacent shipped work the plan must compose with:

- **#1666 ready-gate** (`bindingForwardingLive`): per-row shim steering
  already requires `Ready` in addition to `Registered && Armed`, so
  arming a slot whose XSK is still bootstrapping cannot get traffic
  steered to a dead queue. This is what makes "initialize new slots
  armed from the global state" as safe as the boot-time arm fan-out
  (which also arms not-yet-ready bindings).
- **#869 enabled-gate design note** (status.rs:267-273): `enabled`
  deliberately does NOT require `ready` — that deadlock-avoidance is
  preserved by every option below.
- **#5171/#5134 deferred-worker bring-up**: a `defer_workers=true`
  apply replans with `forwarding_armed == false`, so new slots
  initializing armed from the global state get `false` — matching the
  defer contract; the later bring-up arms everything via the
  `set_forwarding_state` fan-out. The bug only bites when the plan
  changes while the global bit is ALREADY true.
- **#6163/#6165/#5648 required-protocol arm gate**: any arm-direction
  convergence from Go must keep honoring
  `ensureRequiredSnapshotProtocolLocked`. (Only relevant to option B.)
- **#6702 / #6681 (open, unstarted)**: per-interface queue planner.
  Collision check done — they own binding-COUNT consequences
  (UMEM/heartbeat/workers/4096-cap), NOT arm initialization. Our
  identity key (§5, option C) must remain meaningful under their
  per-interface queue extents; `(interface, queue_id)` is
  layout-shape-independent, so it does.
- **State file is write-only** (`helpers/persistence.rs`): the helper
  never restores bindings at startup (lifecycle builds an empty
  `ProcessStatus`), so no persisted-state migration is needed.

## 5. Concrete design — with Multiple Path Options

The design space forks on the two questions the issue poses. Three
viable paths:

### Option A — planner initializes new slots from the live global armed state (minimal, Rust-only)

Thread the helper's current `forwarding_armed` into the planner and use
it as the default for genuinely new slots:

```rust
// planning.rs — signature change (one production caller, snapshot.rs:345)
pub(crate) fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[BindingStatus],
    forwarding_armed: bool,          // NEW: guard.status.forwarding_armed
) -> Vec<BindingStatus>

// replan_bindings_from_candidates — the !had_existing leg becomes:
} else if !had_existing {
    binding.registered = true;
    binding.armed = forwarding_armed; // NEW: was struct-default false
}
```

- **Ownership model:** the global bit (pushed by Go via
  `set_forwarding_state`) remains the single owner of the arm DEFAULT;
  the planner stops inventing a contradictory default.
- **Why the APPLIED global, not Go's desired:** at replan time the
  helper's `forwarding_armed` is exactly what a later
  `set_bindings_forwarding_armed` fan-out would write. Go's
  `disarmBeforeUnsupportedPublishLocked` already ran before the publish,
  so the applied value is never ahead of Go's intent.
- **What it fixes:** the indefinite whole-dataplane disable. After the
  apply's own `reconcile_status_bindings` binds the new XSKs, the next
  `refresh_status` recomputes `enabled=true` and the ctrl gate opens on
  the normal poll — no operator action.
- **Verdict (v4):** RECORDED FOR HISTORY, not a live retreat. A arms
  new slots at replan time, which round 2 showed is the core defect:
  on the deferred path the slots' XSKs never bind (Codex r1 BLOCKER 1),
  and on a failed non-deferred reconcile A reports `enabled=true`
  against a partially-dead worker set (Codex r2 BLOCKER 2). Patching A
  with defer-awareness + activation convergence + the E2 widening +
  the marker lifecycle converges it INTO option C except for keeping
  numeric-slot carry — at which point the only remaining difference is
  the wrong-identity inheritance below, which C also fixes.
- **What it does NOT fix:** numeric-slot carry. A plan reshuffle still
  inherits a predecessor's control record (armed/registered) onto a
  different (interface, queue) identity. The armed-bit consequence is
  mostly masked (when globally armed every carried slot reads
  `armed=true`, which is also what the S5 init would write), but an
  operator per-slot diagnostic disarm (`set_binding_state armed=false`)
  migrates to the WRONG interface across a reshuffle. Pre-existing
  defect, same locus.
- **Size:** ~10 lines + tests (but converges into C once made safe).

### Option B — Go desired-state reconciliation gains per-binding armed convergence (Go-only)

Extend `syncDesiredForwardingStateLocked` so that when the global bit
already equals desired, it additionally scans `m.lastStatus.Bindings`
for `Registered && Ifindex > 0 && !Armed` and converges the drifted
slots (per-slot `set_binding_state(registered=true, armed=true)` — NOT
`set_forwarding_state`, whose helper handler unconditionally runs a full
worker teardown+rebind even for a no-op re-assert, `forwarding.rs:43-58`).

- **Ownership model:** Go becomes the convergence owner for per-binding
  armed, treating the helper's bits as eventually-consistent state to be
  driven to the global value.
- **What is technically possible (corrected in v2 — SMR r1 SMR-1):** the
  manager is the ONLY client of the helper control socket — every
  per-slot request transits `Manager.SetBindingState`/`SetQueueState`
  (`manager_status.go:132-180`, reached via `LegacyDataPlaneAdapter` →
  `server_diag_system_action.go:430-455` / `cli_request_chassis.go:167-176`)
  — so a manager-side override registry (converge only slots the manager
  itself did NOT disarm; clear on global re-arm, plan change, daemon
  restart) IS implementable without a wire-protocol change. v1's "cannot
  distinguish" claim was wrong; the honest rejection is the three points
  below.
- **Why it still loses as PRIMARY:**
  1. **B alone leaves a ~1 status-poll-tick total transit outage per
     expansion commit** (apply lands → new slots unarmed → next poll
     tick converges). A/C close the window to zero at the source. For a
     bug whose entire cost is availability, the fix that shrinks the
     outage to zero beats the fix that bounds it at ~1s.
  2. **B alone keeps the wrong-identity carry defect** (numeric-slot
     state inheritance across reshuffles) — it converges the armed bit
     but leaves `registered`/`last_error`/counter provenance wrong.
  3. The override registry is new manager state with its own lifecycle
     hazards (staleness across daemon restart; slot renumbering between
     the status poll the operator read and the operator's request).
- **Exhaustive drift-producer enumeration (v2, SMR r1 SMR-3 / AGY r1
  Q2):** every writer of `binding.armed` in the tree — planner default
  (planning.rs:518-522), the `set_bindings_forwarding_armed` fan-out
  (status.rs:418-423), `set_binding_state` (binding.rs:29),
  `set_queue_state` (queue.rs:33), lifecycle init (all-false). The state
  file is write-only (`helpers/persistence.rs` — no restore path exists;
  lifecycle builds an empty `ProcessStatus`). Helper restart ⇒ Go
  reconnect ⇒ full apply (fresh plan, global false) ⇒
  `syncDesiredForwardingStateLocked` sees global false ≠ desired true ⇒
  `set_forwarding_state(true)` fan-out arms all. `update_ha_state` never
  touches bindings. Same-plan legs never replan. **With C in place, no
  non-operator producer of armed-bit drift remains** — the planner was
  the only one.
- **Verdict (v4):** REJECT B-as-Go-converger. Round 2 proved a
  converger IS required — but the helper-side `activation_pending`
  lifecycle (§5-C) provides it at the reconcile locus with exact
  provenance, where a Go-side converger would need a manager registry
  AND would still miss the rebind-completion timing semantics (the
  helper converges in the same lock-hold that binds the workers; Go
  would converge a poll-tick later). The issue's third fix-direction
  leg ("make Go's convergence check include each registered binding")
  is answered in detection form by option D below — whose predicate the
  marker now makes exact (`!Armed && !ActivationPending` = genuine
  drift, not pending activation).

### Option D — Go observability-only drift detection (companion to C; v2, SMR r1 SMR-2)

In `syncDesiredForwardingStateLocked`, **only when `desired == true`
and the global bit already equals it** (Codex r3 MINOR 10), when any
binding presents `Registered && Ifindex > 0 && !Armed &&
activation_state == none` (v6 tri-state: `pending` slots are
converging; `operator` slots are claimed — neither is drift), emit an
EDGE-TRIGGERED `slog.Warn` including the state for context (fires on
the drift predicate transitioning false→true, and again when it
clears; never per-tick — the project logging rules forbid >1/s
control-plane Info). No request is issued; nothing auto-reverts. The
predicate is EXACT by construction: what remains is genuinely
unexplained non-forwarding — the tripwire for any FUTURE unmarked
producer. ~15 lines in `manager_ha.go` + a manager test. On an OLD
helper (no state field), every unarmed registered slot reads as
`none` — exactly the old-bug stranding, so the warn doubles as the
mixed-version detector.

- **Value:** satisfies the issue's third leg as a detection surface; if
  a FUTURE drift producer ever appears (a new planner path, a
  mixed-version window nobody enumerated), on-call gets a log line
  naming the exact stranded slot instead of a silent blackout.
- **Cost/risk:** near zero; no semantics change. Bundled into the
  recommended ship.

### Option C — the `activation_state` lifecycle, v6: tri-state provenance + coherent-vector invariant (Rust helper + Go defer gate; superset of A)

v6 rewrite (Codex r4 BLOCKERs 2–7 + MAJOR 8–9; AGY r4 nits adopted;
SMR r4 nits adopted). Round 4 showed the v5 bool still conflated three
provenance classes and that gating convergence on a re-run planner is
environment-sensitive. v6 restructures around two invariants:

**INVARIANT 1 — tri-state provenance.** `BindingStatus.activation_state
∈ {none, pending, operator}` — ONE additive wire field (serde default
`none`; Go optional, ignores unknown). It replaces v5's bool and
distinguishes the THREE ways a slot becomes non-forwarding:

- `pending` — the PLANNER left this slot short of `registered &&
  armed`; converge it at the next successful, defer-authorized armed
  reconcile.
- `operator` — an OPERATOR verb (`set_binding_state` /
  `set_queue_state`) deliberately made this slot non-forwarding
  (`!armed` or `!registered`). NEVER auto-converged.
- `none` — everything else (armed slots; slots disarmed by the global
  fan-out — global ownership, not operator ownership: Codex r4
  BLOCKER 3's distinction, which v5's bool could not express).

Rules:

- **Planner marks `pending` (never arms — AGY r3 f1 kept):**
  - **S1** replan creates an unregistrable slot (`ifindex <= 0`):
    `registered=false, state=pending`.
  - **S2** force-clear on `ifindex <= 0`: `registered=false`;
    `state=pending` UNLESS the record was `operator` (an operator's
    claim survives the flap; AGY r3 f2 / Codex r4 B3).
  - **S3** deferred plan-CHANGING apply: every registered slot
    `armed=false`; `state=pending` unless `operator` (Codex r3 B3's
    was-armed gate, expressed exactly).
  - **S5** new identity at replan: `registered=true, armed=false,
    state=pending`, always.
  - **S4'** post-teardown bring-up failure, moved to COMMON typed
    error handling (Codex r4 BLOCKER 4): inside
    `reconcile_status_bindings`, on `WorkerSpawn |
    WorkerBindIncomplete` from ANY caller (full apply, same-plan
    apply, rebind, binding/queue toggle, forwarding arm), every
    registered non-`operator` slot becomes `armed=false,
    state=pending` BEFORE the Err propagates. No shape scoping, no
    identity diff.
- **E2 re-registration** at replan (`!registered && new ifindex>0`):
  `pending` → `registered=true` (still `!armed, pending`); `operator`
  → `registered=true, armed=false, state=operator` — the operator's
  EXACT claim restored (Codex r3 B4's degradation is gone; the
  degradation note in v5 §10 is deleted); `none` → unreachable by
  enumeration (`!registered` arises only from S1/S2 force-clear or an
  operator unregister).
- **C1:** a slot reaching `registered && armed` (any cause) →
  `state=none`.
- **C2:** operator verbs set `state=operator` on disarm/unregister
  and `state=none` on arm/register, in the SAME field mutation that
  applies the verb's values, BEFORE any `registration_changed`
  reconcile (SMR r4 N2 code-order pin).
- **C3:** the `set_forwarding_state` fan-out sets `state=none` on
  REGISTERED slots (global re-claim: pending work and operator
  overrides both die at an explicit global fan-out, as documented
  since v4); UNREGISTERED slots keep their state so `invalid →
  global arm/disarm → valid` still re-registers via E2 (Codex r3 B4a).

**INVARIANT 2 — the binding vector is ALWAYS coherent with the stored
snapshot's plan** (Codex r4 BLOCKER 2 + MAJOR 9). v5's plan gate
(membership via a pure `replan_queues` at convergence time) is
DELETED along with its live-sysfs authorization race (Codex r4 MAJOR
9: a queue-count change mid-reconcile could shrink or grow the
post-Ok identity set away from the vector actually bound). The
invariant replaces it at the ONE point vector and plan could diverge:
the post-teardown apply-failure path (#4952's retained-B-with-
restored-A hybrid). There, after restoring the previous snapshot, the
handler REPLANS from the restored snapshot against the retained
vector (identity-carry of state: A's identities keep their carried
state incl. S4' pending marks; A-only identities re-appear as
S5-pending — the failed-contraction hole; B-only identities drop
with the rejected plan — the rejected-hybrid hole; same-name/
new-ifindex resolves to the RESTORED snapshot's ifindex — the
wrong-physical hole). The vector then always matches the stored plan,
so convergence needs no membership gate at all. **Note for the
#4952/#5143 pins:** the pinned "retain the rejected vector for
reporting" behavior changes to "report the restored plan's coherent
vector, all non-operator slots unarmed+pending"; the pins' INTENT
(real post-teardown per-binding state, not pre-teardown ghosts) is
preserved — surviving partial workers still refresh into the reported
slots (volatile, cosmetic under `enabled=false`) — and the rejected
plan's per-slot `last_error` remains in the control response's error
stage. The affected pinned tests are updated in the same PR with this
rationale (reviewer-sanctioned: Codex r3 finding 4 offered exactly
this disjunct).

**Convergence — one locus, two gates** (the plan gate is gone):
inside `reconcile_status_bindings`' armed leg, after `Ok` and
write-back, for every `state==pending && registered` slot:
`armed=true, state=none, last_change=now`. Gates:

- **Armed gate:** only when `should_run_afxdp(status)` (armed +
  supported). The disarmed leg never converges.
- **Defer gate with EXPLICIT completion provenance** (Codex r4
  BLOCKER 6 + MAJOR 7): convergence is blocked while the stored
  snapshot carries `defer_workers=true`, UNLESS the caller passed
  `complete_deferred=true` — a NEW additive field on the
  `rebind` control request (`ControlRequest.complete_deferred`,
  serde default false; Go sends it ONLY from the `NotifyLinkCycle`
  path, process_linkcycle.go:219; the busy-binding watchdog
  (maps_sync.go:1484) and any flap rebind do NOT set it).
  Verb-identity is no longer the authorization (the watchdog can send
  the same verb); the provenance field is. Old Go + new helper: flag
  absent → no convergence during defer → fail-closed (safe). New Go +
  old helper: field ignored → the old helper's semantics (safe).
  Outside a defer window (stored `defer_workers=false`) every
  successful armed reconcile converges, from any caller.

**The arm verb, reordered and rolled back** (Codex r3 MAJOR 7 + r4
BLOCKER 5; AGY r4 nit 1 promoted to required):
`set_forwarding_state(true)`: (1) set `forwarding_armed=true` (the
reconcile takes the armed leg, as master); (2) reconcile; (3) on
`Ok`, fan out `armed=true` + `state=none` (registered slots); on
`Err`, restore `forwarding_armed` to its previous value (rollback)
and return `ok=false` — S4' has already marked the slots pending, so
the failure is fail-closed AND self-healing: Go's next desired-state
poll sees `ForwardingArmed=false != desired` and re-issues the arm
through the existing #6165-gated loop (the production retry Codex r4
BLOCKER 5 demanded — no new debt machinery). The disarm direction is
unchanged (fan-out + state-clear first; the disarmed reconcile always
succeeds, status.rs:397-398).

**The Go arm-sync defer gate** (Codex r4 BLOCKER 6 — VERIFIED real):
`syncDesiredForwardingStateLocked` has NO defer check today, so a
compile that stamps `DeferWorkers` and immediately runs the
desired-state sync (manager_compile.go:330 → :408) sends
`set_forwarding_state(true)` while `m.deferWorkers` is true — arming
and binding workers BEFORE the daemon programs the RETH MAC,
defeating the defer the helper just honored (on master this fires
whenever the helper is globally disarmed at compile time — the boot
shape; on an already-armed box the sync no-ops, which is why #5171
usually holds). v6 gates the ARM direction of the sync on
`!m.deferWorkers`: during a defer window the sync does not arm; the
completion (provenance-tagged rebind, or the non-deferred re-apply)
converges instead. The disarm direction is never gated. An explicit
OPERATOR arm during the window remains allowed (explicit
authorization, documented).

**R3 — control-state identity carry (kept, quad updated).** Carry
{`armed`, `registered`, `activation_state`, `last_change`} keyed on
configured-name `(interface, queue_id)`; volatile rebuilt downstream.
Identity semantics unchanged (same-name/new-ifindex carries STATE —
but the failure-path replan resolves the vector's ifindex from the
stored snapshot, so activation is always physically coherent).
`had_existing` stays dead. Queue-scoped overrides remain
membership-at-invocation shorthand (verbs set `state=operator` on
their then-current membership).

**Ownership model (the issue's design question, final answer, v6
form):** a slot's non-forwarding state has exactly three owners,
made explicit in one tri-state field: the PLANNER (`pending` —
converges when a successful defer-authorized armed reconcile binds
the current plan), the OPERATOR (`operator` — converges never, dies
only at a global fan-out), and the GLOBAL default (`none` —
Go-pushed, fanned out post-reconcile on explicit arms). The helper
owns the field because only the helper sees all three producers.

**What it fixes (full inventory):** everything v5 fixed (§5-C v5
inventory) PLUS: the wrong-physical and incomplete-retained-plan
activations (coherent-vector invariant — same-name/new-ifindex,
failed contraction); the live-sysfs authorization race (plan gate
deleted); global-disarm creating false operator-owned state
(tri-state: `none` is global-owned, S2 re-marks it, E2 re-registers
it); operator-claimed slot degradation across flaps (exact-claim
restoration); S4' coverage of same-plan/rebind/toggle/forwarding
failure paths (common typed handler) and the same-plan retry deficit
(pending-aware deficit predicate, §9 item 18); arm-then-fail
stranding (rollback + existing desired-loop retry); the
compile-time arm-sync defer bypass (Go arm gate); spurious-rebind
convergence authorization (`complete_deferred` provenance).

**Size:** tri-state field + S1/S2/S3/S4'/S5 rules (~50 lines), common
S4' in `reconcile_status_bindings` (~10), failure-path
replan-from-restored (~15), convergence (two gates, ~10),
`complete_deferred` plumbing in protocol + rebind.rs +
process_linkcycle.go (~15), arm-verb rollback (~6), Go arm-sync defer
gate (~8), pending-aware deficit predicate (~4), Go `BindingStatus`
field + D predicate (~20), protocol canary + #4952-pin test updates,
docs. No coordinator, gate-semantics, or shim changes.
### Recommendation

**Ship option C + option D** — the v6 model: the tri-state
`activation_state` lifecycle (planner-owned `pending`, operator-owned
`operator`, global-owned `none`; the planner NEVER arms), the
coherent-vector invariant (the binding vector always matches the
stored snapshot's plan — the failure path replans from the restored
snapshot), the common-locus S4' failure marking with the
pending-aware retry predicate, the two-gated convergence
(armed × defer-provenance, with `complete_deferred` as the explicit
completion authorization), the arm-verb rollback feeding the existing
desired-loop retry, the Go arm-sync defer gate, R3 control-only
identity carry, and E2 lifecycle re-registration — plus the
state-aware, desired-gated Go drift detector. Retreat: none lighter
survives review — every simpler shape (arm-at-replan, leg-scoped
activation, ungated marker, bool provenance, replan-at-convergence
gating) died to a named counterexample in rounds 1-4. **Reject B as
Go-converger** (§5-B); the converger the design genuinely needs is
the helper-side lifecycle, and D covers detection.

Rationale in one line: non-forwarding state has exactly three owners
— planner, operator, global default — so put the ownership ON the
record, keep the record coherent with the accepted plan, and let
activation complete only where binding actually happened.

## 6. Public API preservation

- **Wire protocol:** TWO additive fields, both with serde defaults,
  no `CONFIG_SNAPSHOT_PROTOCOL_VERSION` bump (the #3091
  additive-with-default precedent):
  1. `BindingStatus.activation_state: string ∈ {"none","pending",
     "operator"}` (serde default `"none"`; Go's status decode ignores
     unknown fields, so old Go + new helper interoperates; new Go
     treats a missing field as `"none"`, which makes old-helper
     stranding read as drift — the correct mixed-version signal).
     Go's `BindingStatus` gains it as optional.
  2. `ControlRequest.complete_deferred: bool` (serde default `false`;
     old helpers ignore it — safe fail-closed: no defer-window
     convergence; new Go + old helper: the old helper's semantics,
     safe). Sent only by the `NotifyLinkCycle` path.
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind` — signatures and
  response shapes unchanged. `set_binding_state` slot addressing is
  unchanged (slots remain positional).
- **Go manager API:** unchanged (D and the arm-sync defer gate are
  manager-internal).
- **CLI / `show` output:** unchanged shape; `activation-state` may
  surface in verbose binding output as an additive display field.
  Counter/error provenance becomes correct-by-identity (a behavioral
  improvement, not a schema change).
- **Pinned behavior change (reviewer-sanctioned, Codex r3 f4's
  disjunct):** the #4952/#5143 post-teardown failure path now reports
  the RESTORED plan's coherent binding vector (all non-operator slots
  unarmed+pending) instead of retaining the rejected plan's vector.
  The pins' intent (real post-teardown state, fail-closed truth) is
  preserved; the affected pinned tests are updated in the same PR
  with this rationale (§5-C INVARIANT 2, §9).

## 7. Hidden invariants the change must preserve

1. **Defer contract — the REAL one (v3–v6):** a `defer_workers=true`
   PLAN-CHANGING apply must leave the whole vector unarmed (S3;
   non-operator slots `pending`), because its reconcile is SKIPPED and
   `refresh_bindings` reports old workers by numeric slot. Completion
   converges exactly when workers have bound, and ONLY with explicit
   provenance: the `complete_deferred` rebind (NotifyLinkCycle path)
   or a non-deferred apply. The Go arm-sync never arms during a defer
   window (Codex r4 B6); an explicit operator arm remains an explicit
   authorization (documented). A deferred apply with an UNCHANGED
   plan marks nothing.
2. **#869 no-ready-in-enabled:** `enabled` must keep NOT requiring
   `ready`. Untouched.
3. **#1666 ready-gate:** per-row shim steering must keep requiring
   `Ready`. Untouched. In the defer window S3 keeps everything
   unarmed, so the slot-keyed stale `Ready` alias can never produce a
   READY row — and `ctrl.Enabled=0` overrides row contents regardless
   (Codex r3's Q4 verification: ctrl=0 short-circuits the shim before
   binding lookup, lib.rs:405).
4. **Disarm direction never blocked:** the `ifindex <= 0` leg still
   force-clears (marking `pending` unless the record is
   operator-claimed, S2); `set_forwarding_state(false)` still fans
   out `armed=false` to every binding and clears state on registered
   slots — a deliberate global disarm leaves nothing armed to
   auto-activate, while unregistered (S1/S2-marked) slots keep their
   state for E2 (Codex r3 B4a).
5. **Same-plan skip (#2915/#2916/#3007/#3175):** the plan key and the
   candidate set are untouched; identity-carry only runs on the
   full-apply leg that ALREADY decided the plan changed.
6. **One-XSK-per-(netdev,queue) (#1921):** the `seen_linux` dedup and
   candidate iteration order are unchanged; identity uniqueness per
   plan follows from it.
7. **Coordinator filter (`registered && ifindex > 0`):** unchanged;
   worker bring-up must not start reading `armed` OR the state field.
8. **Operator override ownership (v6, tri-state):** operator verbs
   claim slots with `activation_state=operator` (same mutation as the
   verb's values, before any registration-changed reconcile). An
   operator-claimed slot is never marked pending and never converged;
   it flaps to `registered=false` retaining the claim (S2's
   exception) and recovers into its EXACT prior state
   (`registered=true, armed=false, operator` — E2's second arm). Its
   claim dies only at an explicit global fan-out (C3, registered
   slots) — the documented override lifetime. A globally-DISARMED
   slot (`none`) is NOT operator-owned: S2 re-marks it pending on
   flap and E2 re-registers it (Codex r4 B3's case). `set_queue_state`
   remains membership-at-invocation shorthand.
9. **Volatile state rebuilt, not carried (kept):** R3 carries
   {`armed`, `registered`, `activation_state`, `last_change`} only;
   everything else resets at replan and is re-derived. The
   defer-window slot-keyed alias is cosmetic per invariant 3 and
   remains a documented follow-up (§10).
10. **Coherent-vector invariant (v6):** after every handler, the
    binding vector equals the stored snapshot's plan. The one
    historical divergence (post-teardown retained-B/restored-A) is
    eliminated by replanning from the restored snapshot on the failure
    path; every other path replaces or retains vector and plan
    together. The server tests assert the invariant directly (§9
    item 16).
11. **Failure truthfulness (v6):** the planner never arms (S5); on
    ANY post-teardown bring-up failure (full apply, same-plan apply,
    rebind, toggle, forwarding arm) every non-operator registered
    slot goes unarmed+pending in COMMON typed handling (S4') BEFORE
    `refresh_status` recomputes `enabled`; the arm verb rolls its
    global bit back on Err so the Go desired-loop retries; and the
    same-plan deficit predicate treats `pending` as needing
    reconcile regardless of `last_error` (the retained-records
    deficit, Codex r4 B4's second half).
12. **HA portability:** no cluster-protocol or session-sync
    interaction; per-node helper-internal change with additive wire
    fields. Standby nodes run the same armed semantics. Mixed-version
    window: old helper + new Go strands as before (D warns);
    `complete_deferred` absent from old Go → no defer-window
    convergence → fail-closed (safe).
13. **Bootstrap fail-closed floor (Go side):** a plan-changing
    Compile already programs bootstrap ctrl disabled and clears
    binding rows before publish (manager_compile.go:315,
    maps_sync.go:163/178) — the bounded interruption exists on master
    and stays; the fix removes the INDEFINITE tail (§3).
## 8. Risk assessment

| Risk class | Level | Assessment |
|---|---|---|
| Behavioral regression | LOW-MED | Observable changes: (i) expansion-while-armed self-heals (S5 + convergence); (ii) deferred plan-changing applies deliberately fail-close the whole vector until provenance-tagged completion (S3) — posture tightening vs master's contraction mis-steer, cost ≈ 0 per the bootstrap evidence (Codex r3 m9); (iii) ANY post-teardown failure marks all non-operator slots pending (S4', common locus) — master-parity-or-better reporting plus self-healing retry; (iv) the arm verb rolls its global bit back on failure — a failed arm now RETRIES via the existing desired-loop instead of stranding (master's hole; Codex r4 B5); (v) the Go arm-sync no longer arms during defer windows (Codex r4 B6) — restores #5171's design intent at boot; (vi) the #4952 pinned failure-path reporting changes to the coherent restored-plan vector (reviewer-sanctioned, §6); (vii) operator overrides become claim-exact across flaps (tri-state); (viii) D warns on genuinely unexplained non-forwarding only. The dangerous shapes from rounds 1-4 — armed-but-unbound rows, rebind-missed activation, contraction window, hybrid activation, mid-window convergence, arm-then-fail stranding, arm-sync defer bypass, spurious-rebind authorization, sysfs-race authorization — are structurally excluded and pinned by §9 items 12-18. |
| Lifetime / borrow-checker | LOW | Cold path; owned clones already in use; the tri-state is a plain enum on an existing struct; the failure-path replan reuses the existing pure planner. No new lifetimes, no hot-path allocation. |
| Performance regression | LOW | Planner runs once per full apply (control path); the failure-path replan runs once per FAILED apply (error path); convergence is one O(n) pass after an already-O(n) reconcile on control events only. No per-packet/session/poll work. D's drift scan is O(n) on the ~1s poll over ≤ dozens of bindings. |
| Architectural mismatch | LOW-MED | The tri-state is new wire-visible control state with a fully enumerated lifecycle; the coherent-vector invariant SIMPLIFIES the v5 design (the plan gate and its replan-at-convergence are deleted). Must not entangle with #6702/#6681's planner rework: the identity key is layout-shape-independent; whichever lands second rebases the replan function. The pre-existing mid-defer-window early-BIND hazard of registration toggles (Codex r3 B6's other half) remains a filed follow-up (§10) — v6 closes only its early-CONVERGE side, and now also its early-ARM side (the Go arm gate). |
## 9. Test plan

**Rust unit/integration (the fix lives here):**

- `replan_bindings_from_candidates` unit tests (extend the existing
  replan test module — `userspace-dp/src/main_tests.rs`):
  1. **expansion while armed, non-deferred (S5 never-arm)** — new
     slots `registered=true, armed=false, activation_state=pending`;
     carried slots unchanged.
  2. **expansion while disarmed** — same shape (S5 is uniform).
  3. **deferred plan-changing apply (S3 gate)** — every registered
     slot `armed=false`; `pending` on exactly the non-operator slots;
     an operator-claimed slot stays `armed=false, operator`; an
     unchanged-plan deferred apply marks nothing.
  4. **deferred CONTRACTION** — `[a,b,c] → [b,c]` with defer:
     survivors unarmed+pending despite no new identity.
  5. **contraction (non-deferred)** — vanished identities' state does
     not leak onto survivors.
  6. **reshuffle identity carry** — each surviving identity keeps its
     own `armed`/`activation_state` at its NEW slot; an
     operator-claimed identity stays claimed at its new slot.
  7. **E2 + flap matrix (tri-state):** (a) `ifindex == 0` at apply →
     `registered=false, pending` (S1); later valid → re-registered
     (`registered=true, armed=false, pending`); converges at the next
     armed reconcile; (b) operator-UNREGISTERED (valid,
     `state=operator`) → flap → valid → re-registers into EXACT
     claim (`registered=true, armed=false, operator`); (c-i) ARMED
     slot flaps (S2 marks pending) → recovers → re-registered +
     converged; (c-ii) operator-DISARMED slot (`registered,
     armed=false, operator`) flaps → force-cleared WITHOUT pending
     (claim retained) → recovers per (b); (d) invalid → GLOBAL ARM
     fan-out → valid (Codex r3 B4a): the S1 mark SURVIVES the fan-out
     (C3 clears state only on registered slots) → re-registers; (e)
     GLOBAL DISARM → flap → valid (Codex r4 B3): the disarmed
     (`none`) slot is NOT operator-owned → S2 re-marks pending → E2
     re-registers → converges on re-arm.
  8. **identity transition matrix:** same-name/new-ifindex carries
     state; rename/same-ifindex re-initializes; orphan-fallback →
     explicit-parent carries across the ifindex swap.
  9. **queue-override semantics:** queue disarm → expansion adds a
     new member → initializes per S5 (pending, NOT claimed);
     contraction removing all claimed members leaves no residual;
     queue unregister survives a reshuffle; operator verbs SET/CLEAR
     `state=operator` in the same mutation as their values, BEFORE
     any registration-changed reconcile (C2 code-order pin).
  10. **volatile non-carry (R3):** a carried identity's
      `ready`/`bound`/`xsk_registered`/counters/`last_error` reset at
      replan; only the control quad carries.
  11. **`had_existing` death:** inheritance depends ONLY on
      identity-map membership.
- **Convergence unit tests** (`reconcile_status_bindings` armed leg):
  pending+registered slots arm+clear on Ok; marks NOT consumed on
  Err; operator-claimed slots never armed; convergence BLOCKED when
  the stored snapshot is defer=true and the caller lacks
  `complete_deferred`; ALLOWED for the provenance-tagged caller;
  allowed for every caller when the stored snapshot is non-deferred.
- **Common S4' unit tests:** `WorkerSpawn` and `WorkerBindIncomplete`
  from EACH reconcile caller (full apply, same-plan apply, rebind,
  binding toggle, queue toggle, forwarding arm) → all non-operator
  registered slots unarmed+pending; operator-claimed slots untouched.
- **Server-level regressions** (`userspace-dp/src/server/tests.rs`;
  valid map pins, `force_worker_healthy_stub`, assertions on
  ARMED/STATE + reconcile Ok/Err + reconcile stage
  (status.rs:263-265) + immediate post-failure assertions per Codex
  r3 M7 / r4 M8):
  12. **expansion-while-armed** (the issue's demanded test): apply A,
      `set_forwarding_state(true)`, apply B with an additional zoned
      interface; BOTH responses ok, plan keys differ, binding count
      increased, added identity exists, EVERY binding
      `registered && armed && state==none`, `enabled == true`,
      reconcile stage advanced. Red on master, green after.
  13. **deferred expansion, three completion shapes + two blocks:**
      apply A, arm, apply B `defer_workers=true` + inserted
      earlier-sorting candidate: all non-operator slots
      `!armed && pending`, `enabled == false`, IMMEDIATE assertion on
      an untouched pending slot + reconcile-call delta. Complete via:
      (a) same-plan re-apply `defer_workers=false`; (b) full-leg
      re-apply with a changed plan key; (c) `rebind` with
      `complete_deferred=true` — after each, non-operator slots
      `registered && armed && state==none`, `enabled == true`.
      NEGATIVES: (i) a `set_binding_state` registration toggle DURING
      the window does NOT converge the pending slots (and the toggled
      slot's own claim holds); (ii) a plain `rebind` (no provenance)
      DURING the window does NOT converge; (iii) the Go arm-sync
      during the window does not arm (manager-side test below).
  14. **failed bring-up, all shapes + retry (Codex r4 B4/B5/M8):**
      force `WorkerSpawn` and `WorkerBindIncomplete` on (i) expansion
      apply, (ii) E2-only apply, (iii) CONTRACTION apply, (iv)
      global-arm (`set_forwarding_state(true)` after a deferred boot
      apply), (v) rebind, (vi) a registration toggle. IMMEDIATELY
      after each Err assert: every non-operator registered slot
      `!armed && pending` (S4'), `enabled == false`, marks SURVIVE;
      (iv) additionally asserts the global bit ROLLED BACK (so the
      Go desired-loop would retry) and no fan-out ran before the
      failed reconcile. Then a successful retry converges each.
  15. **operator-override survival (tri-state):** operator-disarm a
      slot; commit a plan-changing deferred apply + completion — the
      claimed slot stays `armed=false, operator` while the deferred
      slots converge; repeat across the failure path of 14(i) and the
      flap path of 7(c-ii); a global arm fan-out afterwards clears
      the claim (C3).
  16. **coherent-vector invariant + failure-path replan (Codex r4
      B2/M9):** apply A, apply B (expansion), force B's bring-up to
      fail post-teardown: IMMEDIATELY assert the reported vector
      EQUALS restored A's plan (identities + ifindex), all
      non-operator slots unarmed+pending — NO retained B-only
      identity. Then: (i) an auto-rebind-style plain rebind binds
      A's plan and converges (self-heal to last-good); (ii) the
      failed-CONTRACTION shape (A=[a,b,c], B=[b,c]): after failure
      the vector is [a,b,c] again with `a` pending, and the rebind
      binds `a` — no enabled=true without an `a` worker; (iii) the
      same-name/new-ifindex shape: B=eth0@if11 rejected, A=eth0@if10
      restored: the vector carries if10 and the rebind binds if10.
      The updated #4952/#5143 pins live here (coherent vector, S4'
      marks, surviving-worker volatile refresh).
  17. **#5134-shaped retry + debt-discard interleaving:** deferred
      apply → failed completion → plan-changing commit before the
      retry → IMMEDIATE debt/provenance assertions (marks survive,
      convergence blocked until provenance), then slots converge on
      the later successful armed reconcile.
  18. **same-plan retry deficit (Codex r4 B4 second half):** force a
      spawn failure (retained records with `last_error`), then a
      same-plan apply: the pending-aware deficit predicate MUST fire
      the reconcile (planned==live==runnable with last_error set does
      NOT suppress it), and the reconcile converges the marks.
- The fail-fast invariant (Q6, resolved r1): assertions live ONLY in
  tests and only over well-defined planner/activation transitions.
- Protocol canaries: `userspace-dp/src/protocol/tests.rs` exact-schema
  snapshots updated to pin `activation_state` and
  `complete_deferred` deliberately.
- `make test-rust` (full cargo suite) clean; `cargo build`
  warning-free. Fleet cap honored:
  `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6749`.

**Go (option D + gates + manager tests):**

- Manager unit test for the D warn, desired- and state-gated:
  (i) desired==true + one `Registered && !Armed && state=="none"`
  binding → exactly one warn on the false→true edge, none on
  subsequent ticks, clears after re-arm; (ii) `state=="pending"` or
  `"operator"` → NO warn; (iii) desired==FALSE → NO warn; (iv)
  missing field (old helper) → reads as `"none"` (warn when desired).
- Manager unit test for the arm-sync defer gate (Codex r4 B6): with
  `m.deferWorkers == true` and desired==true, the sync issues NO arm
  (and the disarm direction still passes); with the flag cleared, the
  arm proceeds.
- Manager unit test for `complete_deferred` provenance: the
  NotifyLinkCycle path sets it on the rebind request; the
  busy-watchdog path (maps_sync.go:1484) does NOT.
- `maps_sync` gate test (AGY r1 f3): synthesized post-expansion
  status (new slots converged) through `probeBindingsReady`/
  `bindingForwardingLive` — ctrl admits, shim rows go READY.
- `make test-go` clean.

**Smoke (loss userspace cluster, lock-cell wrapped):** deploy; verify
iperf3 baseline to 172.16.80.200; commit an ADDITIONAL zoned VLAN
unit (e.g. a new `reth0.90` in the wan zone) while armed; assert
transit continues with no manual arm toggle and `show ... bindings`
reports the new slots armed with `activation-state=none`. Re-apply
CoS after the deploy per the cluster protocol
(`apply-cos-config.sh`).

**Docs (module contract, same work item):**
`userspace-dp/src/server/README.md` — the arm-model narrative gains
the tri-state lifecycle: the planner never arms, who sets each
state, the two-gated convergence, the operator-claim rule, the
coherent-vector invariant, and the `complete_deferred` provenance
contract (incl. the rebind completion log gaining the pending count,
AGY r4 n2). **Release note / upgrade note (AGY r1 Q7 + Codex r1 m8 +
AGY r3 f4):** required and PROMINENT on two points: (1) the fix takes
effect only after the HELPER restarts into the new binary (process.go:18
reuses a pingable same-config helper) — call for `systemctl restart
xpf-userspace-dp` on upgrade; (2) the deliberate posture change —
deferred (RETH-MAC-pending) plan-changing commits now fail-close
transit for the whole dataplane until the link-cycle completion,
instead of risking stale shifted rows (previously) or stranding new
slots (the bug).
## 10. Out of scope (explicitly)

- **Go per-binding armed AUTO-convergence (option B)** — rejected
  (§5-B); the converger the design needs is the helper-side
  provenance lifecycle, and D covers detection.
- **#6702/#6681 planner queue-geometry rework** — they own
  binding-count consequences; this fix is compatible but does not
  implement any of their layout change.
- **`bindingForwardingLive` / `enabled` / `probeBindingsReady` gate
  semantics** — the gates are correct; the bug is the DEFAULT they
  were fed. No gate changes. (The all-or-nothing `enabled` gate making
  an operator per-slot disarm a whole-dataplane-off is master's
  semantics, unchanged.)
- **The pre-existing mid-defer-window early-BIND hazard** (Codex r3
  B6's other half): a registration toggle during the defer window
  runs an armed reconcile that BINDS workers before the RETH MAC
  cycle — present on master (the toggle's reconcile is defer-blind).
  v6 closes the early-CONVERGE side (the defer gate) and the
  early-ARM side (the Go arm-sync gate); the toggle's early-BIND
  itself is a separate pre-existing issue filed as a follow-up.
- **Re-keying the coordinator's slot-keyed live-worker lookup
  (`refresh_bindings`)** — the defer-window cosmetic alias is
  documented and neutralized by S3; re-keying it belongs with
  #6702's coordinator-adjacent planner rework. Filed as a follow-up.
- **Persisted-state migration** — none needed (state file write-only;
  the fields are additive with serde defaults).
- **Operator-override persistence across global arm toggles** — the
  fan-out still clears claims (C3, registered slots); making
  diagnostic disarms durable is a separate product decision.
- **The retired v3/v4/v5 machinery** — leg-scoped R1/R2, the full
  fan-out defer-completion, v4's S4 identity-scoped revert, v4's
  arm-at-replan S5, v5's bool marker, and v5's replan-at-convergence
  plan gate are superseded and recorded at bce10126c / f679a791a /
  0c0b9b677.

## 11. Open questions for adversarial review

Resolved across rounds 1-4 (for the record): Q2, Q5, Q6, Q7,
applied-vs-requested init, full fan-out vs scoped (scoped REQUIRED),
Q3 (uniform S3), Q5-toggle (now defer-gated + arm-gated), Q7-boot,
the plan gate itself (deleted with the coherent-vector invariant —
the race Codex r4 M9 found dies with it).

Remaining questions for round 5, each invitable to PLAN-KILL with a
concrete counterexample:

1. **Tri-state completeness.** Exhibit a path to
   `Registered && !Armed` with `activation_state == none` that is NOT
   global-fan-out-created and NOT operator-created — an unowned
   producer that strands D-silent. (Enumeration to attack: every
   replan branch, S3/S4' gates, the C3 reorder+rollback, operator
   verbs, lifecycle init, rebind, both apply legs, #5134, helper
   restart, the #2794 disarmed leg, the failure-path
   replan-from-restored.)
2. **Coherent-vector invariant.** Exhibit a handler path that leaves
   the vector differing from the stored snapshot's plan AFTER v6's
   failure-path replan. (Candidates to attack: the #3789 pre-teardown
   restore leg — existing_bindings restored WITH the previous
   snapshot, coherent by construction?; the defer same-plan leg; the
   bump_fib path; a replan whose own inputs changed mid-apply.)
3. **The Go arm-sync defer gate's completeness.** The gate skips the
   ARM direction while `m.deferWorkers`; the completion relies on the
   provenance-tagged rebind or a non-deferred re-apply. Exhibit a
   production sequence where defer is pended and NEITHER fires —
   e.g. the daemon clears `m.deferWorkers` but the link never cycles,
   so no NotifyLinkCycle arrives (does the daemon ALWAYS call
   NotifyLinkCycle after MAC programming, daemon_apply_dataplane.go:385?
   and does the #5134 debt path cover a completion re-apply?).
4. **`complete_deferred` on the #5134 retry republish.** The debt
   loop republishes with `DeferWorkers=false` against a stored
   defer=true snapshot — a non-deferred APPLY, which converges
   without the provenance flag (stored snapshot after the swap is
   non-deferred). Confirm this is the intended completion semantics
   for that path (the apply IS the newer config, so converging is
   correct), or show a hazard.
5. **Rollback + #6165 protocol gate interplay.** The arm-verb
   rollback lets the Go desired-loop retry a failed arm; the #6165
   gate (manager_ha.go:630-634) can REFUSE that retry when the
   running helper's accepted protocol is stale. Confirm the refusal
   is fail-closed and non-flapping (the gate re-polls first; a
   permanently-stale helper logs once per tick at Warn — acceptable,
   or needs rate-limiting?).
6. **Round-4 disposition table audit.** §1's table maps every r4
   finding to its v6 fold. Which row is claimed-but-wrong this time?
