# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v5 — pending adversarial plan review (round 4)**

- Issue: #6749 (opus-review-001 root R06, severity High)
- Research base: `ad9591177` (origin/master at worktree creation)
- Research branch: `research/6749-armed-state` (plan docs only — no
  production code in this branch)
- v1 @ `8c76670d6` (r1: all DEMAND-REVISION); v3 @ `bce10126c` (r2:
  all DEMAND-REVISION); v4 @ `f679a791a` (r3: all DEMAND-REVISION);
  v5 folds round 3: the planner never arms (AGY r3 f1), was-armed
  gates on every mark rule (AGY r3 f2 / Codex r3 B3/B4), S4' global
  failure mark (Codex r3 B5), plan-gated + defer-gated convergence
  (Codex r3 B2/B6), C3 reordered and scoped to registered (Codex r3
  B4/M7), D gated on desired (Codex r3 m10).

---

## 1. Status

DRAFT v5 — pending adversarial plan review round 4 (Codex + AGY + Claude
SMR). Convergence target: PLAN-READY (recommended path shipped to
`/engineer`) or PLAN-KILL. No production code is written under `/research`.

### Round verdict log

- **Round 1** (v1): all three DEMAND-REVISION. SMR: B-rejection honesty,
  observability leg, close Q2/Q5, identity semantics. AGY: E2
  invalid→valid stranding (MAJOR), volatile zeroing, Go gate test.
  Codex: deferred-activation BLOCKER (defer is not a disarm), identity
  not physical (BLOCKER), E2 concurrence, volatile-vs-control carry,
  queue-override lifetime, B dismissal overstated, unsafe-green tests,
  trigger/outage overstatement.
- **Round 2** (v3): all three DEMAND-REVISION, converging on ONE
  architecture. Codex (6 BLOCKER + 2 MAJOR): the rebind completion path;
  full-leg defer completion + #5134 debt discard; deferred CONTRACTION
  leaves all armed; R1 arm-before-reconcile lie on failed bring-up;
  full fan-out reverses operator maintenance disarms — scoped
  provenance REQUIRED; E2/operator-unregister flap; unsafe-green tests.
  AGY: full-leg stranding (BLOCKER), R1 pre-arm, E2 flap, test gaps,
  fan-out override loss. SMR: the full-leg hole + commitments.
- **Round 3** (v4): all three DEMAND-REVISION. Codex (6 BLOCKER + 2
  MAJOR + 2 MINOR): unversioned marker can activate a REJECTED hybrid
  plan (B-vector retained after failure + auto-rebind → plan-gate the
  convergence); S3 marks operator-disarmed slots (was-armed gate);
  one-bool conflates registration with activation provenance (C3 must
  be scoped to registered; S2 was-armed gate); S4's identity scope
  never guaranteed enabled=false (S4' global failure mark);
  registration-toggle reconcile converges mid-defer-window (defer
  gate, rebind-authorized); C3 clears marks before the fallible arm
  reconcile (reorder arm fan-out after Ok); tests still green unsafe
  impls; S3 expansion cost overstated but global gate still safer; D
  must gate on desired==true. AGY (2 MAJOR + 1 MINOR + 1 NIT): S5 must
  NEVER arm at replan — convergence-only arming deletes S4's revert
  machinery (= adopted); S2 marks operator-disarmed slots on flap
  (= Codex B4, same was-armed gate); test 7(c) must split; S3's
  total-disable needs a prominent release note. SMR r3: S4's revert
  set misses E2 (subsumed by AGY f1's adoption + S4'); Q3/Q5/Q7
  commitment answers (adopted in §11).
- **Round-3 disposition table (the anti-"claims false" record, Codex
  r3 BLOCKER 1):**

  | r3 finding | v5 disposition |
  |---|---|
  | Codex B2 hybrid activation | CLOSED — plan gate on convergence (§5-C) |
  | Codex B3 S3 marks operator slots | CLOSED — was-armed gate on S3 (§5-C S3) |
  | Codex B4 bool conflation | CLOSED — C3 scoped to registered + S2 was-armed gate (§5-C C3/S2) |
  | Codex B5 S4 scope | CLOSED — S4 deleted; S4' global failure mark + S5 never-arm (§5-C) |
  | Codex B6 toggle mid-defer | CLOSED — defer gate + rebind-authorized flag (§5-C) |
  | Codex M7 C3 pre-reconcile | CLOSED — arm fan-out reordered after Ok (§5-C C3) |
  | Codex M8 test holes | CLOSED — §9 items 12-17 rewritten |
  | Codex m9 S3 cost | CLOSED — §11 Q3 resolved (global gate, bootstrap evidence) |
  | Codex m10 D on disarm | CLOSED — D gated on desired==true (§5-D) |
  | AGY f1 S5 pre-arm | CLOSED — planner never arms (§5-C S5) |
  | AGY f2 S2 flap | CLOSED — S2 was-armed gate (§5-C S2) |
  | AGY f3 test 7(c) | CLOSED — §9 item 7 split |
  | AGY f4 S3 release note | CLOSED — §9 docs bullet |
  | SMR3-1 S4-E2 | CLOSED — subsumed by AGY f1 + S4' |
  | SMR3-2/3/4 | CLOSED — §11 commitments |

- **Round-1 detail log** (kept for the record):

- Claude SMR r1: DEMAND-REVISION — SMR-1 B-rejection overstated, SMR-2
  missing observability-only Go leg, SMR-3 close Q2/Q5 from source, SMR-4
  document identity semantics. Folded (v2 §5-B/§5-D/§11/§5-C; carried
  forward in v3).
- AGY r1: DEMAND-REVISION — finding 1 (MAJOR): `had_existing` /
  `last_change` interaction strands an interface transitioning
  `ifindex<=0 → >0`. Folded as edge case E2 with the operator-unregister
  carve-out (v2; kept in v3 R3). Finding 2 (MINOR, zero volatile on
  carry): SUPERSEDED — v3 R3 carries control fields only and zeros
  volatile, adopting the finding (v2 had rejected it; Codex r1 finding 4
  showed the reconciliation path clears volatile anyway, making
  volatile-carry dead weight on the normal path and alias-prone in the
  defer window). Finding 3 (NIT, Go-side gate test): folded into §9.
- Codex r1: DEMAND-REVISION — BLOCKER 1 (the real deferred-activation
  path enters a plan-changing apply with `forwarding_armed=true`
  WITHOUT disarming; armed-from-global on a no-reconcile apply +
  slot-keyed `refresh_bindings` against still-live old workers opens
  ctrl with stale-identity READY rows — v1/v2's §7.1 "defer ⇒ global
  false" assumption was FALSE). BLOCKER 2 (`(interface, queue_id)` is
  unique per plan but is not physical identity — real XSK identity is
  (ifindex, queue)). MAJOR 3 (E2 invalid→valid, concurs AGY r1 f1, adds
  that A fails it too), MAJOR 4 (whole-record carry conflates control
  state with slot-owned runtime telemetry; reconcile resets volatile
  anyway), MAJOR 5 (queue-scoped override lifetime undefined), MAJOR 6
  (B rejection overstated; the deferred design forces an explicit
  activation step), MAJOR 7 (test would green an unsafe implementation;
  required test list), MINOR 8 (trigger frequency + "zero outage"
  overstated; release note must require helper restart). Folded into
  v3's three-rule activation model (§5-C R1/R2/R3), §7, §9, §3.

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
and the global bit already equals it** (Codex r3 MINOR 10 — evaluating
on an intentional global disarm would warn on every healthy slot),
when any binding presents `Registered && Ifindex > 0 && !Armed
&& !ActivationPending`, emit an EDGE-TRIGGERED `slog.Warn` (fires on
the drift predicate transitioning false→true, and again when it clears;
never per-tick — the project logging rules forbid >1/s control-plane
Info). No request is issued; nothing auto-reverts, so an operator
diagnostic disarm simply logs a truthful warn. The marker
(`ActivationPending`, §5-C) is what makes the predicate EXACT: pending
planner activations are excluded (they converge at the next successful
reconcile — warning on them would be noise), and what remains is
genuine drift: operator disarms (truthful, intended) or any FUTURE
unmarked producer (the tripwire). ~15 lines in `manager_ha.go` + a
manager test. On an OLD helper (no marker field), every unarmed
registered slot reads as drift — which is exactly the old-bug
stranding, so the warn doubles as the mixed-version detector.

- **Value:** satisfies the issue's third leg as a detection surface; if
  a FUTURE drift producer ever appears (a new planner path, a
  mixed-version window nobody enumerated), on-call gets a log line
  naming the exact stranded slot instead of a silent blackout.
- **Cost/risk:** near zero; no semantics change. Bundled into the
  recommended ship.

### Option C — the `activation_pending` lifecycle, v5 (Rust helper; superset of A)

v5 rewrite (AGY r3 f1–f3, Codex r3 BLOCKERs 2–7 + MAJOR 8, SMR r3).
Round 3 tightened the lifecycle in five ways, all folded here. The
one-sentence model: **the planner NEVER arms — it only MARKS
(`activation_pending=true`) the slots it left unactivated; a slot arms
only at a successful, plan-authorized, defer-authorized armed reconcile,
or by an operator/global verb.**

**The marker.** `BindingStatus.activation_pending: bool` — additive
wire field (serde `#[serde(default)]`; Go's `json.Unmarshal` ignores
unknown fields — protocol_status.go:440, process_control.go:148,
verified r2). Go's `BindingStatus` gains it as optional for option D
and `show`. Meaning: **"planner/apply machinery left this slot short
of `registered && armed`; converge it at the next successful armed
reconcile for the CURRENT plan."** Operator-owned states
(`registered && !armed && !pending`, or `!registered && !pending`)
never carry it — that distinction is the whole point.

**Set rules (planner/apply machinery ONLY), each gated so an
operator-owned slot (`!armed && !pending` or `!registered &&
!pending`) is NEVER marked (AGY r3 f2 / Codex r3 BLOCKER 3):**

- **S1 — replan creates a slot it cannot register** (`ifindex <= 0`):
  `registered=false, armed=false, pending=true`.
- **S2 — replan force-clears on `ifindex <= 0`:** the
  `registered=true → false` transition marks pending **only if the
  record was `armed` (or already pending) before the clear**. An
  operator-DISARMED slot (`registered && !armed && !pending`) that
  flaps is force-cleared to `registered=false` WITHOUT a mark; on
  recovery it is not re-registered (operator-owned — the documented
  disarm→unregister degradation across a flap, §10; the no-forward
  intent survives, which is what a destructive maintenance verb
  guarantees). An operator-UNREGISTERED slot (`!registered &&
  !pending`) is untouched as before.
- **S3 — deferred plan-CHANGING apply** (full-apply leg with
  `defer_workers=true`): for every registered slot, `armed=false`;
  mark pending **only if the slot was `armed` or already pending**
  (Codex r3 BLOCKER 3 — an operator-disarmed slot is already unarmed;
  S3 leaves it unarmed and UNMARKED, so completion convergence can
  never re-arm it, and test 15 is possible again). This is the global
  pending gate Codex r2 BLOCKER 5 forced for deferred
  contractions/reshuffles; per Codex r3 MINOR 9 + SMR r3 SMR3-2, the
  global gate costs nothing real even for expansions: the all-or-
  nothing `enabled` gate closes ctrl through the window either way,
  and ordinary plan-changing commits already bootstrap-ctrl-off +
  clear rows (manager_compile.go:315, maps_sync.go:163/178). A
  deferred apply with an UNCHANGED plan marks nothing.
- **S4' — post-teardown bring-up failure** (full-apply leg,
  `WorkerSpawn | WorkerBindIncomplete`, snapshot.rs:356-396): for
  EVERY registered slot, `armed=false, pending=true` (was-armed-gated;
  operator-owned slots untouched). v4's S4 (revert only this-apply's
  initialized identities) is deleted: it missed E2 re-registrations
  (SMR r3 SMR3-1) and every shape with no new identity — contractions,
  same-name/new-ifindex, workers/ring-only plan changes (Codex r3
  BLOCKER 5). S4' is shape-independent and, combined with S5's
  never-arm rule, means NOTHING is ever reported armed against a
  failed bring-up: `enabled` recomputes false, ctrl stays closed,
  and the pending marks survive so the NEXT successful armed
  reconcile self-heals. The #4952 retained-vector semantics are
  unchanged (the rejected plan's binding vector is still reported,
  now uniformly unarmed+pending).
- **S5 — new/E2 initialization (AGY r3 f1 — the planner never
  arms):** genuinely-new identities initialize `registered=true,
  armed=false, pending=true` ALWAYS (any defer state, any global
  state). E2 re-registration at replan: `!registered && pending &&
  new ifindex > 0` → `registered=true`, still `armed=false,
  pending=true`. The ONLY paths that set `armed=true` on a
  planner-created slot are the convergence locus below, an operator
  verb, or the global fan-out. v4's arm-at-replan (and with it the
  transient armed-before-bind state AGY r3 f1 attacked) is gone.

**Clear/claim rules:**

- **C1 — converged:** a slot that reaches `registered && armed` (any
  cause) clears the mark.
- **C2 — operator claim:** `set_binding_state` / `set_queue_state`
  clear the mark on every affected slot in BOTH directions (an
  operator disarm claims the unarmed state; an operator arm
  hand-converges). Ordering inside those handlers: claim FIRST, then
  reconcile (SMR r3 SMR3-3).
- **C3 — global fan-out (Codex r3 BLOCKER 4a + MAJOR 7):**
  `set_forwarding_state` clears marks **only on REGISTERED slots** —
  the fan-out's own domain (`armed = req && registered`,
  status.rs:418-423). An unregistered slot (S1/S2 mark) keeps its
  mark across global arm/disarm cycles, so `invalid → global arm →
  valid` still re-registers via E2 (v4's C3 cleared everywhere and
  stranded exactly that shape, D-silent). And the ARM direction is
  reordered (Codex r3 MAJOR 7): `set_forwarding_state(true)` sets the
  global bit, runs the fallible reconcile FIRST, and only on `Ok`
  fans out `armed=true` + clears marks (registered slots). On `Err`
  no slot arms and no mark clears — v4's arm-then-fail ordering
  falsified the "Err consumes no marker" invariant and stranded
  armed-mark-free slots against dead workers with Go seeing
  global==desired and never retrying. The disarm direction is
  unchanged (fan-out + clear-first, never blocked).

**Convergence — one locus, three gates (Codex r3 BLOCKERs 2 + 6):**
in `reconcile_status_bindings`' armed leg, after `afxdp.reconcile`
returns `Ok` and the bindings are written back, for every slot with
`pending && registered && in_current_plan && defer_authorized`:
`armed=true, pending=false, last_change=now`.

- **Armed gate (from v4):** only when `should_run_afxdp(status)`
  (globally armed + supported); the disarmed leg never converges.
- **Plan gate (Codex r3 BLOCKER 2):** the slot's `(interface,
  queue_id)` must belong to the plan of the CURRENT stored snapshot —
  computed at convergence time by running the pure
  `replan_queues(stored_snapshot, workers, bindings)` and collecting
  its identity set (cold path, no side effects). This kills the
  hybrid-plan hazard: full apply B fails post-teardown → snapshot A
  restored but B's vector retained (#4952) → a later REBIND (no
  replan; busy-binding recovery can auto-trigger it,
  maps_sync.go:1474) reconciles A-forwarding with B-layout workers —
  v4 would have armed B's pending slots against A's snapshot,
  bringing the rejected hybrid live. Under the plan gate, B-only
  identities stay pending (master parity: `enabled=false`), A's
  pending slots converge, and a later genuine retry of B converges
  the rest because the stored snapshot is B again.
- **Defer gate (Codex r3 BLOCKER 6):** convergence requires
  `!stored_snapshot.defer_workers` UNLESS the caller is the `rebind`
  handler — the daemon-authorized deferred completion (Codex r2
  BLOCKER 3 established that `NotifyLinkCycle` → `rebind`,
  process_linkcycle.go:219, IS the normal completion path).
  `reconcile_status_bindings` gains a one-bit
  `defer_completion_authorized` parameter: rebind.rs passes `true`,
  every other caller (apply legs, forwarding, queue/binding toggles)
  passes `false`. Without it, an operator registration toggle
  mid-defer-window runs a full armed reconcile (binding.rs:34-53;
  `should_run_afxdp` does not see defer, status.rs:414) and would
  bind + converge every pending slot BEFORE the RETH MAC cycle — the
  premature activation the defer mechanism exists to prevent. (The
  toggle's early-BIND side is pre-existing on master and noted as a
  follow-up in §10; the early-CONVERGE side is what this gate closes.)
- **Err paths:** every fallible caller returns before the convergence
  (snapshot.rs:196 structure; `bound == planned` required for Ok,
  bringup.rs:188), so no mark is consumed and no slot arms against
  unbound workers.

**R3 — control-state identity carry (from v4, quad updated).** Carry
{`armed`, `registered`, `activation_pending`, `last_change`} keyed on
configured-name `(interface, queue_id)`; volatile fields reset at
replan and rebuild downstream. Identity semantics unchanged
(same-name/new-ifindex carries; rename re-initializes;
orphan-VLAN→explicit-parent promotion carries). `had_existing` stays
dead (identity-map membership only). Queue-scoped overrides remain
membership-at-invocation shorthand.

**Ownership model (the issue's design question, final answer):**
`armed` is set by exactly three actors: the GLOBAL default
(Go-pushed `forwarding_armed`, fanned out post-reconcile on explicit
arms), OPERATOR verbs (ephemeral, identity-scoped, claim-protected),
and the CONVERGENCE (slots the planner marked and a successful armed
reconcile for the current plan has now bound). The planner itself
never arms — it only marks its own pending work, because only the
helper can tell that apart from an operator's deliberate disarm.

**What it fixes (full inventory):** the issue's indefinite disable on
expansion-while-armed (S5 + convergence); deferred stranding on all
three completion shapes (S3 + rebind-authorized convergence);
deferred contractions/reshuffles (S3's global gate); armed-but-unbound
reporting after failed bring-up on EVERY plan shape (S4' + S5's
never-arm); the rejected-hybrid activation (plan gate); premature
convergence via registration toggles mid-defer (defer gate);
arm-then-fail stranding (C3 reorder); invalid→global-arm→valid
stranding (C3 scoped to registered); E2 invalid→valid stranding (E2
lifecycle); operator-disarm destruction across flaps, deferred
applies, and completions (was-armed gates on S2/S3/S4'); wrong-
identity control-state carry (R3); retry-after-failure stranding
(self-heals via surviving marks).

**Size:** marker field + S1/S2/S3/S4'/S5 set rules (~45 lines),
convergence with plan+defer gates (~20 incl. the pure replan for the
membership set), `defer_completion_authorized` plumbing (~5), C3
reorder in forwarding.rs (~10), verb clears (~6), Go optional field +
D predicate (~20), protocol canary updates, docs. No coordinator,
gate, or shim changes.
### Recommendation

**Ship option C + option D** — the `activation_pending` lifecycle as
refined in v5 (S1–S5/S3/S4' was-armed-gated set rules with the planner
NEVER arming, C1–C3 clear/claim rules with C3 scoped to registered and
the arm fan-out reordered post-reconcile, the tri-gated convergence
locus — armed × in-current-plan × defer-authorized — inside
`reconcile_status_bindings`, R3 control-only identity carry, E2
lifecycle re-registration) plus the marker-aware, desired-gated Go
drift detector. Retreat: none lighter survives review — v3's
leg-scoped R1/R2 was killed by three independent doors (rebind
completion, full-leg completion, deferred contraction), v4's ungated
marker by the hybrid-plan and operator-claim counterexamples, and
option A shares the arm-at-replan defect the planner-never-arms rule
deletes. **Reject B as Go-converger** (§5-B); the converger the design
genuinely needs is the helper-side marker, and D covers detection.

Rationale in one line: armed state is born in the planner, so the
planner MARKS what it leaves unactivated — never arms it; the
reconcile that actually binds workers for the current plan is the only
moment activation may complete; and only the helper can tell its own
pending work apart from an operator's deliberate disarm.

## 6. Public API preservation

- **Wire protocol:** ONE additive field — `BindingStatus
  .activation_pending: bool` (serde `#[serde(default)]`; Go's status
  decode uses ordinary `json.Unmarshal`, which ignores unknown fields,
  so old Go + new helper interoperates; new Go treats a missing field
  as false, so new Go + old helper interoperates — and option D then
  reads old-helper stranding as drift, the correct signal). Go's
  `BindingStatus` (protocol_binding.go) gains the field as optional.
  `CONFIG_SNAPSHOT_PROTOCOL_VERSION` is NOT bumped: additive-with-
  default fields are exactly the protocol's documented extension
  shape (the #3091 vlan_id/parent_linux_name precedent). The
  exact-schema canaries (userspace-dp/src/protocol/tests.rs) are
  updated to pin the new field deliberately.
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind` — signatures and
  response shapes unchanged. `set_binding_state` slot addressing is
  unchanged (slots remain positional).
- **Go manager API:** unchanged (D is a manager-internal
  edge-triggered warn inside `syncDesiredForwardingStateLocked`).
- **CLI / `show` output:** unchanged shape; the marker may surface in
  verbose binding output as `activation-pending` (additive display
  field, matching how other optional booleans render). Counter/error
  provenance becomes correct-by-identity (a behavioral improvement,
  not a schema change).

## 7. Hidden invariants the change must preserve

1. **Defer contract — the REAL one (v3–v5):** a `defer_workers=true`
   PLAN-CHANGING apply must leave the whole vector unarmed (S3), with
   pending marks on exactly the non-operator-owned slots, because its
   reconcile is SKIPPED and `refresh_bindings` reports old workers by
   numeric slot. A deferred apply with an UNCHANGED plan marks nothing.
   Completion — via same-plan re-apply, full-leg re-apply, OR the
   rebind link-cycle — converges the marks exactly when the workers
   have bound, and ONLY via the rebind-authorized or non-deferred
   paths (Codex r3 BLOCKER 6's defer gate). A test pins every
   completion shape AND the mid-window toggle block (§9 items 13, 17).
2. **#869 no-ready-in-enabled:** `enabled` must keep NOT requiring
   `ready`. Untouched — only the armed defaults change.
3. **#1666 ready-gate:** per-row shim steering must keep requiring
   `Ready`. Untouched. In the defer window S3 keeps everything
   unarmed, so the slot-keyed stale `Ready` alias (§4 item 7) can never
   produce a READY row — and even if it could, `ctrl.Enabled=0`
   overrides row contents (verified by Codex r3 BLOCKER 5's Q4 check:
   ctrl=0 short-circuits the shim before binding lookup,
   lib.rs:405, and all enable writes are conditional,
   maps_sync.go:679/809).
4. **Disarm direction never blocked:** the `ifindex <= 0` leg still
   force-clears (and marks only was-armed/was-pending records, S2);
   `set_forwarding_state(false)` still fans out `armed=false` to every
   binding and clears marks on registered slots — a deliberate global
   disarm leaves nothing armed to auto-activate, while unregistered
   (S1/S2-marked) slots keep their marks for E2 (Codex r3 BLOCKER 4a).
5. **Same-plan skip (#2915/#2916/#3007/#3175):** the plan key and the
   candidate set are untouched; identity-carry only runs on the
   full-apply leg that ALREADY decided the plan changed.
6. **One-XSK-per-(netdev,queue) (#1921):** the `seen_linux` dedup and
   candidate iteration order are unchanged; identity uniqueness per
   plan follows from it.
7. **Coordinator filter (`registered && ifindex > 0`):** unchanged;
   worker bring-up must not start reading `armed` OR the marker.
8. **Operator override ownership (v5):** operator per-slot/queue verbs
   CLAIM the slot (C2 clears the mark in both directions, ordered
   claim-before-reconcile); their overrides are identity-scoped (R3)
   and die only at a global arm fan-out (C3, registered slots). No
   mark rule (S1–S5, S3, S4') may mark an operator-owned
   (`!armed && !pending` or `!registered && !pending`) slot — the
   was-armed gate — so convergence NEVER re-arms an operator state
   (Codex r3 BLOCKER 3, AGY r3 f2). `set_queue_state` remains
   membership-at-invocation shorthand (Codex r1 MAJOR 5). The
   documented degradation: an operator-DISARMED slot whose interface
   flaps recovers as unregistered (its no-forward intent survives; the
   disarm→unregister widening across a flap is recorded in §10).
9. **Volatile state rebuilt, not carried (v3, kept):** R3 carries
   {`armed`, `registered`, `activation_pending`, `last_change`} only;
   everything else resets at replan and is re-derived. The
   defer-window slot-keyed alias is cosmetic per invariant 3 and
   remains a documented follow-up (§10).
10. **Failure truthfulness (v5):** the planner never arms (S5), so
    nothing is ever reported armed before a successful bind; on the
    post-teardown bring-up failure paths (WorkerSpawn /
    WorkerBindIncomplete) every non-operator-owned registered slot
    goes unarmed+pending (S4') BEFORE `refresh_status` recomputes
    `enabled` — fail-closed-truthful on every plan shape (expansion,
    contraction, workers/ring-only), and the surviving marks make the
    NEXT successful armed reconcile self-healing. The arm verb's
    fan-out runs only after its reconcile returns Ok (C3 reorder) —
    no armed-mark-free stranding after a failed global arm (Codex r3
    MAJOR 7). Failed reconciles return `Err` before the convergence
    (snapshot.rs:196), so marks are never consumed by a partial bind.
11. **HA portability:** no cluster-protocol or session-sync
    interaction; per-node helper-internal change with an additive
    wire field. Standby nodes run the same armed semantics. Rejected-
    plan leftovers can never be armed by an auto-rebind (the plan
    gate, Codex r3 BLOCKER 2) — important on HA nodes where the
    busy-binding repair path (maps_sync.go:1474) fires rebinds
    autonomously. Mixed-version window: old helper + new Go strands
    as before (D warns); new helper + old Go self-converges.
12. **Bootstrap fail-closed floor (Go side):** a plan-changing Compile
    already programs bootstrap ctrl disabled and clears binding rows
    before publish (manager_compile.go:315, maps_sync.go:163/178) —
    the commit-window posture is fail-closed on master and stays so;
    the fix removes the INDEFINITE tail, not the bounded
    interruption (§3, Codex r3 MINOR 9's confirming evidence).
## 8. Risk assessment

| Risk class | Level | Assessment |
|---|---|---|
| Behavioral regression | LOW-MED | Observable changes: (i) expansion-while-armed self-heals (S5 + convergence) instead of stranding; (ii) deferred PLAN-CHANGING applies deliberately fail-close the whole vector until completion (S3) — posture TIGHTENING vs master's contraction mis-steer, and per Codex r3 MINOR 9 the expansion window was already bootstrap-interrupted, so the real cost ≈ 0; (iii) failed bring-up marks all non-operator slots pending (S4') — master-parity fail-closed reporting plus self-healing retry (better than master); (iv) the arm verb's fan-out moves after its reconcile (C3) — a failed global arm now fails CLOSED instead of stranding armed-mark-free slots (master had that hole; Codex r3 MAJOR 7); (v) operator verbs claim slots (C2) and their disarms survive flaps-as-unregistered, deferred applies, completions, and failed bring-ups (was-armed gates); (vi) D adds an edge-triggered warn on genuine drift when desired==true. The dangerous shapes from rounds 1-3 — armed-but-unbound rows, rebind-missed activation, contraction window, hybrid-plan activation, mid-window toggle convergence, arm-then-fail stranding — are structurally excluded and pinned by §9 items 12-17. |
| Lifetime / borrow-checker | LOW | Cold path; owned `BindingStatus` clones already in use; the identity map is a local `BTreeMap`; the marker is a plain bool; the convergence's plan-membership set is a pure `replan_queues` call per armed reconcile (no side effects). No new lifetimes, no hot-path allocation. |
| Performance regression | LOW | Planner runs once per full apply (control path); convergence is one O(n) pass + one pure replan (identity extraction only) after an already-O(n) reconcile, on control events only — never per-packet/session/poll. D's drift scan is O(n) on the ~1s poll over ≤ dozens of bindings. |
| Architectural mismatch | LOW-MED | The marker is new wire-visible control state with a fully enumerated lifecycle (S1–S5/S3/S4' set rules, C1–C3 clear rules, one tri-gated convergence locus). Must not entangle with #6702/#6681's planner rework: the identity key is layout-shape-independent; the slot-keyed `refresh_bindings` cosmetic residual is deliberately deferred to their coordinator-adjacent work. One coordination note: whichever lands second rebases the replan function. The pre-existing mid-defer-window early-BIND hazard of registration toggles (Codex r3 BLOCKER 6's other half) is filed as a follow-up, not silently absorbed (§10). |
## 9. Test plan

**Rust unit/integration (the fix lives here):**

- `replan_bindings_from_candidates` unit tests (extend the existing
  replan test module — `userspace-dp/src/main_tests.rs`):
  1. **expansion while armed, non-deferred (S5 never-arm)** — existing
     plan all-armed, add a candidate: new slots `registered=true,
     armed=false, pending=true`; carried slots unchanged.
  2. **expansion while disarmed** — same shape (the S5 rule is
     uniform; no defer/global dependence).
  3. **deferred plan-changing apply (S3 gate)** — armed plan, replan
     with `defer_workers=true`: every registered slot `armed=false`;
     pending=true on exactly the was-armed/was-pending slots; an
     operator-disarmed slot (`registered && !armed && !pending`)
     stays unarmed and UNMARKED; an unchanged-plan deferred apply
     marks nothing.
  4. **deferred CONTRACTION (Codex r2 BLOCKER 5)** — `[a,b,c] → [b,c]`
     with defer: survivors unarmed+pending despite no new identity.
  5. **contraction (non-deferred)** — remove a candidate: vanished
     identities' state does not leak onto survivors.
  6. **reshuffle identity carry** — each surviving identity keeps its
     own `armed`/`pending` at its NEW slot; an operator-disarmed
     (mark-free) identity stays disarmed at its new slot.
  7. **E2 + flap matrix, split per AGY r3 f3:** (a) candidate
     `ifindex == 0` at apply → `registered=false, pending=true` (S1);
     later valid → re-registered (`registered=true, armed=false,
     pending=true`); converges at the next armed reconcile; (b)
     operator-UNREGISTERED (valid, pending=false) → flap → valid →
     STAYS unregistered; (c-i) ARMED slot flaps (S2 marks, was-armed)
     → recovers → re-registered + converged; (c-ii)
     operator-DISARMED slot (`registered && !armed && !pending`)
     flaps → force-cleared WITHOUT a mark → recovers as
     `registered=false, pending=false` (documented degradation;
     never re-armed); (d) invalid → GLOBAL ARM fan-out → valid (Codex
     r3 BLOCKER 4a): the S1 mark SURVIVES the fan-out (C3 clears only
     registered slots) → re-registers.
  8. **identity transition matrix:** same-name/new-ifindex carries;
     rename/same-ifindex re-initializes; orphan-fallback →
     explicit-parent carries across the ifindex swap.
  9. **queue-override semantics:** queue disarm → expansion adds a new
     member → initializes per S5 (pending, NOT disarmed — it converges
     at the apply's own reconcile); contraction removing all
     overridden members leaves no residual; queue unregister survives
     a reshuffle; operator verbs CLEAR marks in both directions (C2).
  10. **volatile non-carry (R3):** a carried identity's
      `ready`/`bound`/`xsk_registered`/counters/`last_error` reset at
      replan; only the control quad carries.
  11. **`had_existing` death:** inheritance depends ONLY on
      identity-map membership.
- **Convergence unit tests** (`reconcile_status_bindings` armed leg):
  pending+registered+in-plan slots arm+clear on Ok; pending slots NOT
  in the stored snapshot's plan are NOT armed (the hybrid gate, Codex
  r3 BLOCKER 2); marks NOT consumed on Err; unmarked unarmed slots
  never armed; convergence blocked when the stored snapshot is
  defer=true and the caller is not rebind-authorized; allowed for the
  rebind-authorized caller.
- **Server-level regressions** (`userspace-dp/src/server/tests.rs`;
  per Codex r1 MAJOR 7 + r3 MAJOR 8: valid map pins
  (server/tests.rs:913), `force_worker_healthy_stub`
  (coordinator/mod.rs:329), assertions on ARMED/MARKER state and
  reconcile Ok/Err outcome — the stub populates planned slots +
  heartbeats but not live `bound`/`xsk_registered` (bringup.rs:751) —
  and pin the reconcile call/stage (status.rs:263-265's
  debug_reconcile_stage) plus plan provenance where relevant):
  12. **expansion-while-armed** (the issue's demanded test): apply A,
      `set_forwarding_state(true)`, apply B with an additional zoned
      interface; assert BOTH responses ok, plan keys differ, binding
      count increased, the added identity exists, EVERY binding
      `registered && armed && !pending`, `enabled == true`, and the
      reconcile stage advanced. Red on master, green after.
  13. **deferred expansion, three completion shapes + the mid-window
      block:** apply A, arm, apply B `defer_workers=true` + inserted
      earlier-sorting candidate: all non-operator slots
      `!armed && pending`, `enabled == false`. Then complete via EACH
      of: (a) same-plan re-apply `defer_workers=false`; (b) full-leg
      re-apply with a changed plan key (Codex r2 BLOCKER 4); (c)
      `rebind` (Codex r2 BLOCKER 3) — after each, every non-operator
      slot `registered && armed && !pending`, `enabled == true`. AND
      the negative: a `set_binding_state` registration toggle DURING
      the window does NOT converge the pending slots (Codex r3
      BLOCKER 6).
  14. **failed bring-up, all shapes (Codex r3 BLOCKER 5 + MAJOR 8):**
      force `WorkerSpawn` and `WorkerBindIncomplete` on (i) an
      expansion apply, (ii) an E2-only apply, (iii) a CONTRACTION
      apply, (iv) a global-arm (`set_forwarding_state(true)` after a
      deferred boot apply — the C3-reorder case). IMMEDIATELY after
      each Err assert: every non-operator registered slot
      `!armed && pending` (S4'), `enabled == false`, marks SURVIVE;
      then a successful retry converges them. (iv) additionally
      asserts the arm verb did NOT fan out before its failed
      reconcile (no armed-mark-free slots).
  15. **operator-override survival (Codex r3 BLOCKER 3):**
      operator-disarm a slot; commit a plan-changing deferred apply +
      completion — the operator-disarmed slot stays `!armed` (claimed,
      never marked, never converged) while the deferred slots
      converge; repeat with the failure path of item 14(i).
  16. **rejected-hybrid (Codex r3 BLOCKER 2):** apply A, apply B
      (expansion), force B's bring-up to fail post-teardown, then
      `rebind` (the auto-recovery shape): assert B-only pending
      identities are NOT armed (plan gate), `enabled == false`, and a
      later successful retry of B converges them (stored snapshot is B
      again). Immediate post-failure assertions REQUIRED (Codex r3
      MAJOR 8) — no eventual-retry-only green.
  17. **#5134-shaped retry + debt-discard interleaving (Codex r2
      BLOCKER 4):** deferred apply → failed completion → plan-changing
      commit before the retry → slots converge on the later successful
      armed reconcile.
- The fail-fast invariant (Q6, resolved r1): assertions live ONLY in
  tests and only over well-defined planner/activation transitions.
- Protocol canaries: `userspace-dp/src/protocol/tests.rs` exact-schema
  snapshots updated to pin `activation_pending` deliberately.
- `make test-rust` (full cargo suite) clean; `cargo build` warning-free.
  Fleet cap honored: `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6749`.

**Go (option D + gate test):**

- Manager unit test for the D warn, desired-gated (Codex r3 MINOR 10):
  (i) desired==true + one `Registered && !Armed && !ActivationPending`
  binding → exactly one warn on the false→true edge, none on
  subsequent ticks, clears after re-arm; (ii) desired==true + one
  `Registered && !Armed && ActivationPending` binding → NO warn;
  (iii) desired==FALSE → NO warn regardless of binding state; (iv)
  missing field (old helper) → reads as drift (warn when desired).
- `maps_sync` gate test (AGY r1 f3): synthesized post-expansion status
  (new slots converged) through `probeBindingsReady`/
  `bindingForwardingLive` — ctrl admits, shim rows go READY.
- `make test-go` clean.

**Smoke (loss userspace cluster, lock-cell wrapped):** deploy; verify
iperf3 baseline to 172.16.80.200; commit an ADDITIONAL zoned VLAN unit
(e.g. a new `reth0.90` in the wan zone) while armed; assert transit
continues with no manual arm toggle and `show ... bindings` reports
the new slots armed with no `activation-pending`. Re-apply CoS after
the deploy per the cluster protocol (`apply-cos-config.sh`).

**Docs (module contract, same work item):**
`userspace-dp/src/server/README.md` — the arm-model narrative gains
the marker lifecycle: the planner never arms, who sets
`activation_pending`, the tri-gated convergence, the operator-claim
rule, and the was-armed gates. **Release note / upgrade note (AGY r1
Q7 + Codex r1 MINOR 8 + AGY r3 f4):** required and PROMINENT on two
points: (1) the fix takes effect only after the HELPER restarts into
the new binary — a pingable same-config helper is reused rather than
replaced (process.go:18), so call for `systemctl restart
xpf-userspace-dp` on upgrade; (2) the deliberate posture change —
deferred (RETH-MAC-pending) plan-changing commits now fail-close
transit for the whole dataplane until the link-cycle completion,
instead of risking stale shifted rows (previously) or stranding new
slots (the bug).
## 10. Out of scope (explicitly)

- **Go per-binding armed AUTO-convergence (option B)** — rejected
  (§5-B); the converger the design needs is the helper-side marker,
  and D covers detection.
- **#6702/#6681 planner queue-geometry rework** — they own
  binding-count consequences; this fix is compatible but does not
  implement any of their layout change.
- **`bindingForwardingLive` / `enabled` / `probeBindingsReady` gate
  semantics** — the gates are correct; the bug is the DEFAULT they
  were fed. No gate changes. (The all-or-nothing `enabled` gate making
  an operator per-slot disarm a whole-dataplane-off is master's
  semantics, unchanged; D's warn makes it visible.)
- **The pre-existing mid-defer-window early-BIND hazard** (Codex r3
  BLOCKER 6's other half): a registration toggle during the defer
  window runs an armed reconcile that BINDS workers before the RETH
  MAC cycle — present on master (the toggle's reconcile is
  defer-blind). v5 closes only the early-CONVERGE side (the defer
  gate); the early-BIND side is a separate pre-existing issue filed
  as a follow-up.
- **Re-keying the coordinator's slot-keyed live-worker lookup
  (`refresh_bindings`)** — the defer-window cosmetic alias (§4 item 7,
  §7.9) is documented and neutralized by S3; re-keying it belongs with
  #6702's coordinator-adjacent planner rework. Filed as a follow-up.
- **Operator-disarm → unregister degradation across a flap** (AGY r3
  f2 / Codex r3 BLOCKER 4's accepted residual): an operator-DISARMED
  slot whose interface flaps recovers as `registered=false,
  pending=false` (its no-forward intent survives; re-registering it
  while keeping the disarm would need a second provenance bit —
  rejected as machinery disproportionate to a destructive-maintenance
  edge). Documented in the server README.
- **Persisted-state migration** — none needed (state file write-only;
  the marker is additive with serde default).
- **Operator-override persistence across global arm toggles** — the
  fan-out still clears them (C3, registered slots); making diagnostic
  disarms durable is a separate product decision.
- **The retired v3/v4 machinery** — leg-scoped R1/R2, the full
  fan-out defer-completion, v4's S4 identity-scoped revert, and v4's
  arm-at-replan S5 are superseded and recorded at bce10126c /
  f679a791a.

## 11. Open questions for adversarial review

Resolved across rounds 1-3 (for the record): Q2 (drift-producer
enumeration), Q5 (VLAN-alias consumer), Q6 (test-only assertion), Q7
(High + release note + helper restart), applied-vs-requested init,
full fan-out vs scoped (scoped REQUIRED — shipped), Q3 (uniform S3 —
Codex r3 MINOR 9's bootstrap evidence + the all-or-nothing gate make
it cost-neutral and strictly safer; SMR r3 SMR3-2), Q5-toggle
(registration-toggle reconcile convergence is now BLOCKED mid-defer
by the defer gate and acceptable outside it — the reconcile genuinely
re-binds; SMR r3 SMR3-3 + Codex r3 BLOCKER 6), Q7-boot (disarmed-leg
non-convergence + C3 semantics close it; SMR r3 SMR3-4).

Remaining questions for round 4, each invitable to PLAN-KILL with a
concrete counterexample:

1. **Marker lifecycle completeness, final form.** Set rules
   S1/S2/S3/S4'/S5 (each was-armed gated), clears C1/C2/C3 (C3 scoped
   to registered), one tri-gated convergence locus. Exhibit a path to
   `Registered && !Armed` with NO mark and NO operator verb — an
   unmarked producer that strands again. (The enumeration to attack:
   every replan branch, the S3/S4' gates, the C3 reorder, operator
   verbs, lifecycle init, rebind, both apply legs, #5134, helper
   restart, the #2794 disarmed-reconcile path.)
2. **The plan gate's cost and sufficiency.** Convergence computes the
   current plan's identity set via a pure `replan_queues` call per
   armed reconcile. Is there a case where the stored snapshot's plan
   CONTAINS the pending identity yet arming it is still wrong (the
   hybrid's inverse — a retained vector slot that belongs to the
   restored plan but whose workers the failed bring-up never
   replaced)? Does `bound == planned` at the Ok boundary (bringup.rs:188)
   already exclude it?
3. **The defer gate's authorization split.** `rebind` is treated as
   the daemon-authorized completion and converges despite a stored
   `defer_workers=true` snapshot; a spurious link-flap rebind
   mid-window would also converge (its workers DID bind). Is any
   deferred state reachable where converging on a non-NotifyLinkCycle
   rebind is wrong — e.g. the flap arrives BEFORE the daemon's MAC
   programming, workers bind on the pre-MAC interface, and the
   subsequent MAC cycle + its rebind re-binds again (self-consistent),
   or is there a hole in that reasoning?
4. **S4' + operator-owned slots on the failure path.** S4' marks
   every non-operator-owned registered slot pending; an
   operator-disarmed slot stays unarmed+unmarked. After the retry
   converges the marked slots, the operator slot keeps `enabled=false`
   single-handedly (the all-or-nothing gate) — master's semantics for
   an operator disarm, D-visible. Any objection?
5. **D's warn on operator disarm vs unmarked drift.** With
   desired==true, D warns on ANY `!armed && !pending` registered
   slot — operator disarms included (truthful, deliberate policy).
   Should D distinguish "slot was NEVER armed since last plan change"
   (stronger bug signal) from "armed then disarmed" (operator shape)
   using `last_change` history, or is the single predicate + operator
   awareness sufficient?
6. **Round-3 disposition table audit.** §1's table maps every r3
   finding to its v5 fold. Which row is claimed-but-wrong this time?
