# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v4 — pending adversarial plan review (round 3)**

- Issue: #6749 (opus-review-001 root R06, severity High)
- Research base: `ad9591177` (origin/master at worktree creation)
- Research branch: `research/6749-armed-state` (plan docs only — no
  production code in this branch)
- v1 @ `8c76670d6` (r1: all DEMAND-REVISION); v3 @ `bce10126c` (r2:
  all DEMAND-REVISION); v4 folds the round-2 convergence: durable
  activation provenance consumed at every successful worker-producing
  reconcile.

---

## 1. Status

DRAFT v4 — pending adversarial plan review round 3 (Codex + AGY + Claude
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
  architecture. Codex (6 BLOCKER + 2 MAJOR): v3's fold claims partly
  false; R1 arms-before-reconcile → armed-but-unbound + partial
  forwarding after failed non-deferred reconcile (WorkerSpawn leaves
  earlier workers running — bringup.rs:172-183); **R2 misses the
  NORMAL completion path — link-cycle completion is `rebind`
  (process_linkcycle.go:219), not `apply_snapshot`**; defer-completion
  via the full-apply leg (+ #5134 debt discard at
  manager_worker_arm_5134.go:50); **deferred CONTRACTION introduces no
  new identity → R1 leaves everything armed → ctrl stays open with
  stale shifted rows**; full fan-out reverses operator maintenance
  disarms (permissions.go:267) even when nothing was deferred — scoped
  provenance is REQUIRED; E2 loses operator-unregister provenance
  across a flap; tests can green unsafe implementations. AGY (1 BLOCKER
  + 2 MAJOR + 1 MINOR + 1 NIT): full-leg defer completion stranding
  (= SMR2-1), R1 pre-arm on failed reconcile (= Codex2-2), E2/operator
  unregister flap (= Codex2-7), test gaps, fan-out override loss. SMR
  r2: the full-leg completion hole + commitment cleanups.
- **v4 answer (all three reviewers' shared architecture):** durable
  activation provenance — an `activation_pending` marker on
  `BindingStatus` — set ONLY by planner/apply machinery, consumed
  (armed+cleared) after EVERY successful worker-producing reconcile
  (same-plan apply, full apply, **rebind**, forwarding arm), and
  claimed/cleared by every operator verb. §5-C defines the lifecycle.

### Round-1 detail log

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

In `syncDesiredForwardingStateLocked`, when the global bit equals
desired but any binding presents `Registered && Ifindex > 0 && !Armed
&& !ActivationPending`, emit an EDGE-TRIGGERED `slog.Warn` (fires on
the drift predicate transitioning false→true, and again when it clears;
never per-tick — the project logging rules forbid >1/s control-plane
Info). No request is issued; nothing auto-reverts, so an operator
diagnostic disarm simply logs a truthful warn. The v4 marker
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

### Option C — durable activation provenance: the `activation_pending` lifecycle (Rust helper; superset of A)

v4 rewrite (Codex r2 BLOCKERs 2–6, AGY r2 f1–f3, SMR r2 SMR2-1 — all
three reviewers converged on this architecture). v3's leg-scoped rules
(R1-at-replan, R2-same-plan-fan-out) died to three independent doors:
the completion path that is actually a `rebind`, defer-completion via
the full-apply leg, and deferred contractions that create no new
identity. v4 replaces leg-scoped rules with a marker lifecycle:

**The marker.** `BindingStatus.activation_pending: bool` — additive
wire field (serde `#[serde(default)]` on the Rust side; Go's status
decode uses ordinary `json.Unmarshal`, which ignores unknown fields —
protocol_status.go:440, process_control.go:148; compatibility verified
by Codex r2 against binding.rs:292). Go's `BindingStatus`
(protocol_binding.go) gains the optional field so option D's predicate
and `show` rendering can consume it. Meaning: **"the planner/apply
machinery left this slot short of `registered && armed` while the
dataplane was expected to forward; converge it at the next successful
worker-producing reconcile."** Operator-owned states never carry it.

**Set rules (planner/apply machinery ONLY):**

- **S1 — replan creates a slot it cannot register** (`ifindex <= 0`:
  candidate present in config, netdev not yet present/renamed):
  `registered=false, armed=false, activation_pending=true`.
- **S2 — replan force-clears a previously-registered slot** (the
  `registered=true → false` transition when `ifindex` resolves to
  `<= 0`, planning.rs:516-519): `activation_pending=true`. A slot
  already unregistered by an OPERATOR (`registered=false` with pending
  already false) is NOT re-marked — that is the E2/flap discriminator
  (Codex r2 MAJOR 7 / AGY r2 f3).
- **S3 — deferred plan-CHANGING apply** (full-apply leg with
  `defer_workers=true`, snapshot.rs:285-354): after the replan, for
  EVERY registered slot (not just new ones): `armed=false,
  activation_pending=true`. This is the global pending gate Codex r2
  BLOCKER 5 forced: a deferred CONTRACTION creates no new identity, so
  v3's per-slot R1 left everything armed with `enabled=true` and stale
  shifted rows flowing through a ctrl that never closed. Under S3 the
  whole vector goes pending-unarmed → `enabled=false` → Go keeps
  `ctrl.Enabled=0` → the defer window is fail-closed for contractions,
  expansions, and reshuffles alike — matching the reality that the
  helper cannot forward the NEW plan until the deferred reconcile
  re-plans and binds it. A deferred apply with an UNCHANGED plan
  (same-plan leg — a pure RETH-MAC-pending re-apply) marks nothing:
  the old workers are already correctly bound for that plan and
  forwarding continues.
- **S4 — post-teardown bring-up failure revert** (full-apply leg,
  `ReconcileError::WorkerSpawn | WorkerBindIncomplete`,
  snapshot.rs:356-396): on the error path, slots INITIALIZED IN THIS
  APPLY (identities absent from `existing_bindings` by
  `(interface, queue_id)` — the apply already has both vectors in
  scope) revert to `armed=false, activation_pending=true`. Carried
  slots keep their armed bits (master parity). This closes the
  armed-but-unbound / partial-forwarding lie (Codex r2 BLOCKER 2 / AGY
  r2 f2): v3's R1 armed new slots at replan, so a failed reconcile
  reported `enabled=true` (the gate ignores `ready`/`bound`) while
  WorkerSpawn had left earlier workers running against dead queue sets
  (bringup.rs:172-183 keeps their records) and Go could publish READY
  rows for the survivors. Under S4 `enabled` recomputes false on the
  error path, ctrl stays closed, and the pending marks SURVIVE the
  failure so the NEXT successful armed reconcile converges the slots
  (Codex r2's "survive failed reconcile" requirement) — the retry
  self-heals instead of stranding.
- **S5 — non-deferred new/E2 initialization (the original fix):** at
  replan on a non-deferred apply, genuinely-new identities and
  E2-re-registered slots initialize `registered=true,
  armed=forwarding_armed`; `activation_pending = !armed` (a globally
  disarmed apply therefore marks pending — the boot case — cleared by
  the boot arm fan-out per C1/C3).

**E2 re-registration (AGY r1 f1, lifecycle form):** at replan, a
carried record with `!registered && activation_pending && new
ifindex > 0` re-registers (`registered=true`, armed per S5's gate).
Without the pending mark, `!registered` is operator-owned and left
alone (the carve-out that survives interface flaps, per S2).

**Clear/claim rules:**

- **C1 — converged:** a slot that reaches `registered && armed` (any
  cause) clears the mark.
- **C2 — operator claim:** `set_binding_state` / `set_queue_state`
  clear the mark on every affected slot, in BOTH directions — an
  operator disarm claims the unarmed state (it must never be
  auto-converged), an operator arm hand-converges. Codex r2 BLOCKER
  6's "cleared by operator calls even for an already-unarmed no-op
  disarm."
- **C3 — global fan-out:** `set_forwarding_state` (either direction)
  clears the mark everywhere — an explicit global arm converges all
  (C1 subsumes it); an explicit global disarm means nothing may
  auto-activate later; a later re-arm fans out again.

**Convergence — the single locus (Codex r2 BLOCKERs 3+4):** in
`reconcile_status_bindings`' ARMED leg (status.rs:400-411,
`should_run_afxdp` true), after `afxdp.reconcile` returns `Ok` and the
bindings are written back: for every `activation_pending &&
registered` slot, set `armed=true, activation_pending=false,
last_change=now`. One locus covers every worker-producing path,
because they ALL flow through this function:

- the full-apply leg (expansion-while-armed: new slots S5-armed at
  replan, any straggler converged here);
- the same-plan apply leg (defer-completion re-apply — the only path
  v3's R2 targeted);
- **`rebind` (rebind.rs:64) — the NORMAL link-cycle completion path
  Codex r2 BLOCKER 3 caught: `NotifyLinkCycle` → Go sends `rebind`
  (process_linkcycle.go:219) — the deferred slots are bound by the
  rebind's reconcile and converged in the same lock-hold.** v3 missed
  this path entirely;
- `set_forwarding_state(true)` (its own fan-out already converges —
  redundant and harmless);
- queue/binding registration-change reconciles.

The failed-reconcile paths return `Err` before the convergence, so no
mark is consumed and no slot is armed against unbound workers (Codex
r2's "consumed only after successful same-plan/full/rebind
completion"; the literal placement after `reconcile_status_bindings`
returns `Ok` was independently confirmed safe by Codex r2 MAJOR 8 —
the error branch returns first, snapshot.rs:196, and successful
bring-up requires `bound == planned` per worker, bringup.rs:188).

**R3 — control-state identity carry (from v3, marker added).** Carry
{`armed`, `registered`, `activation_pending`, `last_change`} keyed on
configured-name `(interface, queue_id)`; volatile fields
(`bound`/`xsk_registered`/`ready`/socket/counters/`last_error`/
latency) reset at replan and rebuild downstream
(`reset_binding_counters` + `refresh_bindings`). Identity semantics
unchanged: same-name/new-ifindex carries; rename re-initializes;
orphan-VLAN→explicit-parent promotion carries armed across the ifindex
swap. `had_existing` DIES (Codex r2 MAJOR 7 + SMR r2 SMR2-2): the
identity-map lookup IS the membership test; the five-field heuristic
conflated existence with state and is deleted. Queue-scoped overrides
remain membership-at-invocation shorthand (Codex r1 MAJOR 5).

**Ownership model (the issue's design question, final answer):**
`armed` = the GLOBAL default (Go-pushed `forwarding_armed`, fanned out
on explicit arms) MINUS ephemeral operator overrides (identity-scoped,
claimed per C2, dying at the next global fan-out) MINUS
planner-pending activations (marked per S1–S5, converged at the next
successful armed reconcile). The helper owns the marker because only
the helper can distinguish "unarmed because the planner hasn't
activated yet" from "unarmed because the operator said so" — the
discrimination v1 tried to do in Go and could not.

**What it fixes (full inventory):** the issue's indefinite disable on
expansion-while-armed (S5 + convergence); the deferred-activation
stranding on ALL THREE completion shapes — same-plan re-apply,
full-leg re-apply, rebind link-cycle (S3 + the convergence locus);
deferred contractions/reshuffles (S3's global gate); armed-but-unbound
reporting after failed bring-up (S4); E2 invalid→valid stranding (E2
lifecycle); wrong-identity control-state carry (R3); retry-after-
failure stranding (S4 marks + convergence — master's posture is
EXCEEDED here: recovery now self-heals).

**Size:** marker field + S1–S5 set rules in/around the replan
(~40 lines), S4 revert (~10), convergence in
`reconcile_status_bindings` (~8), verb/fan-out clears (~6), Go
optional field + D predicate (~20), protocol snapshot-test updates
(the exact-schema canaries in userspace-dp/src/protocol/tests.rs gain
the field), docs. No coordinator, gate, or shim changes.
### Recommendation

**Ship option C + option D** — the `activation_pending` lifecycle
(S1–S5 set rules, C1–C3 clear/claim rules, convergence inside
`reconcile_status_bindings`' armed leg, R3 control-only identity
carry, E2 lifecycle re-registration) plus the marker-aware warn-only
Go drift detector. Retreat: none lighter survives review — v3's
leg-scoped R1/R2 (the previous retreat shape) was killed by three
independent doors (rebind completion, full-leg completion, deferred
contraction); option A shares R1's arm-at-replan defect and is
recorded for history only. **Reject B as Go-converger** (§5-B); the
converger the design genuinely needs is the helper-side marker, and
D covers detection.

Rationale in one line: armed state is born in the planner, so the
planner MARKS what it leaves unactivated; the reconcile that actually
binds workers is the only moment activation may complete; and only the
helper can tell its own pending work apart from an operator's
deliberate disarm.

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

1. **Defer contract — the REAL one (v3/v4, Codex r1 BLOCKER 1 + r2
   BLOCKERs 3+5):** a `defer_workers=true` PLAN-CHANGING apply must
   leave the whole vector unarmed+pending (S3), because its reconcile
   (and XSK re-bind) is SKIPPED and `refresh_bindings` reports old
   workers by numeric slot — for expansions, reshuffles, AND
   contractions. A deferred apply with an UNCHANGED plan marks nothing
   (old workers are correctly bound for that plan). Completion — via
   same-plan re-apply, full-leg re-apply, OR the rebind link-cycle —
   converges the marks exactly when the workers have bound (§5-C
   convergence). A test pins every completion shape (§9 items 12-16).
2. **#869 no-ready-in-enabled:** `enabled` must keep NOT requiring
   `ready`. Untouched — only the armed defaults change.
3. **#1666 ready-gate:** per-row shim steering must keep requiring
   `Ready`. Untouched. In the defer window S3 keeps everything
   unarmed, so the slot-keyed stale `Ready` alias (§4 item 7) can never
   produce a READY row — and even if it could, `ctrl.Enabled=0`
   overrides row contents (maps_sync.go:391-404).
4. **Disarm direction never blocked:** the `ifindex <= 0` leg still
   force-clears (and now MARKS, S2); `set_forwarding_state(false)`
   still fans out `armed=false` to every binding AND clears all marks
   (C3) — a deliberate global disarm leaves nothing to auto-activate.
5. **Same-plan skip (#2915/#2916/#3007/#3175):** the plan key and the
   candidate set are untouched; identity-carry only runs on the
   full-apply leg that ALREADY decided the plan changed.
6. **One-XSK-per-(netdev,queue) (#1921):** the `seen_linux` dedup and
   candidate iteration order are unchanged; identity uniqueness per
   plan follows from it.
7. **Coordinator filter (`registered && ifindex > 0`):** unchanged;
   worker bring-up must not start reading `armed` OR the marker.
8. **Operator override ownership (v4):** operator per-slot/queue verbs
   CLAIM the slot (C2 clears the mark in both directions); their
   overrides are identity-scoped (R3) and die only at the next global
   fan-out (C3). The marker NEVER auto-converges an operator-owned
   state — the discrimination v1 could not do in Go. `set_queue_state`
   remains membership-at-invocation shorthand (Codex r1 MAJOR 5): a
   new member of a previously disarmed queue initializes per S5 (NOT
   disarmed); a queue whose overridden members all vanish carries no
   residual state.
9. **Volatile state rebuilt, not carried (v3, kept):** R3 carries
   {`armed`, `registered`, `activation_pending`, `last_change`} only;
   everything else resets at replan and is re-derived
   (`reset_binding_counters` + `refresh_bindings`). The defer-window
   slot-keyed alias is cosmetic per invariant 3 and remains a
   documented follow-up (§10).
10. **Failure truthfulness (v4, Codex r2 BLOCKER 2):** on the
    post-teardown bring-up failure paths (WorkerSpawn /
    WorkerBindIncomplete), the slots initialized in that apply revert
    to unarmed+pending (S4) BEFORE `refresh_status` recomputes
    `enabled` — the status after a failed bring-up is
    fail-closed-truthful (master parity for carried slots), and the
    surviving marks make the NEXT successful armed reconcile
    self-healing. Failed reconciles return `Err` before the
    convergence runs (snapshot.rs:196 error-branch-first structure),
    so marks are never consumed by a partial bind.
11. **HA portability:** no cluster-protocol or session-sync
    interaction; per-node helper-internal change with an additive
    wire field. Standby nodes run the same armed semantics
    (`desiredForwardingArmedLocked` returns true on standby with data
    RGs), so the lifecycle behaves identically on both cluster roles.
    Mixed-version window: old helper + new Go strands as before (D
    warns); new helper + old Go self-converges (the lifecycle is
    helper-internal; old Go ignores the field).
12. **Bootstrap fail-closed floor (Go side):** a plan-changing Compile
    already programs bootstrap ctrl disabled and clears binding rows
    before publish (manager_compile.go:319, maps_sync.go:121) — the
    commit-window posture is fail-closed on master and stays so; the
    fix removes the INDEFINITE tail, not the bounded interruption (§3).
## 8. Risk assessment

| Risk class | Level | Assessment |
|---|---|---|
| Behavioral regression | LOW-MED | Observable changes: (i) expansion-while-armed self-heals (S5 + convergence) instead of stranding; (ii) deferred PLAN-CHANGING applies now deliberately fail-closed for the whole vector until completion (S3) — on master the contraction/reshuffle shape could stay enabled with stale shifted rows (Codex r2 BLOCKER 5), so this is a posture TIGHTENING toward fail-closed, trading a bounded defer-window outage for eliminating mis-steering; (iii) failed bring-up reverts initialized slots (S4) — master-parity reporting, self-healing retry (better than master); (iv) operator verbs claim slots (C2) and their disarms now SURVIVE defer-completion (v3's full fan-out would have cleared them); (v) D adds an edge-triggered warn on genuine drift (truthful on operator disarms; doubles as the old-helper detector). The dangerous shapes from rounds 1-2 — armed-but-unbound rows, rebind-missed activation, contraction window — are structurally excluded and pinned by §9 items 12-16. |
| Lifetime / borrow-checker | LOW | Cold path; owned `BindingStatus` clones already in use; the identity map is a local `BTreeMap<(String, u32), BindingStatus>`; the marker is a plain bool on an existing struct. No new lifetimes, no hot-path allocation. |
| Performance regression | LOW | Planner runs once per full apply (control path); O(n) map build replaces O(n) map build; convergence is one O(n) pass after an already-O(n) reconcile. D's drift scan is O(n) on the ~1s poll over ≤ dozens of bindings. |
| Architectural mismatch | LOW-MED | The marker is a new piece of wire-visible control state — the design's deliberate answer to "who owns armed" — and its lifecycle is small and fully enumerated (S1-S5/C1-C3/one convergence locus). Must not entangle with #6702/#6681's planner rework: the identity key is layout-shape-independent; the slot-keyed `refresh_bindings` cosmetic residual (§4 item 7) is deliberately deferred to their coordinator-adjacent work. One coordination note: whichever lands second rebases the replan function. |
## 9. Test plan

**Rust unit/integration (the fix lives here):**

- `replan_bindings_from_candidates` unit tests (extend the existing
  replan test module — `userspace-dp/src/main_tests.rs` hosts
  `replan_queues_binds_vlan_unit_on_parent_netdev`):
  1. **expansion while armed, non-deferred (S5)** — existing plan
     all-armed, add a candidate: new slots `registered=true,
     armed=true, activation_pending=false`; carried slots unchanged.
  2. **expansion while disarmed** — global false: new slots
     `armed=false, activation_pending=true` (boot-shape mark).
  3. **deferred plan-changing apply (S3 global gate)** — armed plan,
     replan with `defer_workers=true`: EVERY registered slot
     `armed=false, activation_pending=true`, INCLUDING carried ones;
     an unchanged-plan deferred apply marks nothing.
  4. **deferred CONTRACTION (Codex r2 BLOCKER 5)** — `[a,b,c] → [b,c]`
     with defer: survivors unarmed+pending despite no new identity.
  5. **contraction (non-deferred)** — remove a candidate: vanished
     identities' state does not leak onto survivors.
  6. **reshuffle identity carry** — insert a candidate that sorts
     earlier (or change queue_count): each surviving identity keeps its
     own `armed`/`activation_pending` at its NEW slot; an
     operator-disarmed (mark-free) identity stays disarmed at its new
     slot.
  7. **E2 + flap matrix (AGY r1 f1 / AGY r2 f3 / Codex r2 MAJOR 7):**
     (a) candidate with `ifindex == 0` at apply → `registered=false,
     pending=true` (S1); later valid → re-registered, armed per S5;
     (b) operator-unregistered (valid ifindex, pending=false) → flap
     (`ifindex<=0`, S2 does NOT re-mark) → valid again → STAYS
     unregistered; (c) registered slot flaps (S2 marks) → recovers →
     re-registered + converged.
  8. **identity transition matrix (Codex r1 BLOCKER 2):** same-name /
     new-ifindex carries control state; rename / same-ifindex
     re-initializes; orphan-fallback (parent-name key + child ifindex)
     → explicit-parent carries across the ifindex swap.
  9. **queue-override semantics (Codex r1 MAJOR 5):** queue disarm →
     expansion adds a new member of that queue → new member
     initializes per S5 (NOT disarmed); contraction removing all
     overridden members leaves no residual; queue unregister survives
     a reshuffle on its remaining members; operator verbs CLEAR marks
     on affected slots in both directions (C2).
  10. **volatile non-carry (R3):** a carried identity's
      `ready`/`bound`/`xsk_registered`/counters/`last_error` reset at
      replan; only the control quad carries.
  11. **`had_existing` death:** state-inheritance depends ONLY on
      identity-map membership (e.g. a record with all-false fields but
      present in the old map is still "carried"); the five-field
      heuristic is gone.
- **Convergence unit tests** (`reconcile_status_bindings` armed leg):
  pending+registered slots arm+clear on Ok; pending marks are NOT
  consumed on Err; unmarked unarmed slots (operator-owned) are NOT
  armed.
- **Server-level regressions** (`userspace-dp/src/server/tests.rs`,
  alongside the full-apply tests at :1314/:1475; per Codex r1 MAJOR 7
  these MUST use valid map pins (server/tests.rs:913) and
  `force_worker_healthy_stub` (coordinator/mod.rs:329) — and per Codex
  r2 MAJOR 8 the assertions must account for the stub populating
  planned slots + heartbeats but NOT live `bound`/`xsk_registered`
  (bringup.rs:751), so tests assert on the ARMED/MARKER state and the
  reconcile Ok/Err outcome, not on stub-live volatile fields):
  12. **expansion-while-armed** (the issue's demanded test): apply A,
      `set_forwarding_state(true)`, apply B with an additional zoned
      interface; assert BOTH responses ok, plan keys differ, binding
      count increased, the added identity exists, EVERY binding
      `registered && armed && !activation_pending`, and
      `status.enabled == true`. Red on master (trace: planning.rs:521
      → status.rs:280), green after.
  13. **deferred expansion, three completion shapes:** apply A, arm,
      apply B with `defer_workers=true` + an inserted candidate that
      sorts BEFORE an existing identity (slot reshuffle): assert all
      registered slots `!armed && activation_pending` and
      `enabled == false` (the S3 window). Then complete via EACH of:
      (a) same-plan re-apply `defer_workers=false`; (b) full-leg
      re-apply with a changed plan key (Codex r2 BLOCKER 4 shape);
      (c) `rebind` (Codex r2 BLOCKER 3 shape) — after each, EVERY
      binding `registered && armed && !pending`, `enabled == true`.
      (Where the harness cannot drive a real link cycle, invoke the
      `rebind` control verb directly — it shares the reconcile locus.)
  14. **failed bring-up (Codex r2 BLOCKER 2 / AGY r2 f2):** force a
      `WorkerSpawn` failure and a `WorkerBindIncomplete` failure on a
      non-deferred expansion apply; IMMEDIATELY after the Err response
      assert: initialized slots `!armed && pending`, carried slots
      keep prior armed, `enabled == false`, and the marks SURVIVE;
      then a successful retry apply converges them (self-heal, better
      than master).
  15. **operator-override survival:** operator-disarm a slot; commit a
      plan-changing deferred apply + completion — the operator-disarmed
      slot stays `!armed` (C2 claimed, never auto-converged) while the
      deferred slots converge; D-shaped warn would fire for it
      (asserted in the Go test below).
  16. **#5134-shaped retry:** deferred apply → failed completion →
      republish with `DeferWorkers=false` + bumped generation (and the
      debt-discard interleaving of Codex r2 BLOCKER 4: a plan-changing
      commit before the retry) → slots converge.
- The fail-fast invariant (Q6, resolved r1): assertions live ONLY in
  tests and only over well-defined planner/activation transitions — a
  production `debug_assert!` would panic under a legitimate operator
  diagnostic disarm. Not shipped.
- Protocol canaries: `userspace-dp/src/protocol/tests.rs` exact-schema
  snapshots updated to pin `activation_pending` deliberately.
- `make test-rust` (full cargo suite) clean; `cargo build` warning-free.
  Fleet cap honored: `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6749`.

**Go (option D + gate test):**

- Manager unit test for the D warn: synthesize `lastStatus` with global
  armed + (i) one `Registered && !Armed && !ActivationPending` binding
  → exactly one warn on the false→true edge, none on subsequent ticks,
  warn clears after re-arm; (ii) one `Registered && !Armed &&
  ActivationPending` binding → NO warn (pending activation is not
  drift); (iii) missing field (old helper) → reads as drift (warn).
- `maps_sync` gate test (AGY r1 f3): feed a synthesized post-expansion
  status (new slots armed per S5) through
  `probeBindingsReady`/`bindingForwardingLive` and assert the ctrl gate
  admits and the shim rows go READY — pins that the Go gates consume
  the fixed default as intended.
- `make test-go` clean.

**Smoke (loss userspace cluster, lock-cell wrapped):** deploy; verify
iperf3 baseline to 172.16.80.200; commit an ADDITIONAL zoned VLAN unit
(e.g. a new `reth0.90` in the wan zone) while armed; assert transit
continues with no manual arm toggle and `show ... bindings` reports
the new slots armed with no `activation-pending`. Re-apply CoS after
the deploy per the cluster protocol (`apply-cos-config.sh`).

**Docs (module contract, same work item):**
`userspace-dp/src/server/README.md` — the arm-model narrative (the
`set_bindings_forwarding_armed`/defer sections around :71/:294-324)
gains the marker lifecycle: who sets `activation_pending`, who
consumes it, who may clear it, and the operator-claim rule.
**Release note / upgrade note (AGY r1 Q7 + Codex r1 MINOR 8):**
required, and it must state that the fix takes effect only after the
HELPER restarts into the new binary — a pingable same-config helper is
reused rather than replaced (process.go:18), so the old-helper window
is operationally relevant and the note should call for
`systemctl restart xpf-userspace-dp` (or an equivalent helper bounce)
on upgrade.
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
- **Re-keying the coordinator's slot-keyed live-worker lookup
  (`refresh_bindings`)** — the defer-window cosmetic alias (§4 item 7,
  §7.9) is documented and neutralized by S3; re-keying it belongs with
  #6702's coordinator-adjacent planner rework. Filed as a follow-up.
- **Persisted-state migration** — none needed (state file write-only;
  the marker is additive with serde default).
- **Operator-override persistence across global arm toggles** — the
  fan-out still clears them (C3); making diagnostic disarms durable is
  a separate product decision.
- **The retired v3 machinery** — leg-scoped R1/R2 and the full
  fan-out defer-completion are superseded by the marker lifecycle and
  recorded here for history (v3 @ bce10126c).
## 11. Open questions for adversarial review

Closed across rounds 1-2 (for the record): Q2 (drift-producer
enumeration — §5-B; three reviewers concur), Q5 (VLAN-alias consumer —
no interaction), Q6 (fail-fast assertion is test-only), Q7 (High +
release note + helper-restart requirement), the applied-vs-requested
init value (control-socket serialization + publish-side disarm
ordering), and v3's Q1 (full fan-out vs scoped — round 2 ANSWERED it:
scoped provenance is required, shipped as the marker).

Remaining questions for round 3, each invitable to PLAN-KILL with a
concrete counterexample:

1. **Marker lifecycle completeness.** S1–S5 (set), C1–C3 (clear/claim),
  one convergence locus. Can a reviewer exhibit a path where a slot
  reaches `registered && !armed` with NO mark and NO operator verb —
  i.e. an unmarked producer that strands again? (The enumeration to
  attack: replan S1/S2/S5, S3 gate, S4 revert, operator verbs C2,
  global fan-outs C3, lifecycle init, rebind, same-plan/full apply
  legs, #5134 republish, helper restart.)
2. **Marker lifecycle leaks.** The dual: a path where a slot keeps
  `activation_pending=true` after reaching a state where activation
  can never complete (e.g. its identity vanishes from the plan without
  the record being dropped, or a permanently-failing reconcile) —
  does anything misreport or misbehave with a stale mark? (Marks on
  dropped identities vanish with the record; a permanently-failing
  reconcile leaves the dataplane down for a DIFFERENT surfaced reason
  with `enabled=false` — truthful. Attack it anyway.)
3. **S3's posture tightening.** Deferred plan-changing applies now
  fail-close the WHOLE vector until completion (master's contraction
  shape could stay enabled on stale rows — a mis-steer, so tightening
  is argued correct; but the expansion-only shape on master kept OLD
  identities forwarding through the window and S3 now drops them too).
  Is any production workflow dependent on deferred-apply window
  forwarding on unchanged identities — and if so, is the honest fix a
  per-identity gate (carry old identities armed, pending-gate only
  new/shifted ones) with the shifted-identity alias that reopens?
4. **S4's revert scope.** Only slots initialized in the failed apply
  revert (carried slots keep armed, master parity). Codex r2 BLOCKER 2
  showed surviving workers can publish READY rows for carried slots —
  with `enabled=false` the ctrl gate overrides rows (§7.3). Is
  "ctrl=0 overrides stale READY rows" verified tightly enough
  (maps_sync.go:391-404 + shim behavior), or must the revert widen to
  the whole vector on this path?
5. **Convergence-on-registration-toggle.** The convergence locus also
  covers queue/binding registration-change reconciles (a registration
  toggle triggers `reconcile_status_bindings`, binding.rs:34-53).
  Converging OTHER pending slots as a side effect of an operator's
  registration toggle: acceptable (the reconcile genuinely re-binds
  workers) or a surprise worth scoping out?
6. **D's warn on operator disarm vs pending.** With the marker, D's
  predicate is `!Armed && !ActivationPending`. Is warning on operator
  disarms (truthful but intentional) the right default, or should D
  rate-limit them separately from unmarked-no-operator drift (which is
  the actual bug tripwire)?
