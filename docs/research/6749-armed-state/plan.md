# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v3 — pending adversarial plan review (round 2)**

- Issue: #6749 (opus-review-001 root R06, severity High)
- Research base: `ad9591177` (origin/master at worktree creation)
- Research branch: `research/6749-armed-state` (plan docs only — no
  production code in this branch)
- v1 @ `8c76670d6`; v2 folded SMR r1 + AGY r1 (uncommitted when Codex
  r1 ran); v3 folds Codex r1 (DEMAND-REVISION, 2 BLOCKER + 5 MAJOR +
  1 MINOR) on top.

---

## 1. Status

DRAFT v3 — pending adversarial plan review round 2 (Codex + AGY + Claude
SMR). Convergence target: PLAN-READY (recommended path shipped to
`/engineer`) or PLAN-KILL. No production code is written under `/research`.

### Round-1 verdict log

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
    a second door (R1+R2 close it).
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
   DIFFERENT physical binding — worse than the outage. R1's
   defer-awareness (§5-C) is shaped by (ii).
8. **Volatile state ownership (v3, Codex r1 MAJOR 4 — verified):**
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
- **Defer caveat (v3):** as written above, A is UNSAFE on the
  deferred-activation path for the same reason as v1's C (Codex r1
  BLOCKER 1): a deferred apply with global armed would arm new slots
  whose XSKs never bind. Any A-shaped retreat must adopt R1's
  `armed = forwarding_armed && !defer_workers` and R2's defer-completion
  fan-out unchanged — at which point A differs from C only in keeping
  numeric-slot carry (and its wrong-identity control-state inheritance).
- **What it does NOT fix:** numeric-slot carry. A plan reshuffle still
  inherits a predecessor's control record (armed/registered) onto a
  different (interface, queue) identity. The armed-bit consequence is
  mostly masked (when globally armed every carried slot reads
  `armed=true`, which is also what R1 would initialize it to), but an
  operator per-slot diagnostic disarm (`set_binding_state armed=false`)
  migrates to the WRONG interface across a reshuffle. Pre-existing
  defect, same locus.
- **Size:** ~10 lines + tests (plus the forced R1/R2 defer model).

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
- **Verdict:** REJECT as primary. The issue's third fix-direction leg
  ("make Go's convergence check include each registered binding") is
  answered in detection form by option D below, which carries none of
  the convergence semantics conflict. And the ONE place a converger was
  genuinely required — completing the deferred activation (Codex r1
  MAJOR 6) — is owned helper-side by R2 (§5-C) at the same locus as the
  binding reconcile, with no registry and no wire change.

### Option D — Go observability-only drift detection (companion to C; v2, SMR r1 SMR-2)

In `syncDesiredForwardingStateLocked`, when the global bit equals
desired but any `Registered && Ifindex > 0 && !Armed` binding exists,
emit an EDGE-TRIGGERED `slog.Warn` (fires on the drift predicate
transitioning false→true, and again when it clears; never per-tick —
the project logging rules forbid >1/s control-plane Info). No request
is issued; nothing auto-reverts, so an operator diagnostic disarm simply
logs a truthful warn. ~15 lines in `manager_ha.go` + a manager test.

- **Value:** satisfies the issue's third leg as a detection surface; if
  a FUTURE drift producer ever appears (a new planner path, a
  mixed-version window nobody enumerated), on-call gets a log line
  naming the exact stranded slot instead of a silent blackout.
- **Cost/risk:** near zero; no semantics change. Bundled into the
  recommended ship.

### Option C — stable-identity control-state carry + defer-aware three-rule activation (Rust planner + same-plan leg; superset of A)

v3 rewrite (Codex r1 BLOCKERs 1–2, MAJORs 3–5). The fix is three rules
that together define WHO owns `armed` and WHEN it may be set:

**R1 — planner initialization is defer-aware.** `replan_queues` gains
two parameters (`forwarding_armed`, `defer_workers` — both already in
scope at the single production caller, snapshot.rs:286/345). A
genuinely-new or never-registered (E2) slot initializes:

```rust
binding.registered = true;
binding.armed = forwarding_armed && !defer_workers;
```

- NON-deferred apply (reconcile runs immediately under the same lock):
  new slots arm from the live global; the reconcile binds their XSKs
  before any status is reported; safe per the #1666 ready-gate.
- DEFERRED apply (reconcile SKIPPED, snapshot.rs:351-354): new slots
  stay `armed=false` → `enabled=false` → Go keeps `ctrl.Enabled=0` →
  the window stays fail-closed exactly as master behaves today, and the
  stale-identity alias below can never reach the shim.

  Why this rule is forced (Codex r1 BLOCKER 1, verified): the daemon
  sets `DeferWorkers` for pending RETH MAC programming WITHOUT
  disarming (daemon_apply_dataplane.go:45-71 →
  manager_compile.go:330-331; the pre-publish disarm at
  manager_ha.go:568-599 fires only for unsupported configs). So a
  healthy helper enters a plan-changing deferred apply with
  `forwarding_armed=true` — v1/v2's "defer ⇒ global false" assumption
  was false. Worse, `refresh_status` (status.rs:23) runs
  `afxdp.refresh_bindings`, which maps still-live OLD workers into the
  NEW binding vector by NUMERIC SLOT
  (`workers.live.get(&binding.slot)`, refresh_bindings.rs:25): in a
  reshuffle, a new identity at slot S inherits `ready`/`bound`/socket
  state from the old occupant of S. Had R1 armed that slot, `enabled`
  would recompute true (#869 ignores `ready`), Go's
  `probeBindingsReady` (registered+armed) would pass, ctrl would open,
  and Go would write the new (ifindex, queue) row with a stale slot
  whose XSK belongs to a DIFFERENT physical binding — cross-interface
  mis-steering, worse than the original outage. Arming only on
  immediate-reconcile applies eliminates the window.

**R2 — deferred activation completes at the binding reconcile.** In the
same-plan leg of `apply` (snapshot.rs:175-238), when
`previous_defer_workers == true` and the incoming snapshot is
non-deferred and the reconcile SUCCEEDS, run the existing
`set_bindings_forwarding_armed(&mut guard.status, true)` fan-out
(status.rs:418-423) before `refresh_status`. This arms the R1-deferred
slots exactly when their workers have actually bound.

- The transition predicate is already computed at the call site
  (snapshot.rs:159-162, `same_plan_apply_needs_binding_reconcile`
  returns true for `previous_defer && !next_defer` with runnable
  bindings, planning.rs:27-58).
- The #5134 retry republish (manager_worker_arm_5134.go:61) carries
  `DeferWorkers=false` against a stored defer=true snapshot → same
  transition → covered.
- **Semantic (documented):** defer-completion is the COMPLETION OF THE
  GLOBAL ARM, so its fan-out has the same override-clearing semantics
  as an explicit `set_forwarding_state(true)` — per-slot operator
  disarms do not survive it. During the defer window the whole
  dataplane is already fail-closed (enabled=false via the R1-deferred
  slots), so a diagnostic disarm issued inside that window has no
  observable traffic effect to preserve. This answers Codex r1 MAJOR
  6's "the safe deferred design needs an explicit activation
  convergence step" WITHOUT a Go-side override registry or wire
  provenance — the helper owns the activation at the same locus as the
  binding reconcile.
- Scoped alternative for round-2 judgment (rejected as unnecessary):
  an additive `deferred_unarmed` field on `BindingStatus` (serde
  default false; Go's json.Unmarshal ignores unknown fields) would let
  R2 arm ONLY the R1-deferred slots, preserving defer-window operator
  disarms. Rejected: the window is seconds, fail-closed throughout,
  and the full fan-out mirrors an already-accepted semantic.

**R3 — identity-carry carries CONTROL state only; volatile state is
rebuilt.** The carry key is `(interface, queue_id)` — a
**configured-name control identity**, NOT a physical XSK identity
(Codex r1 BLOCKER 2: the physical XSK is (ifindex, queue) — bind.rs:76;
the same name can rebind a new ifindex, and the orphan-VLAN fallback
labels a binding with the parent name while using the child's ifindex,
planning.rs:421-431). Carried fields: `armed`, `registered`,
`last_change` (plus the E2 re-init below). NOT carried — reset to
`BindingStatus::default()` at replan and re-derived per path:
`bound`/`xsk_registered`/`ready`/socket fields/counters/`last_error`/
latency histograms. On the reconcile path they are reset+rebuilt
anyway (reconcile/reset.rs:9-15 clears them; refresh_bindings
repopulates from live workers), so whole-record carry was dead weight
there (Codex r1 MAJOR 4) — and in the defer window it was the alias
vector of BLOCKER 1. With R3:

- **same name, new ifindex** (NIC replug): control state carries —
  correct, operator intent attaches to the configured name; the
  reconcile binds the new ifindex.
- **rename, same ifindex** (old name leaves config): old identity
  vanishes, new identity initializes from R1 — correct, the plan key
  already forces a replan via `linux_name` hashing.
- **orphan-VLAN → explicit-parent promotion** (SMR r1 SMR-4): keys
  match (parent netdev name) — `armed` carries across the ifindex
  swap; harmless now, because no volatile state rides along and the
  reconcile binds whatever ifindex the new plan resolved.
- **Known cosmetic residual (documented, NOT fixed here):** in the
  defer window, `refresh_bindings`' slot-keyed lookup can still attach
  an old worker's volatile fields to a same-numbered new record for
  `show` output. R1 makes it cosmetic (ctrl off, no READY rows — the
  shim's ctrl gate overrides row contents, maps_sync.go:399-404).
  Re-keying the coordinator's live-worker lookup is a deeper change
  entangled with #6702's planner rework; filed as a follow-up, out of
  scope here.
- **E2 (AGY r1 f1 / Codex r1 MAJOR 3, pre-existing on master):**
  `had_existing` is true for any carried record (the planner stamps
  `last_change`), so a slot force-cleared by `ifindex<=0` never
  re-initializes when the ifindex later becomes valid. The widening:
  capture `never_registered = !binding.registered && binding.ifindex <= 0`
  from the carried record BEFORE the positional ifindex overwrite, and
  treat it like a new slot (`registered=true, armed=<R1 value>`). The
  carve-out: an OPERATOR un-registration (`registered=false` with a
  previously VALID ifindex) keeps its override — the distinction AGY's
  raw `|| !binding.registered` would have lost.
- **Queue-scoped overrides (Codex r1 MAJOR 5):** `set_queue_state` is
  DEFINED as membership-at-invocation shorthand — its handler literally
  iterates the bindings present at call time (queue.rs:21-38). It is
  not a persistent queue-level policy: a NEW member of a previously
  disarmed queue initializes from R1, and if all overridden members
  vanish the queue carries no residual state. Identity-carry preserves
  each overridden binding's disarm across reshuffles; tests pin
  expansion/contraction under queue disarm and queue unregister (§9).

- **Ownership model (the issue's design question, answered):** the
  GLOBAL bit (Go-pushed) owns the arm DEFAULT; the PLANNER applies that
  default to new identities at the moment it can also bind them (R1) or
  defers it to the completion of the deferred reconcile (R2); per-slot
  operator verbs own ephemeral, identity-scoped (R3) overrides that die
  at the next global fan-out (explicit arm or defer-completion).
- **What it fixes:** the indefinite whole-dataplane disable on
  expansion-while-armed (R1), the deferred-activation variant of the
  same stranding (R1+R2 — on master the deferred bring-up also strands
  the new slots: armed=false, bound, never converged), the
  wrong-identity carry of control state across reshuffles (R3), and
  the E2 invalid→valid stranding (R3 widening).
- **Slot numbers stay positional** (assigned in layout order), so
  `set_binding_state(slot=…)` addressing, `show` output shape, and the
  shim's row computation are unaffected. (Correction per Codex r1
  MAJOR 4: the shim's row VALUE carries `slot` and XDP consumes it for
  XSKMAP redirect + heartbeat — what identity-carry changes is only
  state PROVENANCE; slots are recomputed positionally and XSKMAP is
  re-registered by worker bring-up, so slot→XSK consistency is
  rebuilt every reconcile.)
- **Size:** replan function rework + `forwarding_armed`/`defer_workers`
  threading (~60 lines incl. comments), the R2 fan-out at the
  same-plan call site (~10 lines), tests.

### Recommendation

**Ship option C + option D** — the three-rule activation model (R1
defer-aware planner init, R2 defer-completion fan-out, R3
control-state-only identity carry with the E2 widening) plus the
warn-only Go drift detector. Retreat: A-with-R1/R2 (numeric carry kept)
if implementation uncovers a hidden coupling in identity keying (none
found: the coordinator's bring-up and Go's shim-map writer key on
`(ifindex, queue_id)`/`interface`; slots stay positional). **Reject B
as primary** on the three honest grounds in §5-B; the deferred
activation it would have been needed for is owned by R2.

Rationale in one line: the planner is where the contradictory default
is born, so the planner is where the default gets fixed — and the
activation that the deferred path strands belongs to the reconcile that
actually binds the workers, one lock-hold away from the state it
converges.

## 6. Public API preservation

- **Wire protocol:** unchanged. `BindingStatus`, `ControlRequest`/
  `ControlResponse`, snapshot schema, and the state-file payload keep
  identical fields; only the planner's internal carry key and new-slot
  default change. `CONFIG_SNAPSHOT_PROTOCOL_VERSION` is NOT bumped —
  mixed-version interop is unaffected (old Go + new helper: fix works,
  self-contained; new Go + old helper: bug persists until the helper
  restarts into the new binary — same-.deb transient window, same as
  any helper-side fix).
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind` — signatures and
  response shapes unchanged. `set_binding_state` slot addressing is
  unchanged (slots remain positional).
- **Go manager API:** unchanged under C+D (D is a manager-internal
  edge-triggered warn inside `syncDesiredForwardingStateLocked`; no
  interface, request, or status-field change).
- **CLI / `show` output:** unchanged shape; counter/error provenance
  becomes correct-by-identity (a behavioral improvement, not a schema
  change).

## 7. Hidden invariants the change must preserve

1. **Defer contract — the REAL one (v3, Codex r1 BLOCKER 1):** a
   `defer_workers=true` apply must NOT arm new slots even when globally
   armed, because its reconcile (and XSK bind) is SKIPPED and
   `refresh_bindings` reports old workers by numeric slot. R1 encodes
   exactly this (`armed = forwarding_armed && !defer_workers`). The
   completion invariant is the mirror image: the defer-completion
   same-plan reconcile MUST arm the deferred slots after a successful
   bind (R2), or the master-era stranding returns through the deferred
   door. A test pins both halves (§9 item 8).
2. **#869 no-ready-in-enabled:** `enabled` must keep NOT requiring
   `ready`. Untouched — only the armed default changes.
3. **#1666 ready-gate:** per-row shim steering must keep requiring
   `Ready`. Untouched. In the defer window R1 keeps new slots unarmed,
   so the slot-keyed stale `Ready` alias (§4 item 7) can never produce
   a READY row — and even if it could, `ctrl.Enabled=0` overrides row
   contents (maps_sync.go:399-404).
4. **Disarm direction never blocked:** the `ifindex <= 0` leg still
   force-clears `registered/armed/ready`; `set_forwarding_state(false)`
   still fans out `armed=false` to every binding regardless of identity
   carry. A binding whose identity vanished from the plan simply drops
   out of the vector (as today).
5. **Same-plan skip (#2915/#2916/#3007/#3175):** the plan key and the
   candidate set are untouched — `snapshot_binding_plan_key` inputs are
   identical, so the same-plan leg never starts disagreeing with the
   layout. Identity-carry only runs on the full-apply leg that ALREADY
   decided the plan changed.
6. **One-XSK-per-(netdev,queue) (#1921):** the `seen_linux` dedup and
   the candidate iteration order are unchanged; identity uniqueness per
   plan follows from it (a name appears at most once, queue_ids are
   distinct per name).
7. **Coordinator filter (`registered && ifindex > 0`):** unchanged;
   worker bring-up must not start reading `armed`.
8. **Operator override lifetime — now fully defined (v3):**
   per-slot/queue operator overrides are ephemeral, identity-scoped
   (R3), and die at the next GLOBAL fan-out — which after this change
   has TWO sources: an explicit `set_forwarding_state` (today) and a
   defer-completion activation (R2, new). `set_queue_state` is
   membership-at-invocation shorthand, not a persistent queue policy
   (Codex r1 MAJOR 5): a new member of a previously disarmed queue
   initializes from R1; a queue whose overridden members all vanish
   carries no residual state. The E2 `never_registered` widening must
   NOT re-initialize an operator un-registration — the carve-out
   requires the carried record's PRE-overwrite ifindex ≤ 0 (§5-C R3),
   and a test pins it (§9 item 7).
9. **Volatile state rebuilt, not carried (v3, supersedes v2's
   note):** R3 carries `armed`/`registered`/`last_change` only;
   `bound`/`xsk_registered`/`ready`/socket/counters/`last_error`/
   latency reset at replan and are re-derived (reconcile:
   reset_binding_counters + refresh_bindings; defer window:
   refresh_bindings — slot-keyed aliasing there is cosmetic per
   invariant 3 and is a documented follow-up, §5-C R3).
10. **HA portability:** no cluster-protocol or session-sync
    interaction; per-node helper-internal change. Standby nodes run the
    same armed semantics (`desiredForwardingArmedLocked` returns true on
    standby with data RGs), so the fix behaves identically on both
    cluster roles.
11. **Bootstrap fail-closed floor (Go side, v3):** a plan-changing
    Compile already programs bootstrap ctrl disabled and clears binding
    rows before publish (manager_compile.go:319, maps_sync.go:121) —
    the commit-window posture is fail-closed on master and stays so;
    the fix only removes the INDEFINITE tail, not the bounded
    interruption (§3).

## 8. Risk assessment

| Risk class | Level | Assessment |
|---|---|---|
| Behavioral regression | LOW-MED | Observable changes: (i) after an expansion-while-armed, `enabled` recomputes true and ctrl opens without operator action (today: never) — boot-arm semantics extended to plan expansion, backstopped per-row by #1666; (ii) deferred plan-changing applies keep new slots unarmed through the window (same as master) and arm them at completion (today: stranded forever — this is the fix); (iii) the R2 fan-out clears per-slot operator disarms at defer-completion (new override-lifetime edge, documented §7.8); (iv) E2 re-initializes invalid→valid slots, carved out from operator un-registration; (v) volatile fields no longer ride the carry (they were rebuilt downstream anyway — §4 item 8); (vi) option D adds an edge-triggered warn on drift, including operator disarms (truthful). The dangerous shape — armed-but-unbound rows in the defer window (Codex r1 BLOCKER 1) — is structurally excluded by R1 and pinned by §9 item 8. |
| Lifetime / borrow-checker | LOW | Cold path, owned `BindingStatus` clones already in use; the identity map is a local `BTreeMap<(String, u32), BindingStatus>` — no new lifetimes, no hot-path allocation (one map build per REPLAN, which already clones every binding today). |
| Performance regression | LOW | Planner runs once per full apply (control path); O(n) map build replaces O(n) map build. D's drift scan is O(n) on the ~1s poll over ≤ dozens of bindings. R2 is one fan-out loop on a transition that already paid a full reconcile. |
| Architectural mismatch | LOW-MED | Must not entangle with #6702/#6681's planner rework. The identity key `(interface, queue_id)` is layout-shape-independent and survives their per-interface queue extents; both issues confirmed non-overlapping in scope. The slot-keyed `refresh_bindings` cosmetic residual (§5-C R3) is deliberately deferred to their coordinator-adjacent work. One coordination note: whichever lands second rebases the replan function. |

## 9. Test plan

**Rust unit/integration (the fix lives here):**

- `replan_bindings_from_candidates` unit tests (extend the existing
  replan test module — `userspace-dp/src/main_tests.rs` hosts
  `replan_queues_binds_vlan_unit_on_parent_netdev`):
  1. **expansion while armed, non-deferred** — existing plan all-armed,
     add a candidate: new slots `registered=true, armed=true`; carried
     slots unchanged.
  2. **expansion while armed, DEFERRED (R1)** — same with
     `defer_workers=true`: new slots `registered=true, armed=false`.
  3. **expansion while disarmed** — global false: new slots
     `armed=false` on both defer and non-defer legs.
  4. **contraction** — remove a candidate: vanished identities' state
     does not leak onto survivors.
  5. **reshuffle identity carry** — insert a candidate that sorts
     earlier (or change queue_count): each surviving identity keeps its
     own `armed` at its NEW slot; an operator-disarmed identity stays
     disarmed at its new slot.
  6. **orphan-VLAN + fabric identities** — parent-rekeyed and
     fabric-parent candidates carry/arm correctly, INCLUDING the
     orphan-child → parent-promotion case (SMR r1 SMR-4 / v3 R3): plan N
     orphan child keyed on parent netdev, plan N+1 parent zoned → the
     parent's bindings inherit the child's armed state, with NO
     volatile fields riding along.
  7. **E2 invalid→valid transition** (AGY r1 f1 / Codex r1 MAJOR 3):
     plan N candidate with `ifindex == 0` (force-cleared, `last_change`
     stamped), plan N+1 same identity with `ifindex > 0` → slot
     re-initializes `registered=true, armed=<R1 value>`; AND the
     carve-out: a carried record operator-unregistered with a VALID old
     ifindex keeps `registered=false`.
  8. **identity transition matrix (Codex r1 BLOCKER 2):** same-name /
     new-ifindex carries control state; rename / same-ifindex
     re-initializes from R1; orphan-fallback (parent-name key + child
     ifindex) → explicit-parent carries `armed` across the ifindex
     swap.
  9. **queue-override semantics (Codex r1 MAJOR 5):** queue disarm →
     expansion adds a new member of that queue → new member initializes
     from R1 (NOT disarmed); contraction removing all overridden
     members leaves no residual; queue unregister survives a reshuffle
     on its remaining members.
  10. **volatile non-carry (v3 R3):** a carried identity's
      `ready`/`bound`/`xsk_registered`/counters/`last_error` are reset
      at replan; only `armed`/`registered`/`last_change` carry.
  11. **same-identity same-slot no-reshuffle** — control-state outcome
      byte-identical to today (regression pin for the common case).
- **Server-level regressions** (`userspace-dp/src/server/tests.rs`,
  alongside the full-apply tests at :1314/:1475; per Codex r1 MAJOR 7
  these MUST use valid map pins (server/tests.rs:913) and
  `force_worker_healthy_stub` (coordinator/mod.rs:329) so they cannot
  fail early in XSK bring-up, and MUST assert both responses ok, plan
  keys differ, binding count increased, and the added identity exists —
  so they cannot green an unsafe implementation):
  12. **expansion-while-armed** (the issue's demanded test): apply A,
      `set_forwarding_state(true)`, apply B with an additional zoned
      interface, assert EVERY binding `registered && armed` and
      `status.enabled == true`. Red on master (trace: planning.rs:521 →
      status.rs:280), green after.
  13. **armed DEFERRED expansion with insertion before an old identity
      (Codex r1 BLOCKER 1/MAJOR 7):** apply A, arm, apply B with
      `defer_workers=true` + a new candidate that sorts BEFORE an
      existing identity (forces the slot reshuffle + stale-refresh
      shape): assert new slots `registered && !armed`,
      `status.enabled == false`, and NO binding reports `ready` on a
      slot whose identity changed (the fail-closed window). Then the
      defer-completion re-apply (same plan, `defer_workers=false`):
      assert the R2 fan-out ran — EVERY binding `registered && armed`,
      `enabled == true` — and the reconcile actually bound the new
      XSKs (the stubbed worker health reflects the CURRENT layout).
  14. **#5134-shaped retry:** deferred apply → failed bring-up →
      republish with `DeferWorkers=false` + bumped generation → same
      R2 activation converges the slots.
- The fail-fast invariant (Q6, resolved per AGY r1 + Codex r1 MAJOR 7):
  assertions live ONLY in tests and only over well-defined
  planner/activation transitions — a production `debug_assert!` would
  panic under a legitimate operator diagnostic disarm. Not shipped.
- `make test-rust` (full cargo suite) clean; `cargo build` warning-free.
  Fleet cap honored: `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6749`.

**Go (option D + gate test):**

- Manager unit test for the D warn: synthesize `lastStatus` with global
  armed + one `Registered && !Armed` binding → assert exactly one warn
  on the false→true edge and none on subsequent ticks; assert the warn
  clears after re-arm.
- `maps_sync` gate test (v2, AGY r1 finding 3): feed a synthesized
  post-expansion status (new slots armed per C) through
  `probeBindingsReady`/`bindingForwardingLive` and assert the ctrl gate
  admits and the shim rows go READY — pins that the Go gates consume
  the fixed default as intended.
- `make test-go` clean.

**Smoke (loss userspace cluster, lock-cell wrapped):** deploy; verify
iperf3 baseline to 172.16.80.200; commit an ADDITIONAL zoned VLAN unit
(e.g. a new `reth0.90` in the wan zone) while armed; assert transit
continues with no manual arm toggle and
`show ... bindings` reports the new slots armed. Re-apply CoS after the
deploy per the cluster protocol (`apply-cos-config.sh`).

**Docs (module contract, same work item):**
`userspace-dp/src/server/README.md` — the arm-model narrative (the
`set_bindings_forwarding_armed`/defer sections around :71/:294-324)
gains the R1/R2/R3 rules: the defer-aware planner default, the
defer-completion activation, the control-only identity carry, and the
override-lifetime definition. **Release note / upgrade note (v3, AGY r1
Q7 + Codex r1 MINOR 8):** required, and it must state that the fix
takes effect only after the HELPER restarts into the new binary — a
pingable same-config helper is reused rather than replaced
(process.go:18), so the old-helper window is operationally relevant and
the note should call for `systemctl restart xpf-userspace-dp` (or an
equivalent helper bounce) on upgrade.

## 10. Out of scope (explicitly)

- **Go per-binding armed AUTO-convergence (option B)** — rejected as
  primary (§5-B's three grounds); the detection half ships as option D,
  and the one place convergence was genuinely needed (deferred
  activation) is owned helper-side by R2.
- **#6702/#6681 planner queue-geometry rework** — they own binding-count
  consequences; this fix is compatible but does not implement any of
  their layout change.
- **`bindingForwardingLive` / `enabled` / `probeBindingsReady` gate
  semantics** — the gates are correct; the bug is the DEFAULT they were
  fed. No gate changes.
- **Re-keying the coordinator's slot-keyed live-worker lookup
  (`refresh_bindings`)** — the defer-window cosmetic alias (§5-C R3,
  §7.9) is documented and neutralized by R1; re-keying it belongs with
  #6702's coordinator-adjacent planner rework. Filed as a follow-up.
- **Scoped R2 via an additive `deferred_unarmed` wire field** —
  considered and rejected (§5-C R2); recorded here so the option is not
  lost if the full fan-out's override-clearing ever becomes a real
  operator complaint.
- **Persisted-state migration** — none needed (state file write-only).
- **Operator-override persistence across global arm toggles** — the
  fan-out still clears them; making diagnostic disarms durable is a
  separate product decision.

## 11. Open questions for adversarial review

Closed in earlier rounds (kept for the record): Q2 (drift-producer
enumeration — §5-B; SMR r1 SMR-3, AGY r1 Q2, Codex r1 MAJOR 6 all
concur: no non-operator producer beyond the planner), Q5 (VLAN-alias
consumer keys on (Ifindex, QueueID) — no interaction; AGY r1 Q5, Codex
r1 MAJOR 4 concur), Q6 (fail-fast assertion is test-only — AGY r1 Q6 +
Codex r1 MAJOR 7 concur), Q7 (High + release note + helper-restart
requirement — AGY r1 Q7 + Codex r1 MINOR 8 concur).

Remaining questions for round 2, each invitable to PLAN-KILL with a
concrete counterexample:

1. **R2's full fan-out vs scoped activation.** Defer-completion arms
   EVERY registered binding, clearing per-slot operator disarms
   (documented §7.8; rationale: the window is seconds and fail-closed
   throughout, so a defer-window disarm has no observable effect to
   preserve). Is there a REAL operator workflow that disarms a slot and
   then commits a RETH-MAC-pending plan change within the same
   diagnostic session, such that the R2 fan-out destroys state the
   operator still needed? If yes, the additive `deferred_unarmed`
   scoped variant (§5-C R2, §10) must ship instead.
2. **R1's gate is `defer_workers` from the INCOMING snapshot.** Is
   there any path where an apply reconciles (non-deferred) but the new
   slots still don't get bound before status is reported — e.g. a
   reconcile that silently skips a subset of registered bindings
   (bringup.rs:274 skips only `!registered || ifindex<=0`) — which
   would re-open the armed-but-unbound window R1 exists to close?
3. **R3's control-field set.** The carry set is
   {`armed`, `registered`, `last_change`}. Is `last_change` actually
   control state (it feeds nothing but display + the v-old
   `had_existing` computation, which R3's explicit `never_registered`
   makes redundant — should `had_existing` be redefined in terms of
   "identity present in the old map" instead of the current five-field
   heuristic, and does any behavior hinge on the difference)?
4. **Defer-window cosmetic alias.** Acceptable as documented (§5-C R3,
   §7.9), or must the fix additionally suppress `ready` on records
   whose identity moved during a deferred apply (a small targeted
   change: skip the `copy_live_snapshot` branch when the live worker's
   recorded interface/queue differs from the binding's)? The latter
   shrinks the cosmetic residual without re-keying the coordinator —
   is it worth the extra branch in scope?
5. **E2 carve-out completeness.** The `never_registered` widening
   distinguishes never-registered (old ifindex ≤ 0) from
   operator-unregistered (old ifindex > 0). Is there a THIRD
   `registered=false` state a carried record can legitimately hold that
   the widening misclassifies? (Enumeration so far: force-clear on
   ifindex ≤ 0; operator `set_binding_state registered=false`;
   operator `set_queue_state registered=false` — the latter two share
   the carve-out. #2794's `zero_unbound_slot` clears volatile/socket
   fields, NOT `registered`; verified in refresh_bindings.rs.)
6. **D's warn predicate scope.** The warn fires on ANY
   `Registered && Ifindex>0 && !Armed` drift, including operator
   diagnostic disarms (by design — truthful). Should the warn text
   distinguish "never armed since plan change" (likely bug) from
   "armed then disarmed" (likely operator) using `last_change`
   ordering, or is the single generic warn sufficient for v1 of the
   detector?
