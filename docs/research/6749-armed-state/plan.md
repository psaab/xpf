# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v7.1 — pending adversarial plan review (round 7)**

- Issue: #6749 (opus-review-001 root R06, severity High)
- Research base: `ad9591177` (origin/master at worktree creation)
- Research branch: `research/6749-armed-state` (plan docs only — no
  production code in this branch)
- v1 @ `8c76670d6` (r1: all DEMAND-REVISION); v3 @ `bce10126c` (r2:
  all DEMAND-REVISION); v4 @ `f679a791a` (r3: all DEMAND-REVISION);
  v5 @ `0c0b9b677` (r4: Codex DEMAND-REVISION; AGY + SMR
  PLAN-READY-WITH-NITS); v6 @ `6969b6167` (r5: Codex DEMAND-REVISION;
  AGY + SMR PLAN-READY-WITH-NITS); v7 @ `3e388fde8` (r6: AGY
  DEMAND-REVISION; SMR PLAN-READY-WITH-NITS; Codex pending); v7.1
  folds round 6: explicit `defer_completion_authorized` signature +
  latch-consume-on-Ok-inside ordering (AGY r6 f1 / SMR r6 N3),
  daemon-side MAC-retry debt (AGY r6 f2), retry backoff + attempt cap
  + debt/in-flight suppression (AGY r6 f3/f4 = SMR r6 N1).

---

## 1. Status

DRAFT v7.1 — pending adversarial plan review round 7 (Codex + AGY +
Claude SMR). Convergence target: PLAN-READY (recommended path shipped
to `/engineer`) or PLAN-KILL. No production code is written under
`/research`.

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
  S4's scope (S4' global failure mark); toggle mid-defer (defer gate);
  arm fan-out reordered after Ok; planner never arms (AGY f1).
- **Round 4** (v5): Codex DEMAND-REVISION (6 BLOCKER + 3 MAJOR); AGY +
  SMR PLAN-READY-WITH-NITS. Name-only plan gate authorizes
  wrong-physical and incomplete retained plans; bool conflates
  global-disarm with operator ownership; S4' full-apply-only +
  retained-records retry deficit; arm-then-fail strands with no
  production retry; compile-time arm-sync bypasses the defer gate
  (verified); rebind verb-identity is not completion provenance;
  sysfs-race authorization.
- **Round 5** (v6): Codex DEMAND-REVISION (8 BLOCKER + 2 MAJOR); AGY +
  SMR PLAN-READY-WITH-NITS (both nits on the Warn-rate + a docs
  clarification, triple-converged with Codex M10). Codex's round:
  tri-state cannot distinguish operator-DISARMED-then-force-cleared
  from operator-UNREGISTERED (both `!registered && operator`) — v6's
  "exact claim restoration" would re-register explicit unregistrations
  on any replan; failure-path replan-from-restored destroys accepted-A
  operator claims absent from rejected B's vector AND reintroduces
  the live-sysfs race (unreadable queue dir → permanent EMPTY vector:
  rebind never replans, deficit exits for zero runnable, `enabled=false`
  with no slot for D to warn on); `update_fabrics` replaces
  snapshot.fabrics (a plan-key input that ADDS binding candidates)
  without replanning — falsifying the coherent-vector invariant's
  "ONE divergence point"; the daemon clears `m.deferWorkers` right
  after ApplyConfig (:170, BEFORE programRethMAC :247 and completion
  :393/:401) so the v6 arm-sync gate passes inside the MAC-programming
  window — the pre-MAC arm race merely moved; S4' creates unscheduled
  pending sinks (first-Compile returns before ensureStatusLoopLocked;
  rollback-to-true no-ops the sync; failed tagged rebind only warns;
  the watchdog requires Registered && Armed = 0 after S4'); completion
  and #5134 provenance are neither durable (latch never consumed) nor
  generation-safe (bare-bool debt can authorize a newer deferred B),
  and the live-change completion fires even when programRethMAC
  FAILED; #6165 refusal floods Warn at 1/s; tests remain
  false-green-capable.
- **Round-5 disposition table:**

  | r5 finding | v7 disposition |
  |---|---|
  | Codex B2 unregister/disarm collapse | CLOSED — E2 narrowed to `pending` only; operator claims never planner-restored (§5-C) |
  | Codex B3 claim destruction on recovery | CLOSED — failure path restores `existing_bindings` wholesale (claims intact) (§5-C) |
  | Codex B4 update_fabrics invariant violation | CLOSED — replan on fabric-set change (§5-C) |
  | Codex B5 live-sysfs race / empty vector | CLOSED — no replan on the failure path at all (§5-C) |
  | Codex B6 pre-MAC arm race | CLOSED — defer flag spans apply→MAC→completion (daemon reorder, §5-C) |
  | Codex B7 unscheduled pending sinks | CLOSED — Go pending-activation retry + status-loop ordering (§5-C) |
  | Codex B8 latch/generation/MAC-success | CLOSED — latch consumed on successful tagged rebind; #5134 debt generation-scoped; completion gated on MAC success (§5-C) |
  | Codex M9 test holes | CLOSED — §9 items 12-19 rewritten |
  | Codex M10 Warn flood | CLOSED — edge-triggered sync-failure warn (§5-C, §9) |
  | AGY r5 minor-1 / SMR r5 N1 | = Codex M10 (triple convergence) |
  | AGY r5 nit-2 / SMR r5 N2 | CLOSED — §9 docs bullet covers both |
  | SMR r5 N3 | CLOSED — §9 item 14(iv) gains the idempotent re-arm pin |

- **Round 6** (v7): AGY DEMAND-REVISION (1 BLOCKER + 2 MAJOR + 1
  MINOR); SMR PLAN-READY-WITH-NITS (3 nits); Codex pending at v7.1
  fold time. AGY's round: the convergence gate references a caller
  `complete_deferred` flag that is never threaded into
  `reconcile_status_bindings`' SIGNATURE, and the latch-consume
  ordering is ambiguous (clear-before → a failed tagged rebind would
  permanently consume the latch; clear-after → the convergence inside
  blocks on the still-set latch) — v7.1 makes the signature and the
  consume-on-Ok-inside ordering explicit; suppressing completion on
  MAC failure without a daemon-side retry strands transient MAC
  failures indefinitely (the Go retry is itself gated on the flag)
  — v7.1 adds the daemon-side MAC-retry debt; the fixed-5s
  un-backed-off pending-activation retry tears down the FULL healthy
  worker set every 5s on a permanent bind failure — v7.1 adds
  backoff + attempt cap (+ the SMR r6 N1 debt/in-flight suppression);
  the clear→dispatch microseconds let a poll-tick fire an untagged
  rebind racing the tagged completion — v7.1 suppresses the untagged
  retry while a completion is in-flight (noting the race is otherwise
  benign: the stored-defer gate blocks convergence and the MAC is
  already programmed). SMR r6's nits: retry backoff/cap/debt
  suppression (= AGY f3, folded), the MAC-failure corner's
  documentation (= AGY f2, folded with the debt), the latch write
  ordering (= AGY f1, folded).
- **Round-6 disposition table:**

  | r6 finding | v7.1 disposition |
  |---|---|
  | AGY f1 signature + latch atomicity | CLOSED — explicit `reconcile_status_bindings(state, defer_completion_authorized)`; latch consumed inside on Ok, never on Err (§5-C) |
  | AGY f2 transient MAC stranding | CLOSED — daemon-side MAC-retry debt (§5-C completion machinery) |
  | AGY f3 retry thrash | CLOSED — backoff 5s→10s→20s→60s + attempt cap + edge Warn (§5-C retry) |
  | AGY f4 clear→dispatch race | CLOSED — completion-in-flight suppression on the retry; benign-race note (§5-C) |
  | AGY test notes (13/17) | CLOSED — §9 items 13/17 + Go retry tests |
  | SMR r6 N1/N2/N3 | = AGY f3 / f2 / f1 respectively |

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

### Option C — the `activation_state` lifecycle, v7: tri-state provenance + coherent vector + owned retry (Rust helper + Go manager + daemon ordering; superset of A)

v7 rewrite (Codex r5 BLOCKERs 2–8 + MAJOR 9–10; AGY r5 + SMR r5 nits).
Round 5 verified the tri-state's remaining encoding gaps and the
retry-ownership hole, and falsified two v6 mechanics (the
failure-path replan and the transient defer flag). v6's model stands;
v7 corrects its failure-recovery and completion machinery:

**The tri-state (unchanged from v6).**
`BindingStatus.activation_state ∈ {none, pending, operator}`:
`pending` = planner-owned (converge at the next successful,
defer-authorized armed reconcile); `operator` = operator-verb-owned
(never auto-converged, dies only at a global fan-out); `none` =
everything else (armed slots; global-fan-out-disarmed slots — global
ownership). Planner mark rules (never arms): S1 (unregistrable
creation → pending), S2 (force-clear on `ifindex <= 0` → pending
UNLESS the record is `operator`), S3 (deferred plan-CHANGING apply →
all registered slots `armed=false`, `pending` unless `operator`), S5
(new identity → `registered=true, armed=false, pending` always), S4'
(post-teardown bring-up failure → all non-operator registered slots
`armed=false, pending`). C1 (reaching `registered && armed` →
`none`), C2 (verbs set `operator`/`none` in the same mutation as
their values, BEFORE any registration-changed reconcile), C3 (global
fan-out sets `none` on REGISTERED slots; unregistered keep state).

**E2 narrowed to `pending` only (Codex r5 BLOCKER 2).** The
tri-state cannot distinguish "operator-disarmed then planner-force-
cleared" from "operator-unregistered" — both are
`!registered && operator` — so v6's "exact claim restoration" was
unimplementable: E2 would have re-registered explicit unregistrations
on ANY replan, no flap required. v7's rule: at replan,
`!registered && pending && new ifindex > 0` → `registered=true`
(still `!armed, pending`); **`operator` records are NEVER
re-registered or armed by the planner.** The retained claim
(`registered=false, operator`) is the honest degradation, restored
to §10: an operator-claimed slot whose interface flaps recovers
unregistered-with-intent (never armed, never auto-converged); the
operator re-registers by hand when the environment is understood.
Registration and arming of claimed slots belong to operators and
global fan-outs, not to recovery machinery.

**Failure recovery: plain restoration, no replan (Codex r5 BLOCKERs
3 + 5; subsumes r4 B2 + M9).** v6's failure-path replan-from-restored
reintroduced the live-sysfs race (an unreadable queue dir → empty
candidate set → a PERMANENT empty vector: rebind never replans, the
same-plan deficit exits for zero runnable bindings, `enabled=false`
with no slot for D to warn on) and destroyed accepted-A operator
claims absent from rejected B's vector. v7 replaces it with the
simplest coherent form — **the post-teardown apply-failure path
restores `guard.snapshot` AND `existing_bindings` wholesale (the
pre-apply vector captured at snapshot.rs:158, which IS the coherent
last-good vector: A's identities, A's ifindexes, A's operator claims),
then re-marks every non-operator registered slot `armed=false,
pending`** (the common S4' predicate, idempotent — the marks the
in-reconcile S4' put on the discarded B vector die with it). Then
`refresh_status` / `refresh_bindings` reports the REAL volatile state
of any surviving partial workers against that vector (the #4952
rationale — real post-teardown state, no pre-teardown ghosts —
preserved; the retained-B pin changes form, §6). No replan, no
sysfs, no race, no empty vector, no lost claims. The common S4'
itself stays in `reconcile_status_bindings` for the non-restoring
callers (rebind, toggles, forwarding arm, same-plan leg): on
`WorkerSpawn | WorkerBindIncomplete` it marks the CURRENT vector
before the Err propagates (Codex r4 B4's common-locus requirement,
kept).

**Convergence — one locus, two gates, one explicit signature (v7.1,
AGY r6 f1).** `reconcile_status_bindings(state,
defer_completion_authorized: bool) -> Result<(), ReconcileError>` —
the `rebind` handler passes `request.complete_deferred`; every other
caller (apply legs, forwarding, queue/binding toggles) passes
`false`. In the ARMED leg (`should_run_afxdp` true), after
`afxdp.reconcile` returns `Ok` and BEFORE the bindings are written
back / `refresh_status` / the single persist: (1) if
`defer_completion_authorized && guard.snapshot.defer_workers` —
CONSUME the latch: set the stored snapshot's `defer_workers=false`
(one mutation, inside the same critical section, sharing the
handler's one persist — never a separate write, never a window where
the state file says defer=true while in-memory says false, SMR r6
N3); (2) for every `state==pending && registered` slot, set
`armed=true, state=none, last_change=now`. The two gates are therefore
`should_run_afxdp` AND `(!stored_defer || defer_completion_authorized)`
— evaluated against the stored value AT ENTRY (before the consume),
so the tagged rebind converges in the same call that consumes the
latch, and an UNTAGGED caller during a stored-defer window is blocked
exactly as before. On `Err` the latch is NEVER consumed (a failed
tagged rebind leaves the defer state intact for the retry — AGY r6
f1's clear-before hazard is structurally excluded) and S4' marks as
usual. The convergence still cannot fire on a partial bind
(`bound == planned` is required for the Ok, bringup.rs:188).

**INVARIANT 2 (coherent vector), completed — `update_fabrics`
replans (Codex r5 BLOCKER 4).** `update_fabrics`
(handlers/mod.rs:141-168) replaces `guard.snapshot.fabrics` — a
plan-key input that also ADDS binding candidates
(planning.rs:160-173, 462-477) — without replanning, directly
falsifying v6's "the failure path is the ONE divergence point". On a
fabric-set change (the existing `snapshot.fabrics != *fabrics`
check), the handler now ALSO replans bindings (S5 rules apply: new
fabric-parent candidates → `registered=true, armed=false, pending`)
before `refresh_status`. The unchanged-set 30s periodic refresh pays
nothing. Convergence of the new fabric slots rides the normal
machinery (next armed reconcile — and the v7 Go pending-retry below
schedules one).

**Completion machinery, durable and provenance-exact (Codex r5
BLOCKERs 6 + 8):**

- **The daemon's defer flag spans the REAL window.** Today
  `clearDeferWorkers()` runs immediately after `ApplyConfig`
  (daemon_apply_dataplane.go:170) — BEFORE `programRethMAC` (:247)
  and before the completion dispatch (:393/:401) — so a status-poll
  tick inside the MAC-programming window sees the flag cleared and
  the v6 arm-sync gate passes (the pre-MAC arm race Codex r5 B6
  verified). v7 moves the clear to just BEFORE the completion
  dispatch (after MAC programming, before
  `reapplyAfterDeferredMAC`/`NotifyLinkCycle`); the deferred-func
  early-return cleanup (:79) is unchanged. The mandatory re-apply
  then publishes `DeferWorkers=false` (its whole purpose,
  :466-481), and any arm the sync sends after the clear lands on an
  already-programmed MAC — no longer premature.
- **Completion requires a SUCCESSFUL prerequisite — and a failed
  prerequisite gets its own debt (v7.1, AGY r6 f2).** Today the
  live-change completion (`reapplyAfterDeferredMAC`, :401) fires
  whenever `rethMACPending && !needLinkCycleRecovery` — including
  when `programRethMAC` returned an error (warned-only, :267-270).
  v7 tracks per-commit MAC success and skips the completion dispatch
  when programming failed: the defer flag stays set, the slots stay
  pending (fail-closed, visible in `show`). On that failure the
  daemon records a **MAC-retry debt** (mirroring the #5134 worker-arm
  debt pattern): a daemon-side tick re-attempts `programRethMAC` for
  the deferred interfaces on subsequent event/status iterations, and
  on success clears the flag and dispatches the completion — so a
  TRANSIENT MAC failure (netlink busy, buffer pressure) self-heals
  without waiting for an unrelated commit. Any subsequent full apply
  also re-attempts programming naturally (it recomputes
  `rethMACPending`). The stranding corner that remains by design is
  only "failure + a debt that can never succeed" (a genuinely broken
  member interface) — fail-closed, Warn-visible, pending-visible,
  and the operator's to fix. Same for the link-cycle path: the
  `complete_deferred` rebind flag is set only when the cycle
  followed a successful MAC program.
- **The completion CONSUMES the latch (helper side).** A successful
  `complete_deferred=true` rebind sets the stored snapshot's
  `defer_workers=false` after its reconcile (the persisted SSOT,
  `persist_state=true` already covers it). v6's bypass-only
  authorization left the latch set, so LATER pending work was
  blocked until another tagged request or non-deferred apply; with
  the latch consumed, the convergence's defer gate is
  `!stored_defer || complete_deferred` evaluated against the
  CURRENT stored value each time.
- **#5134 debt is generation-scoped.** `RecordDeferredWorkerArmDebt`
  records `pendingWorkerArm` AND the snapshot generation it was
  created for; `retryDeferredWorkerArmLocked` fires only while
  `m.lastSnapshot.Generation == debtGeneration` — a stale A debt can
  no longer authorize a newer deferred B before B's MAC work
  (Codex r5 B8's generation-safety).

**Retry ownership — the Go pending-activation retry (Codex r5
BLOCKER 7).** v6 marked pending states but scheduled no production
reconcile to converge them: first-Compile failures return before
`ensureStatusLoopLocked`; a rollback to a previously-true global
no-ops the desired-sync on equality; a failed tagged rebind only
warns; the busy watchdog requires `Registered && Armed` (zero after
S4'). v7 gives the status loop a discrimination-free retry — free
because the tri-state makes `pending` UNAMBIGUOUSLY planner-created
(operator states are `operator`, global states are `none`):

```
// in the periodic status loop, after syncDesiredForwardingStateLocked:
if desired == true && !m.deferWorkers && !m.pendingWorkerArm &&
   !m.completionInFlight &&
   anyBinding(state == pending) &&
   now >= m.pendingRetryNextAt {
    send plain rebind   // reconciles the CURRENT coherent plan;
                        // convergence arms the pending slots inside
    m.pendingRetryAttempts++
    m.pendingRetryNextAt = now + backoff(attempts)  // 5s,10s,20s,60s cap
    if m.pendingRetryAttempts >= 12 {
        warn once (edge): "bindings stuck pending activation"
        stop retrying until the pending set changes
    }
}
```

The plain rebind is the right verb (reconciles + converges when
`!stored_defer`; control-socket-serialized so it never races an
in-progress bind — the spurious-EBUSY the daemon's own comment
warns about requires an in-progress first bind, which cannot exist
here). **Backoff + cap (v7.1, AGY r6 f3 = SMR r6 N1):** the
`rebind` tears down and respawns the FULL worker set, so a
PERMANENT bind failure (a queue that can never bind) must not churn
healthy workers at a fixed 5s forever — exponential backoff to a
60s cap, and after ~12 attempts (~5 minutes) the retry stops and
emits one edge-triggered Warn; the pending state remains visible in
`show` and any later state change (new commit, toggle, link event)
re-arms the retry. **Two suppressions (v7.1):** while
`m.pendingWorkerArm` is set the #5134 debt owns the retry for its
generation (it republishes the exact snapshot — senior to the
generic rebind); and while a provenance completion is IN-FLIGHT
(`completionInFlight`, a manager-side flag set when the daemon
dispatches `NotifyLinkCycle`/`reapplyAfterDeferredMAC` and cleared
when the tagged rebind / re-apply returns — mirroring
`rgTransitionInFlight`) the untagged retry holds fire, closing the
clear→dispatch microseconds race (AGY r6 f4; the race is otherwise
benign — the stored-defer gate blocks the untagged convergence and
the MAC is already programmed, but the suppression avoids a wasted
worker teardown). During a defer window (flag set — durable per the
daemon fix above) the retry is suppressed; completion owns that
window. And the first-Compile hole closes by starting/ensuring the
status loop BEFORE the compile-path
`syncDesiredForwardingStateLocked` (or on its error path) — the
#5873 orphaned-debt pattern. This is NOT option B resurrected: B
auto-converged blindly and fought operator disarms; the v7.1 retry
only schedules the helper's OWN requested activations and changes
no armed bit itself.

**Logging (Codex r5 MAJOR 10 = SMR r5 N1 = AGY r5 minor-1, triple
convergence).** The arm-verb rollback makes the Go desired-loop
retry a failed arm each tick; when the #6165 required-protocol gate
refuses the retry, `process_status.go:241` logs Warn at 1/s
(~86K/day for a permanent mismatch). The sync-failure log becomes
edge-triggered (fire on the false→true transition of the error
state, once on recovery) with a repeated-tick test.

**R3 (kept):** carry {`armed`, `registered`, `activation_state`,
`last_change`} keyed on configured-name `(interface, queue_id)`;
volatile rebuilt downstream; `had_existing` dead; queue-scoped
overrides membership-at-invocation.

**Ownership model (final form):** a slot's non-forwarding state has
exactly three owners, on the record: PLANNER (`pending` — converges
when a successful defer-authorized armed reconcile binds the current
plan; the Go pending-activation retry schedules that reconcile when
nothing else does), OPERATOR (`operator` — never converged, dies
only at a global fan-out), GLOBAL default (`none` — Go-pushed,
fanned out post-reconcile on explicit arms). The defer window has
exactly two authorized exits: a successful-MAC completion with
provenance (tagged rebind or the mandatory non-deferred re-apply),
or an explicit operator/global verb.

**What it fixes (delta over v6):** the unregister/disarm collapse
(E2 narrowed); failure-recovery claim destruction + live-sysfs race
+ permanent-empty-vector (plain restoration); the update_fabrics
invariant violation (replan on change); the pre-MAC arm race
(durable defer flag); completion-without-success (MAC-success
gating); the unconsumed defer latch; generationless #5134 debt; the
unscheduled pending sinks (Go pending-activation retry + status-loop
ordering); the sync-failure Warn flood (edge-trigger). **Delta v7 →
v7.1 (round 6):** the convergence gate's caller authorization is now
an explicit `defer_completion_authorized` parameter with the latch
consumed inside the armed leg on Ok — never on Err (AGY r6 f1);
transient MAC failures self-heal via a daemon-side MAC-retry debt
instead of stranding until the next commit (AGY r6 f2); the
pending-activation retry is backoff-shaped with an attempt cap and
suppressed while the #5134 debt or a provenance completion owns the
retry (AGY r6 f3/f4 = SMR r6 N1/N3).

**Size:** failure-path restoration + re-mark (~12), common S4' (~8),
E2 narrowing (~4), update_fabrics replan (~12), daemon clear reorder
+ MAC-success gating + MAC-retry debt (~45), convergence signature +
latch consume (~8), #5134 generation scoping (~12), Go
pending-activation retry + backoff/cap/suppressions + loop-order
(~45), edge-triggered warn (~15), C2/C3 rule sites (~8), Go
`BindingStatus`/`ControlRequest` fields + D predicate (~20),
protocol canary + #4952-pin test updates, docs. No coordinator,
gate-semantics, or shim changes.
### Recommendation

**Ship option C + option D** — the v7 model: the tri-state
`activation_state` lifecycle (planner-owned `pending`, operator-owned
`operator`, global-owned `none`; the planner NEVER arms and never
restores operator claims), the coherent-vector invariant completed
(plain restoration on the failure path; `update_fabrics` replans on
change), the common-locus S4' failure marking, the two-gated
convergence (armed × defer-provenance), the durable defer window with
MAC-success-gated completion and latch consumption, generation-scoped
#5134 debt, the discrimination-free Go pending-activation retry,
arm-verb rollback feeding the desired loop, the Go arm-sync defer
gate, R3 control-only identity carry, E2 narrowed to `pending` —
plus the state-aware, desired-gated, edge-triggered Go drift
detector. Retreat: none lighter survives review — every simpler
shape died to a named counterexample in rounds 1-5 (arm-at-replan;
leg-scoped activation; ungated marker; bool provenance;
replan-at-convergence gating; replan-on-restore recovery; transient
defer flag; verb-identity completion). **Reject B as Go-converger**
(§5-B) — and note the v7 pending-activation retry is NOT B: it
schedules no arming, only a reconcile of the current coherent plan,
and the tri-state makes its target unambiguous (planner-requested
activations only, never operator claims).

Rationale in one line: non-forwarding state has exactly three owners
— planner, operator, global default — so put the ownership ON the
record, keep the record coherent with the accepted plan by
restoration rather than re-derivation, let activation complete only
where binding actually happened, and give the helper's own
activations a scheduled retry.

## 6. Public API preservation

- **Wire protocol:** TWO additive fields, both with serde defaults,
  no `CONFIG_SNAPSHOT_PROTOCOL_VERSION` bump (the #3091
  additive-with-default precedent):
  1. `BindingStatus.activation_state: string ∈ {"none","pending",
     "operator"}` (serde default `"none"`; old Go ignores it; new Go
     treats missing as `"none"` — old-helper stranding reads as
     drift, the correct mixed-version signal). Go's `BindingStatus`
     gains it as optional.
  2. `ControlRequest.complete_deferred: bool` (serde default `false`;
     old helpers ignore it — safe fail-closed; new Go + old helper:
     the old helper's semantics, safe). Sent only by the
     `NotifyLinkCycle` path after a SUCCESSFUL MAC program.
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind`, `update_fabrics` —
  signatures and response shapes unchanged. `set_binding_state` slot
  addressing is unchanged (slots remain positional).
- **Go manager API:** unchanged (D, the arm-sync defer gate, the
  pending-activation retry, and the #5134 generation scoping are
  manager-internal). Daemon-internal ordering changes (defer-flag
  lifetime, MAC-success gating) do not alter any interface.
- **CLI / `show` output:** unchanged shape; `activation-state` may
  surface in verbose binding output as an additive display field.
- **Pinned behavior changes (each reviewer-sanctioned through
  rounds 3-5):**
  1. The #4952/#5143 post-teardown failure path now restores the
     PRE-APPLY binding vector (all non-operator slots unarmed+pending)
     instead of retaining the rejected plan's vector — the pins'
     intent (real post-teardown state, fail-closed truth) is
     preserved by `refresh_bindings` against surviving workers plus
     the restored coherent control state (§5-C).
  2. `update_fabrics` now replans bindings when the fabric set
     changes (new fabric-parent candidates appear as pending until
     the next armed reconcile) — previously the binding plan silently
     lagged the persisted fabric set.
  3. The daemon's defer flag now spans apply → MAC programming →
     completion (previously cleared right after ApplyConfig), and the
     live-MAC-change completion dispatch is skipped when MAC
     programming failed (previously fired on warn-only failures).
## 7. Hidden invariants the change must preserve

1. **Defer contract — the REAL one (v3–v7):** a `defer_workers=true`
   PLAN-CHANGING apply must leave the whole vector unarmed (S3;
   non-operator slots `pending`), because its reconcile is SKIPPED.
   The defer window is now DURABLE: the Go manager's flag spans apply
   → MAC programming → completion (no poll-tick arm in the window),
   and completion fires only on a SUCCESSFUL prerequisite — the
   provenance-tagged rebind (`complete_deferred`, link-cycle path) or
   the mandatory non-deferred re-apply (live-change path), the former
   consuming the stored latch on success. An explicit operator arm
   remains an explicit authorization (documented). A deferred apply
   with an UNCHANGED plan marks nothing.
2. **#869 no-ready-in-enabled:** `enabled` must keep NOT requiring
   `ready`. Untouched.
3. **#1666 ready-gate:** per-row shim steering must keep requiring
   `Ready`. Untouched. In the defer window S3 keeps everything
   unarmed, so the slot-keyed stale `Ready` alias can never produce a
   READY row — and `ctrl.Enabled=0` overrides row contents regardless
   (Codex r3's verification: ctrl=0 short-circuits the shim before
   binding lookup, lib.rs:405).
4. **Disarm direction never blocked:** the `ifindex <= 0` leg still
   force-clears (marking `pending` unless the record is
   operator-claimed, S2); `set_forwarding_state(false)` still fans
   out `armed=false` and sets `none` on registered slots — a
   deliberate global disarm leaves nothing armed to auto-activate,
   while unregistered (S1/S2-marked) slots keep their state for E2.
5. **Same-plan skip (#2915/#2916/#3007/#3175):** the plan key and the
   candidate set are untouched; identity-carry only runs on the
   full-apply leg that ALREADY decided the plan changed (plus the two
   v7 additions: the failure path RESTORES rather than replans, and
   `update_fabrics` replans on set change — neither alters the key).
6. **One-XSK-per-(netdev,queue) (#1921):** the `seen_linux` dedup and
   candidate iteration order are unchanged; identity uniqueness per
   plan follows from it.
7. **Coordinator filter (`registered && ifindex > 0`):** unchanged;
   worker bring-up must not start reading `armed` OR the state field.
8. **Operator override ownership (v7):** operator verbs claim slots
   with `activation_state=operator` (same mutation as the verb's
   values, before any registration-changed reconcile). An
   operator-claimed slot is never marked pending, never converged,
   and NEVER planner-restored (E2 is `pending`-only): a claimed slot
   that force-clears on a flap recovers as `registered=false,
   operator` (the documented degradation, §10) until the operator
   re-registers by hand. Its claim dies only at an explicit global
   fan-out (C3, registered slots). A globally-DISARMED slot (`none`)
   is NOT operator-owned: S2 re-marks it pending on flap and E2
   re-registers it. `set_queue_state` remains
   membership-at-invocation shorthand.
9. **Volatile state rebuilt, not carried (kept):** R3 carries
   {`armed`, `registered`, `activation_state`, `last_change`} only;
   everything else resets at replan and is re-derived. The
   defer-window slot-keyed alias is cosmetic per invariant 3 and
   remains a documented follow-up (§10).
10. **Coherent-vector invariant (v7, completed):** after every
    handler, the binding vector equals the stored snapshot's plan.
    Full-apply replan (replaces); same-plan legs (equal key ⇒ equal
    identities); #3789 pre-teardown restore (restores both together);
    post-teardown failure (restores snapshot AND the pre-apply vector
    together — v7); `update_fabrics` (replans on set change — v7);
    rebind / toggles / forwarding (no plan mutation). The server
    tests assert the invariant directly (§9 item 16).
11. **Failure truthfulness + retry ownership (v7):** the planner
    never arms (S5); ANY post-teardown bring-up failure marks all
    non-operator registered slots pending in COMMON typed handling
    (S4'); the arm verb rolls its global bit back on Err (the Go
    desired-loop retries); and the Go status loop's pending-
    activation retry (desired==true, any `pending`, flag clear,
    ≥5s throttle, plain rebind) schedules a convergence reconcile
    whenever nothing else does — first-Compile included (the loop is
    ensured before the compile-path sync).
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
| Behavioral regression | LOW-MED | Observable changes beyond v6: (i) the post-teardown failure path restores the pre-apply vector (all non-operator slots pending) instead of retaining the rejected plan's vector — a reporting change toward coherence, reviewer-sanctioned (§6); (ii) `update_fabrics` replans on fabric-set change — new fabric candidates appear as pending until the next armed reconcile (previously they silently never bound); (iii) the daemon's defer flag spans the full window and the live-change completion requires MAC success — on a MAC-programming failure the dataplane now stays fail-closed with pending slots instead of binding workers onto a wrong-MAC interface (a tightening; the failure was warn-only before); (iv) the status loop may issue a plain rebind (≥5s throttle) while pending slots persist — a new control-socket caller, bounded and serialized, with the same verb the busy-watchdog already issues; (v) the sync-failure warn becomes edge-triggered (a log-volume reduction). All prior rounds' postures (S3 defer gate, S4' failure marking, C3 rollback, operator claims) are unchanged. |
| Lifetime / borrow-checker | LOW | Cold path; owned clones; plain enum; restoration reuses the pre-apply vector already in scope. No new lifetimes, no hot-path allocation. |
| Performance regression | LOW | The pending-activation retry adds at most one rebind per 5s while pending persists (and pending is a failure/defer-window state, not steady state); the update_fabrics replan runs only on set change (the 30s periodic is unchanged otherwise). Everything else is per-control-event cold path. No per-packet/session/poll-tick work beyond the existing 1s poll's O(n) scans. |
| Architectural mismatch | LOW-MED | The retry caller is the one genuinely new actor; it is discrimination-free by construction (the tri-state) and uses the same serialized verb as existing recovery paths. The defer-flag reorder and MAC-success gating touch daemon apply ordering — the most operationally sensitive of the changes, covered by the cluster smoke (§9). Must not entangle with #6702/#6681's planner rework; identity keying is layout-shape-independent. |

## 9. Test plan

**Rust unit/integration (the fix lives here):**

- `replan_bindings_from_candidates` unit tests (`main_tests.rs`):
  1. **expansion while armed, non-deferred (S5 never-arm)** — new
     slots `registered=true, armed=false, state=pending`; carried
     slots unchanged.
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
  7. **E2 + flap matrix (v7 form):** (a) `ifindex == 0` at apply →
     `registered=false, pending` (S1); later valid → re-registered
     (`registered=true, armed=false, pending`); converges at the next
     armed reconcile; (b) operator-UNREGISTERED (valid,
     `state=operator`) → flap → valid → STAYS `registered=false,
     operator` (E2 never restores claims — the v7 narrowing; Codex
     r5 B2); (c-i) ARMED slot flaps (S2 marks pending) → recovers →
     re-registered + converged; (c-ii) operator-DISARMED slot
     (`registered, armed=false, operator`) flaps → force-cleared
     WITHOUT pending (claim retained) → recovers as
     `registered=false, operator` (documented degradation); (d)
     invalid → GLOBAL ARM fan-out → valid: the S1 mark SURVIVES the
     fan-out (C3 clears state only on registered slots) →
     re-registers; (e) GLOBAL DISARM → flap → valid (Codex r4 B3):
     the disarmed (`none`) slot is NOT operator-owned → S2 re-marks
     pending → E2 re-registers → converges on re-arm.
  8. **identity transition matrix:** same-name/new-ifindex carries
     state; rename/same-ifindex re-initializes; orphan-fallback →
     explicit-parent carries across the ifindex swap.
  9. **queue-override semantics:** queue disarm → expansion adds a
     new member → initializes per S5 (pending, NOT claimed);
     contraction removing all claimed members leaves no residual;
     queue unregister survives a reshuffle as CLAIMED and
     un-registered (never planner-restored); operator verbs SET/CLEAR
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
  stored defer=true and the caller lacks `complete_deferred`; ALLOWED
  for the provenance-tagged caller; allowed for every caller when
  stored non-deferred; the successful tagged rebind CONSUMES the
  latch (stored defer→false).
- **Common S4' unit tests:** `WorkerSpawn` and `WorkerBindIncomplete`
  from EACH reconcile caller (full apply, same-plan apply, rebind,
  binding toggle, queue toggle, forwarding arm) → all non-operator
  registered slots unarmed+pending; operator-claimed slots untouched.
- **Server-level regressions** (`userspace-dp/src/server/tests.rs`;
  valid map pins, `force_worker_healthy_stub`, assertions on
  ARMED/STATE + reconcile Ok/Err + reconcile stage + IMMEDIATE
  post-failure assertions per Codex r3-r5):
  12. **expansion-while-armed** (the issue's demanded test): apply A,
      `set_forwarding_state(true)`, apply B with an additional zoned
      interface; BOTH responses ok, plan keys differ, binding count
      increased, added identity exists, EVERY binding
      `registered && armed && state==none`, `enabled == true`,
      reconcile stage advanced. Red on master, green after.
  13. **deferred expansion, three completion shapes + three blocks:**
      apply A, arm, apply B `defer_workers=true` + inserted
      earlier-sorting candidate: all non-operator slots
      `!armed && pending`, `enabled == false`, IMMEDIATE assertion on
      an untouched pending slot + reconcile-call delta. Complete via:
      (a) same-plan re-apply `defer_workers=false`; (b) full-leg
      re-apply with a changed plan key; (c) `rebind` with
      `complete_deferred=true` — after each, non-operator slots
      `registered && armed && state==none`, `enabled == true`, and
      (c) leaves the latch CONSUMED (stored defer=false). NEGATIVES:
      (i) a registration toggle DURING the window does NOT converge;
      (ii) a plain rebind DURING the window does NOT converge; (iii)
      a FAILED tagged completion leaves the latch set and slots
      pending; (iv) a completion dispatched after a FAILED MAC
      program does not fire (daemon-side gate, Go test below).
  14. **failed bring-up, all shapes + retry (Codex r4/r5):** force
      `WorkerSpawn` and `WorkerBindIncomplete` on (i) expansion
      apply, (ii) E2-only apply, (iii) CONTRACTION apply, (iv)
      global-arm after a deferred boot apply (asserts rollback from
      prev=false AND no pre-reconcile fan-out), (iv-bis) idempotent
      re-arm on an already-true global (asserts rollback to true +
      marks survive + the pending-aware deficit fires recovery, SMR
      r5 N3), (v) rebind, (vi) a registration toggle. IMMEDIATELY
      after each Err: every non-operator registered slot
      `!armed && pending`, `enabled == false`, marks SURVIVE; then a
      successful retry converges each.
  15. **operator-override survival (tri-state, v7 form):**
      operator-disarm a slot; commit a plan-changing deferred apply +
      completion — the claimed slot stays `armed=false, operator`
      while the deferred slots converge; repeat across the failure
      path of 14(i) and the flap path of 7(c-ii); a global arm
      fan-out afterwards clears the claim (C3). PLUS the Codex r5 B3
      case: accepted A with an operator-claimed `a`, rejected B=[b,c]
      (contraction) failing post-teardown — the restored vector
      CONTAINS `a` still claimed (plain restoration), never
      re-created pending.
  16. **coherent-vector invariant + plain restoration (Codex r4 B2,
      r5 B3/B5):** apply A, apply B (expansion), force B's bring-up
      to fail post-teardown: IMMEDIATELY assert the reported vector
      EQUALS the pre-apply vector (identities + ifindex + claims),
      all non-operator slots unarmed+pending — NO retained B-only
      identity, NO replan (the live-sysfs race is structurally
      absent: a killed sysfs-queues dir during the failure changes
      NOTHING). Then: (i) a plain rebind binds A's plan and converges
      (self-heal to last-good); (ii) the failed-CONTRACTION shape
      (A=[a,b,c], B=[b,c]): `a` is present in the restored vector
      (carried from the pre-apply vector), pending, and the rebind
      binds it — no enabled=true without an `a` worker; (iii) the
      same-name/new-ifindex shape: the restored vector carries A's
      ifindex. The updated #4952/#5143 pins live here (restored
      vector, S4' marks, surviving-worker volatile refresh).
  17. **#5134 generation scoping + debt-discard interleaving (Go +
      Rust):** deferred apply → failed mandatory re-apply → debt
      recorded WITH generation; a plan-changing commit before the
      retry (newer generation) → the stale debt does NOT fire; the
      retry fires only while the generation matches, and converges
      via the same-plan non-deferred republish. (Go manager test +
      Rust server test for the republish's convergence.)
  18. **same-plan retry deficit (Codex r4 B4 second half):** force a
      spawn failure (retained records with `last_error`), then a
      same-plan apply: the pending-aware deficit predicate MUST fire
      the reconcile (planned==live==runnable with last_error set does
      NOT suppress it), and the reconcile converges the marks.
  19. **update_fabrics replan (Codex r5 B4):** `fabrics=[] → valid
      fab0` (the existing server/tests.rs:2911 shape) now produces
      fabric-parent bindings as `registered=true, armed=false,
      pending`, and the next armed reconcile converges them; an
      unchanged-set update replans nothing.
- The fail-fast invariant (Q6, resolved r1): assertions live ONLY in
  tests and only over well-defined planner/activation transitions.
- Protocol canaries: `userspace-dp/src/protocol/tests.rs` exact-schema
  snapshots updated to pin `activation_state` and
  `complete_deferred` deliberately.
- `make test-rust` (full cargo suite) clean; `cargo build`
  warning-free. Fleet cap honored:
  `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6749`.

**Go (option D + gates + retry + daemon ordering):**

- Manager unit test for the D warn, desired- and state-gated:
  (i) desired==true + `Registered && !Armed && state=="none"` →
  exactly one warn on the false→true edge, none on subsequent ticks,
  clears after re-arm; (ii) `state=="pending"` or `"operator"` → NO
  warn; (iii) desired==FALSE → NO warn; (iv) missing field (old
  helper) → reads as `"none"` (warn when desired).
- Manager unit test for the arm-sync defer gate: with
  `m.deferWorkers == true` and desired==true, the sync issues NO arm
  (disarm still passes); with the flag cleared, the arm proceeds.
- Manager unit test for the pending-activation retry (Codex r5 B7,
  v7.1-shaped): pending binding + desired==true + flag clear →
  exactly one plain rebind, then suppression until the backoff
  elapses; backoff sequence 5s→10s→20s→60s cap on repeated failure;
  attempt cap (~12) → retry stops + exactly one edge Warn; pending +
  flag SET → NO rebind; `m.pendingWorkerArm` set → NO rebind (debt
  owns); `completionInFlight` set → NO rebind; no pending → NO
  rebind; a pending-set change re-arms the retry after the cap.
- Manager unit test for `complete_deferred` provenance: the
  NotifyLinkCycle path sets it ONLY after a successful MAC program;
  the busy-watchdog path (maps_sync.go:1484) never sets it.
- Manager unit test for the edge-triggered sync-failure warn (Codex
  r5 M10 = SMR r5 N1 = AGY r5 minor-1): a persistent refusal logs
  ONCE on the false→true transition, not per tick, and once on
  recovery; a repeated-tick test pins the count.
- Daemon unit test for the defer-flag lifetime + MAC-success gating
  + MAC-retry debt (Codex r5 B6/B8, AGY r6 f2/f4): the flag is SET
  through apply → MAC programming and cleared only before the
  completion dispatch; a failed `programRethMAC` suppresses the
  completion dispatch (no re-apply, no tagged rebind), leaves the
  flag set (assert `m.deferWorkers == true` immediately after the
  failure, AGY r6 test note), and records the MAC-retry debt; a
  later tick re-attempts programming and, on success, clears the
  flag and dispatches the completion; the mandatory re-apply path
  (same-plan, generation-bumped republish) converges without the
  rebind flag.
- `maps_sync` gate test (AGY r1 f3): synthesized post-expansion
  status (new slots converged) through `probeBindingsReady`/
  `bindingForwardingLive` — ctrl admits, shim rows go READY.
- `make test-go` clean.

**Smoke (loss userspace cluster, lock-cell wrapped):** deploy; verify
iperf3 baseline to 172.16.80.200; commit an ADDITIONAL zoned VLAN
unit (e.g. a new `reth0.90` in the wan zone) while armed; assert
transit continues with no manual arm toggle and `show ... bindings`
reports the new slots armed with `activation-state=none`. ALSO
exercise the deferred path: a reth-membership-touching commit (the
RETH MAC flow) completes with workers bound and no manual action.
Re-apply CoS after the deploy per the cluster protocol
(`apply-cos-config.sh`).

**Docs (module contract, same work item):**
`userspace-dp/src/server/README.md` — the arm-model narrative gains
the tri-state lifecycle, the coherent-vector invariant, the
completion-provenance contract (explicitly: clearing the Go-side
defer flag does NOT activate anything — only a provenance-tagged
rebind or a non-deferred apply does, AGY r5 nit-2 / SMR r5 N2), the
operator-claim rule, the failure-restoration semantics, and the
pending-activation retry (incl. the rebind completion log gaining
the pending count, AGY r4 n2). **Release note / upgrade note (AGY r1
Q7 + Codex r1 m8 + AGY r3 f4):** required and PROMINENT on: (1) the
fix takes effect only after the HELPER restarts into the new binary
(process.go:18 reuses a pingable same-config helper) — `systemctl
restart xpf-userspace-dp` on upgrade; (2) the posture change —
deferred (RETH-MAC-pending) plan-changing commits now fail-close
transit until the completion, and a failed MAC program no longer
binds workers onto a stale MAC.
## 10. Out of scope (explicitly)

- **Go per-binding armed AUTO-convergence (option B)** — rejected
  (§5-B). The v7 pending-activation retry is NOT B: it schedules a
  reconcile of the current coherent plan and changes no armed bit
  itself; the tri-state makes its target unambiguous
  (planner-requested activations only, never operator claims).
- **#6702/#6681 planner queue-geometry rework** — they own
  binding-count consequences; this fix is compatible but does not
  implement any of their layout change.
- **`bindingForwardingLive` / `enabled` / `probeBindingsReady` gate
  semantics** — the gates are correct; the bug is the DEFAULT they
  were fed. No gate changes.
- **The pre-existing mid-defer-window early-BIND hazard** (Codex r3
  B6's other half): a registration toggle during the defer window
  runs an armed reconcile that BINDS workers before the RETH MAC
  cycle — present on master (the toggle's reconcile is defer-blind).
  v7 closes the early-CONVERGE side (the defer gate), the early-ARM
  side (the Go arm-sync gate + durable flag), and now schedules the
  CORRECT completion (pending-activation retry); the toggle's
  early-BIND itself is a separate pre-existing issue filed as a
  follow-up.
- **Re-keying the coordinator's slot-keyed live-worker lookup
  (`refresh_bindings`)** — the defer-window cosmetic alias is
  documented and neutralized by S3; re-keying it belongs with
  #6702's coordinator-adjacent planner rework. Filed as a follow-up.
- **Operator-claim registration degradation across a flap** (v7's
  accepted residual, Codex r5 B2's forcing): an operator-claimed slot
  whose interface flaps recovers as `registered=false, operator` —
  its no-forward intent survives exactly, but its registration is not
  planner-restored (the tri-state cannot distinguish
  disarmed-then-force-cleared from unregistered, and restoring both
  shapes identically would resurrect explicit unregistrations).
  Restoring the disarmed shape exactly would need a fourth state or
  an unregister timestamp — rejected as machinery disproportionate
  to a destructive-maintenance edge. Documented in the server README.
- **Persisted-state migration** — none needed (state file write-only;
  the fields are additive with serde defaults).
- **Operator-override persistence across global arm toggles** — the
  fan-out still clears claims (C3, registered slots); making
  diagnostic disarms durable is a separate product decision.
- **The retired v3/v4/v5/v6 machinery** — leg-scoped R1/R2; the full
  fan-out defer-completion; v4's identity-scoped S4 revert; v4's
  arm-at-replan S5; v5's bool marker; v5's replan-at-convergence plan
  gate; v6's failure-path replan-from-restored; v6's transient defer
  flag; v6's verb-identity completion. Recorded at bce10126c /
  f679a791a / 0c0b9b677 / 6969b6167.

## 11. Open questions for adversarial review

Resolved across rounds 1-6 (for the record): Q2, Q5, Q6, Q7,
applied-vs-requested init, full fan-out vs scoped, Q3 (uniform S3),
Q5-toggle, Q7-boot, the plan gate (deleted), the failure-path replan
(deleted), E2's operator arm (deleted — narrowed to pending), the
retry's fixed-5s shaping (backoff + cap + suppressions, AGY r6 f3 /
SMR r6 N1), the transient-MAC stranding (daemon-side MAC-retry
debt, AGY r6 f2), the latch signature/atomicity (explicit
`defer_completion_authorized` + consume-on-Ok-inside, AGY r6 f1 /
SMR r6 N3).

Remaining questions for round 7, each invitable to PLAN-KILL with a
concrete counterexample:

1. **Tri-state completeness, final form.** Exhibit a path to
   `Registered && !Armed` with `activation_state == none` that is
   NOT global-fan-out-created and NOT operator-created — an unowned
   producer that strands D-silent. (Enumeration to attack: every
   replan branch, S3/S4' gates, the C3 reorder+rollback, operator
   verbs, lifecycle init, rebind, both apply legs, the failure-path
   restoration, update_fabrics, #5134, helper restart, the #2794
   disarmed leg.)
2. **Retry interplay exhaustiveness.** With backoff, cap, and the
   two suppressions (debt, in-flight), exhibit a pending state that
   NO actor retries: (i) #5134 debt owns its generation's republish;
   (ii) the backoff retry owns everything else with flag clear;
   (iii) the MAC-retry debt owns failed-MAC defer windows;
   (iv) completion owns successful-MAC windows. Is there a
   generation/defer/pending combination that falls between (i)-(iv)?
3. **The consume-on-Ok ordering under a crash.** The latch is
   consumed inside the armed leg after `Ok`, before write-back /
   refresh / persist. A crash between the coordinator's successful
   bind and the persist leaves the state file defer=true with
   workers actually bound — helper restart replays from Go (full
   apply, non-deferred) and converges anyway. Any real hazard, or
   is the crash window provably harmless?
4. **MAC-retry debt scope.** The debt retries `programRethMAC` on
   daemon ticks. Should it be bounded (attempt cap + edge Warn, like
   the rebind retry) or is unbounded retry correct while the box is
   fail-closed and Warn-visible (mirroring the #5134 debt's
   unbounded republish)? Either way, name the invariant it must not
   violate (e.g. it must never clear the flag or dispatch completion
   on failure).
5. **Round-6 disposition table audit.** §1's table maps every r6
   finding to its v7.1 fold. Which row is claimed-but-wrong this
   time?
6. **Cumulative blast-radius check.** Six rounds in, the diff now
   spans the helper planner + status/convergence paths, two additive
   wire fields, the Go manager (D, arm gate, retry, debt scoping,
   edge-triggered warn), and the daemon apply ordering (defer-flag
   lifetime, MAC-success gating, MAC-retry debt). Does any reviewer
   assess the ACCUMULATED surface as exceeding the bug's High
   severity — i.e. should some pieces (the daemon MAC debt? the
   pending-activation retry?) be split into follow-up PRs to keep
   this one reviewable, and if so which?
