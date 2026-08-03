# Claude SMR plan review — round 1 — #6749 armed-state plan v1 (8c76670d6)

**Reviewer:** Claude SMR (hostile pass; the plan author is also Claude — this
review must attack, not validate. First-pass soft-pass is a documented yellow
flag in this project: #1623, #1619, #1622.)

**Verdict: DEMAND-REVISION** — the mechanism chain and the option-C core
survive hostile verification, but four arguments in the plan are overstated
or left open when source evidence already settles them. A plan that asks
reviewers to trust open questions it could have closed itself is not ready.

---

## Findings

### SMR-1 (MAJOR) — The option-B rejection rationale is overstated; the honest argument is different

Plan §5-B claims a "fatal tension": the Go manager *cannot* distinguish a
planner-default unarmed slot from an operator diagnostic disarm, so any
converger fights the operator verbs. That is not true as stated.

The manager is the ONLY client of the helper control socket — every
`set_binding_state`/`set_queue_state` request transits
`Manager.SetBindingState`/`SetQueueState`
(`pkg/dataplane/userspace/manager_status.go:132-180`, reached via
`LegacyDataPlaneAdapter` → `pkg/grpcapi/server_diag_system_action.go:430-455`
and `pkg/cli/cli_request_chassis.go:167-176`). The manager therefore CAN
track operator-disarmed slots in memory (a `map[uint32]bool` cleared on
global re-arm, plan change, or daemon restart) and converge only slots NOT
in that set. No protocol change, no provenance bit. "Cannot distinguish" is
wrong; "chooses not to pay the state" is the argument.

The reasons B still loses as PRIMARY are different and the plan must state
them honestly:

1. **B alone leaves a ~1 status-poll-tick total transit outage per
   expansion commit** (apply lands → new slots unarmed → next poll tick
   converges). A/C close the window to zero at the source. For a bug whose
   entire cost is availability, the fix that shrinks the outage to zero
   beats the fix that bounds it at ~1s.
2. **B alone keeps the wrong-identity carry defect** (numeric-slot state
   inheritance across reshuffles) — it converges the *armed bit* but leaves
   `registered`/`last_error`/counter provenance wrong.
3. Manager-side override tracking is new state with its own lifecycle bugs
   (staleness across daemon restart, slot renumbering between poll and
   operator request — the slot the operator disarmed is read from a possibly
   stale `lastStatus`).

Folding instruction: rewrite §5-B's verdict around these three points;
delete the "cannot distinguish" claim.

### SMR-2 (MAJOR) — The issue's third fix-direction leg deserves a cheap, safe answer, not just a rejection

The issue text asks for three legs: (i) init new slots from global arm
state, (ii) identity-stable carry, (iii) "make Go's convergence check
include each registered binding (or the helper's Enabled state)", (iv) the
regression test. The plan rejects (iii) outright. A hostile reader notes
there is a *zero-conflict* form of (iii) the plan didn't consider:

**Observability-only leg:** in `syncDesiredForwardingStateLocked`, when the
global bit equals desired but any `Registered && Ifindex>0 && !Armed`
binding exists, emit a one-per-transition `slog.Warn` (rate-limited /
edge-triggered on the drift predicate going true, not per-tick — the
project's logging rules forbid per-tick Info). This auto-reverts NOTHING,
so it cannot fight operator overrides — an operator disarm logging a warn
is *correct* observability. It satisfies "Go's convergence check includes
each registered binding" as a detection surface, gives on-call a log line
naming the exact stranded slot if a FUTURE drift producer ever appears, and
costs ~15 lines. Whether to include it is a reviewer decision, but the plan
must present it rather than pretend (iii) only exists in auto-converge
form.

### SMR-3 (MINOR) — Open questions Q2 and Q5 are answerable from source NOW; leaving them open is lazy

- **Q2 (residual drift producers):** enumerable exhaustively. Every writer
  of `binding.armed` in the tree: planner default (planning.rs:518-522),
  `set_bindings_forwarding_armed` fan-out (status.rs:418-423),
  `set_binding_state` (binding.rs:29), `set_queue_state` (queue.rs:33),
  lifecycle init (all-false). State file is write-only
  (helpers/persistence.rs — no restore path exists; lifecycle builds an
  empty `ProcessStatus`). Helper restart ⇒ Go reconnect ⇒ full apply (fresh
  plan, global false) ⇒ `syncDesiredForwardingStateLocked` sees global
  false ≠ desired true ⇒ `set_forwarding_state(true)` fan-out arms all.
  `update_ha_state` never touches bindings. Same-plan legs never replan.
  **Answer: with C in place, no non-operator producer of armed drift
  remains.** Fold this enumeration into §5-B as the affirmative rejection
  argument (it is strictly stronger than "cannot distinguish").
- **Q5 (VLAN-alias consumer):** `buildUserspaceIngressBindingAliases`
  (maps_sync.go:745) consumes `binding.Ifindex`/`binding.QueueID` rows,
  which the layout assigns positionally (`planning.rs:511-515`) independent
  of state provenance. Identity-carry changes provenance only. **Answer:
  no interaction.** Fold into §7.

### SMR-4 (MINOR) — The orphan-VLAN→parent promotion case must be documented as deliberate physical-identity semantics

The one case where C's identity key does something non-obvious: plan N has
an orphan VLAN child (`reth0.80`, parent not a candidate) whose bindings
are keyed on the PARENT netdev (`ge-0-0-2`, per the re-key at
planning.rs:417-436); plan N+1 zones the parent itself, promoting it to a
candidate and dropping the child (planning.rs:411-416). The parent's new
bindings identity-match the child's old ones and inherit their armed state.
This is CORRECT — the physical XSK (same netdev, same queue) is identical;
only the config-view label changed — but a hostile reviewer will poke it as
"identity changed without the key changing". The plan must document that
the identity is PHYSICAL (netdev, queue) — exactly the granularity at which
an XSK exists — and that this promotion case is the intended behavior, with
a test pinning it (fold into test-plan item 5).

## What survived hostile verification (no finding)

- The failure chain (§4 items 1–6) re-verified link by link against source:
  replan default-false armed (planning.rs:504-522), full-apply replan
  (snapshot.rs:344-350), enabled gate (status.rs:274-281), Go ctrl gate
  (maps_sync.go:391-487), global-bit-only reconcile (manager_ha.go:605-607),
  coordinator not consuming `armed` (reconcile/bringup.rs:274). Complete;
  no missed producer.
- Gate safety: armed-from-global cannot steer traffic to an unbound XSK
  because `bindingForwardingLive` (maps_sync.go:97-99) still requires
  `Ready`; `enabled` keeps the #869 no-ready property; the #5171 defer
  path replans under `forwarding_armed=false` so new slots inherit false;
  `disarmBeforeUnsupportedPublishLocked` (manager_ha.go:568-599) runs
  before publish so a capabilities-flip commit replans under the
  already-false global. Q1's race collapses under control-socket
  serialization (single ServerState lock; publish ordering manager-side).
- Slot-positional consumers unaffected: `set_binding_state` addresses
  slots that remain positionally assigned; shim rows key on
  `ifindex*stride+queue` (maps_sync.go:721), never on slot.
- Blast-radius quantification (§3 trigger inventory) checks out against
  the plan-key inputs (planning.rs:92-174) — including the #3007
  out-of-band `ethtool -L` landmine.

## Required folds for v2

1. Rewrite §5-B per SMR-1 (honest rejection: outage-window + wrong-identity
   residue + state cost; drop "cannot distinguish").
2. Add the observability-only Go leg per SMR-2 as an explicit optional
   sub-option with the edge-triggered-logging constraint.
3. Close Q2 and Q5 in the plan body per SMR-3; renumber remaining open
   questions.
4. Document physical-identity semantics + the orphan-promotion case per
   SMR-4, and extend test-plan item 5 to pin it.

**Verdict: DEMAND-REVISION** — re-review after the four folds. None of the
findings threatens the option-C core; all four are argument-quality defects
that would get this plan killed at /engineer review if left standing.
