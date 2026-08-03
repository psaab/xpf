# Claude SMR plan review — round 4 — #6749 armed-state plan v5 (0c0b9b677)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies — three prior rounds each found real holes, so this pass attacks
the v5 refinements specifically: the never-arm rule, the was-armed
gates, S4', the tri-gated convergence, and the C3 reorder).

**Verdict: PLAN-READY-WITH-NITS** — every attack I mounted against v5
was absorbed by a gate already in the model (trace below). Three nits
worth folding without a re-review: two documentation precisions and one
cosmetic defect. If Codex/AGY r4 surface a real hole, this verdict is
void and we iterate.

---

## Attack trace (what I tried, and why it fails to break v5)

1. **Unmarked-producer hunt (plan Q1).** Re-enumerated every writer of
   `armed` under v5: convergence (tri-gated), operator verbs (claim),
   global fan-out (post-Ok, C3-scoped), planner (never arms). Every
   path to `registered && !armed`: S1/S2/S5 marks (planner-created),
   S3/S4' marks (was-armed gated — operator-owned excluded), operator
   verbs (intended), the C3-disarm fan-out (global intent, marks on
   unregistered slots preserved for E2), lifecycle init (no bindings),
   rebind (never sets armed), #2794 disarmed leg (no binding
   production). No unmarked producer found. The mid-window toggle
   produces pending+BOUND+!armed (early-bind pre-existing hazard,
   converge-blocked by the defer gate) — fail-closed, converged at
   completion, coherent.
2. **Plan-gate drift semantics (my own probe).** The convergence's
   membership set comes from a pure `replan_queues` on the stored
   snapshot, which resolves `rx_queues==0` via LIVE sysfs (#3007). If
   channels changed out-of-band since the apply, the gate can
   false-EXCLUDE a just-bound pending slot (its queue fell out of the
   current extent): it stays pending → `enabled=false` (fail-closed)
   → the next apply replans (the same sysfs value is in the plan key)
   and the stale identity drops with its mark. Bounded, fail-closed,
   self-consistent — but the plan should SAY the gate's set is
   resolved at convergence time and why false-exclusion is the safe
   direction (nit 1). False-INCLUSION cannot arm an unbound slot:
   converged slots are vector members, and `bound == planned` at the
   Ok boundary (bringup.rs:188) covers every registered+ifindex>0
   vector slot (bringup.rs:273) — plan Q2 answered affirmatively.
3. **C3 reorder (Codex r3 MAJOR 7 fold).** `set_forwarding_state(true)`:
   global=true is set first (forwarding.rs:32), so the reconcile takes
   the armed leg exactly as on master; on Ok the fan-out arms +
   clears (registered); on Err no arm/no clear → `enabled=false` →
   pending marks survive → the next successful armed reconcile
   self-heals (master's armed-mark-free stranding needed a manual
   toggle; v5 exceeds it). Unmarked slots on an established-box re-arm
   failure: D-visible (desired==true, `!armed && !pending`) — truthful.
   `wait_for_binding_settle` (:53) polls ready/last_error, not armed —
   reorder-safe.
4. **S4' vs #4952 retained-vector pins.** S4' marks the retained
   B-vector all-pending (non-operator slots) after a post-teardown
   failure: `enabled=false` (fail-closed, master-parity-or-better),
   the per-binding records remain for reporting (the #4952 intent —
   real post-teardown state, now uniformly unarmed instead of a
   mix that could claim enabled=true), and the plan gate stops any
   auto-rebind from arming B-only identities against restored A
   (Codex r3 BLOCKER 2). The A-restored + B-pending state reports
   coherently: A's forwarding, B's layout reported as pending/unarmed,
   volatile state refreshed from the surviving partial workers.
5. **Defer gate authorization.** Rebind-authorized convergence on a
   spurious flap mid-window: workers genuinely bind (the flap tore
   down first — no double-bind), convergence arms in-plan pending
   slots truthfully; the pending MAC cycle follows with its own
   rebind (re-binds on the new MAC). The arm verb during the window
   takes the armed leg (as master) and its post-Ok fan-out authorizes
   everything anyway — the defer gate constrains only the implicit
   convergence, never an explicit operator/daemon verb. Coherent.
6. **S4' shapes.** Expansion / E2-only / contraction / workers-ring
   plan changes / global-arm failure: with S5's never-arm, NOTHING is
   armed before the Ok; S4' then marks every non-operator slot — so
   every failed shape reports `enabled=false` and self-heals on the
   next successful armed reconcile. The residual carried-armed lie
   (master's contraction+spawn-failure reports enabled=true against
   dead workers) is FIXED by S4' rather than matched — better than
   master, and the difference is the point of the fix.
7. **AGY r3 folds.** f1 (never-arm) verified — S4's revert machinery
   is gone and no armed-before-bind state exists at replan; f2
   (S2 was-armed gate) verified against the flap matrix — armed slots
   self-heal, operator-disarmed slots degrade to unregistered with
   intent preserved (documented §10); f3/f4 folded in §9.

## Nits (fold without a re-review)

- **N1 (documentation):** §5-C's plan gate should state that the
  membership set is resolved at CONVERGENCE time (live sysfs for
  `rx_queues==0` snapshots), and that sysfs drift can only
  false-EXCLUDE (fail-closed, bounded until the next apply's replan)
  — attack 2's reasoning belongs in the doc.
- **N2 (implementation pin):** the C2 claim-before-reconcile ordering
  should be a code-level requirement stated in §5-C (binding.rs /
  queue.rs set the mark-clearing fields in the SAME mutation that
  applies the operator's registered/armed values, BEFORE the
  `registration_changed` reconcile runs).
- **N3 (cosmetic):** §1's "Round-1 detail log" bullet renders as a
  sibling of its own sub-bullets (markdown structure).

## Required for convergence

Nothing structural. If Codex + AGY r4 converge (PLAN-READY or
PLAN-READY-WITH-NITS), fold N1–N3 and ship to `/engineer`.

**Verdict: PLAN-READY-WITH-NITS.**
