# Claude SMR hostile plan-review — #6371 r6

Reviewing `docs/research/6371-rgactive-fence/plan.md` @ r6 (commit 7d1c90c63),
base origin/master @ 3ecdc80568a3.

## My r5 PLAN-READY was premature — Codex r5 caught a real race I missed
I signed off r5 PLAN-READY; Codex r5's linearization BLOCKER is a genuine
concurrent-writer race I did not surface: `UpdateRGActive` serializes on the
manager mutex, which orders lock acquisition, not ownership causality. With three
activation-capable paths and five clear categories on different goroutines, a
stale clear-retry can land after a newer legitimate activation (stranding the
owner inactive), or an old activation after a newer peer-fence (resurrecting the
one-shot). `ApplyIfCurrent` validates only after the physical write and
`rgStateMachine.epoch` bumps on every unchanged reconcile, so neither linearizes
the writers. The finding is correct; I should have caught it. r6 folds it.

## Verification of the r6 folds
- **Linearization invariant (§5.2):** the stated contract — one daemon-owned
  per-RG monotonic ownership generation gating **every** true/false writer, a
  stale-gen write **dropped before the physical mutation**, a clear dominating
  until a strictly-newer still-current transition supersedes, convergence/debt
  clearing only if the gen is still current across a fresh readback — does defeat
  both schedules Codex named: the stale clear (older gen) is dropped before it can
  overwrite the newer activation; the old activation (older gen) is dropped before
  it can overwrite the newer fence. Stating it as an invariant (not pseudocode) is
  the right altitude for a research plan. Sound.
- **Residual honesty (§5.4):** now correctly says Path D closes restart +
  peer-fence but **detects-not-fixes** persistent map-write failure (verified:
  `UpdateRGActive` returns on the map-write error before mutating manager/helper
  state, `manager_ha.go:638`), and makes the deferral carry the disclosure +
  filed follow-up + named signer. The contradiction is resolved.
- **Quarantine fail-closed (§5.1):** partial pin-write failure now aborts
  arming / gates all consumers — correct; a surviving nonzero key would otherwise
  re-arm.
- **Wording:** shutdown recovered-by-next-boot (not runtime-convergent); "≥30 s
  floor" not a strict ≤ bound; availability-cost-largely-moot folded. All correct.

## Residual note (not a blocker)
**F-r6-1 (MINOR).** The generation gate must also cover the **boot activation**
path: after §5.1 quarantine (gen0 = all-clear), the first legitimate election
activation is gen1; ensure the quarantine's gen0 does not itself get superseded by
a stale in-flight pre-restart write (there are none across a process restart, but
state that quarantine establishes the initial generation so no pre-quarantine
write can be "current"). This is a one-line clarification for /engineer, not a
design gap.

## Verdict
r6 folds the last substantive item (the linearization invariant) and corrects the
residual-honesty contradiction; every Codex r1-r5 BLOCKER and my own r-series
findings are now incorporated and firsthand-verified. Path D is a complete,
proportionate research deliverable: it establishes the real defect (unbounded
stale-active `rg_active` reactivation via restart + peer-fence one-shot), a fix
that closes both reachable modes under an explicit generation-linearized
fail-closed contract, and an honest, tracked deferral of the one detected-but-
unfixed residual. PLAN-KILL of Option D / Path A′ / the decouple stands. The
remaining specifics (gate wiring, T, snapshot API) are legitimate /engineer scope.

VERDICT: PLAN-READY
