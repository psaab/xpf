# Claude SMR plan review — round 3 — #6749 armed-state plan v4 (f679a791a)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies). Attack surface: the marker lifecycle itself — the v4 model is
the author's own convergence of the three round-2 verdicts, so this pass
must try to break the lifecycle, not ratify it.

**Verdict: DEMAND-REVISION** — one MINOR spec hole in S4's revert set
(E2-re-registered slots escape the failure revert and re-open the
enabled-lie through a side door), plus three open questions the plan can
and should answer outright (Q3, Q5, Q7). No BLOCKER/MAJOR survived.

---

## SMR3-1 (MINOR) — S4's revert set misses E2-re-registered slots; the enabled-lie leaks through the E2 side door

v4 S4 reverts "slots INITIALIZED IN THIS APPLY (identities absent from
`existing_bindings` by `(interface, queue_id)`)". An E2-re-registered
slot (S5: carried record `!registered && pending && new ifindex>0` →
`registered=true, armed=forwarding_armed`) has its identity PRESENT in
`existing_bindings` (as the unregistered record), so it is NOT in the
revert set. Sequence: apply whose only plan delta is an E2
re-registration; S5 arms it; `reconcile_status_bindings` fails with
`WorkerSpawn`/`WorkerBindIncomplete`; S4 reverts nothing; every slot is
`registered && armed` → `enabled=true` (status.rs:274-281) — the exact
armed-but-unbound lie Codex r2 BLOCKER 2 / AGY r2 f2 killed for the
main case. Master's posture on the same path is `enabled=false` (the E2
slot never re-registers — the original bug — forcing the gate closed),
so the un-widened S4 is also a master regression on this narrow path.

Fold: the revert set is {identities absent from `existing_bindings`} ∪
{identities whose `existing_bindings` record was `!registered`}
(i.e. everything S5 initialized OR re-registered in this apply). One
predicate, two clauses; the test in §9 item 14 gains the E2-only
variant.

## SMR3-2 (commitment) — Q3 is answerable: uniform S3 is behaviorally identical to per-identity gating at the traffic level

The plan asks whether deferred-expansion needs per-identity gating
(carry old armed, gate only new/shifted) instead of S3's mark-all. It
does not matter for traffic and the plan should say so: in a deferred
EXPANSION the new slots are unarmed under either variant, so
`enabled=false` either way (the gate is all-or-nothing,
status.rs:274-281) and ctrl is closed for the whole vector in both
variants — identical wire posture to master (whose deferred-expansion
window is also fully fail-closed via the unarmed new slots). The only
shape where the variants differ is the CONTRACTION/reshuffle (no new
unarmed identity to force the gate), which is exactly Codex r2
BLOCKER 5 — and there per-identity gating is the UNSAFE one (stale
shifted rows stay READY under an open ctrl). Uniform mark-all is
simpler, strictly fail-closed where master was ambiguous, and
identical to master everywhere master was already closed. Keep S3
uniform; close Q3.

## SMR3-3 (commitment) — Q5 is acceptable: a registration-toggle reconcile is a genuine worker-producing event

An operator's `set_binding_state` registration toggle runs
`reconcile_status_bindings` (binding.rs:34-53) and therefore converges
OTHER pending slots as a side effect. This is not a leak: the toggle's
reconcile genuinely tears down and re-binds the worker set, so the
convergence precondition ("workers are bound for the current layout")
holds. The operator's own claimed slots are protected by C2 in the
same handler (their marks are cleared before/around the toggle —
ordering must be: claim first, then reconcile; the plan should state
the ordering explicitly). Close Q5 as ACCEPTABLE with the ordering
note.

## SMR3-4 (commitment) — Q7 (boot/disarmed convergence) is already closed by the lifecycle

Any path that binds workers while `should_run_afxdp` is false: none
exists that SHOULD converge — a globally disarmed helper's pending
marks are deliberately not converged (the disarmed leg,
status.rs:376-399, skips convergence by design), and the later
`set_forwarding_state(true)` fan-out arms everything and clears all
marks (C3). A permanently-disarmed (unsupported) config leaves marks
set forever on a dataplane that never forwards — harmless, truthful,
and cleared the moment a global arm ever lands. Close Q7.

## What survived hostile verification (no finding)

- **Unmarked-producer hunt (Q1):** every path to `registered &&
  !armed` enumerated — replan (S1/S2/S5 mark), S3 gate (marks), S4
  revert (marks), operator verbs (claim — intended), global fan-outs
  (C3), lifecycle init (all-false, no bindings), rebind (never sets
  armed), same-plan legs (no replan → no new state), #5134 republish
  (same-plan/full leg covered), #2794 disarmed-reconcile
  (`zero_unbound_slot` clears volatile/socket fields, NOT `registered`
  or `armed` — verified refresh_bindings.rs). No unmarked producer
  found.
- **Marker leaks (Q2):** marks on dropped identities vanish with the
  record; a permanently-failing reconcile leaves `enabled=false` with
  pending marks — truthful (the dataplane is down for a surfaced
  reason), and each retry re-attempts convergence. No misbehavior.
- **ctrl=0 overrides stale READY rows (Q4):** `status.Enabled==false`
  skips the entire enable block (maps_sync.go:391-487); the shim's
  master gate holds transit fail-closed regardless of row contents
  (maps_sync.go:399-404 comments), and the rgTransitionInFlight branch
  (:391-396) only ever FORCES ctrl off, never on. S4's
  carried-slots-keep-armed scope is therefore safe; revert-set
  widening is needed only for the E2 side door (SMR3-1).
- **Convergence placement:** inside `reconcile_status_bindings`' armed
  leg, after `Ok`, on the written-back vector — one locus, Err paths
  return first (snapshot.rs:196 structure), `bound == planned` is
  required for the Ok (bringup.rs:188), so convergence never fires on
  a partial bind.
- **Deferred same-plan apply (pure MAC-pending):** marks nothing;
  workers keep forwarding the unchanged plan; completion rebind
  converges an empty pending set — no-op. Correct.

## Required folds for v5

1. Widen S4's revert set to include E2-re-registered slots (SMR3-1) +
  the §9 item 14 E2-only variant.
2. Close Q3 (uniform S3 identical at traffic level; contraction is the
  discriminating shape), Q5 (acceptable; claim-before-reconcile
  ordering stated), Q7 (closed by C3 + disarmed-leg design).

**Verdict: DEMAND-REVISION** — one spec hole (minor, one-predicate
fold) and three commitments. The marker lifecycle itself stands.
