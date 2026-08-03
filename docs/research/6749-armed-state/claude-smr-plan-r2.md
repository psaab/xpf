# Claude SMR plan review — round 2 — #6749 armed-state plan v3 (bce10126c)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies — this pass must find what v3 missed, not ratify it).

**Verdict: DEMAND-REVISION** — one MAJOR placement hole in R2 found by
walking the leg-selection matrix; v3's own open Q2 asked the question and
the plan text does not answer it. Everything else in v3 survives.

---

## SMR2-1 (MAJOR) — R2's same-plan-only placement misses defer-completion via the FULL-apply leg

R2 (v3 §5-C) lives in the same-plan leg of `apply`
(snapshot.rs:175-238). But the leg is chosen by
`snapshot_binding_plan_key(prev) == snapshot_binding_plan_key(next)`
(snapshot.rs:163-174), and the plan key hashes the **sysfs-resolved**
effective rx_queues for any snapshot carrying `rx_queues == 0`
(#3007, planning.rs:565-581) — plus every candidate field. A
defer-completion can therefore take the FULL-apply leg, where NO
fan-out exists:

1. **Out-of-band channel change during the defer window.** Deferred
   apply P1 lands (new slot X registered, armed=false per R1; stored
   snapshot defer=true). Before the completion re-apply, an operator or
   NIC auto-negotiation event changes channel counts
   (`ethtool -L <if> combined N`). The completion apply
   (P1-content, defer=false) now hashes a DIFFERENT plan key →
   `same_plan == false` → full-apply leg → replan with R3 carry: X is
   now a CARRIED identity (registered=true, armed=false) → R1 does not
   re-initialize it (not new, not `never_registered`) → reconcile binds
   X → X stays `armed=false` → `enabled=false` → ctrl closed →
   **stranded exactly like the master bug**, through a door R2 does not
   cover.
2. **Second commit during the defer window.** Deferred apply P1 → a
   second config commit lands while the RETH MAC is still pending →
   that apply is ALSO deferred (manager_compile.go:330 stamps
   `snap.DeferWorkers = m.deferWorkers`) and stores P2 (defer=true) →
   completion re-apply publishes P2-with-defer=false → same plan →
   same-plan leg → R2 fires. Covered. BUT if the second commit lands
   AFTER the MAC programmed (link cycle done, `m.deferWorkers` cleared)
   and BEFORE the completion re-apply consumed the transition — or the
   completion re-apply itself publishes the CURRENT (commit-2) config
   against stored P1 — the completion takes the full-apply leg (plan
   keys differ) → same stranding as (1).

The fix is one condition move, not a redesign: the R2 transition
predicate is **previous-stored-defer=true AND incoming defer=false AND
`should_run_afxdp(status)`**, evaluated after a SUCCESSFUL reconcile —
in BOTH legs, not just the same-plan leg. `previous_defer_workers` is
already computed before the leg split (snapshot.rs:159-162). In the
full-apply leg the fan-out is redundant with R1 for genuinely-new slots
but is exactly what converges slots that were R1-deferred in a prior
apply and are now carried. The `should_run_afxdp` gate matters: a
boot-time defer completing while globally DISARMED must not arm
bindings (Go's later `set_forwarding_state(true)` fan-out owns that
transition) — the plan's v3 text does not state this gate at all.

Required fold: R2's condition and both-leg placement, including the
`should_run_afxdp` gate; a server test for the full-leg completion
(deferred apply → plan-key-invalidating event → completion re-apply →
all registered bindings armed, enabled true).

## SMR2-2 (MINOR) — v3 open Q1/Q3 left as questions when the plan should commit

- Q1 (full fan-out vs scoped): the plan's own rationale (defer window
  is seconds, fail-closed throughout, operator disarm has no traffic
  effect) is COMPLETE — commit to the full fan-out and drop the scoped
  variant from §5-C into §10-only (it's already recorded there). A plan
  that re-litigates a decided point reads as uncommitted.
- Q3 (`had_existing` heuristic): with R3's explicit `never_registered`,
  the five-field `had_existing` heuristic (planning.rs:505-510) is
  redundant for its only remaining use (the init gate). Redefine
  "carried" as "identity present in the old map" and delete the
  heuristic — one less state-predicate to drift. The plan should state
  this instead of asking.

## What survived hostile verification (no finding)

- R1's defer gate is on the incoming snapshot's flag, which is stamped
  from `m.deferWorkers` at publish time (manager_compile.go:330) — the
  helper cannot see a defer the manager didn't stamp, and the manager
  stamps before publish (ordering verified). No non-deferred apply
  skips binding a registered slot: bringup filters ONLY
  `!registered || ifindex<=0` (bringup.rs:274), and the reconcile is
  all-or-nothing on error paths (fail-closed #4952/#5143 legs).
- R2-after-success cannot fire on failed/partial reconciles in the
  same-plan leg (error legs return before any fan-out — snapshot.rs:196-238
  structure verified); SMR2-1's fold must preserve that in the full leg
  (post-`reconcile_status_bindings` Ok only).
- R3's field set: `bound`/`xsk_registered`/`ready` are rebuilt by
  reset_binding_counters + refresh_bindings on the reconcile path;
  counters/`last_error` same; the defer-window slot-keyed alias is
  cosmetic under R1 (ctrl=0 overrides rows — maps_sync.go:391-404).
- E2 carve-out: the third `registered=false` producer asked about in
  v3 Q5 does not exist — `zero_unbound_slot` clears volatile/socket
  fields only, not `registered` (refresh_bindings.rs, verified).
- Codex r1 dispositions: findings 1-8 each have a v3 fold that matches
  the evidence (verified individually; SMR2-1 is the residual of
  BLOCKER 1's deferred model, not a contradiction of it).

## Required folds for v4

1. R2 moved to a both-leg transition predicate with the
   `should_run_afxdp` gate (SMR2-1), plus the full-leg-completion
   server test.
2. Commit Q1/Q3 decisions (SMR2-2).

**Verdict: DEMAND-REVISION** — one structural hole, two commitment
cleanups. The three-rule model itself stands.
