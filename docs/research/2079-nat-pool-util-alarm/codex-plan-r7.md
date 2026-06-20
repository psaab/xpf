# Codex hostile plan review r7 — #2079

Agent: aa98925183049577a (slow ~5 min, returned a full verdict). A fresh-session
r7-retry (aa0db8139112cf6e0) was also dispatched while this one was slow.

## Verdict: PLAN-REVISE (1 MAJOR + 1 MINOR; 4 confirms)

### Confirmed (r7 folds)
3. Prune is OUTSIDE the numeric gate (config-derived clears run when
   `numericEval` false).
4. `updatePct` in a mutually-exclusive raise / else-if clear / else-if raised
   chain, only for an already-raised pool.
5. §9 eligibility wording is rule-referenced.
6. §6.1 has defensive `rs==nil`/`rule==nil` skips matching `nat.go:16-22`.

### NEW findings (folded into r8)
1. **MAJOR — status-vs-applied gen gate insufficient (apply-window skew).**
   `Commit()` promotes `s.compiled` (`store.go:1199`) BEFORE the dataplane apply
   (`commitAndApply` → `applyConfigLocked(compiled)`, `daemon_apply.go:152,162`;
   dp apply not reached until `daemon_apply.go:689-693`). So a monitor tick in
   that window sees fresh `store.ActiveConfig()` but an OLD
   `lastSnapshot.Generation`; r7's gate `status.LastSnapshotGeneration >=
   appliedGen` passes (old>=old) and still evaluates NEW config capacity against
   OLD counters. FIX: one coherent source of config+generation, or a gate proving
   the manager reached the active config being evaluated. r8: `dp.CoherentNATView()`
   returns `Config = m.lastSnapshot.Config` + deduped `Pools` for the SAME
   generation + `HelperCaughtUp`; monitor never reads `store.ActiveConfig()`.
2. **MINOR — nil-dp / status-unavailable undefined.** Pseudocode called
   `dp.LastStatus()` directly; daemon paths guard `d.dp != nil`
   (`daemon_apply.go:691`, `daemon_forwarding_status.go:77`). r8: `view.Available`
   false → HOLD all (return, no clear).

Both folded into r8. The MAJOR is a genuine concurrency/ordering subtlety the
prior 6 rounds (and AGY) missed — verified against the commit/apply ordering in
source.
