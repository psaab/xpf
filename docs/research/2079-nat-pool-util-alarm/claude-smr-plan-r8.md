# Claude SMR — Hostile Plan Review r8 — #2079

Reviewing plan.md r8 after folding Codex r7's PLAN-REVISE (#1 coherent-source,
#2 nil-dp).

## Verdict: PLAN-READY

Codex r7 #1 was a genuinely deep concurrency/ordering finding that I, AGY, and six
prior rounds missed. I independently verified the commit/apply ordering and agree
the r8 fix is correct and is the RIGHT fix (not a band-aid).

- **#1 (apply-window skew / coherent source):** Verified `Commit()` sets
  `s.compiled = compiled` (`store.go:1199`) and `commitAndApply` calls
  `applyConfigLocked(compiled)` afterward (`daemon_apply.go:162`), with the actual
  dataplane apply deep inside (`daemon_apply.go:689`). So between config-promote
  and dp-apply, `store.ActiveConfig()` is the NEW generation while the helper
  counters (and `m.lastSnapshot.Generation`) are still OLD. r7's
  `status >= applied` gate compared two OLD values (passes) yet the config read
  was NEW — the exact bug. r8's `dp.CoherentNATView()` sources `Config` from
  `m.lastSnapshot.Config` (the config the manager actually built the snapshot
  from) and `Pools` from the status for that same generation, so config and
  counters are the same generation BY CONSTRUCTION — the skew is unrepresentable.
  `numericEval := view.HelperCaughtUp` (status gen == published gen) further
  guards the helper-lag case. This is the correct invariant. RESOLVED.
- **#2 (nil-dp):** `view.Available==false` → HOLD-all (return, no clear). Correct —
  "no data" must not be read as "clear". RESOLVED.

## Independent re-trace of the r8 loop
- Single input: `dp.CoherentNATView()` — no `store.ActiveConfig()` mix. ✓
- `Available` false → HOLD-all return. ✓
- `cfg==nil` / disabled → clear-all + empty + return. ✓
- Dedup: done in the view (`Pools` is per-pool). ✓
- Eligibility: rule-referenced from `view.Config` (same gen). ✓
- `numericEval := view.HelperCaughtUp`; per-pool numeric HELD when lagging;
  prune unconditional. ✓
- States (a) prune-clear / (b) absent-HOLD / (c) bad-sample-HOLD; raise `>=`,
  clear strict `<`, else-if-raised updatePct; lock discipline; both render sites;
  commit validation; uint cast. All intact. ✓

## New issues from r8 — none
Collapsing to a single coherent view actually SIMPLIFIES the contract and removes
a whole class of config-vs-counter skew bugs. The view is a pure lock-guarded
read of `m.lastSnapshot` + the corresponding status — cheap, no socket I/O.

## Note on convergence
Codex's finding cadence: r2-r5 one MAJOR each, r6 no-MAJOR (PLAN-READY-WITH-NITS),
r7 one MAJOR (the apply-window skew — only visible once you trace commit ordering,
a different layer than the r2-r6 monitor-loop findings). r8 closes the
config/counter coherency layer. AGY has been PLAN-READY since r2. This is a
well-stress-tested plan; r8 should converge.

PLAN-READY.
