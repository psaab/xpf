# Claude SMR hostile plan-review — #1782 r2 (`ef1496ef3`)

**Verdict: PLAN-READY**

v2 resolves all my r1 findings and correctly folds Codex's MAJOR findings + AGY's
verified ruling. Re-checked hostilely:

- **My r1 F1/F2/F4 (ranking, first-packet-buffered, 2-PR sequencing):** all
  addressed — §5 is now one causal chain (H2 root / H3 why-slow / H1+H4
  amplifiers), the first-packet-buffered + 800ms-pending × 3s-neg trace is in §4
  and §5/H4, and §7 is an explicit PR-1→capture→PR-2 sequence.
- **Codex H5 (one-representative pending → sibling SYN drops):** correctly
  elevated to a first-class "why multi-flow" mechanism with its own falsifiable
  signature and a dedicated pending-duplicate-drop counter in PR-1. The
  conflict with #1771 §2.2 (an H5-direct fix re-opens frame-pinning) is
  captured in §8/§9 — good, this is the subtle trap.
- **Codex per-binding correction:** H1 is now described per-binding/per-worker,
  not a single global entry; the "common recovery via shared dynamic_neighbors"
  nuance is preserved.
- **AGY snapshot-regen ruled out:** dropped from the candidate set with the
  atomic `apply_manager_neighbors` citation. Correct.
- **Option B safety:** §8 now requires `insert_confirmed_if_unchanged`; the
  residual semantic question (is a kernel DELAY lladdr safe to confirm?) is
  correctly parked as open-question Q7 for `/engineer`, not pre-decided — right
  for a capture-first plan.

Remaining items are all correctly deferred, not plan defects:
- Q7 (DELAY-lladdr-reuse safety) is a real design question but belongs to PR-2
  design once the capture confirms H3 dominates. The plan leans B without
  committing — appropriate.
- The plan does not pre-pick among B/C/D — by design; the capture decides.

No new hostile findings. The plan is honest about PLAN-KILL outcomes (acceptable
SLO / TCP-dominated), the instrumentation gaps are real and minimal, and the
capture's column-to-mechanism mapping is sufficient to disambiguate. Ready.
