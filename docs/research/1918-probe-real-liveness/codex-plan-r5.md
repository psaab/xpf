# Codex hostile plan review r5 — #1918 — task 019ed448-be29-7d21-b399-3d1b59cf6a7b

Verdict: PLAN-KILL (r5-scoped — the fatal finding is the same deadlock AGY r5 raised; resolved
in r6, which matches Codex's own prescribed fix path).

CHECK 1 DEADLOCK-FATAL: r5 step-4 had the runner re-read t.linkGen under t.mu; Apply holds t.mu
while blocking on <-runner.done; an in-flight tick needing t.mu deadlocks both. The production
runner body never takes t.mu (only state.mu) — the plan's gen-check introduced it.
CHECK 2 RETAIN PATH: PASS.
CHECK 3 REMAINING RACE: secondary only (GetStatus TOCTOU), non-blocking.
CHECK 4 TEST: §9 drain test covers F7 ifindex reuse but not the deadlock path.

Codex's prescribed fix path (== r6): "drop the runner-side t.mu re-read entirely. The
drain-before-recreate ordering is sufficient... The generation token can remain as
defense-in-depth only if it uses an atomic load (no t.mu)." r6 makes linkGen atomic.Uint64,
runner reads lock-free, never takes t.mu. CONVERGED with AGY r5 on the identical point.
