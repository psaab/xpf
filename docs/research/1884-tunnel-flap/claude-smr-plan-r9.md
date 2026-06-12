# Claude SMR hostile plan review — #1884 r9 (plan v9, b2163ce9509b)

Verdict: **PLAN-READY**.

## Q1 — cell sweep

Criterion per cell: after the apply, either claim names the link's
actual our-master, or the claim is retained-stale and every future
unbind is identity-gated (so it can neither strand an owned master nor
touch a foreign one).

- stanza=none × list=none: prior=fresh ⇒ unbind, clear (correct);
  prior=stale ⇒ identity mismatch / not-found ⇒ clear, no unbind
  (foreign/gone master untouched); prior=none ⇒ no-op.
- stanza=none × list=0a-ok: observation writes claim=list — faithful,
  any prior overwritten by a verified observation.
- stanza=none × list=0a-fail: retain prior. Kernel still on prior (if
  fresh) — faithful; if config later drops the list, the unbind path
  frees the prior master (the r6/r8 leak class, now closed); no
  strand under permanent 0a failure (kernel state and claim agree).
- stanza=bind-ok × list=any: claim=stanza; the successful bind just
  re-mastered the link — faithful by construction; stanza-wins
  precedence matches today's effective 0a-then-tunnel-apply order.
- stanza=bind-fail × list=0a-ok: observation fallback writes
  claim=list (the r8 counterexample cell) — faithful.
- stanza=bind-fail × list∈{none,0a-fail}: retain prior — same
  reasoning as stanza=none × list=0a-fail; with prior=none there is
  no our-master to strand (a master can only be ours if a successful
  bind or observation once recorded it).

**Induction argument** (closes the sweep): claim≠our-actual-master is
unreachable through manager actions — every successful bind updates
the claim, and every observation-write requires master equality at
write time; divergence can only arise from out-of-band kernel changes,
which by definition make the master not-ours, and the identity gate
then refuses the unbind and clears. An our-master with NO claim is
likewise unreachable (clears happen only on unbound/not-ours/gone/
link-deleted). Both failure directions — stranding an owned master,
unbinding a foreign one — require a state the procedure cannot reach.

## Q2

The r8 fold adds one branch to the claim procedure and two test rows;
nothing else moved. MTU, address, keepalive, ownedNames, reuse-check,
and EEXIST closures are textually intact in v9. No re-opens.

Converged. Recommend final PLAN-READY contingent on the parallel
Codex/AGY r9 ratifications.
