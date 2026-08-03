# Claude SMR plan review — round 8 — #6749 armed-state plan v8.2 (f84e0827a)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies). Attack surface: the v8.2 deltas — the mark-all-pending
fabric gate (no in-handler reconcile), the staged projection + guard
authority, the epoch rollover, the never-capped retry, the debt
contracts, the planned-identity volatile check.

**Verdict: PLAN-READY-WITH-NITS** — every attack I mounted was
absorbed (trace below). Three nits to fold without a re-review: the
rollover ordering needs one explicit sentence, the guard's
mixed-update conservatism needs one, and the claimed-slot rebind
assurance needs one. If Codex/AGY r8 surface a real hole, this
verdict is void and we iterate.

---

## Attack trace (what I tried, and why it fails to break v8.2)

1. **Q3 — lastAcceptedConfigGeneration advance points.** The epoch
   advances only on compile SUCCESS: normal commits, HA-peer config
   sync (rides ApplyConfig → compile), rollback-to-older-config and
   `commit confirmed` auto-revert (both are accepted applies of the
   now-current config — advancing the epoch SUPERSEDES the newer
   generation's debts, which is correct: the debt's config is no
   longer accepted), and the mandatory re-apply's success (settles
   its own debt exactly once). Failed compiles never move it (the
   pre-build allocation at manager_compile.go:214 is burned, not
   accepted — the debt keeps firing for the last ACCEPTED state).
   Every mover named; the debts behave.
2. **Q4 — rollover vs mid-commit defer.** The rollover's two
   branches are disjoint by construction: the SAME precheck
   (`rethMACPending`) drives both — no-MAC-work → clear flag +
   cancel stale debts (supersession); MAC-work → cancel stale
   (generation-mismatched) debts + SET the flag (new epoch). The
   new epoch can never cancel itself because the cancel step is
   keyed on generation mismatch, and the flag-clear only happens in
   the branch the new epoch doesn't take. Needs one explicit
   sentence in the doc (nit N1).
3. **Q5 — identity check vs orphan-VLAN parent re-key.** The
   binding record for an orphan child carries the PARENT netdev
   name + parent ifindex (planning.rs:421-431), and
   `workers.identities` is built from the same binding vector at
   plan time (bringup.rs:273-280) — same source, always equal. No
   legitimate divergence; the check can't zero a healthy slot.
4. **Mark-all gate vs operator-claimed fabric slots.** A claimed
   fabric binding is excluded from the mark-all (`non-operator`),
   so its claim survives. The retry's rebind DOES tear down and
   re-bind its XSK (worker planning filters `registered &&
   ifindex>0`, not armed), but the claim keeps `armed=false` → its
   shim rows stay non-READY (`bindingForwardingLive` requires
   Armed) → no steering. The operator's no-forward intent survives
   the physical rebind exactly. Needs one assurance sentence (nit
   N3).
5. **Fabric projection change inside a defer epoch.** An accepted
   fabric change mark-all-pendings the vector; the generic retry is
   suppressed (flag set); the pendings converge at the defer
   completion (the tagged rebind's convergence is plan-scoped —
   covers fabric-created pendings and S3 defer pendings alike).
   Coherent.
6. **Mixed guard hit.** A fabric update where one candidate's
   projection changes legitimately AND another's sysfs read fails:
   the guard defers the WHOLE update (keeps prior projection +
   vector), not just the failing candidate — partial acceptance
   would diverge the vector from the accepted projection. The
   conservative whole-update defer converges on the next pass
   (sysfs recovers, projection + pendings apply together). Needs
   one sentence (nit N2).
7. **The mark-all gate's window vs the in-handler alternative
   (Q2).** In-handler reconcile: ~10s ctrl=0 window (readiness),
   PLUS a Go fail-closed transaction wrapper (pre-disable, in-flight
   tracking, timeout-but-landed idempotency across the 3s deadline)
   — real new machinery with a deadlock surface (a wedged reconcile
   inside an RPC that must stay cancellable). Mark-all-pending:
   enabled=false in the same tick (Go applies the returned status
   immediately), first retry rebind at ≤5s initial backoff, NO new
   transaction type (the v8 retry machinery already exists and is
   already tested). The mark-all window is shorter, the machinery
   is already owned, and the posture is identical (fail-closed).
   The pick is right.

## Nits (fold without a re-review)

- **N1:** §5-C's rollover bullet needs the explicit ordering
  sentence: rollover-then-open; the cancel-stale-debts step runs in
  BOTH branches (keyed on generation mismatch), and the flag is
  cleared only in the no-MAC-work branch (set in the MAC-work
  branch) — the new epoch can never cancel itself.
- **N2:** §5-C's guard needs the mixed-update sentence: a guard hit
  defers the WHOLE fabric update (prior projection + vector), never
  a partial subset — partial acceptance would diverge the vector
  from the accepted projection; the deferred update re-applies on
  the next pass when sysfs recovers.
- **N3:** §5-C (or §7.8) needs the claimed-slot assurance: the
  pending-retry's rebind re-binds an operator-claimed slot's XSK
  physically (worker planning is armed-blind), but the claim keeps
  the shim rows non-READY — the operator's no-forward intent
  survives physical rebinds.

## Required for convergence

Nothing structural. If Codex + AGY r8 converge (PLAN-READY or
PLAN-READY-WITH-NITS), fold N1–N3 and ship to `/engineer`.

**Verdict: PLAN-READY-WITH-NITS.**
