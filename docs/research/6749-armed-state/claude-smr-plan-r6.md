# Claude SMR plan review — round 6 — #6749 armed-state plan v7 (3e388fde8)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies). Attack surface: the v7 deltas — plain restoration, E2
narrowing, update_fabrics replan, durable defer flag + MAC-success
gating, latch consumption, generation-scoped debt, and above all the
NEW actor: the Go pending-activation retry.

**Verdict: PLAN-READY-WITH-NITS** — the v6-to-v7 folds hold under my
attacks (trace below). Three nits to fold without a re-review: the
retry's failure-churn shaping + its overlap with the #5134 debt loop,
the MAC-failure stranding corner's documentation, and the
latch-consume write ordering. If Codex/AGY r6 surface a real hole,
this verdict is void and we iterate.

---

## Attack trace (what I tried, and why it fails to break v7)

1. **Unowned-producer hunt (plan Q1).** Re-enumerated under v7's
   expanded surface (now including update_fabrics and the failure
   restoration): every non-forwarding state still lands in exactly
   one owner — planner (`pending`), operator (`operator`), global
   fan-out (`none`). The failure-path restoration cannot create
   unowned state: it restores the pre-apply vector (whose states were
   already owned) and re-marks non-operator slots pending. The
   update_fabrics replan creates only S5-pending. No fourth producer.
2. **Plain restoration vs #4952's rationale (my prompt Q7 to
   Codex).** The pin's intent was "report the REAL post-teardown
   per-binding state, not the pre-teardown workers that no longer
   exist". The volatile half of that intent is served by
   `refresh_bindings` regardless of which control vector is present:
   dead workers zero out, survivors report truthfully. The control
   half — WHICH identities the report describes — is strictly more
   truthful as the coherent restored plan than as the rejected one
   (the rejected plan's identities would mislead any recovery
   action). The retained-B mechanism was a means; the rationale is
   preserved. The failing pin assertions are updated in the same PR
   (§9 item 16).
3. **E2 narrowing vs claim semantics.** The collapse Codex r5 B2
   exposed is real in v6 and gone in v7: `pending`-only E2 means no
   planner path ever resurrects an operator decision. The residual
   degradation (claimed slot flaps → recovers unregistered-with-
   claim) preserves the one guarantee a destructive maintenance verb
   must give — the slot never forwards again until the operator
   says so. Correct trade.
4. **The retry's convergence semantics.** The retry sends a PLAIN
   rebind: control-socket-serialized (never races an in-progress
   bind — the daemon's own EBUSY warning requires an in-progress
   first bind, which cannot coexist with a queued rebind), reconciles
   the CURRENT coherent plan, and convergence arms pending inside.
   During a durable defer window it is suppressed (flag set).
   Fabric-parent slots bind regardless of fabric-peer resolution, so
   fabric flap churn does not feed the retry. The one rough edge is
   failure churn (nit N1).
5. **The retry vs the #5134 debt loop (my own find).** A failed
   mandatory re-apply records the debt: the debt retries the
   REPUBLISH every 1s (heavy) while the pending-retry would ALSO
   fire (pending slots, flag cleared by then) — two retry loops
   racing for the same convergence. Not incorrect (both are
   idempotent paths to the same end; the control socket serializes
   them) but wasteful and log-noisy. The retry must suppress while
   `m.pendingWorkerArm` is set — the debt is the senior, more
   targeted mechanism (it republishes the exact snapshot; the rebind
   is the generic fallback). Nit N1 folds this.
6. **MAC-failure corner (plan Q3).** `programRethMAC` failure today
   is Warn-only and the completion fires anyway (:401) — v7's
   suppression is strictly safer. The stranded corner (transient
   failure + no later event): the next apply of ANY kind recomputes
   `rethMACPending` (MAC still wrong) and re-attempts programming —
   the daemon's natural apply path IS the MAC retry mechanism, so
   stranding requires failure + total config/event silence, during
   which the box is fail-closed with pending slots visible in
   `show`. Acceptable; document (nit N2). A daemon-side MAC-retry
   debt is rejected as scope growth for a Warn-visible corner.
7. **Boot-case completion ordering.** The mandatory re-apply on a
   boot box (global=false): its own publish reconciles + converges
   pending (stored defer=false after the swap), and the compile's
   :408 sync then sends the arm (flag already cleared) whose fan-out
   covers anything left — the same apply+arm double-reconcile master
   already performs (pre-existing pattern, not v7-introduced).
8. **Latch consumption (plan Q4).** Order the latch-clear BEFORE
   `refresh_status` + the single persist in rebind.rs: one mutation,
   one write, no window where the state file says defer=true while
   in-memory says false (nit N3).
9. **Durable flag vs the mandatory re-apply.** The flag must clear
   BEFORE `reapplyAfterDeferredMAC` or the mandatory re-apply stamps
   `DeferWorkers=true` and defeats itself; clearing just before the
   dispatch (:393/:401) is exactly right — post-MAC, so a racing
   poll-tick arm in the microseconds after the clear lands on an
   already-programmed MAC (harmless).

## Nits (fold without a re-review)

- **N1 (retry shaping):** the pending-activation retry needs (i)
  backoff — 5s → 10s → 30s → 60s cap — because a permanent bind
  failure otherwise cycles the FULL worker set (healthy included)
  every 5s indefinitely, with session churn each cycle; (ii) an
  attempt cap — after ~12 cycles (~5 min) stop retrying and emit one
  edge Warn (the pending state remains visible in `show`; the
  operator acts); (iii) suppression while `m.pendingWorkerArm` is
  set — the #5134 debt is the senior mechanism for its generation;
  the rebind-retry is the fallback when no debt exists. The manager
  tests (§9 Go block) pin all three.
- **N2 (documented corner):** §5-C's completion section should state
  that a FAILED `programRethMAC` leaves the box deferred until the
  NEXT apply/event (any subsequent apply recomputes
  `rethMACPending` and re-attempts programming — the natural retry
  path), and that the corner (failure + total silence) is
  fail-closed and Warn-visible by design.
- **N3 (write ordering):** the latch-clear in rebind.rs must precede
  `refresh_status` and share the single persist (one mutation, one
  write); the server test (§9 item 13(c)) asserts the persisted
  snapshot shows `defer_workers=false` after a successful tagged
  rebind.

## Required for convergence

Nothing structural. If Codex + AGY r6 converge (PLAN-READY or
PLAN-READY-WITH-NITS), fold N1–N3 and ship to `/engineer`.

**Verdict: PLAN-READY-WITH-NITS.**
