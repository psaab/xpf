# Claude SMR plan review — round 9 — #6749 armed-state plan v8.3 (e7b835f73)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies). Attack surface: the v8.3 production-hardening deltas — the
two-phase defer precheck, the epoch-open MAC debt with applySem, the
Go fabric pre-disable, the acceptance-time rollover, the reset clock,
the identity-keyed error attribution.

**Verdict: PLAN-READY-WITH-NITS** — every attack I mounted was
absorbed (trace below). Five documentation nits to fold without a
re-review. If Codex/AGY r9 surface a real hole, this verdict is void
and we iterate.

---

## Attack trace (what I tried, and why it fails to break v8.3)

1. **Q2 — two-phase precheck false-positive (operator-intended
   admin-down).** An operator downs a configured RETH member
   out-of-band (`ip link set down` for maintenance). The config is
   authoritative in xpf's management model: xpfd owns ALL interfaces
   and reconciles out-of-band drift (it re-adds deleted addresses,
   re-enables drifted settings) — an out-of-band admin-down of a
   CONFIGURED member is exactly that class of drift. The precheck
   only runs at compile time, so the operator's down costs nothing
   until the next commit; that commit opens the defer epoch (MAC
   already correct; link-up phase pending), and the MAC debt's
   setUp retry forces the link back up — consistent with the
   config-is-authoritative model, and the commit waits for the
   member to return before workers start. No intent distinction is
   needed; the model already chose config-over-drift. One doc
   sentence makes the behavior legible (nit N1).
2. **Q3 — first validation window / deadlock.** There is no
   validation gap: the epoch opens inside the daemon's apply flow
   (applySem held), and the INITIAL `programRethMAC` call in that
   same flow IS the first validation attempt — synchronous, before
   the flow releases applySem. On success the debt settles and the
   dispatch fires in the same flow (`deferWorkers &&
   !hasActiveMACDebt` evaluates true); on failure the debt is
   active and the autonomous retry (applySem-acquiring) drives
   subsequent attempts after the flow releases. No
   applySem-vs-status-loop deadlock is constructible: the debt's
   tick never runs inside the opening flow, and the retry skips on
   contention. The plan should state that the initial
   `programRethMAC` IS validation pass 1 (nit N2).
3. **Q4 — pre-disable guard-hit window.** The pre-disable fires on
   requested-projection ≠ cached accepted. A guard-hit (transient
   sysfs) keeps the prior projection AND prior vector — no pending
   marks are created, `enabled` stays true, and the NEXT status
   poll (~1s) re-enables ctrl through the NORMAL readiness path
   (`probeBindingsReady && neighborSyncReady → ctrl.Enabled=1`,
   maps_sync.go:486) — provided the pre-disable does NOT touch the
   liveness state. It must be a plain `ctrl.Enabled=0` write with
   no `neighborsPrewarmed`/`ctrlEnableAt`/`xskLivenessProven`
   reset (unlike the link-cycle disable at
   process_linkcycle.go:202-205, which resets liveness because a
   link cycle destroys the XSKs — a guard-hit destroys nothing).
   Window: ~1 poll tick, self-releasing. State it (nit N3).
4. **Q5 — failed-successor helper mirror.** None needed.
   `manager_compile.go:330` stamps `DeferWorkers` only inside the
   publish path — the failing path itself — so a pre-acceptance
   failure either never reached the helper (transport), was
   rejected with the helper keeping prior state (#3766/#3789
   capture-restore), or LANDED as timeout-but-landed. The last is
   the only interesting one: the helper then holds the deferred
   successor with S3 marks while Go believes the compile failed —
   and the existing #4036 idempotent-retry semantics (a retry
   re-sending the exact (generation, fib) pair is accepted
   exact-equal) re-drives it on the next apply, while the
   completion machinery owns the latch. No mirror rollback exists
   or is needed. One sentence (nit N4).
5. **Q6/Q7 — dropped-queue errors and HA reverse sync.** A bind
   error for a queue the restored plan deleted is correctly
   dropped with the identity (the identity-check's mismatch case
   already refuses the copy; the queue no longer exists in the
   accepted config, and the failure was already surfaced at apply
   time) — consistent with the claim-deletion boundary. And the
   cluster's config-sync monotonicity (newest-wins at the
   configstore) means an "older" peer config only ever lands as a
   deliberate rollback — which the contract already handles
   (rollback advances the accepted epoch and supersedes by design).
   No generation floor needed. One sentence each (nit N5).

## Nits (fold without a re-review)

- **N1 (Q2 doc note):** §5-C's precheck bullet should state that an
  out-of-band admin-down of a CONFIGURED RETH member is treated as
  config-authoritative drift: nothing happens until the next
  commit, and that commit's defer epoch + link-up phase reconciles
  the member back up — the commit waits for the member.
- **N2 (Q3 doc note):** state that the initial `programRethMAC` in
  the apply flow IS validation pass 1 of the epoch-open debt —
  synchronous, applySem-held — so the tag's gate never opens a
  validation-free window.
- **N3 (Q4 implementation rule):** the Go fabric pre-disable is a
  plain `ctrl.Enabled=0` write and MUST NOT reset
  `neighborsPrewarmed`/`ctrlEnableAt`/liveness state — a guard-hit
  destroys nothing, and the next poll's normal readiness gate
  re-enables (~1 tick).
- **N4 (Q5 doc note):** state the timeout-but-landed deferred
  snapshot's convergence path (the #4036 exact-equal idempotent
  retry + the completion machinery) and that no helper-side mirror
  of the manager flag rollback exists or is needed.
- **N5 (Q6/Q7 doc notes):** dropped-queue bind errors die with the
  deleted identity (consistent with the claim boundary); the
  cluster config-sync monotonicity makes reverse-synced older
  configs arrive only as deliberate rollbacks, which the contract
  already supersedes by design.

## Required for convergence

Nothing structural. If Codex + AGY r9 converge (PLAN-READY or
PLAN-READY-WITH-NITS), fold N1–N5 and ship to `/engineer`.

**Verdict: PLAN-READY-WITH-NITS.**
