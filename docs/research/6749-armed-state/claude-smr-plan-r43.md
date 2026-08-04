# Claude SMR plan review — round 43 — #6749 armed-state plan v8.38 (07762de4d)

**Reviewer:** Claude SMR (hostile; the yellow-flag note stands —
the trace below is the evidence, and this round includes a
source-verified resolution of the respawn question my own
attack-surface raised). Attack surface: the marker's lifecycle,
the restart window, the fence caveat, the §9 (a) assertions,
and Q1 (43rd enumeration).

**Verdict: PLAN-READY-WITH-NITS** — 0 BLOCKER + 0 MAJOR + 0
MINOR + 2 NIT. After the full hostile sweep (including the
dedup's incarnation safety, which I verified against source
this round), only two statement-level nits survived. Codex
remains infra-blocked (twenty-second documented attempt).

---

## SMR43-1 (NIT) — the dedup's incarnation-safety citation (self-raised, source-resolved)

I attacked the dedup's helper-respawn window: the manager's
`lastSnapshotHash` is manager-side and survives the HELPER's
death, so a same-content commit landing during a respawn
could hash-match against a fresh helper that has NOTHING
(absent, not enforced). Resolution (verified against source):
the dedup's gate is `hash == m.lastSnapshotHash &&
m.publishedSnapshot != 0` (process_status.go:77), and
`stopLocked()` resets `m.publishedSnapshot = 0` (and
`publishedPlanKey`) on helper stop (process.go:259) — so the
dedup can never fire over a respawn (the first publish after
a stop is a full send by construction), and the hash ledger
continues coherently from there. The plan should cite this
pair (the gate + the reset) as the dedup's incarnation
guard — one sentence — because the v8.37/v8.38 text
introduces the dedup-completion machinery without ever
saying why the respawn case is safe.

## SMR43-2 (NIT) — the Compile-leg same-content case's wrapper coverage

For a same-content commit whose Compile dedups at publish
time (the new revision, identical forwarding content): the
helper never receives the new generation, no cursor installs
— and the case is fully covered by the WRAPPER (the daemon's
own applyConfigLocked completion stamps from the result's
`capturedDigest` and pushes via the structured transaction —
the standing Compile-leg tails), and the NEXT transition's
invalidation is content-equivalent regardless of which
generation the helper physically holds (the stale-prior
composition A → C2 and the deduped pair B → C2 are the same
set, since B's content == A's content). One sentence so the
Compile-leg dedup case is not read as a hole in the
completion machinery.

## Attack trace (what I tried, and why it fails to break v8.38)

1. **The restart-window re-drive's side effects.** The
   spurious re-drive's Compile rebuilds and dedups — its
   XDP/pin/shim/bootstrap map mutations
   (manager_compile.go:177-350) target the CURRENT plan
   (identical content) — idempotent by construction (the
   classifier/bootstrap mutations are plan-keyed writes of
   the same values; the publish-leg-entry validation
   (v8.14) already guarantees the ordering). Coherent.
2. **The marker across a real acceptance.** A real send's
   acceptance advances `acceptedCommitRevision` past the
   marker; the comparator is a max; both operands are
   monotonic; the comparator never regresses. Coherent.
3. **The note CAS across the dedup.** The CAS's
   `expected_rev` reads `acceptedCommitRevision` (unadvanced
   by the dedup) — matching the helper's stored value — the
   idempotent-success arm; the next real send advances both
   sides in order. Coherent.
4. **Q1, forty-third enumeration.** The v8.38 mechanics
   (the marker lifecycle, the restart window, the fence
   caveat, the §9 (a) assertions) mutate NO binding slots on
   any refuse/degrade path. No new `Registered && !Armed &&
   state==none` producer. Q1 holds.
5. **The r42 disposition table.** Every row re-derived against
   the file: SMR42-1/AGY f1 (the restart-window statement +
   §9 (a) assertions), SMR42-2 (the fence caveat), AGY f2 —
   all present and correctly cited.

## Required for convergence

Nothing mandatory. Optional for v8.39 (or `/engineer`-time):
SMR43-1's incarnation-guard citation (process_status.go:77 +
process.go:259); SMR43-2's wrapper-coverage sentence. AGY
r43 pending at this writing — its verdict may add to this
list (a DEMAND from AGY returns the loop to the fold).

**Verdict: PLAN-READY-WITH-NITS** (2 NIT — the attack trace
stands as the evidence this is not a soft pass).

---

## Post-AGY addendum (round 43, after `agy-plan-r43.md` landed)

AGY r43 returned DEMAND-REVISION (1 BLOCKER + 1 MAJOR + 1
MINOR + 1 NIT). My evaluation, source in hand:

- **AGY f1 (BLOCKER — stale `contentConvergedRevision` after a
  HELPER respawn supposedly strands the fresh helper
  unconfigured indefinitely): NOT-VERIFIED.** AGY's trace
  stops at the GO-LOCAL comparator (`active(5) > max(accepted(4),
  converged(5))` ⇒ false) and never engages the plan's OWN
  respawn-recovery authority: the echo-0 helper-behind case
  keeps the STARTUP RE-APPLY OWNER (plan.md:5485 — a
  zero-stored helper's status echo fires the startup
  re-apply independently of the comparator), and the fresh
  helper accepts everything zero-stored (the standing
  SMR20-8 benign-respawn rule). The recovery's own publish
  cannot dedup: `stopLocked()` resets
  `m.publishedSnapshot = 0` (verified process.go:259), so the
  dedup's `publishedSnapshot != 0` gate is closed and a real
  send lands. The dataplane is never unconfigured past the
  echo-0 owner's own latency. The observation underneath (the
  marker survives a HELPER death while the manager lives) is
  real but harmless: the marker's ONLY reader is the GO-LOCAL
  comparator, whose quietness during the window is safe
  precisely because the comparator was never the recovery
  path (the echo-0 owner is). A hygiene clear-on-helper-death
  is OPTIONAL (it would make the comparator fire once
  redundantly with the echo-0 owner — idempotent); NOT
  clearing is safe. The plan gains one sentence citing the
  echo-0 owner as the respawn recovery authority (so no
  implementer mistakes the comparator for it).
- **AGY f2 (MAJOR — §9 (a) tests only the manager restart,
  not the helper respawn):** valid as a TEST-COVERAGE point
  (not as evidence for f1's blackhole): §9 (a) gains the
  helper-respawn recovery assertion (the echo-0 startup
  re-apply owner drives the full bring-up after a deduped
  pair — the dataplane is never unconfigured past the
  owner's latency — and the comparator's quietness is NOT
  the recovery authority).
- **AGY f3 (MINOR — the wasted cycle's Compile side effects
  run before the dedup decision):** valid documentation
  point, folds as one sentence (the restart-window cycle
  includes the Compile-side XDP/pin/shim/bootstrap
  mutations, idempotent-vs-the-running-helper because the
  rebuild targets the CURRENT plan with identical content
  (plan-keyed writes of the same values — and the
  publish-leg-entry validation (v8.14) already orders them
  before any send decision)).
- **AGY f4 (NIT — the hash's session-policy coverage
  citation):** valid; folds (the content hash covers the
  session-policy structures (zone assignments, address
  books, application definitions), so a session-policy
  change forces a hash mismatch and bypasses the dedup
  entirely — the SMR42-2 fence caveat's proof obligation).

The v8.39 fold carries all four clarifications with AGY f1
recorded NOT-VERIFIED (with the echo-0 evidence).
