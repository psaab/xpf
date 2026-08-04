# Claude SMR plan review — round 31 — #6749 armed-state plan v8.26 (c09cceed3)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.26 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the steal fences (entry liveness, stamp CAS, applySem
ordering), the bounded steal (cancellation, ladder decay,
replacement), the revert's missing-entry no-op, the §9 (a)
assertions, and Q1 (31st enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 1 MINOR + 2
NIT. The MINOR is self-found in my own entry-fence fold (the fence
checks liveness at ENTRY but the steal needs only `m.mu` to fire
while the drain executes under `applySem` — the claim can die
MID-execution, and the plan never walks the landed-but-unrecorded
side effects). Codex remains infra-blocked (tenth documented
attempt).

---

## SMR31-1 (MINOR) — the mid-drain steal's landed-but-unrecorded side effects need their idempotency statement

The entry fence checks liveness in the claim's `m.mu` operation,
but the steal itself needs only `m.mu` to bump the generation —
so it can fire while the stale drain executes its tails under
`applySem` (no `m.mu` held mid-tails). My v8.26 fold walks only
the entry case. The mid-drain cases (state them): (i) the
invalidation was composed AT ENTRY against the drain-time
EXPOSED pair, and no exposure can move while the drain holds
`applySem` — the composition stays correct after the claim
dies (the deletes that follow are the composed set, never an
A→B-over-C set); (ii) the stamp's CAS passes (the store cannot
move under `applySem` either) — the stale stamp LANDS, and it
is CORRECT (the pair is store-active; the stamp marks it
applied) — but the phase's completion RECORD is refused by the
generation guard, so the stealer RE-EXECUTES the phase: the
re-execution's side effects are the idempotent ones (a second
identical stamp CAS — passes-or-noops on the same value; a
second identical push — the receiver's `SyncApply` no-ops on
identical content (daemon_apply_commit.go:356-360)); (iii) the
push likewise. So the mid-drain steal is safe by the
composition rule + the CAS + the receiver no-op — and the
re-execution is bounded by the ladder. Stated, with §9 (a)
exercising the steal-mid-tails interleaving (the landed stamp
plus the refused record plus the stealer's idempotent
re-execution).

## SMR31-2 (NIT) — the cancellation's window is one operation

The stale claimant's ctx cancellation lands BETWEEN tail
operations (a mid-flight conn write finishes on its own bound
(the TCP timeout + `handleDisconnect`), a synchronous store
call returns on its own) — the CAS form makes either order
safe, stated (the cancellation bounds the goroutine's
remaining life to one operation, not to the next tick).

## SMR31-3 (NIT) — the steal-spawned goroutine population's bound

With cancellation, each steal-spawned goroutine exits within
one operation of its cancellation — the residual population is
the kernel-wedged (ctx-uncancellable) class only, which is the
budgeted D-state class (out-of-band operator), stated next to
(f).

## Attack trace (what else I tried, and why it fails to break v8.26)

1. **The replacement × the hanging live claim.** A second steal
   is refused while a live claim stands; the live claim's own
   steal-timer rides the ladder (60s floor) — so the steal
   cadence is the ladder's, never a spin, and cancellation
   reaps the predecessor. Coherent.
2. **The defer-revert × the steal.** A panicking claimant's
   revert races the steal: both touch the entry under `m.mu` —
   the revert sees the bumped generation and no-ops (the
   missing/stolen-entry contract), the stealer owns the phase.
   Coherent.
3. **The fence × the notice drain.** The notice drain's claim
   IS the entry-fence operation (one `m.mu` op: check liveness
   + claim) — no separate fence to forget. Coherent.
4. **Q1, thirty-first enumeration.** The v8.26 mechanics
   (entry fence, stamp CAS, cancellation, ladder-decay steal,
   replacement) mutate NO binding slots on any refuse/degrade
   path. No new `Registered && !Armed && state==none` producer.
   Q1 holds.
5. **The r30 disposition table.** Every row re-derived against
   the file: AGY f1 (the three fences + the SMR30-1
   retraction), AGY f2 (cancel + decay + replacement), SMR30-2
   (the revert's no-op), SMR30-3, AGY f3 (§9 (a)) — all
   present and correctly cited.

## Required for convergence

v8.27: SMR31-1's mid-drain idempotency statement + the §9 (a)
interleaving assertion; SMR31-2/SMR31-3 folded. AGY r31 was
infra-limited this round (RESOURCE_EXHAUSTED 429 — retry
pending; the round completes 2-of-3 either way per the
standing exception, with the AGY retry documented).

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 1 MINOR +
2 NIT — statement-level; the v8.26 fences held).
