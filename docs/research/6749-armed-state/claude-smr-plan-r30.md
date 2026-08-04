# Claude SMR plan review — round 30 — #6749 armed-state plan v8.25 (c9c70de90)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.25 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the claim lease's steal semantics (the overlapping
execution it licenses), the defer-revert's own failure modes, the
due-check's residue, the §9 (a) additions, and Q1 (30th
enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 1 MINOR + 2
NIT. The MINOR is self-found in my own lease fold (the steal
licenses TWO overlapping executions of the same phase — the plan
must prove each tail operation tolerates the overlap, and it
currently says nothing). Codex remains infra-blocked (ninth
documented attempt).

---

## SMR30-1 (MINOR) — the steal's overlapping execution needs its three idempotency proofs stated

The lease's steal runs the phase while the STALE claimant may
still be mid-execution (a slow-but-alive tail is exactly the
case the steal exists for) — so TWO executions of the same
phase overlap, and the generation guard refuses only the stale
claimant's completion RECORD, never its execution. My v8.25
text is silent on why the overlap is safe. The proofs (state
them next to the lease): (i) the session invalidation —
idempotent deletes (a re-issued delete of the same session is a
no-op); (ii) the peer push — the second structured send
allocates a fresh wire generation and sends the SAME text, and
the receiver's `SyncApply` no-ops on identical content
(compiled == nil → the early return,
daemon_apply_commit.go:356-360 — VERIFIED), while the
sender-side marker records the same sentPair from each result
(idempotent); (iii) the applied stamp — a last-writer-wins set
on the same revision (idempotent). And the §9 (a) steal
assertion must exercise the overlap (the stale claimant
completes AFTER the steal — its late advance is refused AND
its late effects are the idempotent ones).

## SMR30-2 (NIT) — the defer-revert's own missing-entry tolerance

The `defer` wrapper's revert calls the manager's `m.mu` method
on an entry that a concurrent pass may have GC'd (the phase
went terminal via the stealer before the panicking claimant's
defer ran): the revert rides the SAME uniform missing-entry →
already-terminal contract (a no-op), stated once — the
panic-safe path never dereferences a missing key either.

## SMR30-3 (NIT) — the advisory mark × the due-check

A sweep mark on a not-yet-due entry: the claim refuses (the
due-check lives in the claim), the mark re-fires on the next
pass — harmless, stated (no mark-clearing machinery needed).

## Attack trace (what else I tried, and why it fails to break v8.25)

1. **The first-failure due-check edge.** A fresh entry
   (nextAttempt unset) claimed by the notice drain: admitted
   (the unset case is the zero-time due) — the notice fast path
   never waits for an entry that never failed. Coherent.
2. **The lease × GC composition.** A stolen-then-completed
   entry goes terminal and is GC'd on the next pass; the stale
   claimant's late advance hits either the generation refusal
   (entry present) or the missing-entry contract (entry GC'd)
   — both safe no-ops. Coherent.
3. **The ladder reset × the steal.** A stealer that succeeds
   resets the entry's ladder (AGY's per-phase-success form); a
   stealer that fails advances it — the steal never gets a free
   cadence. Coherent.
4. **Q1, thirtieth enumeration.** The v8.25 mechanics
   (defer-revert, lease/generation, atomic release, due-check,
   reset form) mutate NO binding slots on any refuse/degrade
   path. No new `Registered && !Armed && state==none` producer.
   Q1 holds.
5. **The r29 disposition table.** Every row re-derived against
   the file: AGY f1 (defer-revert + lease), SMR29-1/AGY f2
   (atomic release + due-check), SMR29-2 (superseded by the
   lease), SMR29-3/AGY f3 (the reset form), AGY f4 (§9 (a)) —
   all present and correctly cited.

## Required for convergence

v8.26: SMR30-1's three idempotency proofs + the §9 (a) overlap
assertion; SMR30-2/SMR30-3 folded. AGY r30 pending at this
writing — its verdict may add to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 1 MINOR +
2 NIT — proof-documentation level; the v8.25 model held).
