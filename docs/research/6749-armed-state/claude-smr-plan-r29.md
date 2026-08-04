# Claude SMR plan review — round 29 — #6749 armed-state plan v8.24 (50f0ef069)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.24 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the claim-or-skip tri-state's release semantics, the
stuck-claim bound, the nextAttempt ladder's scope and reset, the
§9 (a) additions, and Q1 (29th enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 2 MINOR + 1
NIT. Both MINORs are self-found in my own v8.24 claim/backoff
wording (the claim's release-on-failure is not pinned atomic with
the nextAttempt set — the 1Hz loop returns via the back door; and
the stuck-claim's bound rests on an unstated assumption about the
tail operations' own timeouts). Codex remains infra-blocked
(eighth documented attempt).

---

## SMR29-1 (MINOR) — the claim's release-on-failure must set `nextAttempt` atomically with the release

My v8.24 text has the claim-or-skip tri-state AND the per-entry
`nextAttempt` backoff, but never composes them: a claimant whose
tail FAILS must release the phase claimed → pending — and if the
release and the `nextAttempt` set are not ONE `m.mu` operation,
a second claimant (the next scheduler tick, 1s away) picks the
phase up IMMEDIATELY and the tight 1Hz retry loop SMR28-2 died
to kill returns via the claim path. Pin: the release-on-failure
is one `m.mu` transition (claimed → pending, `nextAttempt` set
in the same hold), and the claim-or-skip refuses claims whose
`nextAttempt` is in the future (the due-check lives in the
claim, not just the iterate pass — the notice-triggered drain
respects it too). The failed attempt's partial effects are
idempotent by construction (invalidation deletes; the push's
own redelivery owns; the stamp is a set), so a re-attempt never
double-effects — stated.

## SMR29-2 (MINOR) — the stuck-claim bound rests on an unstated assumption

A claimant that neither completes nor releases (a hung tail —
the peer push blocking on a half-dead connection, a storage
call wedged): my tri-state leaves the phase claimed forever,
the entry never terminal, the pending set growing by one per
stuck claim. The v8.24 text assumes the tail operations are
internally bounded without saying so. Pin: the claim records
`claimedAt`, and the claim's lifetime is bounded BY CONSTRUCTION
— each tail operation's own bound is named (the peer push: the
connection's write path with `handleDisconnect` on error
(sync_conn_config.go:243-252); the stamp: the store's
synchronous return; the invalidation: local kernel calls) — a
claim outliving the sum of those bounds is treated as the
budgeted kernel-unreapable/D-state class (the 60s Warn +
out-of-band operator, already in §8) rather than given a new
lease mechanism (rejected as new machinery for a budgeted
class). Stated next to the tri-state.

## SMR29-3 (NIT) — the `nextAttempt` ladder's scope and reset

Pin: the ladder is per-ENTRY (the tails are one logical unit —
a failure anywhere backs off the entry), shared by every
claimant of that entry, and resets only on the entry's terminal
transition (a successful INTERMEDIATE phase does not reset it —
the failure was real and the next attempt of the remaining
phases keeps the cadence).

## Attack trace (what else I tried, and why it fails to break v8.24)

1. **The claim × GC composition.** The pass GCs only terminal
   entries; a claimed phase is not terminal; a stuck claim
   therefore holds its entry — bounded by SMR29-2's named
   bounds. Coherent.
2. **The notice vs the due-check.** A notice for an entry whose
   `nextAttempt` is in the future: the notice-triggered drain's
   claim refuses (the due-check lives in the claim) — the
   notice fast path never accelerates a backed-off entry.
   Coherent (given SMR29-1).
3. **The wrapper's accessor × the due-check.** The synchronous
   wrapper claims its OWN entry's phases — its claim is
   first-party (the entry exists because its acceptance
   installed it), so the due-check never refuses the first
   claim (nextAttempt unset). Coherent.
4. **Q1, twenty-ninth enumeration.** The v8.24 mechanics
   (tri-state, nextAttempt, uniform contract) mutate NO binding
   slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
5. **The r28 disposition table.** Every row re-derived against
   the file: SMR28-1 (tri-state + §9 (a) claim-collision),
   SMR28-2 (nextAttempt + §9 (a) backoff), AGY f2/f3 (uniform
   contract + §6 + §9 (a)) — all present and correctly cited.

## Required for convergence

v8.25: SMR29-1's atomic release-with-nextAttempt + the
claim-side due-check; SMR29-2's named bounds + the D-state
fold; SMR29-3's scope/reset. AGY r29 pending at this writing —
its verdict may add to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 2 MINOR +
1 NIT — composition pins; the v8.24 model held).
