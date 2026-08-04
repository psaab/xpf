# Claude SMR plan review — round 32 — #6749 armed-state plan v8.27 (a5f2918c7)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.27 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the mid-drain steal trace, the cancellation scope, the
population bound, the §9 (a) interleaving assertion, and Q1 (32nd
enumeration).

**Verdict: DEMAND-REVISION** — 0 BLOCKER + 0 MAJOR + 1 MINOR + 1
NIT. The MINOR is self-found in my own mid-drain walk (the
stealer's composition reads the exposed pair at ITS OWN entry —
across an intervening exposure C2 in the applySem gap, the walk
never says the union is exactly the right deletion set). Codex
remains infra-blocked (eleventh documented attempt).

---

## SMR32-1 (MINOR) — the C2-gap composition note

My v8.27 walk says the stealer "RE-EXECUTES the phase" and
composes at ITS entry — but the stealer acquires `applySem`
AFTER the stale drain releases it, and an intervening exposure
C2 can land in that gap (C2's own apply holds `applySem`
first). The stealer's composition then reads C2, not the C the
stale drain composed against — and the walk never proves the
union is correct. Walk it (state it): the stale drain's
deletes are A→C (composed at its entry, correct then); C2's
own wrapper/cursor composes C→C2 (its own tails); the
stealer's deletes are A→C2 (composed at ITS entry). The union
deletes exactly (A∪C)\C2 — everything not C2-authorized that
was A- or C-authorized — and every C2-permitted session
survives all three (the stale drain skipped it as C-permitted,
the stealer skips it as C2-permitted). The composition rule
(drain-time EXPOSED at EACH drain's own entry) is what makes
the union correct — the stealer does NOT re-run the stale
drain's composition, it runs its own. And the two cursor
entries are independent (B's entry's phases vs C2's own
acceptance's tails — no cross-entry interference: each
composes against the shared `m.lastExposedPair` at its own
entry, and the claim-or-skip serializes only within an entry).
Stated next to (i); §9 (a) gains the C2-gap interleaving (the
union assertion, not just the idempotent re-execution).

## SMR32-2 (NIT) — the record-before-timer case

A drain that finishes before the namedBound records complete
normally and the steal-timer never fires (it fires only on
claimed-not-complete — the timer is cancelled by the
completion, same `m.mu` op as the record). Stated.

## Attack trace (what else I tried, and why it fails to break v8.27)

1. **The C2-gap × the cursor's pair identity.** B's cursor
   entry's phases key on B's acceptance; C2's exposure installs
   its OWN entry (C2's acceptance is a separate event with its
   own transport). The entries never share phases; the shared
   `m.lastExposedPair` is the only coupling and it is read
   under `m.mu` at each drain's entry. Coherent.
2. **The CAS × C2's stamp.** C2's wrapper stamps C2 (CAS on
   store-current = C2's revision, passes); the stale drain's
   stamp for B... its claim died at the steal — the stamp CAS
   on store-current — if C2 already stamped, the store's
   applied is C2 and B's stamp... the CAS form (expected
   store-current) refuses B's stamp after C2's lands (the
   applied revision moved past) — wait, the CAS checks the
   store's ACTIVE revision vs the stamp's revision: B's stamp
   after C2 is store-active: B is no longer store-active ⇒ the
   stamp's own store-currency gate (SMR24-1/v8.20) skips it —
   never a regression. Coherent (two layers: the stamp's
   currency gate AND the CAS).
3. **Q1, thirty-second enumeration.** The v8.27 mechanics
   (mid-drain trace, cancellation scope, population bound, §9
   (a) interleaving) mutate NO binding slots on any
   refuse/degrade path. No new `Registered && !Armed &&
   state==none` producer. Q1 holds.
4. **The r31 disposition table.** Every row re-derived against
   the file: SMR31-1 (the trace + §9 (a)), SMR31-2 (scope),
   SMR31-3 (bound) — all present and correctly cited.

## Required for convergence

v8.28: SMR32-1's C2-gap note + the §9 (a) union assertion;
SMR32-2 folded. AGY r32 pending at this writing — its verdict
may add to this list.

**Verdict: DEMAND-REVISION** (0 BLOCKER + 0 MAJOR + 1 MINOR +
1 NIT — proof-elaboration level; the v8.27 mechanics held).
