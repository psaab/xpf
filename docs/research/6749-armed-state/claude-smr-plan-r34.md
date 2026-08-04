# Claude SMR plan review — round 34 — #6749 armed-state plan v8.29 (f67996d5f)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.29 folds are MY text, written this session,
and the finding below is self-found in MY OWN v8.26 stamp-CAS
phrasing, which I verified against the actual store code this
round). Attack surface: the EXPOSED-currency gate, the corrected
union formula, the generalization, the §9 (a) assertions, and Q1
(34th enumeration).

**Verdict: DEMAND-REVISION** — 1 BLOCKER + 1 MINOR + 0 NIT. The
BLOCKER is self-found in my own v8.26 "stamp CAS (expected
store-current revision)" fold, which is the wrong model against
the actual digest-based stamp machinery (`store.go:787-853` —
read this round). AGY r34 (1 BLOCKER + 1 MINOR) found the same
defect independently from the plan side. Codex remains
infra-blocked (thirteenth documented attempt).

---

## SMR34-1 (BLOCKER) — the "stamp CAS (expected store-current revision)" model is wrong against the actual digest machinery (= AGY r34 f1)

Verified against source (store.go:787-853): the stamp machinery
is DIGEST-based, with NO revision CAS anywhere —
`MarkActiveApplied()` stamps `configTextDigest(s.active)` (the
CURRENT active tree), `MarkAppliedDigest(digest)` stamps a
caller-captured digest UNCONDITIONALLY (overwrite, no
staleness check — the #6296 TOCTOU-safe form), and
`ActiveApplied()` is the read-side comparison
(`appliedDigest == digest(current active)`). My v8.26 fold's
"CAS form (expected store-current revision)" is plan-invented
and has TWO failure modes against this machinery: (i) a CAS
keyed on the ACTIVE revision REFUSES the very stamp the v8.29
exposed-currency gate just admitted (C1 exposed, C2
store-active-but-gated: active == C2 ≠ C1 — the gate and the
CAS contradict, and `appliedDigest` stays at A for the whole
gated window — AGY f1's trace, confirmed); and (ii) a CAS-free
overwrite lets a LATE stale stamp regress the marker
(digest(C2) → digest(C1) after C2's stamp — the AGY r30 f1
regression the v8.26 fold existed to kill, reopened if anyone
implements the phrasing literally). The correct form (which
matches the code): the stamp is the CAPTURED-DIGEST stamp
(`MarkAppliedDigest(pair.capturedDigest)` — the pair's own
digest, captured at acceptance/apply time under the apply
serialization — NEVER `MarkActiveApplied()`, which re-reads
`s.active` and would stamp the never-applied successor (the
AGY r30 f1 / #6296 class)); and the anti-stale protection is
the v8.29 EXPOSED-currency ADMISSION gate (a stale notice's
stamp is SKIPPED before any stamp call — the read-side
`ActiveApplied()` digest comparison is the only "CAS" the
machinery needs; the v8.26 revision-CAS phrasing is RETRACTED).
The rollback case is the payoff: C2 rolled back to C1 after
C1's captured-digest stamp landed ⇒ `ActiveApplied()` reports
C1 applied (true — C1 is enforced) instead of a phantom
"unapplied" state.

## SMR34-2 (MINOR) — §9 (a) must assert the stamp LANDS (= AGY r34 f2)

The gated-successor assertion says "stamp FIRES" — but an
implementation that calls the stamp and fails an internal
active-keyed check still FIRES the push and greens the test
while `appliedDigest` never advances. The assertion must check
the digest itself: after C1's notice drain with C2 gated,
`appliedDigest == configTextDigest(C1's text)` (and after C2's
own apply, `== digest(C2)`) — a stamp-that-doesn't-land FAILS.

## Attack trace (what else I tried, and why it fails to break v8.29)

1. **The push ordering at the peer.** C1's push (the notice
   drain, admitted by the exposed-currency gate) and C2's push
   (post-exposure, via the drain's re-wake) are serialized by
   `applySem`; the wire generations allocate per send
   (monotonic); the peer applies in wire order. Coherent.
2. **The SUPERSEDED marking under the new key.** Only a NEWER
   EXPOSED pair supersedes; a gated successor does not — C1's
   entry completes normally; when C2 later exposes, C2's OWN
   entry (installed at C2's acceptance) carries C2's tails. No
   double-stamp: C1's captured-digest stamp lands at T1, C2's
   at T2, each the correct tree at that time. Coherent.
3. **The formula's residue.** Every "surviving" context in the
   doc re-read: the only remaining survival claims are the
   corrected (A∪C)∩C∩C2 form and the subsumption (delete-set,
   not survival). Clean.
4. **Q1, thirty-fourth enumeration.** The v8.29 mechanics
   (exposed-currency gate, corrected formula, generalization,
   §9 (a) assertions) mutate NO binding slots on any
   refuse/degrade path. No new `Registered && !Armed &&
   state==none` producer. Q1 holds.
5. **The r33 disposition table.** Every row re-derived against
   the file: AGY f1 (the re-key + SUPERSEDED-on-same-key), AGY
   f2 (the corrected formula in §5-C (ii) + the r32 row + §9
   (a)), SMR33-1 (i) (the generalization), SMR33-2 (subsumed) —
   all present and correctly cited.

## Required for convergence

v8.30: SMR34-1's captured-digest stamp form + the revision-CAS
retraction (= AGY f1); SMR34-2's digest-land assertion (= AGY
f2).

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MINOR + 0 NIT —
one phrasing-level model error against the real machinery,
with the correct form identified; the rest of v8.29 held).
