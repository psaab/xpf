# Claude SMR plan review — round 33 — #6749 armed-state plan v8.28 (676b176d5)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
noted and consciously resisted: this is the first near-clean SMR
verdict of the campaign, so the attack trace below is the evidence
for it, not a formality). Attack surface: the C2-gap composition
note, the stamp prose form, the timer note, the §9 (a) C2
assertion, the whole cursor/steal machinery's residual surface,
and Q1 (33rd enumeration).

**Verdict: PLAN-READY-WITH-NITS** — 0 BLOCKER + 0 MAJOR + 0
MINOR + 2 NIT. After the full hostile sweep, only two
statement-level nits survived. Codex remains infra-blocked
(twelfth documented attempt).

---

## SMR33-1 (NIT) — the union generalization + the stealer's subsumption

My v8.28 note proves the single-gap union ((A∪C)\C2). Two
strengthenings worth one sentence each: (i) the rule
generalizes — N successive gaps (C2…Ck) leave the stealer
composing A→Ck and the union exactly (A∪C∪…∪Ck-1)\Ck (the
drain-time-EXPOSED-at-each-entry rule, not a new case); and
(ii) the stealer's own delete set is SUBSUMED by the other two
(A\C2 ⊆ (A\C) ∪ (C\C2) — elementwise: an A-authorized,
C2-revoked session is either C-authorized (in C\C2) or not
(in A\C)) — so the stealer provably CANNOT over-delete beyond
the already-correct union, which is the strongest form of the
safety argument and should replace the bare "idempotent"
phrasing.

## SMR33-2 (NIT) — C1's skipped push has its coverage statement

In the gap case, C1's entry's push phase is skipped by the
currency gate (C1 no longer store-active): the peer's
convergence rides C2's own push (C2's wrapper/sender tails)
or the periodic reconciler's next trigger edge (the marker
shows last-sent < current) — never a stuck peer, stated (the
crash rule's re-derivation (exposed < active ⇒ re-run
exposed→active) is the backstop for anything skipped).

## Attack trace (what I tried, and why it fails to break v8.28)

1. **The steal-timer × the ladder.** The steal fires at
   claimedAt + the entry's CURRENT ladder step (a steal is a
   failure by construction and advances the ladder) — never a
   fixed spin and never before the named bound. Coherent.
2. **The gap × the stamp CAS.** C2's wrapper stamps C2 (CAS
   passes); the stealer's stamp for C1 is skipped by the
   store-currency gate (C1 not store-active) before the CAS
   is even consulted — two layers, no regression either way.
   Coherent.
3. **The gap × the push.** C1's push skipped (currency); C2's
   own push carries the newer config; the reconciler's marker
   (last-sent < current) re-drives it if C2's push was itself
   held (SMR23-7's hold rule) — the peer never leads the
   primary's exposed state and always converges. Coherent
   (SMR33-2 states it).
4. **The record-before-timer.** A fast drain records complete
   before the namedBound; the steal-timer is cancelled in the
   same `m.mu` op as the record — no post-completion steal.
   Coherent.
5. **The no-gap stolen case.** The stealer completes ALL
   phases (the pair is still store-active — stamp CAS passes,
   push lands) and the entry completes (not SUPERSEDED) — the
   SUPERSEDED form is exactly the gap case. Coherent.
6. **Q1, thirty-third enumeration.** The v8.28 mechanics
   (C2-gap note, stamp prose, timer note, §9 (a) assertion)
   mutate NO binding slots on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
7. **The r32 disposition table.** Every row re-derived against
   the file: SMR32-1 (the note + §9 (a)), AGY f2 (the prose),
   SMR32-2 (the timer) — all present and correctly cited.
8. **The full-model residual sweep.** The remaining live
   machinery across v8.18-v8.28 (restartSuppressed, the
   deferred arm, the listener + currency gate + drain-time
   composition, the registry + OVERLAP clear + liveness, the
   stage timeout, the fence registry + read discipline, the
   settlement lifecycle, the structured send + closures, the
   cursor tri-state + lease + fences + GC + iterate + backoff)
   — each component's cross-connections re-walked; no
   unwalked seam remains that I can find at MINOR or above.

## Required for convergence

Nothing mandatory. Optional for v8.29 (or `/engineer`-time):
SMR33-1's generalization + subsumption sentence; SMR33-2's
push-coverage sentence. AGY r33 pending at this writing — its
verdict may add to this list (a DEMAND from AGY returns the
loop to the fold).

**Verdict: PLAN-READY-WITH-NITS** (2 NIT — the first SMR
non-DEMAND verdict of the campaign; the attack trace stands as
the evidence it is not a soft pass).
