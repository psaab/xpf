# AGY plan review — round 32 — #6749 armed-state plan v8.27 (a5f2918c7)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r32-prompt.txt` (130,809 bytes —
r31 transport + the r31 table swapped in, the v8.27 normative edits
replayed, the boilerplate rewritten + compressed for the v8.27
deltas). Raw output: `/tmp/agy-6749-r32.out`. Background bash
`b693dqva6` (direct `agy --print-timeout 9m --print`).

**Verdict: PLAN-READY-WITH-NITS** (1 MINOR + 1 NIT) — the second
non-DEMAND verdict of the campaign, with the mid-drain trace
assessed "mathematically sound" and the cancellation partition
accepted.

---

1. **[MINOR] Missing explicit C2-interpose steal assertion in §9
   (a)** (plan §9 (a)): the interleaving assertion covers the
   steal-mid-execution case but not the successor exposure C2
   landing BETWEEN the stale drain's `applySem` release and the
   stealer's acquire — the stealer must compose A→C2
   idempotently, detect C1 as non-store-active (skipping its
   stamp/push), and mark C1 SUPERSEDED. (= SMR r32 SMR32-1's
   C2-gap note; folded v8.28 in §5-C (ii) (the union proof:
   stale A→C + C2's own C→C2 + stealer A→C2 deletes exactly
   (A∪C)\C2 with every C2-permitted session surviving — the
   drain-time-EXPOSED-at-each-entry rule is what makes the
   union correct — plus the two entries' independence) AND the
   §9 (a) C2-interpose assertion.)
2. **[NIT] "A second identical stamp CAS on the same value" prose
   precision** (plan §5-C (ii)): when the store revision moved
   before the stealer's entry, the stealer does not CAS — the
   store-currency gate skips the stamp entirely. Folded v8.28
   (" (or skipped via store-currency gating when the pair is no
   longer store-active)").

Evidence wishes (informational): `setAppliedDigest`'s exact
signature/lock order; the `phaseCursor` struct layout and
generation counter overflow handling.

PLAN-READY-WITH-NITS
