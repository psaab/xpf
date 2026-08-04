# AGY plan review — round 25 — #6749 armed-state plan v8.20 (783c9581d)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r25-prompt.txt` (124,510 bytes —
r24 transport + the r24 table swapped in, the v8.20 normative edits
replayed, the boilerplate rewritten for the v8.20 deltas). Raw
output: `/tmp/agy-6749-r25.out`. Background bash `b4kevrgzs`
(direct `agy --print-timeout 9m --print`).

**Verdict: PLAN-READY-WITH-NITS** (2 MINOR + 2 NIT) — the first
non-DEMAND verdict of the campaign on this issue.

---

1. **[MINOR] §9 (a) assertion repeats `C-permitted` in the deletion
   clause** — VERIFIED a PROMPT-TRANSPORT typo: the r25 review
   prompt's §9 (a) replay read "an A-permitted, B-revoked,
   C-permitted session is deleted", but plan.md's §9 (a) already
   reads `C-revoked` (the v8.20 §9 (a) edit used the correct form;
   the r25 prompt-build script's replay mistyped it). No plan
   defect; recorded in the r25 disposition table as
   CLOSED-NO-PLAN-DEFECT.
2. **[MINOR] The SMR24-1 disposition row's SUPERSEDED rationale is
   inaccurate** (= SMR r25 SMR25-1): "the newer pair's chain covers
   the composition" is the abort-only leak SMR24-1 traced (C's B→C
   delta never covers A-permitted/B-revoked/C-revoked sessions);
   SUPERSEDED must mark ONLY the stamp/push skipped-by-design while
   the prior → CURRENT invalidation RUNS. Folded v8.21 in the
   normative text AND the r24 table row + the §9 (a) pin (a
   skip-everything implementation fails).
3. **[NIT] The pending-cursor sweep's `applySem` acquisition is
   unpinned** (= SMR r25 SMR25-2): folded v8.21 — the sweep rides
   the 1s status-application pass and its per-entry execution is
   the SAME `applySem`-acquiring drain path as the notice's (one
   routine, two triggers).
4. **[NIT] Evidence wish** — the v8.20 notice-drain handler and the
   manager cursor method signatures (new machinery; no source yet —
   plan-level only at research stage).

Evidence wishes (informational): the new daemon notice-drain loop,
the manager-side cursor check-and-advance method, the sweep
routine.

PLAN-READY-WITH-NITS
