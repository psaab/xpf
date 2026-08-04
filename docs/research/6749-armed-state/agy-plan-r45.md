# AGY plan review — round 45 — #6749 armed-state plan v8.40 (c13b6da34)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r45-prompt.txt` (127,696 argv
bytes — the r44 transport with the r44 table swapped for the v8.40
normative edits replayed, staged via `/tmp/agy-6749-r45-stage1.txt`
(132,595 bytes) and trimmed byte-by-byte to fit MAX_ARG_STRLEN).
Raw output: `/tmp/agy-6749-r45.out` (4,426 bytes, `AGY-EXIT=0`,
empty stderr). Dispatched by the prior session (direct `agy
--print-timeout 9m --print`); output collected and evaluated this
session.

**Verdict: PLAN-READY-WITH-NITS** (1 MINOR + 2 NIT). AGY's own
attack-surface summary: "New Hazards: None introduced by v8.40.
`stopLocked()` resetting `publishedSnapshot = 0` correctly handles
dedup suppression across both helper respawn and plan-change
restarts." The §1 r44 disposition table audit: "The 6 rows in §1
correctly map and fold all r44 findings (AGY f1-f4 and SMR44-1-2)."

---

1. **[MINOR] Test plan gap for the DIRECT (Compile-leg)
   same-content dedup** (plan §9 item 20 (a)): §5-C (ii)
   establishes the dual division — deferred-leg same-content
   commits ride the catch-up completion notice; direct
   (Compile-leg) same-content commits install no cursor and are
   covered by the daemon wrapper's standing Compile-leg tails
   (`capturedDigest` stamp + structured-transaction push) — but
   §9 (a) asserts only the deferred case. "An implementation could
   pass the deferred test while omitting wrapper tail execution on
   direct deduped applies." **SMR post-AGY evaluation: VALID** —
   re-derived against the item's full assertion list; folded v8.41
   (§9 (a) gains the direct-case assertion: the wrapper tails
   STILL execute + `ActiveApplied() == true`; a skip FAILS).
2. **[NIT] §11 item 6 stale heading** ("Round-22 disposition table
   audit ... left un-updated from v8.18", cited at
   `plan.md#L1106`): **SMR post-AGY evaluation: NOT-VERIFIED** —
   the committed blob's §11 item 6 (plan.md:10779 @ `c13b6da34`)
   already reads "Round-44 disposition table audit" and maps the
   r44 findings to the v8.40 fold; the L1106 citation does not
   match the reviewed file. Folded anyway as the standing per-round
   maintenance (item 6 re-points to the r45 table / v8.41).
3. **[NIT] `acceptedCommitRevision` persistence across respawns
   unstated** (plan §5-C (ii)): the disambiguation separates the
   echo-0 owner from the GO-LOCAL comparator but never says WHY
   the comparator evaluates false on a fresh-helper respawn —
   `m.acceptedCommitRevision` is manager-side lineage state that
   persists across helper process restarts. "To prevent
   implementers from mistakenly resetting `m.acceptedCommitRevision`
   on helper process exit." **SMR post-AGY evaluation: VALID as a
   documentation gap** (the semantic was entailed, never stated);
   folded v8.41 (§5-C (ii) states the structural-quietness
   sentence).

Evidence residue (informational): AGY's wedged-helper note
("a non-responsive wedged helper times out on control requests and
is owned by the control-failure recovery class (which calls
`stopLocked()`, converting it to helper death)") converges with
SMR45-2's wedge-vs-death posture sentence — both fold in v8.41.

PLAN-READY-WITH-NITS
