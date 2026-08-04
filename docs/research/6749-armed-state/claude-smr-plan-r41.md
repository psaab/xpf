# Claude SMR plan review — round 41 — #6749 armed-state plan v8.36 (29a9ca319)

**Reviewer:** Claude SMR (hostile; the yellow-flag note stands —
and this round I walked the dedup path's interaction with the
lineage machinery BEFORE writing). Attack surface: the dedup
completion bookkeeping, the manager-local wire posture, the
auxiliary/boot notes, the §9 (a) additions, and Q1 (41st
enumeration).

**Verdict: DEMAND-REVISION** — 1 BLOCKER + 1 MINOR + 1 NIT.
The BLOCKER is self-found in my own v8.36 dedup-completion fold
(completing the tails without the convergence semantics leaves
the GO-LOCAL drain looping on every same-content pair — and
the v8.36 fold as written has that loop). Codex remains
infra-blocked (twentieth documented attempt).

---

## SMR41-1 (BLOCKER) — the dedup-completion without the convergence exemption loops the GO-LOCAL drain on same-content pairs

Walk the full same-content case in the v8.36 model (an
address-only commit landing during the XSK-startup window —
the excerpt's own scenario): the staged snapshot's forwarding
content is identical to the published one. (i) The dedup
suppresses the SEND — the helper never receives the new
generation, so the helper's stored lineage
(`commit_revision`/`publication_rev`/`snapshot_token`) stays
OLD, and there is NO observed acceptance — so
`m.acceptedCommitRevision` does not advance (it advances only
on observed acceptance, per the two-revision contract).
(ii) The v8.36 completion I folded runs the notice + stamp +
push (correct as far as it goes). (iii) But the GO-LOCAL
rule's firing condition is `ActivePair().revision >
m.acceptedCommitRevision` AND no live registration — BOTH
TRUE and STAY true: the re-drive's full-apply rebuild
produces the same snapshot, whose publish DEDUPS AGAIN (the
content is still identical), so no acceptance can EVER be
observed for the pair — the drain loops at the 60s floor
FOREVER, building and deduping the same pair (a permanent
self-inflicted version of the SMR23-1 loop the
restart-suppression marker exists to kill). (iv) And even
where the wrapper-leg handles the same-content commit (a
normal non-deferred commit), the deferred-restage variant
(the pending-XSK restage of the same pair — T1 deduped, T2
re-staged) re-enters the same path. The fold is incomplete
without the convergence semantics: the dedup match IS the
content-convergence proof, and it must be recorded as such —
(a) the dedup path marks the pair CONTENT-CONVERGED
manager-side (the active pair's forwarding hash == the
accepted snapshot's hash), and the GO-LOCAL rule and the
NONZERO helper-behind leg do NOT fire for a content-identical
gap (the convergence exemption — today's code already carries
the same-plan/hash logic this rides); (b) the completion
(push + stamp) runs from the dedup path exactly as v8.36
specifies (the stamp is digest-keyed, generation-independent
— the config's forwarding semantics ARE enforced); and (c)
the helper-lineage caveat is stated: the dedup never advances
the helper's stored lineage (no send, no observed acceptance
— the note CAS / fence keep the LAST-SENT lineage), and the
next non-deduped send converges it (the lineage is monotonic
— skipping deduped revisions is coherent).

## SMR41-2 (MINOR) — the deferred-restage same-pair variant's coverage

T1 staged and deduped (same content), T2 re-staged the same
pair (a newer restage — the OVERLAP clear discarded T1's
object): T2's content may ALSO dedup (unchanged forwarding) —
the exemption (SMR41-1 (a)) covers both (the convergence is
content-keyed, not object-keyed) and the cursor for the
newest restage owns the completion (the OVERLAP-cancelled
T1's cursor is dead per the standing rule). §9 (a) asserts
both the drain-loop absence (SMR41-1) and this variant.

## SMR41-3 (NIT) — the §6 posture sentence's precision

The manager-local pin's §6 sentence should name the zero-set
growth explicitly (the semantic hash's exclusion list gains
`capturedDigest`), not just "the builder's zero set grows".

## Attack trace (what else I tried, and why it fails to break v8.36)

1. **The helper-lineage vs the note CAS.** The note CAS's
   `expected_rev` reads the manager's accepted lineage — for
   a deduped pair the accepted lineage did not advance (no
   observed acceptance), so the CAS's expected value is the
   last-sent revision — matching the helper's stored value —
   no false refusal. Coherent (given SMR41-1 (c)).
2. **The stamp × the dedup.** The stamp is
   digest-keyed — the helper enforces content identical to
   the pair's — stamping the pair's digest records the truth
   (the pair's forwarding semantics are live). The next
   real send (a forwarding-relevant change) carries a NEW
   digest — its stamp supersedes naturally. Coherent.
3. **The push × the dedup.** The structured send transaction
   carries the pair's TEXT and revision to the peer — the
   peer's own machinery applies it independently of the
   primary's helper lineage (the peer's exposure machinery
   converges its local config — the held-push rule
   (unexposed pairs) does not apply here (the pair IS
   enforced)). Coherent.
4. **Q1, forty-first enumeration.** The v8.36 mechanics
   (dedup completion, manager-local posture, auxiliary/boot
   notes) mutate NO binding slots on any refuse/degrade
   path. No new `Registered && !Armed && state==none`
   producer. Q1 holds.
5. **The r40 disposition table.** Every row re-derived against
   the file: AGY f1 (the dedup-completion rule + §9 (a)),
   SMR40-1/AGY f2 (manager-local + zero-set), SMR40-2,
   SMR40-3, AGY f3 — all present and correctly cited.

## Required for convergence

v8.37: SMR41-1's convergence exemption (the content-converged
recording + the GO-LOCAL/helper-behind exemption + the
helper-lineage caveat) — the dedup-completion is unsafe
without it; SMR41-2's §9 (a) assertions; SMR41-3 folded.
AGY r41 pending at this writing — its verdict may add to
this list.

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MINOR + 1 NIT —
one missing semantic half of my own fold, with the shape
identified; the rest of v8.36 held).
