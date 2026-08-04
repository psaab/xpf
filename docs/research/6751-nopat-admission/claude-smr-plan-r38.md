# Claude SMR hostile plan review — #6751 plan v15.26 (round 37 fold-check + the fold-landing audit)

Reviewer: Claude SMR. Posture: hostile — v15.26 folds AGY r37's two
nits and Codex r37's blocker/major/minors, and this pass is
DOUBLE: the substance, and the process failure the round exposed.
Codex r38 and AGY r38 have not been dispatched yet.

## The process failure, owned

Codex r37 said the §9 pins and the Rule 6 incarnation text were
absent; AGY r37 said they were present at specific lines. Both
could not be right. The audit found: (1) three of my earlier
python replace folds (v15.24 finding-4 daemon-issued incarnation,
v15.25 n5 normative text, v15.25 m4 §9 pins) silently no-opped on
line-wrap mismatches — python `str.replace` with a missed target
fails silently, and my "applied" prints fired regardless; (2) the
v15.23-era text they were meant to replace (the "(boot epoch)"
phrasing) was still in the rule body, and BOTH reviewers read
real text — Codex the stale sentence, AGY the header summary,
which AGY then hallucinated into a line-cited §9 verification.
The repairs in v15.26 are grep-verified, and every fold since now
asserts its target before replacing. The reviewer-visible
consequence (two reviewers citing contradictory "facts" about the
same lines) is exactly the failure mode the hostile-review loop
exists to catch, and it caught it — one round late.

## B1 fold (generation-bound admission), attacked

The generation-binding closes the pre-install-child seam Codex
executed: children stamped at Accept/dial completion, pre-fence
children (tracked AND untracked) killed before the drain clock
starts, stale-stamp children rejected at every later stage. The
one residual I can construct: a child accepted DURING the kill
sweep (accepted after the sweep started but before the listener
fully closed) — the sweep must either re-check after listener
close or the generation stamp itself is the guard (the child's
stamp predates the fence's current generation, so its later
stages reject it regardless of when it was accepted). The fold
has the stamp as the stage-independent guard, so the seam is
closed even if the kill sweep misses the accept. Sound.
The old peer's local install of an accepted child (unkeyed setup
is immediate, sync_auth.go:329) happens on the PEER's side — our
fence cannot prevent the peer from installing its own accepted
connection; what it prevents is that connection surviving as a
VALID peer of ours: the peer's local C0, installed before our
fence, dies on the peer's own disconnect-detection bound once our
listener refuses the retry stream — which is exactly what the
quiet interval's bound covers. The counterexample Codex gave (C0
surviving past expiry) required the retry stream to keep C0's
peer-side timers alive; the transport refusal stops that stream.
Sound.

## M2 fold (no window clearing; suspect owes a prime), attacked

The 5s window was never definitive (lost-base alias == base value,
daemon_ha_userspace_convert.go:399); clearing only via the
complete-prime pass or the row's own close is the only honest
rule, and the owed-prime-with-fence-bound gives the genuine row a
real release path instead of "the next bulk, whenever." The
residual (suppression until session lifetime when the prime never
completes) is the documented, already-accepted class.
Attack: the prime-REQUEST's own liveness vs the re-fence — a
receiver that fences for every suspect under a legacy-alias storm
fences repeatedly; the fence cycle is ~2.5 × keepalive, and the
readiness timeout is the terminal bound. Bounded, priced, and
vastly better than a wrong clear.

## m3 fold (stage carrier inventory), verified

The "NO alias-specific handling" text is replaced by the precise
ownership-vs-metadata distinction with the four carrier surfaces
named and the four §9 tests pinned.

## §9 repair, verified line-by-line this time

All four inserted blocks grep-verify present: the PATH-A
transaction suite, the failure-semantics pins (worker refusal →
Failed + fence; purge failure → Failed; timeout/unknown →
Pending + teardown; (E2,1)-after-(E1,100); stale-replica; S_new
reverse resolution — AGY r32 nit 2, which had ALSO silently
failed to land two rounds earlier), the alias-stage propagation
suite, and the pre-install children fence suite with both stalls
named.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.26 that
I can construct, and the plan's text now matches its claims under
grep, not just under authorship intent. Both forks remain settled;
the option-(a) core is untouched. Process nit for the rest of the
campaign: every fold must assert-and-verify, and reviewer
line-citations should be spot-checked against the blob before
being quoted in round comments (AGY's hallucinated line cites this
round were confidently wrong). If Codex r38 and AGY r38 converge,
this is terminal.
