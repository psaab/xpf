# Claude SMR hostile plan review — #6751 plan v15.34.1 (final convergence verification, round 46/47 fold-check)

Reviewer: Claude SMR. Posture: hostile — this is the final
verification pass over the complete v15.34.1 blob (v15.34 + the
AGY r46 nit folded). Codex is infra-blocked (weekly usage quota,
reset Aug 10th; two documented attempts — the full r46 review and
a probe — both returned the quota error; the codex-infra-blocked
exception in the standing rules applies and convergence proceeds
2-of-3: Claude SMR + AGY). AGY r47 has not been dispatched yet.

## Verification of the final state

The r45/r46 folds are all grep-verified present: the epoch-pass
SNAPSHOT-AUTHORITY scoping; the deferred entry's explicit terminal
(provisional admission with alias-suspect at a legacy BulkEnd;
"never left UNRESOLVED past the row's own lifetime or the peer's
capability upgrade"; §9's "never installs a PERMANENT broken
companion"); the generation-bound live-transition arming with the
day-2 regression; the mode predicate's both-transitions epoch
selection and the branch-(ii) "current epoch != arming epoch"
precondition; the "OMITS the id field — receiver decodes zero"
terminology; the reconciliation-hold deduplication; and now the
AGY r46 nit (the deferred-overflow line carries the
capability-qualified BulkEnd resolution with the provisional
admission named).

## Final hostile sweep

I ran the contradiction-class sweep one last time over the full
blob: 'definitive' (every remaining use is capability-qualified or
the by-definition COMPLETE-PRIME pass), 'never confirms' (none
unscoped), 'every completed BulkEnd' (all capability-qualified),
'current store' as a confirmation source (none — the decode-time
base-identity index is the named source everywhere), '2.5×' or
'7.5s' (none), the six-event parenthetical (now seven including
abort), and the poisoned-companion absolute (scoped to id-capable
windows). All clean. The text-level contradiction class that
produced the last six rounds of findings is exhausted — and this
time the claim is grep-backed, not asserted.

The remaining nits are implementation-level by construction: the
exact fence-generation primitive naming, the cold-start bound's
concrete multiple (named as the existing syncReadyTimeout), and
the stage field's wire enum values. These are PR decisions with
tests pinned, not plan defects.

## Verdict

**PLAN-READY-WITH-NITS** — and, on the complete final blob, this
is my terminal verdict: both forks (behavior option (a),
substrate PATH A) are settled, the option-(a) core has survived
four independent no-kill-shot confirmations plus Codex's explicit
behavioral verification of the evidence/authority split, and no
BLOCKER or MAJOR survives that I can construct. If AGY r47
converges (its r40 and r44 verdicts were already clean
PLAN-READYs), the research is PLAN-READY.
