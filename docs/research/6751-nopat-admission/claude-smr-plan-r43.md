# Claude SMR hostile plan review — #6751 plan v15.31 (round 42 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.31 folds Codex r42's
four blockers + two majors + nit and AGY r42's two nits. One of the
blockers (fence engagement never armed the hold) was a genuine
logic hole, not a text contradiction; this pass attacks it and the
conditioned private-RG gate hardest. Codex r43 and AGY r43 have not
been dispatched yet.

## B1 fold (retained-text scoping, final sweep), attacked

The three remaining un-scoped spots (confirm-at-insertion's index
text, the every-BulkEnd-definitive index scoping, and the §9
recaps) now carry the capability qualifier, and the legacy-window
resolution names the decode-time base-identity index as the
predicate's source with the impossible "current store" corrected
(M6 folded in the same passage). I grep-swept 'definitive' across
the blob: every remaining use is either scoped by the capability
qualifier or is the COMPLETE-PRIME definitive pass (which is by
definition capability-advertising). The contradiction class is
exhausted at the text level.

## B2/B3 fold (fence-state revalidation + engagement arms the hold), attacked

The logic hole was real: without engagement-side arming, the
fence's degraded release was a no-op against the #466
warm-disconnect preserve rule. The fold: the fence-engagement
lifecycle event's commit unit SETS SYNC READINESS FALSE with its
tag AND re-arms the classic RETH VRRP sync hold via the startup
path; the #466 preserve rule survives for ordinary unfenced
disconnects.
Attack 1 — does engagement-side readiness-false regress the
ordinary disconnect case? The arming happens only in the
fence-engagement event's commit unit; ordinary disconnects still
hit the #466 preserve path unchanged. The two paths are disjoint
by event type. Sound.
Attack 2 — re-arming the classic hold vs its 30s bound: the
re-arm uses the same startup path (daemon_run_bringup.go:226-239
/ vrrp/manager.go:351-376), so the re-armed hold inherits the
30s bound, and the fence's degraded release fires at the
fence-owned terminal within it. Ordering is coherent.

## B4 fold (gate conditioned on sync configured), attacked

Attack 3 — the predicate's exact shape: the gate engages only when
chassis-cluster session sync is configured with fabric endpoints
(the same arming predicate as the startup release timer,
daemon_run_bringup.go:238-240). A default private-RG cluster
(PrivateRGElection=true by default, no sync config) is a no-op —
today's behavior exactly. A sync-configured private-RG cluster
gets the gate. The §9 no-op case is pinned. The stranded-cluster
class (gate with nothing to wait for) dies by construction.

## M5 fold (§8 pricing + §9 refusal + permissive-test update), verified

The deliberate-policy reversal is priced with its history refs
(issue-history.md:8513-8527 / pr-history.md:4277-4289), the
failover delay is compared to the classic RETH VRRP hold's
accepted class, and the existing permissive expectation at
vip_readiness_test.go:345-389 is explicitly updated alongside —
not silently contradicted.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.31 that
I can construct, and the text-level contradiction class appears
exhausted (grep-verified this time, not assumed). Both forks
remain settled; the option-(a) core is untouched. If Codex r43
and AGY r43 converge, this is terminal.
