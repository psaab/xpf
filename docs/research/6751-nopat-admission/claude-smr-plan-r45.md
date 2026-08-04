# Claude SMR hostile plan review — #6751 plan v15.33 (round 44 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.33 folds Codex r44's
three blockers + minor + nit (AGY r44 converged PLAN-READY with
zero findings). Codex r44 verified the evidence/authority split is
behaviorally sound (legacy ids decode to zero, pinned by the 5212
test); the remaining work was consistency, which is now applied.
Codex r45 and AGY r45 have not been dispatched yet.

## B1 fold (five passages carry the split inline), verified

The four passages Codex named (:704/:2423's "no confirmation, no
purge", :2490/:3071's unconditional insertion confirmation,
:2561's P1-every-BulkEnd, :2644's poisoned-companion absolute)
now each carry the evidence-vs-authority qualifier inline: the
FRAMING-ONLY rule governs window-authority decisions only; the
insertion confirmation stays evidence-based on every window class
(id=0 fails by itself on a true old-sender window — the behavior
Codex verified against sync_protocol.go:491 and the 5212 test);
P1 re-evaluates only at completed capability-advertising BulkEnds;
the companion prevention is scoped to id-capable windows. A
grep sweep of 'definitive' and 'confirm' shows no remaining
unconditional use.

## B2 fold (mode-aware commit predicate), attacked

The never-connected release contradicted its own commit predicate
(the lifecycle rule required connected-state validation, which is
exactly what the never-connected case cannot satisfy). The
mode-aware predicate: the event carries the connection epoch AT
ARMING, and the commit unit branches on (arming epoch, current
epoch): (0, 0) → cold-start degraded release; (>0, changed) →
invalidated (no release — the no-release-without-reconnect
invariant at session_sync_readiness_test.go:33 survives);
(>0, unchanged) → normal release.
Attack 1 — the epoch-zero collision: two successive cold boots
both have arming epoch zero. Does a stale event from boot N commit
in boot N+1 (both epoch 0)? The event's lifecycle TAG
((abortGeneration, lifecycleSequence)) is the ordering token —
the abortGeneration advances on any teardown, and a cold-start
event from a prior boot fails the tag CAS even with identical
connection epochs. The epoch comparison is the mode selector, not
the ordering token. Sound.
Attack 2 — a cold start that connects DURING the bound: the arming
epoch transitions 0 → 1; the event's commit sees current epoch 1
≠ arming epoch 0... does the cold-start release fire into a
half-connected state? The mode rule's branch (i) requires "still
zero at commit" — a commit after the epoch advanced falls to
branch (ii) or (iii): invalidated (epoch changed) — the correct
outcome: the freshly-connected peer's own bulk path drives
readiness normally. Sound.

## B3 fold (one shared sessionSyncConfigured predicate), verified

The predicate ("session sync configured with a usable endpoint
pair — control-link OR fabric — regardless of takeover mode")
now governs BOTH the gate's configured check AND the cold-start
timer's arming, so control-link-only private RG and
NoRethVRRP && !PrivateRGElection never-connected starts get the
bound identically. The two previously-split arming sites
(daemon_run_bringup.go:229's fabric-pair-only arm and
daemon_ha_sync.go:81's connection-required arm) collapse into
one.

## m4/n5 folds, verified

The cold-start bound is named as the existing syncReadyTimeout
(daemon.go:1148); §9 pins all four regression cases
(simultaneous-never-connected, control-link-only, whole direct
domain, peer-dead election state); the recap names all seven
events including abort.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.33 that
I can construct. Both forks remain settled; the option-(a) core is
untouched. If Codex r45 and AGY r45 converge, this is terminal.
