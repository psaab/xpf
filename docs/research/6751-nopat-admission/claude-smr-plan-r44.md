# Claude SMR hostile plan review — #6751 plan v15.32 (round 43 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.32 folds Codex r43's
four blockers + minor and AGY r43's nit. Two of the four are the
first findings in many rounds about the plan's own new machinery
being wrong (the evidence-vs-authority split and the
never-connected terminal) rather than text placement. Codex r44
and AGY r44 have not been dispatched yet.

## B1 fold (evidence-based insertion confirmation vs window-authority decisions), attacked

The v15.29-v15.31 capability-gate text had over-broadened: "a
non-capable window NEVER confirms" would have forbidden the
decode-time insertion confirmation on windows where it is exactly
correct. The fold's split: insertion confirmation is
EVIDENCE-BASED (equal NON-ZERO ids — intrinsic per-frame evidence,
correct on any window; a true old-sender's id=0 frames fail the
predicate by themselves), while the capability gate governs
WINDOW-AUTHORITY decisions (definitive pass, lineage clears,
purges — the deferred "definitive BulkEnd" and P1 re-evaluation
are capability-qualified, and the "prevents poisoned companions"
absolute is scoped to id-capable windows).
Attack 1 — the mixed deployment the split serves: new sender that
has not yet learned the receiver's advertisement (pre-learn window
within new↔new) emits nonzero-id aliases; the insertion
confirmation drops them cleanly. Under the over-broad rule those
aliases would have been admitted as canonical — the exact broken
companion the quarantine exists to prevent. The split is not a
weakening; it is the quarantine's actual designed cell.
Attack 2 — can a malicious/buggy sender forge equal nonzero ids to
get its aliases confirmed? The ids are the sender's own stable
session ids; the confirmation requires the alias's id to equal the
sibling BASE's id (the pair shares one id by construction of the
derivation). A forged pair would need the base's actual id — which
the attacker already controls if they control the sender; at that
point the sender is trusted infrastructure, and the receiver's
 defenses are about correctness, not adversarial senders (the
cluster stream is PSK-authenticated). Sound.

## B2 fold (whole direct domain + endpoint-pair predicate + peer-dead bypass survives), attacked

Attack 3 — the endpoint-pair predicate's completeness: control-link
preferred, fabric fallback (daemon_ha_sync.go:774). A deployment
with BOTH configured uses control-link; one with only fabric uses
fabric; one with neither is unconfigured (no-op). All three
classified correctly.
Attack 4 — the peer-dead bypass's survival vs the gate: crash
takeover (peer dead) is ungated (election.go:427) — the gate
applies to election decisions with a LIVE peer. §9 tests election
state, not merely RG.Ready. Correct: a dead peer means no sync is
possible anyway, and availability-first is the designed posture.

## B3 fold (never-connected cold-start bounded release), attacked

Attack 5 — does the cold-start degraded release re-introduce the
split-brain the no-release rule guards? The release fires at the
cold-start bound EVEN when never connected — but takeover then
proceeds by NORMAL VRRP PRIORITY with the heartbeat-alive
precondition. Heartbeat alive means the peer is up; VRRP priority
elects exactly one master; the gate's delay only suppressed the
would-be-master's ELIGIBILITY during the bound. First-ever boot:
both take over by priority with empty tables (designed). Reboot
with sessions: the would-be-master takes over with its OWN table
(its own sessions, correct) and syncs when TCP recovers. The
no-release-without-reconnect regression
(session_sync_readiness_test.go:33) survives for the
connected-then-disconnected case it was written for. Coherent.

## B4 fold (re-arm through the lifecycle queue), verified

The shared-pointer stale-timer race (old callback resumes after a
new fence's re-arm, observes syncHold==true, releases the NEW hold
and stops the NEW timer, manager.go:354/372/389) dies because the
re-arm never installs an independent untagged AfterFunc — the
hold's release commits only inside the current fence generation's
lifecycle event (or the fence-owned terminal is the sole release
path). §9 pins the stale expiry explicitly (fire old expiry after
higher-generation re-arm; assert no readiness flip, no VRRP-hold
release, no private-gate release).

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.32 that
I can construct. Both forks remain settled; the option-(a) core is
untouched. If Codex r44 and AGY r44 converge, this is terminal.
