# Claude SMR hostile plan review — #6751 plan v15.27 (round 38 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.27 folds AGY r38's two
nits and Codex r38's two blockers + two majors + minor. The two
blockers are the fourth and fifth refinements of the re-prime
fence; this pass attacks them hardest, because each refinement has
been one layer shallower than the race. Codex r39 and AGY r39 have
not been dispatched yet.

## B1 fold (accept-proof window), attacked

The v15.26 generation-binding stamped children at Accept but let a
mid-window accept take the CURRENT generation and stall through to
release. The v15.27 rule: (i) `Accept` refuses atomically while
the fence is engaged — no stamp is issued, so no mid-window child
can exist to stall; (ii) the generation advances AGAIN at release
(after listener quiescence + final sweep), so any residual
mid-window stamp is stale at release.
Attack 1 — the accept-refusal atomicity: `Accept` in Go is a
blocking call on the listener; the fence's refusal must be a
check between Accept's return and the stamp's issuance, in the
same critical section as the stamp — the plan's "atomically"
means: the fence-engaged flag and the stamp are read/issued under
one lock, so a child either gets a pre-fence stamp (killed by the
sweep / rejected later) or is refused outright. The sweep's own
snapshot-unlock-close order (sync_admission.go:111) is covered by
(ii): anything that slipped past the sweep with a mid-window stamp
is stale after the release-side advance. Both seams closed; §9
pins accept-after-sweep-start → resume-after-release.
Attack 2 — does the release-side advance break legitimate
post-release admissions? Post-release children are stamped with
the NEW generation at their Accept (after release), so they are
current by construction; only mid-window stamps go stale. Sound.

## B2 fold (two-mode both-empty proof), attacked

The legacy no-heartbeat-ACK peer retains C0 (never redials while
registered, sync_conn.go:446; its missed-heartbeat counter never
increments, sync_conn_read.go:27). The fold's mode (ii): the
completion condition is the OBSERVED PRIME — the peer's own
needColdPrime arm is the remote-empty proof, and a missed receive
deadline re-fences.
Attack 3 — can the legacy C0 survive FOREVER, re-fencing to the
readiness timeout every time? The peer's C0 dies via its own
read-path teardown: the sync protocol carries per-frame read
deadlines (sync_protocol.go:59), and once we close our side, the
peer's pending read on C0 fails at that deadline regardless of
heartbeat-ACK behavior — UNLESS the legacy peer also lacks the
read deadline. Codex's own cite (sync_test.go:4655/4736) says the
legacy peer stays connected past the SILENCE limit, which is the
heartbeat-ACK-based detector, not the read deadline. The fold
relies on the read-path teardown being present in the legacy
implementation; if a deployment's legacy peer lacks BOTH
detectors, the terminal bound is the readiness timeout's degraded
release — documented, bounded, and strictly better than a false
proof. This residual is now explicit in the plan rather than
assumed away.

## M3 fold (disposition vs lineage), verified

The "CURRENT store as the definitive state" wording is replaced in
both §5.6 and §9: the 5s timer resolves only the quarantine
DISPOSITION; the admitted row keeps `alias-suspect` UNRESOLVED;
only the complete-prime pass or the row's own close clears. The
fail-on-timeout-clear regression is pinned. The alias-only →
timeout → clear → promote → export trace is dead at the root
(there is no clear at the window anymore).

## M4 fold (authoritative stage carrier), attacked

Attack 4 — the two-additive-fields reconciliation: §6 now names
`pub_token` AND the lineage stage, the stage rides the import
request (JSON + binary codec, additive-optional), lands in the
table via `entry.metadata` (upsert_synced.rs:64), and the
promotion Open is GATED on it (session/mod.rs:1516 emits only for
clear/unmarked rows). The one question the fold leaves to
implementation: the stage field's wire enum values (suspect /
lineage / clear) and the old-helper degradation (absence →
legacy, which is the already-ratified mixed-version posture).
Consistent end-to-end.

## m5 fold (prime-request/re-fence liveness suite), verified

Coalescing (one owed prime clears all suspects at its definitive
pass), capable-peer completion, ignored-request fence cycle, and
post-prime re-arm are all pinned — the legacy-alias storm cannot
become a tight re-fence loop.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.27 that
I can construct. The one explicitly documented residual (a legacy
peer lacking BOTH disconnect detectors re-fences until the
readiness timeout's degraded release) is honest and bounded. Both
forks remain settled; the option-(a) core is untouched. If Codex
r39 and AGY r39 converge, this is terminal.
