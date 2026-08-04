# Claude SMR hostile plan review — #6751 plan v15.34 (round 45 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.34 folds Codex r45's
three blockers + minor + two nits and AGY r45's nit. The findings
in the last three rounds have been almost entirely text placement
around an already-verified design; B3's live-transition arming is
the one substantive addition. Codex r46 and AGY r46 have not been
dispatched yet.

## B1 fold (snapshot-authority vs evidence, in the epoch-pass text), verified

The EPOCH-DEFINITIVE passage's non-capable branch now says exactly
what Codex's r45 required: the epoch pass never performs
SNAPSHOT-AUTHORITY confirmation/purge/clear, while decode-time
EVIDENCE confirmation remains allowed on every window class (and
cannot fire on a true old-sender window anyway, since its frames
decode the id to zero — the verified fact from
sync_protocol.go:491 / sync_rtflow_session_id_5212_test.go:64).
The contradiction with the insertion-confirmation passages is
resolved at the text level, matching the behavior Codex verified.

## B2 fold (explicit deferred-entry terminal), attacked

The forced choice (provisional admission at the legacy BulkEnd vs
retain quarantine) resolves as provisional admission with
alias-suspect — the ratified mixed-version cell's own position —
with the guarantee revised from "never left uninstalled
indefinitely" to "never left UNRESOLVED past the row's own
lifetime or the peer's capability upgrade".
Attack 1 — does provisional admission with the mark actually
suppress the broken companion's harm? The mark suppresses EXPORT
(the standby never re-exports the suspect row to a third party),
and the row terminates at the next capable pass, the row's close,
or the session timeout. The residual is: the RECEIVER's own
fabric-redirect path may use the provisional row during its
lifetime — which is exactly today's behavior for that row class
(the status quo, not worse, and time-bounded). The guarantee's new
shape is honest: it no longer claims what a true old sender can
never provide.
Attack 2 — the §9 "never installs a broken companion" correction
to "never installs a PERMANENT broken companion": accurate (the
provisional row is the temporary residual shape; the guarantee is
about permanence).

## B3 fold (generation-bound live-transition arming), attacked

Attack 3 — the day-2 transition's generation binding: every
FALSE→TRUE arms under the next lifecycle generation with
cancellation of the prior arming; every TRUE→FALSE cancels. The
connection-time arm at daemon_ha_sync.go:51 may never occur after
a day-2 configure (heartbeat before construction at :767, address
resolution failure at :786, retry-only dials at sync_conn.go:435)
— the config-transition arm (not the connection arm) is the
correct trigger, and it fires regardless of connection state.
The day-2 regression (configure → arms and commits; deconfigure →
cancels) is pinned. Sound, and the zero-transport restart guard
(daemon_apply_tail.go:243) is named.
Attack 4 — flapping transport configuration (day-2 churn):
each FALSE→TRUE re-arms with a strictly newer tag; the prior
arming cancels; no stale timer fires — the tag CAS handles the
churn. Bounded by the same lifecycle machinery as everything
else.

## m4/n5 folds, verified

The mode predicate's epoch advances on both transitions (not
syncPeerConnEpoch, which advances only on connect —
daemon_ha_sync.go:57/109); the branch (ii) precondition is now
"current epoch != arming epoch" (covering the
cold-start-connects-mid-bound case AGY r45 named); the old sender
"OMITS the id field — receiver decodes zero" terminology is
corrected; the reconciliation-hold sentence is deduplicated.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.34 that
I can construct. Both forks remain settled; the option-(a) core is
untouched. If Codex r46 and AGY r46 converge, this is terminal.
