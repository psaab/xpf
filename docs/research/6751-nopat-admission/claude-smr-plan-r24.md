# Claude SMR hostile plan review — #6751 plan v15.10 (round 23 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.10 folds Codex r23's two
blockers, both of which are "the plan claimed X and the code pins
not-X" findings: the callback's lifecycle mutations are NOT convergent
(and my r23 review's claim that "convergent work is the whole callback"
was overbroad), and #2170's ordering is NOT universal (deliberate cap
and zero-generation escape hatches my r23 review accepted from AGY's
verification without checking the caps myself). This review owns both
errors and verifies the folds against the pinned code. Codex r24 has
not been dispatched yet.

## Owning the r23 errors

My r23 review asserted the callback's work is convergent because it
reads current state. Codex r23 showed the callback FIRST invokes
`onSessionSyncPeerConnected` (daemon_ha_sync.go:934), whose mutations
(syncPeerConnected=true, connection epoch advance, heartbeat-suppression
reset, bulk-prime flag clearing, readiness arming — :51/:68/:81) are
unconditional lifecycle writes, not convergent reads. And my acceptance
of the #2170-covers-everything claim missed the deliberate degrades
(sync_conn_gen.go:23/45 cap at 200k keys; :176 generation-0 deletes;
:263 unconditional gen-0 delete behavior pinned by
sync_gen_guard_test.go:128; :233 receiver-cap no-high-water pinned by
:635; :830 tombstone-clear-then-resurrect reorder). Both folds are
necessary; I verify them below.

## Class-(b) generation-ordering, verified

The fold splits the callback into (a) convergent reads (verified by
AGY r23: `clusterConfig()`, `nudgeDHCPLeaseSync()`,
`nudgeIPsecSASync()`, `reconcileConfigSyncToPeer("peer-connect")` all
evaluate live daemon state at execution) and (b) lifecycle mutations
generation-ordered AT THEIR COMMIT POINT. The commit-point rule
(revalidate abort generation not advanced AND slot still admitted at
each lifecycle state store) closes the connect-after-disconnect race
(the disconnect callback's `syncPeerConnected=false` at
daemon_ha_sync.go:109 cannot be overwritten by a stale connect
callback's `true`, because the stale write's generation fails the
commit guard). The rule uses the same commit-time guard as clause (4)
— one guard, applied at every mutation point including daemon
lifecycle state, which is the only consistent shape. The pinned test
(abort after callback launch but before state commit) covers exactly
the race Codex constructed.

## Journal three-layer disposition, verified

- Layer (a) abort-generation-bound envelopes: prevents the
  ABORT-adjacent resurrection/kill — the reorder this issue's abort
  lifecycle can create. Cheap (envelope-level stamp + drain-time
  check), no per-message semantics change.
- Layer (b) zero-generation / cap-saturated replay as the documented
  UNORDERED class: the honest classification — those replays carry no
  ordering information by design (the caps are deliberate
  memory-bounds, sync_conn_gen.go:23/45), and their reorder damage is
  bounded by the next authoritative bulk reconcile, which is the sync
  protocol's convergence backstop for everything. The fold does NOT
  pretend the caps are guardable.
- Layer (c) sender-cap → fresh authoritative bulk drive: converts
  saturation from an unordered-delta posture to a bulk-driven
  (authoritative) cadence for the affected keys. Clean — the bulk
  needs no per-key ordering.
- The gen-0 tombstone-clearing residual (sync_gen_guard_test.go:128/
  635/830) is correctly scoped OUT: it is pinned #2221-family behavior
  with its own tests, changing it is its own issue, and the
  abort-envelope guard prevents the ABORT-SPECIFIC instance. Honest
  scoping.

## Attacks attempted

- Does the class-(b) commit guard deadlock with the serialized loop?
  The guard is one atomic load at each lifecycle store (same as clause
  (4) everywhere) — no lock ordering change.
- Does layer (a)'s envelope discard lose VALID replays after a normal
  (non-abort) reconnect? The envelope binds the ADMISSION generation,
  not just the abort generation; a normal reconnect advances the slot
  generation, and a replay queued pre-reconnect is... discarded at
  drain (stale binding) — which is CORRECT: the pre-reconnect replay
  is superseded by the reconnect's cold-prime bulk, which is
  authoritative. No valid state is lost (the bulk re-sends it).
- Does the fresh-bulk-on-cap trigger storm under persistent
  saturation? Bounded by the bulk machinery's own pacing (a bulk per
  trigger edge, not per key) — noted for implementation.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.10. The
callback lifecycle is generation-ordered at commit, the journal has an
honest three-layer disposition (abort-envelope guard, unordered-class
bounding by authoritative reconcile, cap-driven bulk fallback), and
the residual #2221 window is correctly scoped out with a named
follow-up. If Codex r24 converges, this is terminal.
