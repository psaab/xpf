# Claude SMR hostile plan review — #6751 plan v15.11 (round 24 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.11 folds Codex r24's two
blockers and one major, and all three are the kind of finding that
proves the reviewers are still earning their keep: my v15.10 "atomic
under the lifecycle lock" claim was check-then-store in disguise, the
journal-envelope guard covered only one of four outbound flow shapes,
and the cap-recovery bulk re-arms itself through its own stamping
path. This pass verifies the three folds against the pinned code and
attacks their edges. Codex r25 has not been dispatched yet.

## Generation-tagged CAS lifecycle commits, verified

Codex r24 blocker 1's two sub-points are both closed by the CAS shape,
not by any lock: (a) the check-then-store window disappears because
there IS no check step — the (generation, value) pair commits by
compare-and-swap that refuses to move backward, so a stale connect's
`true` cannot overwrite a newer disconnect's `false` even if the
detach lands between any two instructions of the callback; (b) the
disconnect callback is now symmetrically guarded — a stale
disconnect's `false` fails the same CAS because the stored generation
is newer, closing the old-disconnect-after-new-connect case Codex
named explicitly (daemon_ha_sync.go:109 vs :51). The complete
inventory (connect :51/:68/:81, disconnect :109, bulk-received :90,
bulk-ack-received :103) is named, and §9 pins one race per callback
plus the two named races. The monotonic-advance rule is the only
correct shape here — any design with a separate validation step has
the window, and this one does not.

## Epoch-bound send guard at the send effect point, verified

Codex r24 blocker 2's evidence chain is accurate: `QueueDeleteV4/V6`
journals only on `queueMessage` FAILURE (sync_conn_write.go:36/77);
successful deltas enter `sendCh` DIRECTLY as raw `[]byte`; and
`sendLoop` can dequeue one, wait indefinitely for any active
connection, and send it over a REPLACEMENT connection
(sync_conn_write.go:135/268). The journal-envelope guard (binding at
enqueue) could never cover the direct path or the already-dequeued
retry. The v15.11 guard binds at the DEQUEUE/SEND effect point: every
outbound delta (upsert, delete, journal replay, direct raw-byte,
already-dequeued retry) is epoch-bound at dequeue, and the sendLoop
discards any delta whose bound epoch is older than the connection it
would send on. The discard is safe because the new epoch's cold-prime
bulk is the authoritative backstop — every still-valid session is
re-conveyed by it, so nothing is lost by dropping pre-reset deltas.
All four flow shapes are covered uniformly by one rule at the one
point they all pass through (the actual send effect).

## Episode latch + anti-self-rearm, verified

Codex r24 major 3's self-trigger chain is real: `putGenBounded`
refuses every unseen key at capacity, `BulkSync` itself stamps every
session via `stampInstallGenV4/V6` (sync_bulk.go:95/135), so a
refusal-armed bulk re-arms its successor, and the one-second sweep
(sync_conn_sweep.go:47/118) makes the cycle perpetual. The v15.11
rule set closes it on three axes: (i) coalescing on a dirty/pending
flag with a minimum inter-bulk cooldown; (ii) the EPISODE LATCH
permitting at most one recovery bulk per window; (iii) refusals caused
by `stampInstallGenV4/V6` DURING an active recovery bulk being
recorded but barred from arming the next episode until the cooldown
expires AND a new non-bulk-triggered refusal occurs — so a recovery
bulk can never re-arm itself. The latch rule (iii) is the load-bearing
one; (i)-(ii) bound the rate.

## Attacks attempted

- Does the epoch-bound send guard drop VALID deltas on a NORMAL
  (non-abort) reconnect? A normal reconnect advances the connection
  epoch; a delta dequeued pre-reconnect is discarded as stale — which
  is correct, because the reconnect's cold-prime bulk re-conveys the
  session state authoritatively. No valid state is lost; the bulk
  carries it.
- Does the CAS rule break any lifecycle field that is legitimately
  non-monotonic in VALUE (not generation)? The CAS orders by
  generation, not value — `syncPeerConnected` may flip true→false→true
  freely as long as the generations advance. Correct semantics.
- Does the episode latch starve cap-saturated sessions from syncing
  during the cooldown? They sync via the delta stream (unordered class,
  bounded by the next authoritative bulk — which now arrives at most
  one cooldown later by construction). Bounded, documented.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.11. The
lifecycle commits are linearizable by construction (CAS, no window),
the send guard covers every outbound flow shape at the one point they
all share (the send effect), and the cap recovery is episode-latched
with an explicit anti-self-rearm rule. If Codex r25 converges, this
is terminal.
