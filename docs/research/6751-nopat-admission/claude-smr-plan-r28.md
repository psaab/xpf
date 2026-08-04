# Claude SMR hostile plan review — #6751 plan v15.15 (round 27 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.15 folds Codex r27's two
blockers (content-order cut; authoritative recovery), its minor
(unconditional timer invalidation), and its two nits (stall seam;
flag names), plus AGY r27's nit (drain bound in the parameter
summary). The content-version binding rule (V1-V4) is NEW design
surface written for this fold, not reviewer text — this pass attacks
it hardest. Codex r28 and AGY r28 have not been dispatched yet.

## Blocker-1a fold (epoch captured at the generation stamp), attacked

The fold moves the envelope's epoch stamp from `queueMessage`
(enqueue) to the per-key generation draw (`stampInstallGenV4/V6` /
`takeDeleteGenV4/V6`). Codex's window — abort between
stamp/encode and enqueue handing pre-abort content the new epoch —
closes by construction: the content-version tuple (generation, epoch)
is minted at one point.

Attack 1 — the journal-replay path: my first draft of this fold
stamped journal replays at generation-draw too, which would have
discarded every replayed delete on the replacement connection (their
generations are drawn pre-abort) — silently killing the delete
journal's purpose. Caught and fixed before commit: the fold now
re-envelopes replays at replay-enqueue, with the journaled generation
still ordering against same-key installs and the gen-0 subset staying
in the documented unordered class. Verified against
sync_conn_write.go:69/135 and the r23 three-layer disposition (the
unordered class is bounded by the next authoritative bulk — unchanged).
Attack 2 — does any first-offer path draw NO generation? Direct
raw-byte entries (`queueMessage` callers that bypass the stamp
helpers) would stamp epoch at enqueue with no content-version point —
the fold names "direct raw-byte entry" alongside stamped deltas; the
honest reading is that such entries stamp at enqueue (their content
is built at call time, the window is internal to the caller). The
sendCh call sites (sync_conn_write.go:56/63/77/87 + journal replay)
are all covered by one of the two rules; §9's raw-byte test exercises
the enqueue-stamped shape. Acceptable; implementation must keep the
two stamp points exhaustively mapped to call sites.

## Blocker-1b fold (V1-V4 content-version binding), attacked

Attack 3 — generation-map lock does not serialize the sessions map:
true and irrelevant. The invariant needed is only that every content
CHANGE is generation-stamped (QueueSessionV4/V6 stamp; QueueDelete
draws; unqueued churn is caught by V2's live-vs-copy compare). A
change landing after the callback's live re-read draws a strictly
greater generation and resolves at the receiver in both wire orders.
Attack 4 — change-then-change-back while unqueued: live == copy, the
recorded generation is used, and the content IS current — correct by
definition of content versioning.
Attack 5 — V2 double-mint vs a racing QueueSessionV4: both serialize
on the generation-map lock (putGenBounded); frames carry their own
bound generations; the receiver takes the max. Safe.
Attack 6 — V3 omission vs the received-set: the receiver deletes K at
BulkEnd reconcile for absence — correct because the sender is
authoritative and K is genuinely gone (close tombstone durable via
the delete journal as the second leg).
Attack 7 — a dropped replacement delta (queue full) between copy and
BulkEnd: the receiver keeps the provisional stale row until the
sweep-replay/backfill (#5450) re-conveys — bounded, and identical in
shape to today's shipped in-flight-change-during-bulk behavior. Not
a regression; the (V4) note documents it.
Attack 8 — per-frame live re-read cost: one extra map lookup per bulk
frame under a Go mutex, against an already per-frame writeMu-bound,
yield-every-64 loop. Negligible.

## Blocker-2 fold (authoritative-only recovery), attacked

Attack 9 — livelock bound: "abort does not consume the episode latch"
plus owed-state persistence raises the starvation question Codex r27
(2)(d) posed. The terminal bound is explicit in the fold: the
prime-retry generation cap and the readiness-timeout degraded release
(the owed state discharges at the next scheduled prime opportunity).
Worst case equals today's shipped posture — hold released with a
possibly-stale peer table under sustained churn, which #466's
preserve-on-reconnect already tolerates. Honest, not hidden.
Attack 10 — the #5085 wiring note (daemon_ha_sync.go:974-985) already
establishes doBulkSync as the only authoritative cold-prime; the fold
extends the same rule to barrier-abort recovery and names the
event-stream exporter's three disqualifying properties (no
BulkStart/BulkEnd, no absence reconciliation, lossy transport) with
export.rs:85/143 + legacy_dataplane.go:611 evidence. Consistent.

## Minor/nit folds, verified

- Unconditional `stopSyncReadyTimer` in `stopClusterComms`: the fold
  moves the call out of the `if ss != nil` branch and names the
  connected-state revalidation as the second gate. The ss==nil
  teardown path can no longer leave an armed timer uninvalidated.
- Stall seam: the fold now places the stall BETWEEN pre-gate reads
  and gate entry, with the gate (CAS + revalidation + effects) one
  atomic unit — matching the serialized-queue semantics Codex
  demanded.
- Flag names: both `inboundBulkAcked` mentions now read
  `bulkEverCompleted`/`outboundBulkAcked` with the direction note;
  the stray `minor 2)` fragment is repaired into a real sentence.
- §9: the r27 additions (content-version before/between/after,
  authoritative-recovery, unconditional invalidation) are present and
  non-vacuous; AGY r27's drain-bound parameter is in the summary.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.15 that I
can construct. The one self-found design defect (journal-replay
epoch stamping) was fixed in the same fold before commit. Remaining
implementation-level notes, not plan defects: the two epoch stamp
points must be exhaustively mapped to `queueMessage` call sites, and
the owed-state discharge opportunity must be named at implementation.
If Codex r28 and AGY r28 converge, this is terminal.
