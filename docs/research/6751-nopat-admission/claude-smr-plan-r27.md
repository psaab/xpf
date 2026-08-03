# Claude SMR hostile plan review — #6751 plan v15.14 (round 26 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.14 folds Codex r26's two
blockers (readiness-timeout bypass; lossless-bulk ordering), its minor
(§9 test enumeration), and its nit (binding-point wording). This pass
attacks the fold, verifies the inventory claim against the code, and
looks for the races the fold claims to close but might not. Codex r27
and AGY r27 have not been dispatched yet.

## Blocker-1 fold (readiness-timeout joins the lifecycle inventory), attacked

Codex r26's race, restated against the code: `armSyncReadyTimer`'s
`time.AfterFunc` callback validates `syncReadyTimerGen` and
`syncPeerConnected` (daemon_ha_sync.go:41-44), and a callback that
passes those checks and then stalls can resume after a newer
disconnect/cold-start committed readiness false and still execute
`SetSyncReady(true)` (:46) — `Timer.Stop()` cannot retract an
executing callback (:19-27). The fold makes timer expiry only ENQUEUE
a transition-tagged readiness-timeout event whose commit unit
re-validates (arming generation + connected state) AND performs the
`SetSyncReady(true)` under the strict-inequality tag CAS.

Attack A — both orderings:
E_t (expiry, tag T_t) vs E_d (disconnect/cold-start, tag T_d > T_t).
- E_d commits first: readiness false, timer gen bumped. E_t's commit
  fails the arming-generation re-validation; even if that passed, the
  CAS T_t < T_d fails. No effect. Correct.
- E_t commits first: readiness true at T_t. E_d commits at T_d > T_t:
  readiness false. Final state is the disconnect's. Correct.
Attack B — stop paths without a disconnect event:
`stopSyncReadyTimer` bumps `syncReadyTimerGen` (:22) on the
bulk-received (:94), disconnect (:130), and comms-teardown (:1413)
paths, so any already-enqueued expiry event fails arming-generation
re-validation at commit. The teardown ordering (:1413 bump before
:1414 `ss.Stop()`) means no expiry event can commit a readiness flip
into a half-torn-down sync lifecycle. Sound.
Attack C — the designed timeout path still works: cold-start connect
commits readiness false + arms (gen A1); expiry event E_t admitted
with T_t > T_connect; commit revalidates A1 + connected + IsSyncReady
false and CAS-succeeds → readiness true via timeout. Unregressed.
Attack D — inventory completeness, verified against the tree: EVERY
`SetSyncReady` mutation site is daemon_ha_sync.go :46 (timer — now the
readiness-timeout event), :83 (connect cold-start), :99
(bulk-received), :134 (disconnect, !wasEverPrimed). No call site
exists outside the four inventory events (`grep -rn SetSyncReady
pkg/ cmd/` — only the four plus the sync_state.go definition). The
"complete event inventory" claim is true as folded.

## Blocker-2 fold (epoch barrier, bulk keeps lossless direct writes), attacked

Codex r26's objection: v15.13 said prime frames are "enqueued through
the same envelope path", but `sendCh` is non-blocking and lossy
(sync_conn_write.go:36) and the bulk intentionally bypasses it with
lossless direct writes because an incomplete snapshot + `BulkEnd`
deletes live peer sessions (sync_bulk.go:17/50; reconcile-on-BulkEnd
sync_conn_read.go:205). The fold: the bulk KEEPS direct writes; an
epoch barrier (advance → stop old-epoch admissions → drain → lossless
bulk → `BulkEnd` only after every frame confirmed) serializes prime
against delta; a drain that misses its bound aborts the prime BEFORE
it starts, retried by the recovery machinery.

Attack E — drain-window interleave: a delta enqueued after the epoch
advance stamps the NEW epoch and can be sent before, between, or after
bulk frames. Its content post-dates the abort, exactly like the
prime's snapshot, and the receiver's per-key #2170 generation guard
adjudicates any same-key overlap. All three interleaves are safe; the
fold now says so explicitly (the barrier-(i) parenthetical).
Attack F — prime starvation: under sustained churn the drain bound can
repeatedly abort the prime. Correctness never depends on the prime
completing (provisional installs converge at the NEXT COMPLETE bulk;
the partial-bulk disposition is named and bounded), and the worst case
degrades to the readiness-timeout degraded release — bounded by the
retry-generation cap and the episode latch, not a liveness regression
against today. Acceptable at plan level; implementation must name the
barrier bound.
Attack G — `BulkEnd` integrity: the guarantee "never emitted after a
dropped/stale bulk frame" rests on the per-frame write failure
aborting before `BulkEnd` (each frame already carries its own 2s
deadline, sync_protocol.go:59) plus the receiver's incomplete-bulk
rules (receive deadline, no ACK, fail-closed quarantine drop). The
chain is closed.
Attack H — no-prime flips untouched: the barrier engages only where a
prime is scheduled; routine single-fabric flips neither advance the
epoch nor barrier, so the delta stream (the authority there) is
undisturbed. Unregressed.

## Minor-3 fold (§9 enumeration), verified line-by-line

Codex r26 named four missing pins; §9 now enumerates: (1) B queued
behind A still queued at abort, dequeued after N+1 is up, discarded by
envelope — present; (2) routine no-prime fabric flip RETAINING deltas —
present; (3) stale bulk-received producing NO timer-stop /
`ReleaseSyncHold` / sync-ready effects — present; (4) the equal-tag
`true@G`/`false@G` overwrite regression — present. Plus the
blocker-1 stalled-after-validation case and the blocker-2
prime-barrier case. Six pins, all present, none paraphrased away.

## Nit-4 fold (binding-point wording), verified

The sentence now reads "moved from the dequeue/send effect BACK to
enqueue-time content-origin stamping" — the direction is correct and
matches v15.13's actual rule.

## Attacks attempted that did NOT yield findings

- Cross-generation tag collision: per-generation sequence + lexicographic
  tuple CAS (r26b analysis) — unchanged by this fold.
- Readiness-timeout event enqueued on "the same serialized lifecycle
  queue": the daemon-side timer and the connection callbacks share one
  admission point by construction of rules (i)-(ii); no second
  tag-minting site is introduced.
- Envelope-vs-bulk bandwidth: the barrier adds no frames, only a drain
  wait; `writeMu` remains the dominant serializer.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.14. Both
r26 blockers close by construction (double-gated readiness event;
lossless-bulk barrier with an exact `BulkEnd` integrity guarantee),
the §9 enumeration is complete, and the inventory claim verified
against the code. One implementation-level note, not a plan defect:
the barrier's drain bound and the readiness event's queue-admission
point must be named concretely at implementation time (§9's build
step already anticipates this). If Codex r27 and AGY r27 converge,
this is terminal.
