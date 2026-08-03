# Codex hostile plan review — #6751 (round 26)

# PLAN-NEEDS-REVISION

Reviewed v15.13 at `71f7ee78c`. Two BLOCKERs remain.

1. **BLOCKER — readiness-timeout callback bypasses the lifecycle tag/commit discipline.**

   The plan calls its lifecycle inventory complete but lists only abort, admission, disconnect, bulk-received, and bulk-ack-received events ([plan.md:833](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:833), [plan.md:865](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:865)). It omits readiness-timer expiry.

   The timer callback independently validates `timerGen`/`syncPeerConnected`, then later calls `SetSyncReady(true)` ([daemon_ha_sync.go:40](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:40)). Concrete remaining race:

   1. Timer passes the checks at lines 41–44.
   2. A newer disconnect/cold-start transition commits and marks readiness false.
   3. The old timer resumes and marks readiness true at line 46.

   `Timer.Stop()` cannot retract a callback already executing ([daemon_ha_sync.go:19](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:19)). Thus the claim that *all* safety-critical sync-ready effects occur inside a committed lifecycle event is false.

   Timer expiry must itself enqueue a transition-tagged lifecycle event, with its validation and `SetSyncReady(true)` inside the serialized commit unit. Add the corresponding stalled-after-validation regression test.

2. **BLOCKER — the prime-envelope fold does not define a lossless ordered bulk path.**

   The plan says prime frames are “enqueued through the same envelope path” as deltas ([plan.md:934](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:934), [plan.md:948](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:948)). But the existing `sendCh` path is explicitly non-blocking and lossy when full ([sync_conn_write.go:36](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:36)). Bulk intentionally bypasses it through lossless direct writes because an incomplete snapshot followed by `BulkEnd` would delete live peer sessions ([sync_bulk.go:17](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:17), [sync_bulk.go:50](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:50)). The receiver reconciles immediately upon `BulkEnd` ([sync_conn_read.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:205)).

   Therefore:

   - Routing bulk frames through current `sendCh` can lose frames and still deliver `BulkEnd`.
   - Leaving bulk on direct `writeMu` writes preserves losslessness but does not order it behind already-enqueued newer deltas.

   The plan must specify a concrete lossless epoch-enveloped mechanism: ordering/barrier or atomic bulk batch, backpressure/cancellation behavior, and a guarantee that `BulkEnd` cannot be emitted after any dropped/stale bulk frame. Until then, the authoritative-prime backstop supporting discarded deltas is not established.

3. **MINOR — the three promised round-25 regression tests are absent from §9.**

   Section 9 currently tests a delta already dequeued before abort and an already-dequeued retry ([plan.md:1546](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1546)). It does not explicitly pin:

   - B queued behind A, remaining queued until after abort;
   - routine no-prime fabric flip retaining deltas;
   - stale bulk-received event producing no timer-stop, `ReleaseSyncHold`, or sync-ready effects.

   The exact equal-tag `true@G/false@G` regression is also asserted in §5.6 but not explicitly enumerated in §9.

4. **NIT — stale binding-point sentence contradicts v15.13.**

   [plan.md:956](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:956) says the binding point moved “from enqueue to the send effect”; v15.13 moves it from dequeue/send to enqueue.

For the covered callback events, queue-admission-only tag minting plus strict-inequality tag CAS does close the exact equal-generation overwrite. The no-prime epoch-advance rule also matches the current single-fabric behavior. I found no new blocker in the settled option-(a) core registry/mint/holder/tri-state/staged-replacement/drain design or the alias signature/omission discipline; the open blockers are in the lifecycle and authoritative-prime folds above.

Codex session ID: 019fc9d5-922d-7ef3-86e0-d5d2eaf46679
Resume in Codex: codex resume 019fc9d5-922d-7ef3-86e0-d5d2eaf46679
