# Codex hostile plan review — #6751 (round 25)

# PLAN-NEEDS-REVISION

1. **BLOCKER — generation-CAS is linearizable per store, but the event generations are not strictly ordered.**

   The plan stamps each connection slot with the current abort generation ([plan.md:723](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:723)), while the CAS accepts an event generation equal to the stored generation ([plan.md:815](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:815)). Therefore:

   - Teardown advances abort generation to G.
   - The disconnect event is tagged G.
   - The replacement connection is admitted under current generation G.
   - Its connect callback commits `true@G`.
   - The delayed disconnect callback commits `false@G`, because `G >= G`.

   Thus the exact old-disconnect-after-new-connect race claimed closed at [plan.md:818](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:818) remains possible. Today both callbacks are independently launched goroutines ([sync_conn.go:569](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:569), [sync_conn.go:142](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:142)).

   Loading or incrementing a generation inside the callback is not a solution: a delayed callback could then “forge ahead” by obtaining a newer generation at execution time. The event needs a strictly ordered tag assigned at the lifecycle transition’s commit point, such as `(abortGeneration, lifecycleSequence)`, and equal-tag retries must not permit an opposing value.

   Non-monotonic values themselves are fine: `true→false→true` works when tags strictly advance. The missing property is strict event ordering, not monotonicity of the value.

   Additionally, per-field CAS does not cover the callbacks’ external effects. A stale bulk-received callback can race after a newer lifecycle transition and still stop the readiness timer, release the VRRP sync hold, and mark sync ready ([daemon_ha_sync.go:90](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:90)). Those operations cannot be protected merely by storing `syncBulkPrimed` as a generation/value pair. The plan must make failed/stale event admission suppress all associated effects and prevent a newer transition from interleaving between event admission and safety-critical hold release.

2. **BLOCKER — binding deltas at dequeue is too late, and the cold-prime backstop is not universal or ordered after them.**

   `sendCh` currently stores raw messages at enqueue ([sync_conn_write.go:36](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:36)). `sendLoop` processes one dequeued message until success before dequeuing the next ([sync_conn_write.go:268](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:268)). Consequently:

   1. Deltas A and B enter `sendCh` under epoch N.
   2. A is dequeued and waits while the connection aborts.
   3. Epoch N+1 connects; the proposed guard correctly discards A.
   4. B is only now dequeued, so [plan.md:866](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:866) binds it to N+1 even though its content predates the abort.
   5. B travels on the replacement connection. A generation-zero B can unconditionally delete newer state.

   The new tests cover the already-dequeued A case but not the queued-behind-A case ([plan.md:1455](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1455)).

   The claimed cold-prime backstop is also not guaranteed for every connection epoch. Current logic arms cold-prime only on a both-slots-empty transition ([sync_conn.go:235](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:235), [sync_conn.go:278](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:278)); routine single-fabric flips explicitly do not re-bulk ([sync_conn.go:178](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:178), [sync_conn.go:208](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:208)). Therefore, if every replacement connection advances the compared epoch, valid deltas can be discarded without authoritative replay.

   Even where cold-prime occurs, `flushDeleteJournal` merely enqueues messages ([sync_conn_write.go:135](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:135)), while bulk sessions are written directly under per-frame `writeMu` acquisitions ([sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:95)). The bulk is not necessarily ordered after queued deltas.

   The guard needs content-origin stamping at enqueue—normally by changing `sendCh` to carry an epoch envelope—or an atomic abort-time drain/reclassification protocol. The plan must also define exactly which transitions advance the compared epoch and require an authoritative prime whenever advancing it causes valid deltas to be discarded.

3. **MINOR — the four requested round-24 attack tests are present, but the suite does not expose the remaining send-queue race.**

   Section 9 includes the directly dequeued raw delta, already-dequeued retry, persistent-cap self-rearm, and fresh zero-generation unordered-envelope tests at [plan.md:1455](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1455). Add:

   - Two pre-abort deltas where the first is dequeued and the second remains buffered until after epoch advance.
   - A normal single-fabric replacement proving either that the delta remains admissible or that a bulk is guaranteed.
   - A stale bulk-received callback racing a newer cold-start hold, proving it cannot call `ReleaseSyncHold`.

The cap-recovery fold is otherwise sound: bulk stamping really does hit every session ([sync_bulk.go:103](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:103), [sync_bulk.go:143](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:143)), and the episode latch plus “cooldown expired and new non-bulk refusal” rule at [plan.md:885](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:885) closes self-rearming.

I found no new BLOCKER in the settled registry/mint/holder/tri-state/staged-replacement/drain design. The remaining blockers are in the alias abort/lifecycle discipline, so convergence has not yet been reached.

Codex session ID: 019fc9c0-9b1c-7d71-9d30-6d199428946f
Resume in Codex: codex resume 019fc9c0-9b1c-7d71-9d30-6d199428946f
