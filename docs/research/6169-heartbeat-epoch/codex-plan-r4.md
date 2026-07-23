V4 is not ready. Persist-before-emit fixes the exact round-3 “unpersisted H escapes” schedule, but its replacement failure policy permits sustained dual-primary. Additional persistence and transaction gaps remain. This is major, not KILL.

| Round-3 finding | Result |
|---|---|
| 1. Unpersisted epoch escapes | Core fixed; failure/ownership response still unsafe |
| 2. Undefined election fence | Old fence removed, but an ownership hold is still required |
| 3. Key-generation linearization | Main K1/K2 ordering fixed; `lastSeen` remains outside the final transaction |
| 4. Live empty→key activation | Barrier is not concretely implementable as nonblocking and its safety assumption is false |
| 5. Epoch-strip and bounds | Fixed correctly |

### Blocking findings

1. **Markerless rejection creates a one-way partition, not fail-closed takeover.**

A legal staggered-restart schedule:

1. Higher-priority preempt node A was primary; B retained `sawEpoch(A)`.
2. A restarts and its epoch persistence fails. V4 makes A emit signed markerless frames ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:181)).
3. Bring-up `UpdateConfig` immediately elects ([group_state.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:125)); preempt bypasses the fresh-boot wait and promotes A ([election.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:419)).
4. B rejects A’s markerless frames through the restored epoch-strip gate, so A is absent only from B’s view.
5. B times A out and promotes ([heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:404)).
6. A still accepts B’s durable marked frames, but higher-priority preempt keeps A primary ([election.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:172)).

UDP provides no rejection acknowledgement. Therefore §5.4’s claim that peer timeout is sufficient fail-closed behavior ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:186)) is false: both nodes remain primary until persistence recovers.

A genuinely fresh joining peer is safe because `sawEpoch=false`; simultaneous fresh daemon restarts also reset both floors. A returning or surviving peer with Manager-scoped `sawEpoch` is the blocker. Markerless→higher-durable-marker recovery is otherwise safe.

Fixing this requires an explicit local election-eligibility hold that demotes an existing primary and guards every promotion path, comparable to the existing kernel hold ([kernel_selfrecover.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/kernel_selfrecover.go:52)). That revives the sole-node/dual-persistence-failure availability policy v4 claims to have eliminated.

2. **Persist-before-emit proves durability, not monotonicity against the peer’s floor.**

The algorithm rejects `prev > now+MARGIN` as corrupt and resets `prev` to zero ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:173)). An intact file can therefore regress with no state loss:

- Boot with a far-forward clock and durably emit `Tfuture`.
- Correct the clock and restart.
- Reject intact `Tfuture` as “far future.”
- Persist and emit lower `Treal`.

Thus the claimed “state-loss AND backward-clock” residual is incorrect. Clock correction beyond `MARGIN` alone suffices. The peer rejects the lower epoch, producing the same one-way partition and possible dual-primary—not merely “self-lock.”

3. **Async persistence retries can overwrite a newer durable epoch.**

V4 gives `asyncRetryPersist()` no Manager-wide serialization, cancellation, or stale-generation rule ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:177)):

- G1 chooses `C1`, fails, and sleeps.
- A later key generation G2 writes and emits `C2 > C1`.
- G1 wakes and durably overwrites the file with `C1`.

Even if G1’s in-memory completion is generation-checked, the durable floor has regressed. The design needs one serialized persistence worker/read-choose-write transaction, with the candidate above both the durable and already-emitted high-water, plus a current-generation check before marker publication.

4. **The live-key barrier lacks a coherent nonblocking transaction.**

Today `UpdateConfig` holds `m.mu`, publishes the key, and elects before returning ([group_state.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:17), [key publication](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:85)). The sender fetches the live key every tick ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:723)).

Guaranteeing persistence before that election must either block `UpdateConfig` outside `m.mu`, eagerly resolve at Manager construction, or define a two-phase pending-key state. V4 chooses none. Deferring only `UpdateConfig`’s election is insufficient because heartbeat, timeout, readiness, and monitor paths independently elect—for example [readiness.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/readiness.go:60).

The assertion that the peer cannot already have `sawEpoch` is also false for same-key clear/re-enable, staggered configuration, or a surviving peer while this node booted temporarily unkeyed.

### Other real defects

- The main key-generation ordering is sound if key publication, generation bump, and floor reset are one `m.mu → admission` transaction. However, v4 writes `lastSeen` before the final generation check ([plan §5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:146)). If K2 then causes handler application to be dropped, `lastSeen!=0` while `peerAlive=false`. The timeout path never calls `handlePeerNeverSeen`, and `handlePeerTimeout` returns immediately, potentially stranding a fresh non-preempt node secondary forever ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:877), [heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:359)). Move `lastSeen` into the final generation-checked transaction.
- Plan §5.3 literally locks `m.mu` and calls `handlePeerHeartbeat`, which already locks `m.mu` ([heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:294)). It must specify a locked helper or internal generation check.
- V4 dropped the required extra 16-byte tail reservation. Current authenticated marshaling reserves only 52 bytes ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:418)); marker-enabled frames must reserve 68 or maximal frames can reach 1488 bytes while the receiver reads 1472.
- #5639’s commit-time generation recheck does not evict an unauthenticated sync connection installed before arming. Sync authentication is fixed at handshake ([sync_auth.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:329)), and unauthenticated wrappers remain pass-through. Stage −1 must also drain/rehandshake installed unauthenticated connections, or revalidate generation before every message application.

The `bodyEnd>=16` guard and explicit `sawEpoch && !hasEpoch` rejection are correct. The key-derived marker and `(epoch,counter)` center remain worth implementing, so PLAN-KILL is not justified. But a normal staggered restart plus one persistence failure can split ownership, and the persistence/key-transition state machine is still incomplete.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
177,419
