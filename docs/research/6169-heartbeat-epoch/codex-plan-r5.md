V5 is still not ready. Several round-4 defects are genuinely fixed, but the unified ownership state machine still admits dual-primary and single-fault outage schedules.

## Blocking findings

1. The never-seen exception recreates dual-primary.

“Never seen” means only that this Manager has not accepted a heartbeat since receiver start—not that no peer exists. After 30 seconds, `lastSeen==0` invokes `handlePeerNeverSeen`, which promotes through `electSingleNode` ([heartbeat.go:877](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:877), [heartbeat.go:891](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:891), [heartbeat_manager.go:454](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:454)). `peerEverSeen` is process-local and initially false ([manager.go:129](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/manager.go:129)).

Concrete schedule:

- B is healthy PRIMARY and retains `sawEpoch(A)`.
- A restarts, persistence fails, and the epoch hold demotes it.
- The B→A receive direction is partitioned; A→B still works.
- B rejects A’s markerless frames and remains/promotes PRIMARY.
- A receives nothing, classifies B as “never seen,” and v5 explicitly permits held A to promote ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:207)).
- Both are now PRIMARY.

`noteRejectedFromPeer()` cannot help A because A receives no frames. UDP silence cannot distinguish a genuine single-node deployment from a one-way receive partition. V5 must choose safe outage for a configured two-node cluster, require external fencing/witness, or provide an explicit standalone topology mode. The claimed combination of sole-node availability and partition safety is impossible from heartbeat absence alone.

The exception is also not revocable. The existing kernel guard returns `electNoChange` while held rather than demoting an already-primary node ([election.go:44](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:44)); `electSingleNode` similarly just returns ([election.go:405](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:405)). Its one-time demotion occurs only when the hold is armed ([kernel_selfrecover.go:52](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/kernel_selfrecover.go:52)). Therefore, after A’s exceptional promotion, later peer evidence does not demote it.

2. Asymmetric persistence failure does not reliably produce peer takeover.

V5 assumes healthy B rejects markerless A and times it out ([plan:215](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:215)). After B restarts or re-primes, however, `sawEpoch=false` by design ([plan:127](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:127)), so B accepts A’s signed markerless v1 frame.

The reused hold advertises A merely as ordinary SECONDARY; it does not advertise election ineligibility ([kernel_selfrecover.go:61](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/kernel_selfrecover.go:61)). If held A has higher priority, preempt election makes healthy B secondary ([election.go:172](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:172)); the initial neither-primary election does likewise ([election.go:247](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:247)). A is held secondary and B yields: one persistence failure causes indefinite both-secondary outage.

The design needs a peer-visible yielded/ineligible state or an equivalent rule that makes a healthy peer take ownership even when `sawEpoch=false`.

3. Literal kernel-hold reuse cannot compose two independent sources.

There is currently one boolean ([manager.go:123](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/manager.go:123)). `ClearKernelUpgradeHold` clears it and immediately elects ([kernel_selfrecover.go:91](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/kernel_selfrecover.go:91)); `ResetFailover` also clears it independently ([failover.go:170](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/failover.go:170)).

Consequently, literal reuse permits:

- kernel recovery to clear an unresolved epoch hold;
- epoch persistence recovery to clear an unverified-kernel hold;
- failover reset to clear the epoch hold.

The semantics also conflict: the kernel hold must never allow isolated promotion, while the epoch hold does. V5 leaves this as an open design question ([plan:334](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:334)). It requires separate source flags or a typed bitmask, source-specific clear operations, and an aggregate promotion gate.

4. Read-max-write prevents overwrite regression, but strict successor allocation is missing.

The serialized worker is the right fix for stale retry overwrites. However, v5 requires every new Manager to use a strictly higher epoch ([plan:121](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:121)) while §5.4 now specifies only `max(durable,candidate)` and never defines `candidate`, `durable+1`, emitted high-water, overflow behavior, or which value becomes the emitted epoch ([plan:189](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:189)).

With durable/emitted `P`, a reboot and `candidate<=P` may successfully rewrite/publish `P`, clear the hold, and reset the counter. The peer then rejects `(P,new-low-counter)`. An election-eligible higher-priority node can remain primary while the rejecting peer times it out and promotes—the prior dual-primary schedule returns.

The worker must normatively allocate and durably publish a value strictly above both the durable floor and any emitted/chosen high-water, then atomically publish that exact value and clear only the current generation’s epoch hold. `MaxUint64` must fail held, never wrap or regress.

Dropping the far-future heuristic is otherwise correct: an ordinary crc-valid future value is safe if advanced with checked `+1`; it need not wait for wall time. But CRC does not detect rollback to an older complete `{epoch,crc}`, and a valid `MaxUint64` has no successor. Those residuals are missing from §6.

Also, rotating the key cannot repair an ongoing write/fsync failure. Contrary to [plan:219](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:219) and [plan:247](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:247), both nodes remain `markerEnabled=false` and held after rotation. Storage recovery or an explicit degraded override is required.

5. The live-key barrier still lacks sender-side key-generation atomicity.

The sender currently builds the heartbeat body, releases `m.mu`, and only afterward reads the live key ([heartbeat.go:723](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:723), [heartbeat_manager.go:263](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:263), [manager.go:390](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/manager.go:390)). V5 specifies receiver-side generation checking but only says `buildHeartbeat` gates marker emission ([plan:368](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:368)).

A sender can snapshot a K1 marker/PRIMARY body, K2 activation can arm the hold and demote locally, and the paused sender can then derive/sign that stale body with K2. Thus a K2-valid marker and stale PRIMARY advertisement can escape while K2 is unresolved. The sender needs one snapshot binding `{keyGen,key,markerEnabled,epoch,RG states}`, or a generation recheck before transmission.

6. Rejected-peer presence and #5639 remain incompletely linearized.

Both rejection branches unlock before `noteRejectedFromPeer()` ([plan:149](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:149), [plan:152](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:152)). This recreates the same class of race fixed for `lastSeen`: never-seen election or K2 reset can occur before an unversioned K1 note lands. Moreover, generic rejection includes unauthenticated failures, while authenticated stale replays are explicitly available to the threat actor. Rejected replay therefore becomes a liveness signal capable of holding a persist-failed survivor secondary indefinitely.

The #5639 drain requirement fixes the exact round-4 “already installed connection” defect, but not all application races. Current sync setup removes the connection from pre-auth tracking, applies a legacy pending frame, and only then installs it ([sync_conn.go:100](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_conn.go:100), [sync_conn.go:119](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_conn.go:119), [sync_conn.go:130](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_conn.go:130)). Owner arming in that gap cannot drain it before the unauthenticated message applies. Closing an installed connection also cannot retract a payload already read immediately before `handleMessage` ([sync_conn_read.go:71](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_conn_read.go:71)). The prerequisite needs a generation check before pending/in-flight message application or a fully linearized arm-and-drain protocol.

## Confirmed resolutions

- All actual PRIMARY assignments do funnel through `runElection` and `electSingleNode`; readiness, monitor, heartbeat, timeout, preempt, and failover paths can therefore share a correct composite gate.
- Moving `lastSeen` inside the generation-checked transaction fixes the round-4 stranded-node race.
- A `handlePeerHeartbeatLocked` split is feasible: the existing handler already executes under `m.mu`, and its election callee expects that lock. O(1)/64-entry admission at roughly 10 Hz is acceptable.
- The 68-byte tail reservation is now correct.
- Removing far-future rejection is correct for valid, non-exhausted values.
- A genuinely serialized, atomic durable read-max-write worker prevents an older retry from lowering the file.

These defects are repairable, so PLAN-KILL is not justified. But the central claimed three-case ownership proof is false, and the live-key/persistence transitions remain insufficiently specified for safe implementation.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
167,915
