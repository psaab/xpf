V6 is not ready. The consistency choice is correct, and most round-5 fixes hold, but the new ownership transition still has two blocking safety gaps.

## Blocking findings

1. Peer takeover can precede physical demotion.

Section 5.4 promises “advertise ineligible, demote, peer owns,” and the sender snapshots the new logical state ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:203), [sender snapshot](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:240)). But current hold demotion only changes `Manager.State` and enqueues an event ([kernel_selfrecover.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/kernel_selfrecover.go:52)). The heartbeat sender independently snapshots that state ([heartbeat_manager.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:251), [heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:723)).

Actual VRRP resignation and dataplane deactivation happen later in the daemon event consumer ([daemon_ha.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha.go:340)). Events are nonblocking and may be dropped ([manager.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/manager.go:439)); the channel holds only 64 events ([manager.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/manager.go:358)), while the plan permits 255 RGs.

Concrete schedule:

- A physically owns an RG; B is ready secondary.
- Live key-enable arms `epochIneligible`. A’s Manager becomes secondary and queues demotion.
- Before A resigns VRRP/deactivates forwarding, it advertises ineligibility.
- B immediately promotes under the new rule.
- Both dataplanes own until A’s delayed—or dropped—demotion completes.

Existing coordinated failover already uses an explicit actuation barrier for exactly this reason ([daemon_ha_sync.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_sync.go:993)). V6 needs a two-phase transition: arm the local promotion gate, complete/fence physical demotion, then advertise peer-visible ineligibility or otherwise release peer takeover. The daemon-side barrier is missing from the plan and blast radius.

2. The ineligibility flag has no rolling-upgrade-safe wire contract.

Current RG records are fixed five-byte `{id, priority, weight, state}` entries with no flags field ([heartbeat.go layout](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:93), [encoding](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:231), [decoding](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:319)). V6 merely says “a new RG flag,” while retaining the protocol version and adding only `BootEpoch` to the public packet API ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:208), [§9](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:315)).

An old receiver recognizes only weight zero or exactly `StateSecondaryHold` as unconditional peer yield ([election.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:144), [election.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:165)). An unknown state bit/tail flag falls through to priority election ([election.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:247)).

Thus upgraded high-priority A can be ineligible while old lower-priority B accepts A’s markerless heartbeat, cannot recognize the yield, and remains secondary. A’s aggregate gate also holds it secondary: indefinite both-secondary from one persistence failure.

The design must specify encoding, parser masking, precedence, and a legacy projection—such as advertised weight zero or `StateSecondaryHold`—or capability-gate the feature. The mandatory mixed-version tests must cover this asymmetric failure.

3. The operator override is not safety-preserving.

“Audited” is not fencing. If A is force-promoted while live B is partitioned, dual-primary is immediate. Even when B was genuinely powered off, B can later return before A’s storage recovers and take ownership while overridden A remains primary. V6 specifies neither durable external fencing nor automatic override revocation/demotion on peer evidence ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:229)).

The command must either:

- require durable peer fencing and define rejoin/clear semantics; or
- be explicitly classified as a break-glass consistency waiver that can create dual-primary.

It must also override only `epochIneligible`, never `kernelUpgradeHold`.

## Additional specification defects

- The engagement predicate is missing. The invariant literally gates every configured-cluster primary on `markerEnabled`, but supported keyless clusters intentionally emit legacy heartbeats ([heartbeat.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:723)). The plan needs a normative rule such as `epochRequired = configuredCluster && keyConfigured`, including keyed→empty behavior.
- The Appendix still asks for persist-fail “sole-node promote” ([plan Appendix](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:403)), contradicting configured-cluster never-promote. Tests must distinguish configured sole survivor → safe outage from true standalone → epoch disengaged/promotes.

## Confirmed resolutions

- Logical PRIMARY assignments do funnel only through `runElection` and `electSingleNode` ([election.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:341), [election.go](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:439)). A correctly implemented aggregate gate therefore covers heartbeat, timeout, never-seen, readiness, monitor, preempt, config, and failover paths.
- Dedicated `epochIneligible` and `kernelUpgradeHold` sources compose correctly; `ResetFailover` must not clear epoch ineligibility.
- Strict successor allocation is sound under intact durable storage. MaxUint64 correctly fails held. Valid filesystem rollback can erase both the durable and volatile emitted floors and repeat/regress an epoch, but §6 explicitly documents that residual; the “ever emitted” claim should be scoped to no valid-file rollback.
- The single `{keyGen,key,markerEnabled,epoch,RG,eligibility}` snapshot closes the stale-K1-body-signed-under-K2 race.
- Dropping `noteRejectedFromPeer` is correct.
- The #5639 application-time generation check is the right bar, provided it is linearized through the actual side effect. Generation must follow deferred work such as queued config all the way to `configApplyLoop`, not merely be checked before `handleMessage`.

These are fixable, so PLAN-KILL is not justified. But the advertise-before-actuation schedule invalidates the ownership proof and requires a cross-layer state-machine revision, not editorial cleanup.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
202,117
