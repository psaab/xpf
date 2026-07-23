# Codex hostile plan-review — #6371 r1 (VERDICT: PLAN-NEEDS-REVISION)

Extracted from `codex exec` (medium). Six findings, all firsthand-verified in the r2 plan.

---

For the narrower failure stage—BPF clear succeeds, then every control-socket operation fails—the plan is substantially right: Go has latched `Active=false`, so nothing can refresh `true`. But the wall-clock bound is just under 11 seconds, not ≤10, because timestamps are whole seconds and expiry uses inclusive `now_secs <= until` ([runtime.rs:343](/home/ps/git/bpfrx/.claude/worktrees/6371-research/userspace-dp/src/afxdp/types/runtime.rs:343)).

2. The plan analyzes the wrong clear point for normal RETH transfer.

The cluster event calls `SetCluster(false)` before `ResignRG` ([daemon_ha.go:287](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:287)). In normal userspace RETH mode, desired activity remains `clusterPrimary || allVRRPMaster`; while VRRP is still MASTER, the transition is unchanged ([rg_state.go:250](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/rg_state.go:250)). The repository explicitly tests this behavior ([rg_state_test.go:88](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/rg_state_test.go:88)).

Consequently:

- The `SetRGActive` block at line 367 is normally skipped.
- `signalFailoverActuated` still fires at line 389.
- The actual clear happens later in the asynchronous VRRP BACKUP handler ([daemon_ha.go:567](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:567)).

`ResignRG` merely sets priority zero and queues a nonblocking signal ([manager.go:715](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/vrrp/manager.go:715)). Priority-zero advertisements, VIP removal, BACKUP transition, and the daemon event all happen later ([instance.go:1009](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/vrrp/instance.go:1009)). Therefore the ACK is not proof that either the VIP or forwarding state has moved. Path A′’s retry around line 367 misses the usual RETH clear path entirely.

3. The ACK is not a peer-promotion fence, so Option D’s blackhole proof is false.

`ManualFailover` immediately publishes owner state `SecondaryHold` ([failover.go:120](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/cluster/failover.go:120)). Peer election explicitly promotes upon seeing that state ([election.go:160](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/cluster/election.go:160)); an existing test codifies it ([election_test.go:330](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/cluster/election_test.go:330)). Independently, a priority-zero VRRP advertisement starts a 1 ms peer takeover timer ([instance.go:1107](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/vrrp/instance.go:1107)).

Thus withholding the ACK does not reliably keep the peer secondary:

- With heartbeat or VRRP delivery, the peer can promote anyway, so Option D does not prevent dual forwarding.
- Without those signals, direct mode can blackhole—but the peer does not already “have the VIP” as the plan claims.

Kill literal Option D, but because it is not a valid fence—not because the plan proved a deterministic ≥15-second blackhole.

4. The claimed fabric mitigation does not exist.

`prepareUserspaceRGDemotionWithTimeout` only waits for a session-sync barrier ([daemon_ha_userspace_readiness.go:132](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha_userspace_readiness.go:132)). It does not demote helper flow caches. Commit `fce172532` explicitly removed that preflight. The comments in the cluster-event path are stale, and userspace mode skips Linux blackhole-route injection ([daemon_ha.go:1060](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:1060)). A failed helper update therefore leaves existing forwarding local; calling the exposure “fabric-mitigated” is unsupported.

5. The forwarding-path conclusion needs narrower wording.

I found no live reader of `rg_active` or `ha_watchdog`. The legacy loader is retired ([loader.go:124](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/loader.go:124)), the AF_XDP shim has no references, and `check_egress_rg_active` is an uncalled legacy definition. Ordinary new flows, session hits, cache hits, and flowless transit are lease-gated.

But the gate is not literally universal:

- Trusted fabric ingress deliberately bypasses inactive ownership ([ha.rs:176](/home/ps/git/bpfrx/.claude/worktrees/6371-research/userspace-dp/src/afxdp/forwarding/ha.rs:176)).
- The peer-return fast path is another fabric-only exception.
- Frames admitted before expiry can remain in bounded TX queues and transmit later because natural lease expiry does not issue `DemoteOwnerRGS`.

Those exceptions do not sustain ordinary independent old-owner transit, but they mean the lease bounds new ordinary admission—not “every packet on every path by ten seconds.”

6. Path A′ is not a bounded retry.

The context is checked only before entering `UpdateRGActive`; it does not cancel the underlying I/O ([controllers.go:92](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/controllers.go:92)). A socket attempt permits a two-second dial followed by a three-second small-request deadline ([process_control.go:106](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/process_control.go:106)). Three attempts can consume roughly 15 seconds, not 150 ms, while the actuation barrier is only three seconds ([daemon_ha.go:188](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:188)). Path A′ can itself cause the failed ACK it promises never to cause.

The #5079 constants are 30 seconds with a 15-second floor, but production configures 26 seconds by default (`2×3s + 20s`) ([daemon_ha_sync.go:1067](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha_sync.go:1067)). It is an election-time recovery lease, not a forwarding fence.

The honest outcome is not pure PLAN-KILL/no-code. Kill Option D and reject Path A′ as written, then redesign:

- Latch desired inactive before fallible legacy-map I/O and attempt the live helper update regardless; report map and socket failures separately.
- Decide whether the dead compatibility map should remain on the safety-critical path at all.
- Define distinct RETH and direct-mode transfer phases. If confirmed local fencing is required, do not expose `SecondaryHold` or priority-zero VRRP before that fence; ACK withholding afterward is too late.
- Cover the actual VRRP BACKUP clear path, not only cluster-event line 367.
- Give retries real per-attempt deadlines or move them outside the barrier-critical path.
- Test two-node heartbeat/VRRP behavior and inject map-write versus socket failures independently, including continued watchdog refresh.

The targeted daemon, cluster, and userspace-manager tests passed and confirm the state-machine and `SecondaryHold` election behavior above.

VERDICT: PLAN-NEEDS-REVISION
tokens used
405,319
FAIL. I would not approve the r1 plan. It correctly identifies the dead eBPF reader, but its reachability proof, transfer ordering, and Path A′ architecture are wrong.

1. A genuinely unbounded failure mode exists.

`UpdateRGActive(false)` writes the vestigial `rg_active` map first and returns immediately on error, before setting `m.haGroups[rgID].Active=false` ([manager_ha.go:631](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_ha.go:631)). With an independent persistent `rg_active` map failure but healthy `ha_watchdog` map and socket:

- The daemon continues its 500 ms watchdog ([daemon_ha_sync.go:723](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha_sync.go:723)).
- `UpdateHAWatchdog` retains stale `Active=true` and republishes the full HA state every three seconds ([manager_ha.go:729](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_ha.go:729), [manager_ha.go:781](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_ha.go:781)).
- Each `update_ha_state(true)` renews the Rust lease ([state.rs:4](/home/ps/git/bpfrx/.claude/worktrees/6371-research/userspace-dp/src/afxdp/ha/state.rs:4)).

That can continue forever. The plan’s assertion that Go memory is already inactive after any failed clear is false.

For the narrower failure stage—BPF clear succeeds, then every control-socket operation fails—the plan is substantially right: Go has latched `Active=false`, so nothing can refresh `true`. But the wall-clock bound is just under 11 seconds, not ≤10, because timestamps are whole seconds and expiry uses inclusive `now_secs <= until` ([runtime.rs:343](/home/ps/git/bpfrx/.claude/worktrees/6371-research/userspace-dp/src/afxdp/types/runtime.rs:343)).

2. The plan analyzes the wrong clear point for normal RETH transfer.

The cluster event calls `SetCluster(false)` before `ResignRG` ([daemon_ha.go:287](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:287)). In normal userspace RETH mode, desired activity remains `clusterPrimary || allVRRPMaster`; while VRRP is still MASTER, the transition is unchanged ([rg_state.go:250](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/rg_state.go:250)). The repository explicitly tests this behavior ([rg_state_test.go:88](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/rg_state_test.go:88)).

Consequently:

- The `SetRGActive` block at line 367 is normally skipped.
- `signalFailoverActuated` still fires at line 389.
- The actual clear happens later in the asynchronous VRRP BACKUP handler ([daemon_ha.go:567](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:567)).

`ResignRG` merely sets priority zero and queues a nonblocking signal ([manager.go:715](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/vrrp/manager.go:715)). Priority-zero advertisements, VIP removal, BACKUP transition, and the daemon event all happen later ([instance.go:1009](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/vrrp/instance.go:1009)). Therefore the ACK is not proof that either the VIP or forwarding state has moved. Path A′’s retry around line 367 misses the usual RETH clear path entirely.

3. The ACK is not a peer-promotion fence, so Option D’s blackhole proof is false.

`ManualFailover` immediately publishes owner state `SecondaryHold` ([failover.go:120](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/cluster/failover.go:120)). Peer election explicitly promotes upon seeing that state ([election.go:160](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/cluster/election.go:160)); an existing test codifies it ([election_test.go:330](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/cluster/election_test.go:330)). Independently, a priority-zero VRRP advertisement starts a 1 ms peer takeover timer ([instance.go:1107](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/vrrp/instance.go:1107)).

Thus withholding the ACK does not reliably keep the peer secondary:

- With heartbeat or VRRP delivery, the peer can promote anyway, so Option D does not prevent dual forwarding.
- Without those signals, direct mode can blackhole—but the peer does not already “have the VIP” as the plan claims.

Kill literal Option D, but because it is not a valid fence—not because the plan proved a deterministic ≥15-second blackhole.

4. The claimed fabric mitigation does not exist.

`prepareUserspaceRGDemotionWithTimeout` only waits for a session-sync barrier ([daemon_ha_userspace_readiness.go:132](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha_userspace_readiness.go:132)). It does not demote helper flow caches. Commit `fce172532` explicitly removed that preflight. The comments in the cluster-event path are stale, and userspace mode skips Linux blackhole-route injection ([daemon_ha.go:1060](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:1060)). A failed helper update therefore leaves existing forwarding local; calling the exposure “fabric-mitigated” is unsupported.

5. The forwarding-path conclusion needs narrower wording.

I found no live reader of `rg_active` or `ha_watchdog`. The legacy loader is retired ([loader.go:124](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/loader.go:124)), the AF_XDP shim has no references, and `check_egress_rg_active` is an uncalled legacy definition. Ordinary new flows, session hits, cache hits, and flowless transit are lease-gated.

But the gate is not literally universal:

- Trusted fabric ingress deliberately bypasses inactive ownership ([ha.rs:176](/home/ps/git/bpfrx/.claude/worktrees/6371-research/userspace-dp/src/afxdp/forwarding/ha.rs:176)).
- The peer-return fast path is another fabric-only exception.
- Frames admitted before expiry can remain in bounded TX queues and transmit later because natural lease expiry does not issue `DemoteOwnerRGS`.

Those exceptions do not sustain ordinary independent old-owner transit, but they mean the lease bounds new ordinary admission—not “every packet on every path by ten seconds.”

6. Path A′ is not a bounded retry.

The context is checked only before entering `UpdateRGActive`; it does not cancel the underlying I/O ([controllers.go:92](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/controllers.go:92)). A socket attempt permits a two-second dial followed by a three-second small-request deadline ([process_control.go:106](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/process_control.go:106)). Three attempts can consume roughly 15 seconds, not 150 ms, while the actuation barrier is only three seconds ([daemon_ha.go:188](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:188)). Path A′ can itself cause the failed ACK it promises never to cause.

The #5079 constants are 30 seconds with a 15-second floor, but production configures 26 seconds by default (`2×3s + 20s`) ([daemon_ha_sync.go:1067](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha_sync.go:1067)). It is an election-time recovery lease, not a forwarding fence.

The honest outcome is not pure PLAN-KILL/no-code. Kill Option D and reject Path A′ as written, then redesign:

- Latch desired inactive before fallible legacy-map I/O and attempt the live helper update regardless; report map and socket failures separately.
- Decide whether the dead compatibility map should remain on the safety-critical path at all.
- Define distinct RETH and direct-mode transfer phases. If confirmed local fencing is required, do not expose `SecondaryHold` or priority-zero VRRP before that fence; ACK withholding afterward is too late.
- Cover the actual VRRP BACKUP clear path, not only cluster-event line 367.
- Give retries real per-attempt deadlines or move them outside the barrier-critical path.
- Test two-node heartbeat/VRRP behavior and inject map-write versus socket failures independently, including continued watchdog refresh.

The targeted daemon, cluster, and userspace-manager tests passed and confirm the state-machine and `SecondaryHold` election behavior above.

VERDICT: PLAN-NEEDS-REVISION
