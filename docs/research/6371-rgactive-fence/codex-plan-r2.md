# Codex hostile plan-review — #6371 r2 (VERDICT: PLAN-NEEDS-REVISION)

BLOCKER: the r2 decouple reactivates a demoted helper (poll re-derives Active from the rg_active map). Independently confirmed firsthand. Drove the r3 rewrite.

---

Not ready. Path B’s load-bearing premise is false: `rg_active` is dead to packet programs, but it is still live control-plane authority.

1. Blocker — the proposed decoupling can reactivate a demoted helper.

   Failure sequence:

   1. The map still contains `active=true`.
   2. The proposed clear gets a map-write error, latches `false`, and successfully sends `update_ha_state(false)`.
   3. The one-second status poll rereads `rg_active` and overwrites `m.haGroups` back to `true` via [process_status.go](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/process_status.go:208) and [manager_ha.go](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_ha.go:257).
   4. The watchdog path detects `true != last-published false` and immediately sends the full HA state through [manager_ha.go](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_ha.go:751), reactivating and renewing the helper lease.
   5. Reconcile can repeatedly send `false`, followed by poll/watchdog restoring `true`.

   This defeats the claimed ~11-second bound and can oscillate indefinitely. Holding `m.mu` only prevents an interleaving during the call; it does not resolve divergence after unlock. Startup also replays Active from the map at [manager_compile.go](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_compile.go:360).

   Required revision: establish one Active authority. Either retire both map writes and every runtime/startup Active read, with explicit restart semantics, or introduce per-RG desired-state/dirty-map repair state that prevents stale map values from overriding an acknowledged live transition.

2. `errors.Join` is not a sufficient outcome contract.

   A map-only failure after a successful live clear is not a helper-liveness or dual-active failure, yet a joined error makes the daemon leave the transition pending and fire the proposed security alarm. Conversely, a live-update failure must never be reported as applied.

   The activation path must likewise return failure if its live publish fails; map success must not mask it. Because socket timeouts are application-ambiguous and later reconciliation may succeed, the defensible invariant is “do not mark activation applied without a confirmed live result,” not “the helper can never activate later.” Typed partial outcomes or separate map-repair debt are needed.

3. The six round-one corrections are not all faithfully carried through.

| Finding | Round-2 result |
|---|---|
| RETH demotion | Normal MASTER→BACKUP trace is correct, but line 367 is not exclusively direct mode. Userspace RETH already in BACKUP/partial posture can clear at the cluster-event site; [rg_state_test.go](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/rg_state_test.go:54) exercises that state. Use `cluster-event`, not `direct`, in taxonomy and metrics. |
| ~11-second bound | Correct only after inactive state has been latched, and only for new ordinary admission. Before VRRP-BACKUP, watchdog updates continue renewing Active. A stuck/missed BACKUP transition has no demonstrated lease bound. |
| Option D | Correctly killed. `SecondaryHold` election and priority-0 VRRP promotion are independent of the ACK. |
| No fabric mitigation | Correct. `fce172532` removed it; the surviving preparation is a session-sync barrier. |
| Gate exceptions | Fabric-ingress and peer-return exceptions are correctly acknowledged. “TX queues drain slightly past expiry” is too strong: queued volume is bounded, but no wall-clock drain bound is established. |
| Path A′ retry | Correctly killed: one operation can consume 2-second dial plus 3-second roundtrip, with no in-flight context cancellation. |

4. The alarm design is incomplete.

   Instrumenting only the two event handlers misses the reconcile clear at [daemon_ha.go](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:837), where dropped events recover and persistent failures recur. It also misses the security-critical peer-fence clear in [daemon_ha_sync.go](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha_sync.go:1260).

   A persistent alarm needs state, hysteresis, and clearing after confirmed success. A counter can count attempts independently. The plan currently both mandates alarm+metric and leaves that choice open, without defining how `show security alarms` obtains or clears this state.

5. Interaction corrections remain:

   - PLAN-KILL of Option D remains correct; this defect does not rehabilitate the ACK as a promotion fence.
   - The 26-second #5079 lease belongs to the demoted owner, not the requester, and is an election-eligibility lease—not a forwarding fence.
   - Several #5640 comments still incorrectly describe the ACK as preventing peer promotion, including `cluster/sync.go`, `cluster/sync_failover.go`, `daemon.go`, and `daemon_ha_sync.go`; the documentation scope must enumerate them.
   - The stale-map reactivation race violates the intended #485 demotion ordering by publishing Active again after resignation, with no remaining fabric preflight to mitigate it.

I would not require the deep transfer-phase redesign solely because a correctly implemented post-latch failure permits roughly 11 seconds of fail-closed ordinary admission. Deferral can be reasonable after explicit security-risk acceptance. It is not justified by this plan’s current “unbounded is unreachable” argument, because the proposed narrow fix itself creates an unbounded reactivation path and the pre-BACKUP RETH phase lacks a hard bound.

Focused daemon state-machine, userspace map-merge, and cluster failover tests pass, but none exercises the necessary regression: frozen stale `rg_active=true`, failed map clear, successful live clear, followed by status poll and watchdog. That test plus restart replay coverage must be added.

VERDICT: PLAN-NEEDS-REVISION
