# Codex hostile plan-review — #6371 r5 (VERDICT: PLAN-NEEDS-REVISION)

Convergence table: r4-B1/B2/B3/B4/H7 CLOSED. Remaining: a per-RG ownership-generation linearization invariant for concurrent writers, and a persistent-map-write detected-not-closed wording fix. Drove r6.

---

R5 materially improves the design, but it is not yet plan-ready. Boot quarantine is sound; the remaining blocker is generation arbitration across concurrent physical writes.

| r4 finding | r5 status |
|---|---|
| B1 SeedApplied/NeedsApply | Closed—mechanism removed |
| B2 false hitless claim | Closed—fail-closed cost disclosed |
| B3 re-arm-to-clear window | Closed |
| B4 skip-replay left pin set | Closed—all 16 keys are zeroed |
| B5 peer-fence one-shot | Direction fixed, concurrency invariant incomplete |
| H6 alarm convergence | Predicate fixed; some details remain |
| H7 tombstones/read API | Closed |

1. BLOCKER — clear generations do not yet arbitrate physical writes.

The daemon has three activation-capable paths and five clear categories running from different goroutines. `UpdateRGActive` serializes calls under the manager mutex, but that orders lock acquisition—not ownership generations.

A reachable schedule is:

1. Reconcile snapshots clear intent generation G.
2. A legitimate ownership event supersedes G, successfully writes `true`, and records `applied=true`.
3. The stale G retry subsequently writes `false`.
4. It notices generation mismatch only after the physical write. The intent is gone and `NeedsApply` is false, leaving the legitimate owner inactive indefinitely.

The inverse can let an older activation overwrite a newer peer fence; if activation success retires the fence debt, the peer-fence one-shot reappears. Existing `ApplyIfCurrent` validates bookkeeping only after `SetRGActive` has mutated the map/helper ([daemon_ha.go:93](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:93), [rg_state.go:217](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/rg_state.go:217)). Nor can raw `rgStateMachine.epoch` be reused: every unchanged periodic reconciliation increments it ([rg_state.go:250](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/rg_state.go:250)).

The minimal plan revision is an invariant, not engineer-level pseudocode:

- One daemon-owned per-RG monotonic ownership generation and apply gate must cover every `true` and `false` writer.
- A clear dominates until a strictly newer, still-current ownership transition supersedes it.
- A stale operation must be prevented from writing, or must immediately re-drive the latest generation after completing.
- Convergence may clear debt only if the generation remains current across fresh pin/helper readback.
- A resolved inactive intent/tombstone must survive until ownership supersession.

The daemon-level intent plus reconcile consumer remains the right overall structure; it just needs this linearization contract.

2. Material factual contradiction — persistent map-write failure is detected, not closed.

The plan claims every reachable unbounded mode is closed ([plan.md:155](/home/ps/git/bpfrx/.claude/worktrees/6371-research/docs/research/6371-rgactive-fence/plan.md:155)), then correctly admits that an indefinitely failing map write remains indefinitely active ([plan.md:157](/home/ps/git/bpfrx/.claude/worktrees/6371-research/docs/research/6371-rgactive-fence/plan.md:157)). `UpdateRGActive` returns before changing manager/helper state when the map write fails ([manager_ha.go:635](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_ha.go:635)). Retry plus alarm makes that residual visible; it does not terminate it.

The authority cleanup may still be deferred, but the plan must describe this as an accepted, detected-but-unfixed residual and require the promised concrete follow-up and named security/HA acceptance. It cannot call the cleanup purely non-hazard-related.

Other conclusions:

- Boot placement is achievable. Replay is the first map-derived publication; status starts afterward, and the daemon watchdog later still ([manager_compile.go:371](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_compile.go:371), [manager_compile.go:399](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_compile.go:399), [daemon_ha_sync.go:723](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha_sync.go:723)). No earlier hidden pin consumer exists.
- A partial quarantine-write failure must abort dataplane arming or retain a gate suppressing replay, poll, and watchdog. Bare “log + proceed” would re-arm the surviving nonzero key. Add a failure-injection test.
- All five clear categories are accounted for. Shutdown is correctly recoverable by next-boot quarantine, but it cannot honestly be called runtime-convergent because reconcile is canceled and joined before shutdown clearing.
- Fail-closed boot is an acceptable security invariant. Peer-authoritative boot is an availability enhancement, not required now.
- “≤30 seconds” should not be presented as a strict upper bound: the code defines a 30-second startup floor plus scheduling/election work.

VERDICT: PLAN-NEEDS-REVISION
