Reviewed the exact `fe899556f` blob and source read-only. I made no file changes; a concurrent untracked `claude-smr-plan-r10.md` appeared and was left untouched.

1. [BLOCKER] The r8/r9 disposition tables are materially false.

| Row | Audit |
|---|---|
| r8 f4 MAC contract | REOPENED/BLOCKER |
| r8 f5 fabric transaction | REOPENED/BLOCKER |
| r8 f6 mixed-version | CLOSED narrowly—mandatory restart plus D remains load-bearing |
| r8 f7 retry clock | REOPENED/MAJOR |
| r8 f8 identity/error | REOPENED/MAJOR |
| r8 f9 rollover/operator latch | REOPENED/BLOCKER |
| r8 M8 tests | OPEN/MAJOR |
| r8 AGY pass | Historical result only |
| r8 SMR N1/N2/N3 | N1 contradicted by later tests; N2/N3 narrowly closed |
| AGY r9 f1 | REOPENED/BLOCKER |
| AGY r9 f2 | PARTIAL/BLOCKER |
| AGY r9 f3/f4/f5 | CLOSED narrowly |
| SMR r9 N1–N5 | PARTIAL—N4 unresolved; N1 scope and N5 tests incomplete |
| Codex r9 f5 | REOPENED/BLOCKER |
| Codex r9 f6 | REOPENED/MAJOR |
| Codex r9 f7 | REOPENED/MAJOR |
| Codex r9 f8 | OPEN/MAJOR |
| Codex r9 f9 | Design statement sound; required paired test absent |
| Codex r9 f10 | REOPENED/BLOCKER |

2. [BLOCKER] The three-bucket MAC design still reproduces the entire-dataplane outage.

The plan says correct-MAC/down members create independent, nonblocking recovery debt with no epoch, latch, or pending marks ([plan.md:1077](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1077)). But if any other member has a MAC mismatch, the epoch opens with every desired member unvalidated and completion waits until every member is MAC-correct and administratively up ([plan.md:1092](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1092)).

Counterexample: A has a MAC mismatch; B has the correct MAC but is unplugged. A opens the global defer epoch and unarms the vector. B can never settle, so `complete_deferred` never fires and the global enabled gate stays closed. This is exactly AGY r9 f1’s outage.

Bucket ii is also undefined for real configurations:

- `Disable` is authoritative ([types_interfaces.go:22](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/config/types_interfaces.go:22)); `RethToPhysical` does not exclude it ([types.go:62](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/config/types.go:62)); compiler and networkd deliberately keep it down ([compiler_iface.go:628](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/compiler_iface.go:628), [networkd.go:595](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/networkd/networkd.go:595)). The debt would fight accepted configuration by repeatedly calling `setUp`.
- A missing member cannot be classified “MAC correct.” If it returns with its factory MAC, the link-up-only debt has no safe transition into a deferred MAC-programming epoch.
- For Q5, current `programRethMAC` returns success on MAC equality without inspecting link state ([daemon_reth.go:240](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_reth.go:240)). Therefore a precheck→validation flap can falsely settle unless an explicit reread/reclassification is added. Making that member blocking merely recreates the mixed-bucket outage.

The daemon/manager handoff is likewise unspecified: the current `LinkController` has only three operations ([apply.go:130](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/apply.go:130)), while the plan promises unchanged manager APIs ([plan.md:1380](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1380)).

3. [BLOCKER] Unconditional helper-authoritative `status.Fabrics` adoption creates incoherent snapshots.

A poll cannot race a locked control request because both paths hold `m.mu`. But two legitimate divergence windows remain:

- During pending-XSK startup, `Compile` intentionally stores newer B in `m.lastSnapshot` without publishing it ([manager_compile.go:245](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:245), [manager_compile.go:304](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:304)). The status loop applies helper-A status before attempting the deferred publish ([process_status.go:169](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_status.go:169)). Unconditional adoption overwrites B’s fabrics with A’s, producing a B-config/A-fabric hybrid.
- After a lost full-`apply_snapshot` ACK, Rust may have stored B while Go retains A: Go sends before decoding the response ([process_control.go:145](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_control.go:145)) and assigns `m.lastSnapshot` only after clean success ([manager_compile.go:350](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:350)). A B status then splices only B’s fabrics into A.

Route, scheduler and worker-arm publishers clone that hybrid wholesale ([manager_overlay.go:188](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_overlay.go:188), [manager_compile.go:575](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:575)).

Fabric adoption must be qualified by the known full-snapshot lineage. Helper-ahead/Go-ahead cases require whole-snapshot resolution or publisher fencing, never single-field splicing. Codex r9 f5 is not closed.

4. [BLOCKER] The stored-generation guard and latch ownership remain invalid.

A route-overlay publication is the same accepted configuration epoch, yet it increments snapshot `Generation` and sends a full snapshot ([manager_overlay.go:188](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_overlay.go:188), [manager_overlay.go:239](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_overlay.go:239)). Rust consequently advances `LastSnapshotGeneration` ([snapshot.rs:150](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/snapshot.rs:150)), while the plan explicitly says overlay/FIB publications do not advance `lastAcceptedConfigGeneration` and must not discard the debt ([plan.md:1186](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1186)).

Thus `LastSnapshotGeneration > debtEpochGeneration` suppresses A’s legitimate tagged retry after an ordinary A overlay, even though the overlay cloned A’s `DeferWorkers=true` latch. A `(generation,fib)` comparison is not sufficient: those counters order snapshots, not accepted-config ownership. The design needs an explicit accepted-config/defer epoch or provisional-successor token.

It also has a pre-poll race: after B lands and its ACK is lost, A’s completion can run before any poll reports B’s generation. The guard then sees stale A status and can consume B’s latch.

Finally, operator global arm still clears only the manager Boolean and helper latch ([plan.md:1033](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1033), [plan.md:1152](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1152)). Only successful tagged completion is specified to clear `m.lastSnapshot.DeferWorkers` ([plan.md:1140](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1140)). A later route/scheduler clone can therefore re-latch the helper with no remaining completion owner. R8 f9 and r9 f10 remain open.

5. [MAJOR] Identity and retry invariants are still self-contradictory.

The correct design requires immutable `workers.identities` ([plan.md:804](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:804)), but hidden invariant 3 still mandates the independently relaxed socket tuple ([plan.md:1423](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1423)). Item 16 then says mismatch zeroing preserves a live error ([plan.md:1694](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1694)) before correctly saying mismatches copy no error ([plan.md:1711](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1711)).

Likewise, the f7 disposition says events never touch the exponent, but pseudocode says config/link events reset attempts ([plan.md:1231](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1231)); invariant 11 still specifies an attempt cap and reset-on-change ([plan.md:1492](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1492)); and the Go test still requests config/link resets ([plan.md:1825](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1825)). An implementation can follow those sections and remain pinned at destructive five-second teardowns.

6. [MAJOR] The advertised r9 test folds are absent; implementation can green with every blocker intact.

- Item 12 has final-state checks plus separate units, not the required production reconcile-entry hook ([plan.md:1594](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1594)).
- Item 13 lacks lost-ACK successors with and without MAC work and calls only the manager Boolean plus helper latch “ALL authorities” ([plan.md:1630](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1630)).
- Item 16 lacks the promised dropped-identity-row and retained operation-stage pins, besides contradicting itself.
- Item 17 omits UNKNOWN adoption, nil-config teardown and reverse-applied versus applied-identical HA pairs ([plan.md:1720](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1720)).
- Item 19 omits lookup/update/readback fault injection, guard-hit and UNKNOWN-no-commit timing, and status-adoption→partial-clone preservation ([plan.md:1751](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1751)).
- The retry suite lacks the required 60-second-floor event storm.
- The MAC tests contradict the design: they require correct-MAC/down to reopen an epoch ([plan.md:1874](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1874)), then require bucket ii not to open one ([plan.md:1893](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1893)). The stale-attempt test is impossible as written because it proposes accepting a successor while holding the capacity-one `applySem` that every acceptance path needs ([daemon.go:485](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon.go:485)).

Items 14, 15 and 18 are adequate only for their narrow scopes.

7. [MAJOR] Open-Q and hazard-budget conclusions are mixed, and the advertised budget is not signable.

- Q1: I found no additional same-version producer. The complete control writers remain planner, binding/queue verbs and global fan-out ([planning.rs:504](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:504), [binding.rs:27](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/binding.rs:27), [queue.rs:29](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/queue.rs:29), [status.rs:418](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/status.rs:418)). The documented mixed-version case remains the only extra producer.
- Q2: blocking the SEND when zero cannot be verified is correct; sending would combine unknown ctrl state with an independently unknown RPC outcome. But “disable failure means dataplane already closed” is false for update failure or nonzero readback. Also, an initial lookup failure followed by successful write/readback already proves zero, yet the existing helper still returns an error ([process_linkcycle.go:57](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_linkcycle.go:57)). The plan must define which proof controls and how the currently void `SyncFabricState` path surfaces failure.
- Isolated guard-hit and UNKNOWN-no-commit windows are defensible fail-closed choices. Persistent control failure and forever 60-second bind probes are also defensible with alarms.
- “~15s worst case” is not a wall-clock bound: it can include the control RPC, 5-second scheduling delay, 10-second readiness wait, status tick and jitter—approximately 19 seconds from pre-disable.
- Repeated guard rejection is missing from the budget: the requested projection remains different, so every retry pre-disables again. Persistent sysfs failure or an event storm can turn individually bounded pulses into effectively unbounded disruption.
- “Unplugged RETH member has no dataplane impact” is false in the mixed-bucket trace above.

These are new hazards versus master: global mixed-debt defer, configuration-fighting link recovery, missing→wrong-MAC recovery without a safe epoch, hybrid fabric snapshots, ownerless re-latches, false stored-generation suppression, and potentially repeated guard-hit disable pulses.

DEMAND-REVISION
