**PLAN-READY(D)**

I have completed the round-2 confirmation of the restructure plan v2 at [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/docs/research/1825-daemon-restructure/plan.md) (commit `551d203ff`). The edits in v2 have been verified for accuracy against the worktree codebase:

1. **Status Header**: Correctly updated (lines 5–8) to reflect Codex round-1 feedback and the SMR amendments.
2. **Section 5.2 (Daemon Struct & Selectors)**:
   * **116 fields**: Verified in [daemon.go:L66-324](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon.go#L66-324).
   * **167 methods on `*Daemon`**: Verified across the 30 production files, uniformly spelled `func (d *Daemon)`.
   * **`rgStateMachine`**: Verified exactly 20 methods in [rg_state.go](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/rg_state.go).
   * **Selector counts**: Verified exactly 269 unique unexported lowercase selectors (`\bd\.[a-z]`) and 3 exported uppercase selectors (`d.RefreshFabricFwd`, `d.CompileHealthSnapshot`, `d.NeighborPeriodicPhaseAges`), totaling 272.
   * **Neighbor coupling**: Verified exactly 35 distinct `d.*` member paths accessed between [daemon_neighbor.go](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_neighbor.go) and [daemon_neighbor_listener.go](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_neighbor_listener.go).
   * **`collectNeighborProbeTargets`**: Confirmed to be internal to the neighbor cluster. Its only reference in [daemon_apply.go:L801](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_apply.go#L801) is a non-functional comment mention.
   * **Neighbor $\rightarrow$ HA callback**: Verified that `d.warmNeighborCache()` is called in [daemon_neighbor.go:L551](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_neighbor.go#L551) and defined in [daemon_ha.go:L1081](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_ha.go#L1081).
3. **Section 9 Option C (DHCP & Nictune Coupling)**:
   * **`daemon_dhcp.go`**: Verified exactly 3 methods on `*Daemon` and exactly 9 distinct `d.*` selectors accessed in [daemon_dhcp.go](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/daemon_dhcp.go).
   * **`internal/nictune` coupling caveat**: Confirmed that `applyCoalescence` (in [coalescence.go:L55](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/coalescence.go#L55)) couples to `*priorHostTunables` and captures `mlx5CoalesceState` (in [coalescence.go:L110](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/coalescence.go#L110)), both defined in [host_tunables.go:L549,L580](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/host_tunables.go#L549). Host-tunables restoration in [host_tunables.go:L672](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/host_tunables.go#L672) also depends on the `rssExecutor`/`isExecNotFound` abstraction defined in [rss_indirection.go](file:///home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/pkg/daemon/rss_indirection.go).

The PLAN-READY(D) verdict stands on v2. Option D (PLAN-KILL) is the correct path to avoid unnecessary codebase churn and conflicts with active features.
