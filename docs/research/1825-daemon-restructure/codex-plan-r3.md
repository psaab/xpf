PLAN-READY(D)

Verified at `0a60b6d43c13` on `research/1825-daemon-restructure`.

The §5.2 caller list in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1825-daemon/docs/research/1825-daemon-restructure/plan.md:120) matches the tree:

- `d.resolveNeighbors(cfg)` at `daemon_apply.go:834` and `daemon_ha_vip.go:179`
- `go d.forceProbeNeighbors(cfg)` at `daemon_ha_vip.go:178`
- `d.resolveNeighborsInner(cfg, false)` at `daemon_health.go:84`
- `d.maintainClusterNeighborReadiness()` at `daemon_health.go:85`
- `d.runPeriodicNeighborResolution(ctx)` at `daemon_run.go:742`
- `d.neighborListener(ctx)` at `daemon_run.go:750`

The excluded prior citations are comment-only as stated: `daemon_ha.go:367` says `"background by runPeriodicNeighborResolution / maintainClusterNeighborReadiness"`, and `daemon.go:109/127` are comments on periodic neighbor supervision/start gating.

Diff scope for `plan.md` is limited to the status header plus the corrected §5.2 list. Commit-wide note: `HEAD^..HEAD` also adds three round-2 review artifact docs, but no production code changed.

Codex session ID: 019eb2d1-146f-74a0-97b5-4f34ea6cfe3c
Resume in Codex: codex resume 019eb2d1-146f-74a0-97b5-4f34ea6cfe3c
