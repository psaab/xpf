PLAN-NEEDS-REVISION

1. **Medium — Probe table allocation is still not an explicit reserved range.**  
   r2 required deterministic per-test mark/table IDs with explicit ranges; v3 pins the mark and priority range, but leaves the table as abstract `probe-table-base + idx` at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/docs/research/1827-multiwan/plan.md:208). The same paragraph depends on concrete table IDs for commit-time collision checks and startup flushes at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/docs/research/1827-multiwan/plan.md:215) and [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/docs/research/1827-multiwan/plan.md:220). This matters because routing instances auto-assign tables from 100 at [compiler_routing.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/config/compiler_routing.go:275), and mgmt VRF already reserves 999 at [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/daemon_apply.go:185). Fix: name the exact probe table range, e.g. `probeTableBase..probeTableBase+49`, and require collision checks against routing-instance tables plus reserved daemon tables like mgmt 999.

All other r2 folds look faithful: per-test mark/rule priority, dev+onlink, same-target test, named `PublishRouteOverlaySnapshot`, post-`apply_snapshot` FIB bump, shared `assembleFRRConfig`, overlay preservation on full apply, throttle, churn metric, and first-week gates are present.

Codex session ID: 019eb2e0-7f3c-7900-bced-8751a877cae6
Resume in Codex: codex resume 019eb2e0-7f3c-7900-bced-8751a877cae6
