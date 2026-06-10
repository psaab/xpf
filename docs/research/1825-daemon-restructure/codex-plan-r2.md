PLAN-NEEDS-REVISION

The requested v1 fixes did land: section 1 marks v2, section 5.2 uses `269` unexported / `272` total selectors, neighbor is `35` not `36`, `collectNeighborProbeTargets` is marked internal, and `warmNeighborCache` is called out as neighbor→HA. Section 9 adds the `daemon_dhcp.go` narrow-seam row and the `internal/nictune` coupling caveat.

One new/still-stale error remains in section 5.2. The plan says:

> `daemon_health.go:84, daemon_ha.go;`  
> `daemon_run.go:742, daemon.go;`

But current source only has comment-only mentions in `daemon_ha.go` and `daemon.go`, while the plan’s own measurement note says comment-only mentions are excluded from cross-caller lists. The actual external calls are from `daemon_apply.go`, `daemon_ha_vip.go`, `daemon_health.go`, and `daemon_run.go`.

I did not modify the worktree.

Codex session ID: 019eb2ce-0bb6-7ce3-bc3a-4b9fb60cb8ec
Resume in Codex: codex resume 019eb2ce-0bb6-7ce3-bc3a-4b9fb60cb8ec
