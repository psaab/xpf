PLAN-NEEDS-REVISION

1. **High — Pin-route design is under-specified and likely wrong for same target via two uplinks.**  
   Evidence: v2 describes one dedicated probe table and one `fwmark` rule at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/docs/research/1827-multiwan/plan.md:200). That avoids transit FIB leakage, but a single table cannot hold two different `/32` routes to the same probe target via two next-hops, which is a normal dual-WAN pattern. Existing rule managers also own fixed priority windows: next-table `100-199`, PBR `31000-31999`, rib-group `33000-33099` at [rules.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/routing/rules.go:24).  
   Concrete fix: reserve an explicit probe rule priority range outside existing clear windows and before main, allocate deterministic per-test mark/table IDs, and add tests for two probes using `1.1.1.1` through different next-hops. Also collision-check probe table IDs against routing-instance `TableID`s and include dev/onlink handling for the pinned route.

2. **High — The userspace route-only snapshot actuator needs a named API, not just “rebuilds + pushes”.**  
   Evidence: v2 says the actuator rebuilds and pushes a snapshot at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/docs/research/1827-multiwan/plan.md:245), but the current public userspace path is `Compile`, which removes XDP link pins, compiles the shim, syncs attachments, starts/updates the helper, and publishes HA state at [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/dataplane/userspace/manager.go:529). Calling that would reintroduce broad apply side effects; duplicating its publish bookkeeping in daemon would drift.  
   Concrete fix: require a userspace manager method such as `PublishRouteOverlaySnapshot(cfg, overlay, schedulerState)` that reuses snapshot build/hash/publish bookkeeping internally, does not call `Compile`/`ApplyConfig`, and has tests for overlay-only hash delta, skipped duplicate publish, and FIB-generation re-resolution.

3. **Medium — FRR assembly carve-out is plausible, but the plan must spell out the complete helper contract.**  
   Evidence: current FRR assembly needs DHCP routes, `RethMap`, inferred IPv6 next-hop interfaces, backup-router, `GenerateRoutes`, policy export, cluster mode, and per-instance forwarding behavior at [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/daemon_apply.go:740). `ApplyFull` also mutates `ConsistentHash` as a side effect at [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/frr/manager.go:134).  
   Concrete fix: define `assembleFRRConfig(cfg, overlay)` as the sole constructor for both full apply and route-only actuation, and keep the post-`ApplyFull` consistent-hash sysctl handling shared too.

R1 resolution status:

- r1-1 full-apply rejection: accepted, subject to findings 2 and 3. The carve-out is real if FRR assembly and snapshot publication are shared properly.
- r1-2 `fib_generation`: accepted. Explicit `BumpFIBGeneration()` plus a named established-flow re-resolution test is sufficient.
- r1-3 pin routes: direction is correct, but finding 1 blocks approval.
- r1-4 FBF exposure: accepted. PR-1 commit-rejecting `instance-type forwarding` targets is the right fence.
- r1-5 preferred-metric parity: accepted. Engine-side winner selection and one distance-1 FRR static is a reasonable stand-in given FRR static limitations.
- r1-6/7/8/9/10: accepted. Whole-entry replacement, coalescing, PR split, primary-only probing, and downgraded smoke claims are now materially addressed.

Open questions:

1. Winner-resolution parity: yes, acceptable.
2. Actuator extraction: FRR helper yes; userspace publish API must be added to the plan.
3. Pin plumbing: use per-test marks/tables, explicit priority/table/mark ranges, collision checks, and same-target tests.
4. Takeover window: acceptable for PR-1; do not add HA overlay sync yet.
5. Debounce/hold-down: 1s debounce and hold-down `0` are acceptable; expose reload duration/churn metrics.
6. PR split: correct. Pin plumbing belongs with PR-1a because RPM needs it independent of ip-monitoring.
7. PLAN-KILL tripwires: mostly concrete; add first-week checks for the route-only userspace publish API and same-target pin-route support.

Codex session ID: 019eb2d6-e99b-7a61-a60b-791a75a6709b
Resume in Codex: codex resume 019eb2d6-e99b-7a61-a60b-791a75a6709b
