Codex Task started in the background as task-mqakaon1-f8fmp9. Check /codex:status task-mqakaon1-f8fmp9 for progress.
CODEX_ID=task-mqakaon1-f8fmp9
PLAN-NEEDS-REVISION

**Findings**

1. A.3 adoption is broken if implemented literally. A.1 assigns `t.ownedNames = desired` before the per-tunnel loop, then A.3 defines adoption as `not in t.ownedNames`. That makes every desired tunnel “owned” before the anchor branch runs, so restart adoption, WG→GRE, and foreign-compatible TUN adoption do not trigger MTU normalization. Evidence: [plan.md:153](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:153), [plan.md:166](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:166), [plan.md:213](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:213), [plan.md:324](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:324). Fix: snapshot `oldOwned := t.ownedNames` before overwriting, and use `oldOwned` for adoption decisions.

2. The MTU ownership claim is still incomplete. `ApplyTunnels` runs before `d.dp.ApplyConfig`, and userspace snapshots read live netlink MTU after `CompileUserspaceShim`; compile-time `LinkSetMTU` only happens through the zone interface path. A configured tunnel MTU on a tunnel not listed in a security zone can be reset to 1500 and then published as 1500. Evidence: [daemon_apply.go:257](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:257), [daemon_apply.go:453](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:453), [manager.go:562](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/userspace/manager.go:562), [manager.go:571](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/userspace/manager.go:571), [compiler_iface.go:299](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go:299), [compiler_iface.go:449](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go:449), [interfaces.go:368](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/userspace/interfaces.go:368), [tunnels.go:106](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/userspace/tunnels.go:106). Either pass desired MTU into tunnel reconcile or validate that tunnel endpoints requiring MTU are always in the compiler path.

3. A.5’s VRF ownership invariant is false. The plan says tunnel master is owned exclusively by `TunnelConfig.RoutingInstance`, but daemon apply binds `routing-instances <ri> interface ...` members before tunnel apply, and config supports tunnel interfaces in that list. A tunnel with RI membership but no `tunnel routing-instance` would be bound at step 0a and then unbound by A.5. Evidence: [plan.md:262](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:262), [daemon_apply.go:216](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:216), [types_routing.go:338](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/types_routing.go:338), [parser_ast_test.go:2333](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/parser_ast_test.go:2333). Fix requires complete desired-master knowledge in `ApplyTunnels`, or no unbind when only `TunnelConfig` is available.

4. `appliedAddrs` can forget a configured link-local that still exists. A.4 deletes stale link-local only if it is in `applied`, then updates `appliedAddrs[name]` to addresses “now ensured.” If `AddrDel` fails for a removed configured `fe80`, the address remains present but is no longer configured, so it drops out of `applied` and future applies skip it forever. Evidence: [plan.md:242](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:242), [plan.md:251](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:251), current best-effort delete pattern at [tunnel.go:453](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:453). Keep failed-delete applied LLs tracked until they are absent or deletion succeeds.

5. Removed-link ownership is dropped on `LinkDel` failure. A.1 ignores removal errors and then sets `ownedNames` to `desired`, so a removed tunnel whose `LinkDel` transiently fails is orphaned and not retried on later applies. Evidence: [plan.md:158](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:158), [plan.md:163](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:163), [plan.md:166](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:166). Retain ownership until delete succeeds or lookup returns not found.

**Round-1 Closure**

F1 is textually closed by A.7’s runner-down `LinkSetUp` skip, matching the keepalive loop gates at [tunnel.go:573](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:573) and [tunnel.go:587](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:587).

F2 is closed only on the successful path; A.4’s applied-set rule fixes blanket LL skip, but finding 4 leaves a failure-path leak.

F3 is not closed because findings 1 and 2 break the adoption MTU story.

F4 is closed: A.3 requires TUN mode, NO_PI, and persistent TUN; Rust opens `IFF_TUN | IFF_NO_PI` at [slowpath.rs:355](/home/ps/git/bpfrx/.claude/worktrees/1884-research/userspace-dp/src/slowpath.rs:355), and netlink parses NO_PI/persist at [link_linux.go:4092](/home/ps/go/pkg/mod/github.com/vishvananda/netlink@v1.3.1/link_linux.go:4092).

F5 is closed: A.7 normalizes retry with the same `<=0 => 3` rule as [tunnel.go:533](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:533).

**Section 11 Answers**

1. No, not as written. Zoned configured MTU is restored before userspace snapshot, but unzoned configured MTU is not. With no operator MTU, 1500 persists by design.

2. Yes. `AddrDel` failure is the concrete hole; `AddrAdd` failure on introduction is acceptable if only successful adds enter `appliedAddrs`.

3. The skip should be strictly keyed on runner-down. If an operator manually downs the link while runner state is still up, apply should call `LinkSetUp`; the keepalive loop only brings up on `!state.Up`.

4. Apply→Clear→Apply is fine only if all deletes succeed and `Clear` clears both maps. Name-only ownership cannot detect external same-name replacement, and delete failure drops ownership.

5. No additional false-“changed” trap found if A.6 compares exactly the listed fields and ignores PMTU/TOS/encaplimit/flags. Type/IP/TTL normalization is necessary per [plan.md:278](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:278).

6. The one-time bounce is acceptable only after fixing desired-MTU restoration before snapshot. As written, it can become the published MTU, so adoption should reset to desired MTU when configured, else 1500.

Codex session ID: 019eba93-bc61-7ff2-965e-898bffc3d77c
Resume in Codex: codex resume 019eba93-bc61-7ff2-965e-898bffc3d77c
