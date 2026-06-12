Codex Task started in the background as task-mqakp5m1-zj7i9n. Check /codex:status task-mqakp5m1-zj7i9n for progress.
CODEX_ID=task-mqakp5m1-zj7i9n
verdict — PLAN-NEEDS-REVISION

**Blocking Finding**

`appliedRI` still has a stale-authority bug. v3 closes the original blanket-unbind issue, but the new rule can unbind a 0a routing-instance interface-list bind that happened earlier in the same apply.

Counterexample: apply N has `tunnel routing-instance A`, so `appliedRI[name] = A`. Apply N+1 removes the tunnel stanza and adds the tunnel to routing-instance B’s `interfaces` list. The daemon’s 0a loop binds B before tunnels run ([daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:216), [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:229)), then `ApplyTunnels` runs later ([daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:257)). v3’s rule unbinds solely on `appliedRI[name] != "" && tc.RoutingInstance == ""` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:332)), contradicting the stated invariant that “0a-list bindings are never touched” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:335)).

This needs a master-identity check before `LinkSetNoMaster`: only unbind if the current master is still the VRF that the tunnel manager previously bound. Also specify `appliedRI` cleanup on deletion/Clear; A.1 deletes `appliedAddrs` only ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:188)), and `clearLocked` cleanup names only `ownedNames`/`appliedAddrs` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:198)).

**R2 Closure Check**

All five r2 findings are textually folded:

- F1: closed by “`oldOwned := t.ownedNames` ... `ADOPTION authority`” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:167)) and “`adopting := !oldOwned[tc.Name]`” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:226)).
- F2: closed by “`MTU-set-on-ADOPT, to the DESIRED value`” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:250)) and the `tc.MTU` plumbing text ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:273)).
- F3: original blanket-unbind finding closed by `appliedRI` ownership text ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:320)); new lifecycle defect above remains.
- F4: closed by retaining failed link-local deletes: “`stale-delete FAILED`” and “`keep it tracked until AddrDel succeeds or ... absent`” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:304)).
- F5: closed by “`retain ownership on failed delete so the next Apply retries`” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:180)).

**Open Questions**

1. MTU precedence is correct for per-unit tunnels: interface MTU is parsed into `ifc.MTU` ([compiler_interfaces.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/compiler_interfaces.go:41)), unit MTU is parsed into `unit.MTU` with inet6 taking the smaller value ([compiler_interfaces.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/compiler_interfaces.go:537)), and runtime applies interface MTU before unit MTU override ([compiler_iface.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go:449), [compiler_iface.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/compiler_iface.go:549)). Additive consumers look safe: HA sync sends config text, not typed `TunnelConfig` ([daemon_ha_sync.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_ha_sync.go:335)); userspace raw config is excluded from snapshot hash ([builder.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/userspace/builder.go:82)); Rust stores raw config as `serde_json::Value` ([snapshot.rs](/home/ps/git/bpfrx/.claude/worktrees/1884-research/userspace-dp/src/protocol/snapshot.rs:243)); `TunnelConfig.String()` is explicit and redacts only WG private key ([types_routing.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/types_routing.go:330)).
2. appliedRI replacement by 0a bind is not acceptable as written; see blocking finding.
3. ownedNames growth is bounded. `next` starts as desired only, and a removed name is retained only when `LinkByName` succeeds and `LinkDel` fails ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:170)). If the link is gone on the next apply, no retention path fires, so `t.ownedNames = next` drops it ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:190)).
4. Upgrade adoption MTU write is acceptable. Old anchor creation did not set MTU on the TUN attrs ([tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:123)), so writing configured MTU or default 1500 on first adoption is convergence, not a new bounce.
5. No r1 closure is reopened by the MTU/AddrDel/ownedNames folds. The only blocker I found is the new `appliedRI` lifecycle hole above.

Codex session ID: 019eba9e-0ab1-73f3-93c6-3db1ddaf4fb3
Resume in Codex: codex resume 019eba9e-0ab1-73f3-93c6-3db1ddaf4fb3
