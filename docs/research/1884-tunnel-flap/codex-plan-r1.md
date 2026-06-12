Codex Task started in the background as task-mqajqwho-qb4ffq. Check /codex:status task-mqajqwho-qb4ffq for progress.
CODEX_ID=task-mqajqwho-qb4ffq
PLAN-NEEDS-REVISION

**Findings**

1. Keepalive retention breaks the DOWN state. A.7 keeps an unchanged runner alive, but `Apply` still brings the reused link up. Once `KeepaliveState.Up` is already false, `keepaliveLoop` only increments failures and never calls `LinkSetDown` again because the down action is gated by `state.Up` being true: [pkg/routing/tunnel.go:587](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:587), [pkg/routing/tunnel.go:593](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:593). Counterexample: keepalive downs tunnel, unrelated commit reuses anchor and calls `LinkSetUp`, runner remains `Up=false`, future failed probes do not down it again. Fix: skip `LinkSetUp` when retaining a down runner, or restart/reset the runner deliberately. Also stop/drain before any real recreate; today destructive apply drains first via [pkg/routing/tunnel.go:97](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:97) and [pkg/routing/tunnel.go:660](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:660).

2. The shared address reconciler would leak configured `fe80::` tunnel addresses after removal. The plan copies WG’s “skip link-local” behavior, and WG currently never deletes stale link-local addresses: [pkg/routing/tunnel.go:452](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:452). But GRE unit tunnel addresses are populated from unit config: [pkg/config/compiler_interfaces.go:648](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/compiler_interfaces.go:648), and tests include configured `fe80::8/64`: [pkg/config/parser_cluster_test.go:1143](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/parser_cluster_test.go:1143). A removed configured link-local would persist forever under reuse. Do not blanket-skip link-local for GRE/IPIP anchors.

3. The `wireguard -> gre` same-name mode flip is not an acceptable residual. WG deliberately forces a reduced MTU: [pkg/routing/tunnel.go:363](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:363), [pkg/routing/tunnel.go:416](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:416). GRE anchor create has no MTU policy: [pkg/routing/tunnel.go:123](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:123). Userspace snapshots read the live link MTU and feed it into tunnel endpoints: [pkg/dataplane/userspace/interfaces.go:375](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/userspace/interfaces.go:375), [pkg/dataplane/userspace/tunnels.go:113](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/dataplane/userspace/tunnels.go:113). Since `ApplyTunnels` runs before dataplane `ApplyConfig`, this leaks directly: [pkg/daemon/daemon_apply.go:259](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:259), [pkg/daemon/daemon_apply.go:457](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:457). Add an MTU ownership rule or treat this as incompatible.

4. Mode-only TUN reuse is too weak for anchors. Go creates anchors with `TUNTAP_NO_PI`: [pkg/routing/tunnel.go:126](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:126). Rust opens the device with `IFF_TUN | IFF_NO_PI`: [userspace-dp/src/slowpath.rs:17](/home/ps/git/bpfrx/.claude/worktrees/1884-research/userspace-dp/src/slowpath.rs:17), [userspace-dp/src/slowpath.rs:355](/home/ps/git/bpfrx/.claude/worktrees/1884-research/userspace-dp/src/slowpath.rs:355). Reusing a foreign TUN with packet-info enabled can make Rust attach fail where delete+recreate would heal it. Check at least `NO_PI`; do not rely on WG’s Mode-only precedent.

5. Keepalive identity must be normalized. Config says `KeepaliveRetry == 0` means default 3: [pkg/config/types_routing.go:302](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/config/types_routing.go:302). `startKeepalive` applies that default before storing state: [pkg/routing/tunnel.go:533](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:533), [pkg/routing/tunnel.go:541](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:541). If identity compares raw `0` against stored `3`, unchanged config restarts every apply.

**Open Questions**

1. No caller I found requires Apply-as-full-reset. The public facade is [pkg/routing/routing.go:143](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/routing.go:143); real callers are daemon apply and legacy CLI: [pkg/daemon/daemon_apply.go:259](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:259), [pkg/cli/apply.go:83](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/cli/apply.go:83). Not PLAN-KILL.

2. `LinkSetNoMaster` is safe only under a stated ownership invariant. The daemon also binds routing-instance interfaces before tunnel apply: [pkg/daemon/daemon_apply.go:216](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/daemon/daemon_apply.go:216). If tunnel VRF membership is owned only by `TunnelConfig.RoutingInstance`, say that and test it.

3. Preserving DOWN while calling `LinkSetUp` is wrong. See finding 1.

4. Legacy attr comparison needs normalized TTL, IP family/type, keys, and default retry-style care. False positives only restore today’s flap, but tests must use kernel-shaped returned attrs.

5. EEXIST retry is equivalent only if the retry uses the kernel-fetched link and preserves the `hiddenUntil` race coverage from [pkg/routing/iface_reuse_test.go:29](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/iface_reuse_test.go:29) and [pkg/routing/iface_reuse_test.go:123](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/iface_reuse_test.go:123).

6. Mode is not sufficient; verify `NO_PI`. `ONE_QUEUE` is not a useful comparison target.

7. Do not document WG-to-GRE MTU leakage as acceptable. Fix the MTU ownership story or recreate on that transition.

Codex session ID: 019eba85-aa4e-7232-87c2-ae4a4e30649f
Resume in Codex: codex resume 019eba85-aa4e-7232-87c2-ae4a4e30649f
