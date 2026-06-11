I will read the research plan file `docs/research/1827-pr4-loadshare/plan.md` to understand the details of the proposed Path D kill and the specific arguments to hostile-verify.
I will search for `resolve_route_target_v4` across the codebase using `grep_search` to confirm the location of the route target resolution logic and verify the `.first()` check in `fib.rs`.
I will view the content of `userspace-dp/src/afxdp/forwarding_build/fib.rs` around lines 150 to 210 to check the next-hop resolution and confirm the claim that it flattens the next-hop vector using `.first()`.
I will search for `RouteEntryV4` in the codebase to locate the structure definition and verify if it holds a single next_hop.
I will view `userspace-dp/src/afxdp/types/forwarding.rs` to verify the structure definition of `RouteEntryV4` and `RouteEntryV6` and confirm they hold a single next-hop rather than a vector.
I will search for `RouteEntryV4` in `userspace-dp/src/afxdp/forwarding/mod.rs` using `grep_search` to verify how routes are resolved in the dataplane and confirm that no flow hash is applied.
I will search for occurrences of `RouteEntryV4` in `userspace-dp/src/afxdp/forwarding/mod.rs` with line numbers to find where route lookup happens.
I will view lines 1620 to 1660 of `userspace-dp/src/afxdp/forwarding/mod.rs` to see how routing table lookup behaves.
I will search for `lookup_forwarding_resolution` in the codebase to find where the final lookup resolution for v4/v6 happens.
I will search for `lookup_forwarding_resolution` within `userspace-dp/src/afxdp/forwarding/mod.rs` to locate the exact lines where it is defined.
I will view lines 1190 to 1260 in `userspace-dp/src/afxdp/forwarding/mod.rs` to verify how `lookup_forwarding_resolution_v4` is implemented.
I will view lines 1261 to 1340 in `userspace-dp/src/afxdp/forwarding/mod.rs` to see how static routes are processed and resolve.
I will perform a search for PBR or routing instances to see how Policy Based Routing is implemented in the dataplane and if any ECMP logic exists there.
I will run a targeted search for routing instances and policy routing terms inside `userspace-dp` under the worktree directory.
I will search for occurrences of `routing_instance` in `userspace-dp/src/afxdp/forwarding/mod.rs` to see if there is any routing instance lookup that might have dynamic next-hop selection.
I will view lines 940 to 1005 in `userspace-dp/src/afxdp/forwarding/mod.rs` to understand the firewall filter / routing instance selection flow and check if there's any flow hashing or load sharing logic.
I will view lines 860 to 939 of `userspace-dp/src/afxdp/forwarding/mod.rs` to see how table overrides from firewall filters are passed to the routing lookup functions and confirm there is no dynamic flow hash or ECMP logic there either.
I will search for `resolve_tunnel_forwarding_resolution` in `userspace-dp/src/afxdp/forwarding/mod.rs` to verify tunnel forwarding resolution.
I will view lines 1500 to 1570 in `userspace-dp/src/afxdp/forwarding/mod.rs` to verify how tunnel route target resolution behaves and if it contains any multipath/ECMP/hashing features.
I will search for `nat64` in `userspace-dp/src` to see if there are any NAT64 routes or custom resolution logic that might perform dynamic selection.
I will search for occurrences of `lookup_forwarding_resolution` in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to verify how route resolution is invoked in the main packet processing path.
I will view lines 630 to 670 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to verify the routing invocation.
I will search for `prefer_local_forward_candidate_for_fabric_ingress` and `enforce_ha_resolution_snapshot` in the codebase to see if they perform any alternative route selection.
I will search for `prefer_local_forward_candidate` across `userspace-dp/src` to locate its definition.
I will view `userspace-dp/src/afxdp/forwarding/mod.rs` around line 393 to verify the logic of `prefer_local_forward_candidate_for_fabric_ingress`.
I will search for route lookup references inside `userspace-dp/src/nat64.rs` to verify its forwarding/resolution behavior.
I will view the content of `userspace-dp/src/nat64.rs`.
I will search for `config_render.go` and `daemon_ipmon.go` to verify the exact file paths.
I will search for `daemon_ipmon.go` to locate it in the worktree.
I will view lines 110 to 140 of `pkg/frr/config_render.go` to see the logic of the static route rendering to FRR.
I will view `pkg/daemon/daemon_ipmon.go` around lines 160-180 to see how consistent hashing is configured/enabled.
I will view `pkg/config/compiler_routing.go` around lines 160-260 to verify next-hop vec determinism and config-order sorting.
I will view `pkg/dataplane/userspace/routes.go` around lines 135 to 165 to verify how routes are sorted during snapshot generation.
I will view `userspace-dp/src/protocol/control.rs` around lines 505 to 535 to verify what fields are carried by `SessionSyncRequest` and if they include `egress_ifindex`, `tx_ifindex`, `next_hop`, and `neighbor_mac`.
I will view lines 450 to 505 of `userspace-dp/src/protocol/control.rs` to confirm the name of the struct containing these fields.
I will search for `RouteOverlayEntry` to see where it is defined and how it is structured.
I will view lines 330 to 360 of `pkg/config/types_system.go` to see the structure of `RouteOverlayEntry` and confirm if it holds any metadata about weights or is restricted to simple prefix/next-hop mapping.
I will search for `multi-wan.md` to see its location and read the FBF recipe.
I will list the contents of the `docs` directory to see if `multi-wan.md` is present.
I will view `docs/multi-wan.md` to examine the shipped FBF recipe and load-sharing pattern.
I will search for `docs/pr/1827-pr3-nat/plan.md` or look up its content to check what was established regarding session pinning.
I will view the last 30 lines of `userspace-dp/src/afxdp/forwarding/mod.rs` to verify the exact ending line of `choose_v6_route`.
I will view lines 80 to 110 of `userspace-dp/src/afxdp/forwarding_build/fib.rs` to verify how routes are sorted at build time.
I will view lines 1350 to 1380 in `userspace-dp/src/afxdp/forwarding/mod.rs` to verify that v6 route lookup uses the first matching entry from a list sorted by prefix-len descending.
I will search for `next_hops` or `RouteSnapshot` in `pkg/dataplane/userspace/protocol.go` using grep.
I will view lines 40 to 65 of `pkg/dataplane/userspace/routes.go` to verify how the next-hop array is built.
I will search for `next_hops` in `userspace-dp/src/protocol/snapshot.rs` using grep.
I will view the first 25 lines of `pkg/dataplane/userspace/routes.go` to check the doc comment.
I will write a detailed adversarial review report to the artifact directory. This report will detail the hostile verification of each of the 6 points and document precise file and line references.
I have performed a thorough adversarial review of the proposed PR-4 load-share research plan. I verified all assertions against the source files in the worktree `/home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research`. 

The detailed analysis has been compiled into the artifact [adversarial_review.md](file:///home/ps/.gemini/antigravity-cli/brain/b3b89b34-a74c-4cd4-8a75-15fd5e80e0ce/adversarial_review.md).

### Numbered Findings

1. **Dataplane ECMP selection does not exist:** As stated, the dataplane does not support ECMP next-hop selection. At build time, the next-hop vector is flattened to a single next-hop in [fib.rs:163](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/forwarding_build/fib.rs#L163) (and [fib.rs:197](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/forwarding_build/fib.rs#L197) for IPv6) via `.first()`. The entries themselves in [forwarding.rs:123-140](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/types/forwarding.rs#L123-L140) only store a single next-hop, and lookups in [mod.rs:1213-1220,1361-1368](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/forwarding/mod.rs#L1213-L1220) return the first match without hashing. No counter-examples (PBR override, tunnels, fabric redirects, or NAT64 translation) deviate from this single-hop logic.
2. **Kernel vs. Dataplane Divergence:** Pre-existing divergence is confirmed. Multi-next-hop routes render one static line per next-hop in [config_render.go:127](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/frr/config_render.go#L127), and consistent hashing is enabled in the kernel via [daemon_ipmon.go:165-176](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/daemon/daemon_ipmon.go#L165-L176) if configured. This creates a state where slow-path (punted) traffic hashes across links while fast-path transit traffic uses only the first next-hop.
3. **HA Symmetry Mechanics:** Configuration next-hop ordering is deterministic in [compiler_routing.go:163,179,213,235,246](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/config/compiler_routing.go#L163). Asymmetry on identical tables is averted because HA session synchronization transmits the resolved egress/MAC data in `SessionSyncRequest` in [control.rs:512-525](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/protocol/control.rs#L512-L525) instead of re-evaluating lookups locally. The unstable `sort.Slice` edge on duplicate keys is confirmed in [routes.go:143-151](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/routes.go#L143-L151).
4. **No Actuation Surface for Weights:** The overlay entry structure `RouteOverlayEntry` in [types_system.go:345-359](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/config/types_system.go#L345-L359) only accepts a single `NextHop` string and enforces whole-entry replacement in [routes.go:160-191](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/routes.go#L160-L191). There is no existing way to pass multiple weighted next-hops to the dataplane without major Rust changes.
5. **Session Pinning Limits Value:** Locally created sessions reuse stored routing resolutions as verified in [plan.md:99-114](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/docs/pr/1827-pr3-nat/plan.md#L99-L114). A weight change only shifts new flows, leading to convergence failure in environments dominated by elephant flows. Forcing convergence would require dropping active connections, making the feature high-risk for minimal value in 2-uplink deployments.
6. **Parity and Disposition:** Equal-cost per-flow load balancing (Path B) would require the same core Rust modifications as weighted balancing while offering very little additional value over the existing FBF steering recipe in [multi-wan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/docs/multi-wan.md). Closing #1827 as completed by PR-1..3 is the correct path.

PLAN-READY
