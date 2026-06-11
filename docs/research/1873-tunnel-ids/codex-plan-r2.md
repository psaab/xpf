**Findings**

MAJOR 1. R-C is incomplete. It covers `tx/dispatch` build failures, but tunnel-marked decisions can still reach slow-path reinjection outside that failure path.

Evidence:
- [forwarding/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/forwarding/mod.rs:1534) returns a tunnel-marked resolution even when the outer tunnel transport lookup is not forwardable: `disposition: outer.disposition`, and [forwarding/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/forwarding/mod.rs:1539) preserves `tunnel_endpoint_id`.
- [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2763) unconditionally calls `maybe_reinject_slow_path_from_frame` after non-forward dispositions.
- [slow_path.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:142) extracts the L3 packet, and [slow_path.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:212) enqueues it to the slow-path TUN. There is no tunnel-id gate in `maybe_reinject_slow_path_from_frame`.

Worked trace: route `10.0.0.0/24` through GRE endpoint id `824`; endpoint exists, but its outer destination has `NoRoute` or `MissingNeighbor` in the transport table. `resolve_tunnel_forwarding_resolution` returns `NoRoute/MissingNeighbor` with `tunnel_endpoint_id=824`; `poll_descriptor` then reinjects the original inner packet to the kernel slow path unencapsulated. That is the same plaintext-leak class R-C is meant to close.

R-C caller enumeration:
- `tx/dispatch` build failure: [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/mod.rs:575) and [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/mod.rs:855) set build failure; [slow_path.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:60) reinjects when `fallback_to_slow_path`.
- `tx/dispatch` missing FabricRedirect target: [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/mod.rs:223) enters the fallback; [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/mod.rs:225) can call `maybe_reinject_slow_path_from_frame` directly for `Owned` frames.
- `poll_descriptor` LocalDelivery: [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2164) calls `maybe_reinject_slow_path`.
- `poll_descriptor` non-forward dispositions: [poll_descriptor/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2763) calls `maybe_reinject_slow_path_from_frame`.
- `poll_stages` IPsec passthrough is safe for this issue: [poll_stages.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/poll_stages.rs:444) hardcodes `tunnel_endpoint_id: 0`.

**Open Questions**

1. Mixed-version window: acceptable as a documented window. The wire carries only the bare u16, with no version/shim surface: [sync_protocol.go](/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/cluster/sync_protocol.go:154) writes `val.FibGen`, and [codec.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/event_stream/codec.rs:208) encodes `TunnelEndpointID u16`. I do not see a persistent failure once both nodes run the same allocator.

2. R-B fail-closed: correct. Allowing colliders into a snapshot is unsafe because Rust installs endpoints into a map by id: [tunnels.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/forwarding_build/tunnels.rs:72) does `state.tunnel_endpoints.insert(endpoint.id, ...)`, so duplicate ids mean one owner wins. I verified `wg1408.0` and `wg78.0` both fold to `824`; a commit error is the right operator-visible failure.

3. R-D propagation: sound if implemented through real Close deltas. Close deletes live/session/conntrack/shared state at [session_delta.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_delta.rs:164), removes shared maps at [session_delta.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_delta.rs:171), and replicates worker deletes at [session_delta.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_delta.rs:188). Go maps close to cluster deletes at [daemon_ha_userspace.go](/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/daemon/daemon_ha_userspace.go:765), and received deletes call `DeleteWithCompanions*` at [sync_conn.go](/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/cluster/sync_conn.go:832). Standby local purge will not resync back because non-primary event deltas are ignored at [daemon_ha_userspace.go](/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/daemon/daemon_ha_userspace.go:566).

4. Missed id consumer: I found no density/array-by-id consumer. Runtime maps are `FastMap<u16, TunnelEndpoint>` at [forwarding.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/types/forwarding.rs:23), WG engines are also map-keyed at [forwarding.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/types/forwarding.rs:31), and routes carry the value at [interfaces.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/forwarding_build/interfaces.rs:81).

5. Go re-stamp of `val.FibGen`: not needed under Path A plus R-D. Go stores tunnel ids from deltas into `FibGen` at [daemon_ha_userspace.go](/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/daemon/daemon_ha_userspace.go:228); surviving tunnel ids stay stable, and removed/remapped ids must be deleted, not restamped.

6. R-C completeness: not complete; see MAJOR 1. The plan must cover helper-level slow-path reinjection, not only forwarded-frame build failure.

7. R-D over-engineering: no. R-C drops unresolved encap, but it does not prevent wrong-tunnel encap when an old stored id now resolves to a new valid endpoint. Live sessions re-resolve stored ids at [session_glue/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_glue/mod.rs:90), and WG/GRE builders then use that id at [wg.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/frame/wg.rs:52) and [gre.rs](/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/gre.rs:306). R-D is necessary.

Required change:
1. Broaden R-C to a single enforced invariant at the slow-path boundary: any `decision.resolution.tunnel_endpoint_id != 0` must not enqueue the inner packet to the kernel slow-path TUN, except an explicitly safe local-tunnel delivery path. Add tests for tunnel-marked `NoRoute`, `MissingNeighbor`, FabricRedirect missing binding with `Owned` frame, and build-failure paths.

PLAN-NEEDS-REVISION (1 required change)

Codex session ID: 019eb90e-b0c7-7200-bd8a-b676ff04f1b4
Resume in Codex: codex resume 019eb90e-b0c7-7200-bd8a-b676ff04f1b4
