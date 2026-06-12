Verdict: **PLAN-READY**.

I did not find a verified counterexample to v2. The two round-1 MAJOR issues are closed by the new design, assuming implementation follows the ordering exactly.

**Key Verifications**

1. **Rotation gate closes same-id `gre -> wireguard` stale-thread window.**  
   Same-id mode flip is reachable because IDs are name-only: [pkg/config/tunnelid.go:9](/home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/config/tunnelid.go:9), [pkg/dataplane/userspace/tunnels.go:100](/home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/dataplane/userspace/tunnels.go:100). WG rows bypass GRE source/dest requirements: [pkg/dataplane/userspace/tunnels.go:58](/home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/dataplane/userspace/tunnels.go:58), [userspace-dp/src/afxdp/forwarding_build/tunnels.rs:20](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/forwarding_build/tunnels.rs:20). Current refresh stores new forwarding before thread reconcile: [userspace-dp/src/afxdp/coordinator/mod.rs:1137](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs:1137), [userspace-dp/src/afxdp/coordinator/mod.rs:1155](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs:1155). Current GRE encap only fetches by id and checks logical owner ifindex, not mode: [userspace-dp/src/afxdp/gre.rs:306](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/gre.rs:306), [userspace-dp/src/afxdp/gre.rs:314](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/gre.rs:314).  
   With D.1b, the reloaded endpoint has `mode == "wireguard"`, so `endpoint_attachment_valid` is false and the old GRE thread parks before build. That closes my round-1 trace.

2. **Unpublish-before-join plus drain stop check bounds the busy-producer join.**  
   Current loop checks `stop` only outside the delivery-drain loop: [userspace-dp/src/afxdp/tunnel.rs:52](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs:52), then drains until `Empty`/`Disconnected`: [userspace-dp/src/afxdp/tunnel.rs:53](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs:53). Producers load and clone senders per packet: [userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:159](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:159), [userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:167](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:167), and the queue is large: [userspace-dp/src/afxdp/mod.rs:313](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/mod.rs:313).  
   Store #1 removes stale senders before stop, so new producers cannot enqueue; old cloned senders are bounded by the new inner-loop stop check. `Disconnected` is already tolerated: [userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:183](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:183).

3. **HA coherence narrowing is correct.**  
   Current code loads HA once in `enforce_ha_resolution_at`: [userspace-dp/src/afxdp/forwarding/mod.rs:539](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/forwarding/mod.rs:539), and again for reverse synthesis: [userspace-dp/src/afxdp/tunnel.rs:212](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs:212). Workers already use one HA load per loop and pass it down: [userspace-dp/src/afxdp/worker/loop_body/mod.rs:491](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:491), [userspace-dp/src/afxdp/worker/loop_body/mod.rs:649](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:649). v2 matches that model and correctly avoids claiming cross-source atomicity.

4. **F1 keepalive overclaim is gone and source supports removal.**  
   Go starts keepalive against `tc.Destination`: [pkg/routing/tunnel.go:303](/home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/routing/tunnel.go:303), the loop probes `state.RemoteAddr`: [pkg/routing/tunnel.go:569](/home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/routing/tunnel.go:569), and `probeICMP` uses `net.DialTimeout`: [pkg/routing/tunnel.go:615](/home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/routing/tunnel.go:615).

**Open Questions**

1. **Parked delivery writes:** ratified. I did not find a harmful trace beyond bounded stale/in-flight delivery. The delivery path is local-delivery only: [slow_path.rs:156](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:156), and the generic tunnel-marked slow-path leak gate remains after it: [slow_path.rs:198](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:198). Removed/mode-flipped endpoints stop matching new GRE decap state, and residual cloned-sender races are bounded by store #1 plus the drain stop check.

2. **Two-store reconcile:** acceptable. Workers load the delivery map at the slow-path point, not once for a long batch: [slow_path.rs:159](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:159). Between stores, fail-closed drops/unavailable delivery are acceptable.

3. **SMR-1 gate:** `!handles.is_empty()` is the right minimum gate. `handles` is per worker while `live`/`identities` are per binding: [worker_manager.rs:5](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/worker_manager.rs:5). Sparse worker IDs are explicitly supported: [worker_manager.rs:17](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/worker_manager.rs:17). GRE selection also requires `live.bound`: [tunnel.rs:383](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs:383).

4. **Rotation-gate cost:** acceptable. Minor correction: these are `FastMap`, not `BTreeMap`, lookups in current source: [types/forwarding.rs:23](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/types/forwarding.rs:23), [types/forwarding.rs:36](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/types/forwarding.rs:36). Still only on Arc rotation.

5. **Missed matrix:** no blocker found. `refresh_fabric_links` only mutates fabrics and republishes forwarding: [coordinator/mod.rs:980](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs:980), [coordinator/mod.rs:993](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs:993). RG promote only forces neighbor warming: [coordinator/mod.rs:1355](/home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs:1355). D.1’s forwarding/HA reload covers both.

No files modified.

Codex session ID: 019eb9fd-23dc-7171-bfae-e0ac340f3bab
Resume in Codex: codex resume 019eb9fd-23dc-7171-bfae-e0ac340f3bab
