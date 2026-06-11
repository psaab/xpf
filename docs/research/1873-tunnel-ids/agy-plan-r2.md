I will list the contents of the `/home/ps/git/bpfrx` directory to locate the plan document and other relevant files.
I will list the contents of `/home/ps/git/bpfrx/.claude/worktrees/1873-research` to verify the worktree path and locate the plan document.
I will list the contents of `/home/ps/git/bpfrx/.claude/worktrees/1873-research/docs/research/1873-tunnel-ids` to locate the plan document and round-1 reviews.
I will view the content of the DRAFT v2 plan document at `/home/ps/git/bpfrx/.claude/worktrees/1873-research/docs/research/1873-tunnel-ids/plan.md`.
I will search for `maybe_reinject_slow_path` in the worktree codebase to locate the exact source files and line numbers where slow-path reinjection occurs.
I will view the contents of `/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` to understand the slow-path reinjection behavior and verify R-C completeness.
I will view the `userspace-dp/src/afxdp/tx/dispatch/mod.rs` around line 575 to see the context of build-failure fallback and the dispatch loop logic.
I will view the preceding lines (400-550) in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see what type of forwarding and loops are being processed there.
I will view the lines (600-700) in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to follow the build failure handling and identify where `handle_forward_build_failure` is called.
I will view lines 700-800 in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see the rest of the direct-TX block and the call to `handle_forward_build_failure`.
I will view lines 800-900 in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to find the rest of the copy fallback path and see where `handle_forward_build_failure` is called.
I will view lines 900-950 in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see the rest of `handle_forward_build_failure` handling.
I will view lines 200-400 in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see how the main loop extracts incoming packets, makes forwarding decisions, and delegates to the builders or fallback.
I will use grep to find the definition of `ForwardingDisposition` to see the possible routing options.
I will search for `ForwardingDisposition` in the source files to locate its definition.
I will search for the definition of the `ForwardingDisposition` enum to see all its variants.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/types/forwarding.rs` around line 237 to inspect `ForwardingDisposition`.
I will view `userspace-dp/src/afxdp/poll_stages.rs` around line 452 to see what triggers the slow-path reinjection there.
I will view the file `userspace-dp/src/afxdp/poll_descriptor/mod.rs` around line 2164 to inspect the first caller of the slow-path reinjection functions.
I will view the next few lines (2191-2230) in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what happens for other non-forward dispositions, particularly if they fall back to slow-path reinjection.
I will view lines 2231-2300 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to continue tracing the other dispositions.
I will view lines 2301-2350 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see how other parts of `MissingNeighbor` are handled and check for slow-path reinjection calls.
I will view lines 2351-2450 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what is done when neighbor is missing.
I will view lines 2451-2550 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what is done with the frame when neighbor is missing.
I will view lines 2551-2650 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what is done with the frame.
I will view lines 2651-2750 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to find the rest of neighbor missing handling.
I will view lines 2751-2808 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what is done with the remaining code and check where line 2763 is.
I will view lines 2100-2140 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to see what checks determine if a packet is forwarded or falls into the non-forwarded block.
I will view lines 2000-2100 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to find the enclosing control structure.
I will search for `build_live_forward_request_from_frame` to see where it is defined and how it can return `None`.
I will view `userspace-dp/src/afxdp/forward_request.rs` around line 61 to see when `build_live_forward_request_from_frame` returns `None`.
I will view lines 161-185 in `userspace-dp/src/afxdp/forward_request.rs` to see the remainder of `build_live_forward_request_from_frame`.
I will view lines 1960-2000 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to understand the outer routing logic for a packet descriptor.
I will view lines 1900-1960 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to find the start of the forwarding logic.
I will view lines 1800-1900 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to find where the `disposition` variable is matched or checked.
I will view lines 1700-1800 in `userspace-dp/src/afxdp/poll_descriptor/mod.rs` to locate the `disposition` match block start.
I will search the repository for where `FabricRedirect` is set to see if it can ever be associated with a non-zero `tunnel_endpoint_id`.
I will view the `userspace-dp/src/afxdp/forwarding/mod.rs` file around line 344 to see how `FabricRedirect` is built.
I will view lines 371-400 in `userspace-dp/src/afxdp/forwarding/mod.rs` to see the definition of `resolve_zone_encoded_fabric_redirect_by_id`.
I will search for assignments to `tunnel_endpoint_id` in the codebase to see where it can be non-zero.
I will search for `tunnel_endpoint_id` in `userspace-dp/src/afxdp/disposition.rs` to see where it gets assigned in resolving forwarding decisions.
I will search for `tunnel_endpoint_id` in `userspace-dp/src/afxdp/session_glue/mod.rs`.
I will view `userspace-dp/src/afxdp/session_glue/mod.rs` around line 90 to see how it uses `tunnel_endpoint_id`.
I will search for assignments to `tunnel_endpoint_id` in Go files (where config maps routes and endpoints) to see how routes are assigned tunnel endpoint IDs.
I will search for `tunnels.go` to find where the tunnel mapping and ID assignment logic lives in Go.
I will view the contents of `pkg/dataplane/userspace/tunnels.go` to see the current positional ID assignment logic and how it's integrated.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/mod.rs` around line 466 to see how the coordinator processes tunnel endpoint snapshots.
I will search for `local_tunnel_source_loop` definition in the codebase to see how it uses `tunnel_endpoint_id`.
I will view the contents of `userspace-dp/src/afxdp/tunnel.rs` to see the logic of the local tunnel source loop.
I will view lines 150-300 in `userspace-dp/src/afxdp/tunnel.rs` to see the logic of `build_local_origin_tunnel_tx_request`.
I will search for the definition of `resolve_tunnel_forwarding_resolution` in the codebase to understand how tunnel resolution works and what disposition it returns on failure.
I will view `userspace-dp/src/afxdp/forwarding/mod.rs` around line 1502 to see the logic of `resolve_tunnel_forwarding_resolution`.
I will search for `no_route_resolution` to see how it initializes `tunnel_endpoint_id`.
I will view `userspace-dp/src/afxdp/forwarding/mod.rs` around line 1488.
I will search for `pending_neigh` in the codebase to see how unresolved packets are retried once their neighbor resolves.
I will view `userspace-dp/src/afxdp/neighbor_dispatch.rs` around line 85 to see how `retry_pending_neigh` handles packet dispatching and slow-path fallback.
I will view lines 251-300 in `userspace-dp/src/afxdp/neighbor_dispatch.rs` to see what is done with the packet when rewrite in place fails.
I will search for `rewrite_forwarded_frame_in_place` in the codebase to understand if it supports tunnels or returns `None`.
I will view `userspace-dp/src/afxdp/frame/mod.rs` around line 630 to see if `rewrite_forwarded_frame_in_place` supports tunnels or returns `None`.
I will search for `rewrite_prepare_eth` to see how it handles tunnel endpoints.
I will view `userspace-dp/src/afxdp/frame/mod.rs` around line 464.
I will search for `.enqueue(` calls to ensure no other code bypasses the `maybe_reinject_slow_path` helpers.
I will list files in `pkg/config` to locate validation routines.
I will search for validation or compilation logic in `pkg/config/compiler_interfaces.go` to see where interface/tunnel configuration is validated.
I will view `pkg/config/compiler_interfaces.go` from line 25 to 100 to see where configuration compilation/validation resides.
I will search for `session_delta.rs` in the codebase to verify how `SessionDeltaKind::Close` is processed and propagated.
I will view lines 140-220 in `userspace-dp/src/afxdp/session_delta.rs` to inspect the close event flush and propagation code.
I will search for `WorkerCommand` definition in the codebase.
I will view the `WorkerCommand` definition in `userspace-dp/src/afxdp/types/runtime.rs` around line 246.
I will search for `DeleteSynced` processing inside the codebase to see how workers handle session deletions.
I will view the `WorkerCommand` processing block in `userspace-dp/src/afxdp/session_glue/mod.rs` around line 608 to see how `DeleteSynced` behaves.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs` to see what actions it performs.
I will search for construction of `SessionDelta` in the codebase.
I will view `userspace-dp/src/session/mod.rs` around line 1189 to see how deletion deltas are queued.
I will view `userspace-dp/src/afxdp/session_delta.rs` from lines 1 to 100 to understand the session delta flushing machinery.
I will search for `replicate_session_delete` to see where else session deletion is initiated from the coordinator context.
I will view `userspace-dp/src/afxdp/session_glue/mod.rs` around line 718 to inspect how deletion deltas are processed and replicated.
I will view lines 660-700 in `userspace-dp/src/afxdp/session_glue/mod.rs` to find the enclosing function name and understand the session delete replication flow.
I will search for `shared_sessions` usage in the coordinator module to see how the coordinator thread interacts with the shared session maps.
I will list the files in `/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/server/` to see where the API or control planes are located.
I will search for `shared_sessions` in `userspace-dp/src/server/` to see how the server (acting as the Go-to-Rust bridge or HA sync receiver) handles synced sessions.
I will search for `DeleteSynced` or `SessionKey` in `userspace-dp/src/server` to locate the bridge code.
I will search for `delete` (case-insensitive) in `userspace-dp/src/server/helpers.rs` to see what session/conntrack deletions are performed there.
I will view the first 200 lines of `/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/server/helpers.rs` to see what types and functions it exports.
I will view `userspace-dp/src/server/helpers.rs` from lines 280 to 365 to see how synced sessions are parsed and processed.
I will search for `build_synced_session_entry` calls to find the HA sync receiver code.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/server/handlers/sync_session.rs` to see what handlers are defined and how they process deletions or sync updates.
I will search for `TunnelEndpoints` in the Go codebase to find all places where tunnel endpoint snapshots or their IDs are used.
I will view `pkg/dataplane/userspace/maps_sync.go` around line 1529 to inspect the loops over `TunnelEndpoints`.
I will view `pkg/dataplane/userspace/manager_ha.go` from line 845 to 885 to see how it uses `TunnelEndpoints`.
I will search for `FibGen` in Go files to see how it is used in the Go shadow conntrack or other components.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/bpf_map/mod.rs` to inspect the BPF map check.
I will search for `tunnel_endpoint_id` (case-insensitive) in the entire codebase, excluding the `docs` directory, to see if there are any other consumers.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/daemon/daemon_ha_userspace.go` around line 230 to verify the mapping of `TunnelEndpointID` into the shadow conntrack.
I will search for `tunnel_sources` in the coordinator module to see how the coordinator manages the lifetime of local tunnel sources.
### Adversarial Plan Review (DRAFT v2)

This review evaluates the DRAFT v2 plan for Positional Tunnel-Endpoint IDs (#1873) against the codebase in the worktree `/home/ps/git/bpfrx/.claude/worktrees/1873-research` under branch `research/1873-tunnel-ids`.

---

### Part 1: Answers to Section 11 Open Questions

#### Q1: Mixed-Version Upgrade Window (Without a Shim)
**Verdict**: Acceptable and self-healing.
- **Trace**: During an ISSU, upgraded Node 0 uses FNV hash IDs (e.g., `5432`), while Node 1 (old) only has positional IDs (`1..N`). When Node 0 syncs a session referencing `tunnel_endpoint_id: 5432`, Node 1's `sessionSyncTunnelEndpointLocked` fails to find it and resolves it as `NoRoute` (`EgressIfindex = 0`).
- **Self-Healing Mechanism**: Live sessions on Node 1 are not locked to the initial resolution. Per [session_glue/mod.rs:90-103](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_glue/mod.rs#L90-L103), when `decision.resolution.tunnel_endpoint_id != 0`, the helper calls `resolve_tunnel_forwarding_resolution` dynamically per packet:
  ```rust
  if decision.resolution.tunnel_endpoint_id != 0 {
      let resolved = super::resolve_tunnel_forwarding_resolution(
          forwarding,
          Some(dynamic_neighbors),
          decision.resolution.tunnel_endpoint_id,
          0,
      );
  ```
  As soon as Node 1 upgrades and receives the new snapshot, `resolve_tunnel_forwarding_resolution` dynamically re-resolves the stored ID `5432` to the correct logical egress interface, restoring normal forwarding without requiring a manual flush.

---

#### Q2: R-B Fail-Closed Collision Policy for Upgrading Users
**Verdict**: A loud commit error is the correct policy.
- **Alternative Danger**: If we use "drop-later-sorting + error log," the daemon starts successfully, but one of the colliding tunnels (e.g., `wg78.0`) is silently omitted from the snapshot and blackholed in the dataplane. Silent traffic blackholes are notoriously difficult for operators to diagnose.
- **Commit Error Logic**: Forcing a commit failure at [pkg/config/compiler_interfaces.go:25](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/config/compiler_interfaces.go#L25) is loud, safe, and guarantees control-plane policy alignment before any packets are dropped. The release note must explicitly instruct operators to rename colliding interfaces.

---

#### Q3: R-D Purge Propagation & Standby-Side Handling
**Verdict**: Coherent and safe; no sessions will linger or resync.
- **Standby-Side Execution**: Both active and standby nodes apply configuration snapshots independently. During an upgrade/commit, the standby node's own coordinator executes the R-D walk, identifies changed/removed IDs, and deletes matching entries from its local session tables.
- **Propagation Path**: Deletions on the active node generate `SessionDeltaKind::Close` events that flow through `flush_session_deltas` at [session_delta.rs:150-192](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_delta.rs#L150-L192) and are replicated to peer workers via `replicate_session_delete` in [session_glue/mod.rs:718-719](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_glue/mod.rs#L718-L719).
- **Idempotency**: If Node 2 (standby) has already run its local R-D walk, the incoming peer delete-sync event is processed via `delete_synced_session` in [server/handlers/sync_session.rs:29-37](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/server/handlers/sync_session.rs#L29-L37) which handles the delete request idempotently without error.

---

#### Q4: Consumer Map ID Surface Check
**Verdict**: No hidden ID indexing consumers exist.
- Go-side consumers in `pkg/dataplane/userspace` were verified:
  - [maps_sync.go:1529](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/maps_sync.go#L1529) and [maps_sync.go:1551](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/maps_sync.go#L1551) iterate over `snapshot.TunnelEndpoints` slices using linear iteration to read configurations (e.g., WireGuard listen ports).
  - [manager_ha.go:854](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/manager_ha.go#L854) and [manager_ha.go:867](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/manager_ha.go#L867) linearly scan `snapshot.TunnelEndpoints` to resolve IDs or lookup configurations:
    ```go
    for _, endpoint := range snapshot.TunnelEndpoints {
        if endpoint.ID == id {
            return endpoint, true
        }
    }
    ```
- There are no dense array-by-id indexing structures that would break under large or sparse FNV hash IDs.

---

#### Q5: Go-Side `val.FibGen` Re-stamping
**Verdict**: Verified; no re-stamping is needed.
- Because FNV hash IDs are pure functions of interface names under Path A, the ID of a surviving tunnel remains constant. The stored `val.FibGen` in the Go shadow conntrack (see [daemon_ha_userspace.go:228-230](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/daemon/daemon_ha_userspace.go#L228-L230)) remains valid.
- For removed or remapped tunnels, R-D actively purges the session from Rust, generating `SessionDeltaKind::Close` events (processed via `flush_session_deltas` at [session_delta.rs:144-146](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/session_delta.rs#L144-L146)) that clean up the Go conntrack entry, preventing stale IDs.

---

#### Q6: R-C Completeness and Production Reinjection Sites
**Verdict**: There are exactly **two** production sites where a tunnel-marked decision can reach `maybe_reinject_slow_path` / `maybe_reinject_slow_path_from_frame`. However, a major completeness gap was identified in `retry_pending_neigh` (see **MAJOR Finding 1** below).

##### Production Sites:
1. **Site 1**: [tx/dispatch/slow_path.rs:61](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L61) (inside `handle_forward_build_failure`):
   ```rust
   if fallback_to_slow_path {
       maybe_reinject_slow_path_from_frame(..., decision, ...);
   }
   ```
   If a worker's tunnel-encap build fails in the dispatch loop, it maps to `fallback_to_slow_path = true` and reaches here.
2. **Site 2**: [poll_descriptor/mod.rs:2763](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2763):
   ```rust
   maybe_reinject_slow_path_from_frame(..., decision, ...);
   ```
   If `build_live_forward_request_from_frame` returns `None` (e.g., due to a CoS drop or missing egress binding), the packet is reinjected into the slow path.

##### Excluded Sites (Non-Tunnel / Safe):
- [tx/dispatch/mod.rs:225 & 238](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/mod.rs#L225): This is for `FabricRedirect` decisions which are always initialized with `tunnel_endpoint_id: 0`.
- [poll_stages.rs:452](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/poll_stages.rs#L452): Inside `stage_ipsec_passthrough_check`, the IPsec decision is explicitly created with `tunnel_endpoint_id: 0`.
- [poll_descriptor/mod.rs:2164](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2164): Inside `LocalDelivery` handling, which is host-bound traffic (not encapsulated/forwarded tunnel traffic), so `tunnel_endpoint_id` is 0.

---

#### Q7: R-D Over-Engineering Assessment
**Verdict**: R-D is absolutely necessary.
- Without R-D, the one-time positional-to-hash upgrade would permanently blackhole existing tunnel sessions. The session table would retain stale entries with positional IDs (e.g., `1`), which would fail outer-route lookup, return `NoRoute`, and be dropped by R-C.
- With R-D, these old sessions are actively purged, forcing the next matching packet to trigger a session-miss. The session-miss path performs a fresh route lookup, matches the new FNV hash ID (e.g., `5432`), installs the correct new session, and traffic resumes immediately.

---

### Part 2: Adversarial Scrutiny & Findings

#### MAJOR Finding 1: Plaintext Leak in `retry_pending_neigh` for Resolved Tunnel Packets
- **Location**: [userspace-dp/src/afxdp/neighbor_dispatch.rs:241-250](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/neighbor_dispatch.rs#L241-L250)
- **Description**: 
  When a tunnel packet is buffered in `pending_neigh` because its outer peer MAC is unresolved, the packet's `decision` is stored with `tunnel_endpoint_id != 0`. When the neighbor resolves, `retry_pending_neigh` dispatches it:
  ```rust
  let pkt = binding.pending_neigh.remove(&key).expect("key from this map");
  let mut decision = pkt.decision;
  decision.resolution.neighbor_mac = Some(neighbor_mac);
  decision.resolution.disposition = ForwardingDisposition::ForwardCandidate;
  ```
  It then calls `rewrite_forwarded_frame_in_place`:
  ```rust
  let Some(rewrite_result) = rewrite_forwarded_frame_in_place(
      &*area,
      pkt.desc,
      pkt.meta,
      &decision,
      false,
      expected_ports,
  ) else {
      binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
      continue;
  };
  ```
  Because both `src_mac` (from the physical interface) and `neighbor_mac` are populated, `rewrite_prepare_eth` succeeds and rewrites the Ethernet header of the packet. 
  
  However, `rewrite_forwarded_frame_in_place` only rewrites MAC/VLAN fields on the *existing* frame—it does not support copying or encapsulating the frame (which requires adding GRE/WireGuard headers and changing the packet length). Since the original packet in `pending_neigh` was buffered as a raw inner L3 packet from ingress, it is transmitted directly over the physical network interface (`target_ifindex`) without any tunnel encapsulation. This causes a **critical plaintext leak**.
- **Required Revision**:
  We must prevent `retry_pending_neigh` from transmitting tunnel-marked packets in plaintext. Since `retry_pending_neigh` does not support copy-mode encapsulation, these packets must be dropped:
  ```rust
  if decision.resolution.tunnel_endpoint_id != 0 {
      binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
      continue;
  }
  ```

---

#### Q8: Out-of-Scope Call on GRE Local-Origin Threads
- **Verdict**: Correctly ruled out of scope.
- **Verification**: In [userspace-dp/src/afxdp/coordinator/mod.rs:466-495](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/mod.rs#L466-L495), the `local_tunnel_source_loop` thread captures a cloned copy of `ForwardingState` at spawn time. Because `spawn_local_tunnel_sources` is only called at bringup ([reconcile/bringup.rs:445](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs#L445)), incremental commits do not refresh these threads.
- Under Path A, the captured ID remains stable, and R-C/R-D safely drop or purge the old logical interfaces, meaning the FNV change does not degrade the existing behavior. Ruled out of scope with follow-up issue committed.

---

### Part 3: Verdict

**PLAN-NEEDS-REVISION**

1. **Required Change 1**: Add a drop gate inside `retry_pending_neigh` in [userspace-dp/src/afxdp/neighbor_dispatch.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/neighbor_dispatch.rs) to ensure that any tunnel-marked packet (`decision.resolution.tunnel_endpoint_id != 0`) processed from the pending neighbor buffer is dropped rather than rewritten in-place and transmitted as plaintext.
