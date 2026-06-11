I will locate and read the plan document at `/home/ps/git/bpfrx/.claude/worktrees/1873-research/docs/research/1873-tunnel-ids/plan.md` first, as well as identify the repository structure.
I will read the contents of the plan document to understand the proposed implementation.
I will list the root directory contents of the worktree to identify where all these files reside.
I will search for the location of `manager_ha.go` within the workspace.
I will list the contents of the `pkg/dataplane/userspace` directory, as it contains several Go files mentioned in the prompt.
I will view `pkg/dataplane/userspace/tunnels.go` to examine `buildTunnelEndpointSnapshots` and understand how tunnel-endpoint IDs are currently generated and used.
I will search for all references to `buildTunnelEndpointSnapshots` to see how it is called and how `interfaces` changes.
I will view `pkg/dataplane/userspace/builder.go` around line 42 to see where the `interfaces` snapshot comes from.
I will view `pkg/dataplane/userspace/interfaces.go` to understand how `buildInterfaceSnapshots` behaves and what eligibility gates are applied there.
I will view `pkg/dataplane/userspace/manager_ha.go` from line 740 to 880 to examine the HA synchronization logic and how tunnel endpoint IDs are synced and resolved.
I will view `pkg/cluster/sync_protocol.go` around the offsets described (e.g. 154, 239, 371, 472) to see how tunnel endpoint IDs are serialized/deserialized and whether there are assumptions about them.
I will search for `daemon_ha_userspace.go` in the codebase to find its location and read the code.
I will search for `daemon_ha_userspace.go` specifically in the active worktree path.
I will list the contents of the `pkg/daemon` directory to see if `daemon_ha_userspace.go` resides there.
I will view `pkg/daemon/daemon_ha_userspace.go` around line 228 to see how the daemon handles userspace HA synchronization and tunnel endpoint IDs.
I will list the directory contents of `userspace-dp/src/afxdp` to find where the Rust files are located.
I will view `userspace-dp/src/afxdp/forwarding_build/tunnels.rs` to see how Go-provided tunnel snapshots are mapped into the Rust forwarding tables.
I will view `userspace-dp/src/afxdp/forwarding_build/wg.rs` to see how WG engine instances are populated and how IDs are referenced.
I will search for `spawn_wg_control_threads` and `spawn_local_tunnel_sources` in `userspace-dp/src/afxdp/coordinator/mod.rs` to find the exact line numbers.
I will search for `spawn_local_tunnel_sources` in the same file to locate it.
I will view lines 350 to 520 of `userspace-dp/src/afxdp/coordinator/mod.rs` to examine the control threads and local tunnel sources implementation.
I will search for occurrences of `spawn_local_tunnel_sources` inside the coordinator code to verify if it is indeed called only at bringup.
I will search for any other reference to `spawn_local_tunnel_sources` within the `userspace-dp/src` directory.
I will view the code in `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` around line 362 to verify the context of `spawn_local_tunnel_sources`.
I will search for occurrences of the `bringup` function call to see if it only runs at initial startup.
I will search for the word `bringup` to find where the bringup reconciliation is invoked.
I will search for occurrences of `bring_up_workers` to see when worker bringup is run.
I will view `userspace-dp/src/afxdp/coordinator/reconcile/mod.rs` to see how/when `bring_up_workers` is called.
I will search for `tunnel_sources` in the `userspace-dp/src/` directory to see how the coordinator handles local tunnel source cleanup on reload.
I will view lines 200 to 240 of `userspace-dp/src/afxdp/coordinator/mod.rs` to see how the coordinator handles local tunnel source threads on shutdown/reload.
I will view the `teardown.rs` file to see how the coordinator tears down state on reload.
I will search for `reconcile` definitions and usages to see how configuration updates are handled and if there is any path that updates the configuration without restarting the local tunnel sources.
I will search for `local_tunnel_source_loop` to see how it uses `tunnel_endpoint_id`.
I will view `userspace-dp/src/afxdp/tunnel.rs` from line 1 to 150 to understand `local_tunnel_source_loop`.
I will search for `refresh_runtime_snapshot` in the `userspace-dp/src/` directory to see if there is another way configuration snapshots are refreshed without tearing down the local tunnel sources.
I will view `refresh_runtime_snapshot` in `userspace-dp/src/afxdp/coordinator/mod.rs` around line 591 to see if it stops and restarts `tunnel_sources` or if they are left running.
I will view `userspace-dp/src/server/handlers/snapshot.rs` to see when `refresh_runtime_snapshot` is called.
I will search for `struct ForwardingState` to see its fields and understand if it shares state with the coordinator via `Arc`s or if it is independent.
I will search for `struct ForwardingState` in the codebase.
I will view the definition of `ForwardingState` in `userspace-dp/src/afxdp/types/forwarding.rs`.
I will search for `reconcile_status_bindings` in the Rust source code.
I will view lines 290 to 380 of `userspace-dp/src/server/helpers.rs` to examine `reconcile_status_bindings`.
I will search for `snapshot_binding_plan_key` to see what fields determine whether a full reconcile is run.
I will view `userspace-dp/src/server/helpers.rs` from line 390 to 450 to understand what config changes trigger a full reconcile vs a same-plan refresh.
I will search for the definition of `include_userspace_binding_interface`.
I will view lines 530 to 550 of `userspace-dp/src/server/helpers.rs` to see what interfaces are included in the binding plan.
I will view lines 146 to 230 of `userspace-dp/src/afxdp/tunnel.rs` to see what `build_local_origin_tunnel_tx_request` does.
I will search for references to `tunnel_endpoints` or forwarding resolution in `userspace-dp/src/afxdp/frame/wg.rs` to verify the claim that stored session IDs are re-resolved per packet against the current forwarding state.
I will view lines 40 to 80 of `userspace-dp/src/afxdp/frame/wg.rs` to examine the packet forwarding logic for WireGuard tunnels.
I will view `userspace-dp/src/afxdp/gre.rs` around line 308 to see how GRE encapsulation handles tunnel endpoint lookup and potential drops.
I will search for occurrences of `wg_encap_frame` and `encapsulate_native_gre_frame` to trace their callers and verify if returning `None` drops the packet.
I will view lines 230 to 280 of `userspace-dp/src/afxdp/frame/mod.rs` to see what happens when `None` is returned.
I will search for `build_forwarded_frame` callers to confirm that returning `None` drops the packet.
I will view lines 480 to 520 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see how the worker handle a packet when `build_forwarded_frame_from_frame` returns `None`.
I will view lines 515 to 570 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs`.
I will view lines 571 to 600 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see what happens when the build function returns `None`.
I will search for `fallback_to_slow_path` in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see what happens when it is set to true.
I will view lines 560 to 620 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see how `fallback_to_slow_path` triggers redirection of the packet.
I will search for usage of `fallback_to_slow_path` in the same file to locate where the fallback is executed.
I will search for `fallback_to_slow_path` variable references to trace how the fallback path is executed.
I will view lines 880 to 920 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see what happens when `fallback_to_slow_path` is true.
I will search for `handle_forward_build_failure` to see how it routes failed packets.
I will view `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` from line 25 to 120 to examine `handle_forward_build_failure`.
I will view lines 121 to 200 of `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` to see how the slow path reinjection works.
I will view lines 201 to 250 of `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs`.
I will view `userspace-dp/src/afxdp/session_glue/mod.rs` around line 91 to check the resolution of stored session IDs against the current forwarding state.
I will search for `resolve_tunnel_forwarding_resolution` to see how it looks up the endpoint.
I will view lines 1480 to 1515 of `userspace-dp/src/afxdp/forwarding/mod.rs`.
I will search for `codec.rs` to locate the event stream codec file.
I will search for `codec.rs` in the entire worktree directory.
I will list the contents of the `event_stream` directory inside `userspace-dp/src`.
I will view `userspace-dp/src/event_stream/codec.rs` from line 190 to 230.
I will search for `TunnelEndpointID` inside `pkg/dataplane/userspace/eventstream.go` to see where the event stream parsing reads the tunnel endpoint ID.
I will search for `FastMap` definition to confirm its container type.
I will search for any pattern of `tunnel_endpoint_id as usize` or `id as usize` inside the Rust code to check for array-by-id indexing.
I will list the contents of the `userspace-dp/src/afxdp/bpf_map` directory to see if there are any BPF maps that might store tunnel IDs.
I will search for `tunnel` or `endpoint` inside the `userspace-dp/src/afxdp/bpf_map` directory to see if there are any BPF map stores for tunnels.
I will view lines 1 to 40 of `userspace-dp/src/afxdp/bpf_map/mod.rs` to see how BPF maps handle tunnel endpoint IDs.
I will search for `tunnel_endpoint_id` inside the `userspace-dp/src/afxdp/bpf_map` directory to see if it is referenced elsewhere.
I will search for `TunnelEndpoints` in the Go codebase to see if there are any other consumers of the tunnel endpoint IDs.
I will search for the loop over `TunnelEndpoints` in `maps_sync.go` to see what it does.
I will search for `TunnelEndpointID` in the Go codebase.
# Adversarial Plan Review: stable tunnel-endpoint IDs across config commits (#1873)

We have reviewed the implementation plan `docs/research/1873-tunnel-ids/plan.md` against the active codebase at `/home/ps/git/bpfrx/.claude/worktrees/1873-research`. Below is the detailed adversarial analysis, including verified counter-examples and file:line evidence.

---

### Finding 1: Security Hazard — Absent/Stale IDs Cause Plaintext Leak via Slow-Path Fallback (Refutes Plan §5/§7)
* **Severity:** CRITICAL
* **Description:** The plan claims that when a tunnel is removed, its ID dereferences to `None`, which causes `frame/wg.rs:53` and `gre.rs:308` to drop the frame as a "fail-safe" (Plan §5, Path A). 
* **Proof:** While `wg::wg_encap_frame` and `gre::encapsulate_native_gre_frame` indeed return `None` on lookup failure, this does **not** drop the packet. Instead, it triggers a fallback to the kernel slow-path, where the unencapsulated packet can leak in plaintext.
* **Trace:**
  1. In [userspace-dp/src/afxdp/frame/wg.rs:52](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/frame/wg.rs#L52), `forwarding.tunnel_endpoints.get(&id)?` returns `None` when the ID is absent.
  2. In [userspace-dp/src/afxdp/frame/mod.rs:246-248](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/frame/mod.rs#L246-L248), this `None` propagates up, causing `build_forwarded_frame_from_frame` to return `None`.
  3. In the worker's fast path ([userspace-dp/src/afxdp/tx/dispatch/mod.rs:571-574](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/mod.rs#L571-L574)), this `None` sets `build_failed = true` and `fallback_to_slow_path = true`.
  4. This triggers `handle_forward_build_failure` ([userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:60-73](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L60-L73)), which enqueues the unencapsulated L3 packet to the slow-path TUN device `xpf-usp0` via `slow_path.enqueue(packet)`.
  5. The Linux kernel receives the plaintext packet on `xpf-usp0` and looks up the routing table. Because the tunnel interface has been removed, the kernel routes the packet via the default route over the physical WAN interface, leaking private traffic in **plaintext** to the physical network.

---

### Finding 2: Eligibility Gate Collision Shift — Permanent HA ID Mismatch (Refutes Plan §7 Invariant 4 & §11 Q6)
* **Severity:** MAJOR
* **Description:** Under Path A as specified, `addEndpoint` is called inside `buildTunnelEndpointSnapshots` during sorted-name configuration traversal but returns early if the interface is not in the kernel. This creates eligibility-gate dependent collision resolution, causing surviving tunnel IDs to shift when other tunnels flap, leading to HA ID mismatches.
* **Proof:**
  * In [pkg/dataplane/userspace/tunnels.go:56-59](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/tunnels.go#L56-L59), the eligibility gate check is run:
    ```go
    iface, ok := ifaceByName[ifName]
    if !ok {
        return
    }
    ```
  * In [pkg/dataplane/userspace/tunnels.go:20](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/tunnels.go#L20), `ifaceByName` is populated only with interfaces that have a live `Ifindex > 0`. If a link is down or transiently absent in the kernel (e.g. at boot), `ok` is false and `addEndpoint` returns early.
  * **Counter-Example Trace:** 
    * Suppose we have two configured tunnels `wg0` (sorts first) and `wg1` that hash to the same value `X`.
    * **Case 1 (Both Up):** `addEndpoint("wg0")` reserves `X`. `addEndpoint("wg1")` collides, probes, and gets `X+1`. `wg1` ID is `X+1`.
    * **Case 2 (`wg0` Transiently Down/Absent):** `wg0` fails the `ifaceByName` gate and returns early. `addEndpoint("wg1")` is called, finds `X` free, and gets ID `X`.
    * When `wg0` comes back up, a new snapshot is built. `wg1` is re-evaluated, collides with `wg0`, and shifts to `X+1`. This triggers a WG session reset and drop on `wg1`, which was stable the entire time.
    * If FW0 and FW1 have differing link statuses for `wg0` at boot, they will assign different IDs to `wg1`, leading to permanent HA sync drift and routing errors.

---

### Finding 3: Stale GRE Local-Origin Threads in Same-Plan Refreshes (Refutes Plan §10 Out of Scope Claim)
* **Severity:** MAJOR
* **Description:** The plan dismisses GRE local-origin thread stability as "pre-existing, orthogonal" (Plan §10). However, because GRE virtual interfaces are excluded from the binding plan key, a config commit updating GRE tunnels runs `refresh_runtime_snapshot` instead of `reconcile`. This leaves local GRE threads running with stale `ForwardingState` and stale IDs, causing cross-tunnel data leaks and incorrect routing.
* **Proof:**
  * In [userspace-dp/src/server/helpers.rs:539-541](file:///home/ps/git/bpfrx/userspace-dp/src/server/helpers.rs#L539-L541), tunnel interfaces are explicitly excluded from the binding plan key:
    ```rust
    if iface.tunnel {
        return false;
    }
    ```
  * Therefore, adding, removing, or updating a GRE tunnel configuration keeps the binding plan key unchanged, running `refresh_runtime_snapshot` instead of `reconcile` ([userspace-dp/src/server/handlers/snapshot.rs:95](file:///home/ps/git/bpfrx/userspace-dp/src/server/handlers/snapshot.rs#L95)).
  * `refresh_runtime_snapshot` ([userspace-dp/src/afxdp/coordinator/mod.rs:591](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs#L591)) does **not** call `spawn_local_tunnel_sources`.
  * The running thread for the GRE tunnel continues to loop using the old `ForwardingState` copy and old `tunnel_endpoint_id` it captured at spawn time ([userspace-dp/src/afxdp/tunnel.rs:19-35](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tunnel.rs#L19-L35)).
  * If a tunnel ID shifts under collision or a tunnel is removed:
    * The local GRE thread continues to write sessions with the old `tunnel_endpoint_id` ([userspace-dp/src/afxdp/tunnel.rs:191](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tunnel.rs#L191)).
    * The worker threads running with the new `ForwardingState` will resolve the old ID to the wrong tunnel (cross-tunnel leak) or `NoRoute` (dropping reverse traffic).
    * The GRE thread continues to encapsulate packets using the old destination IP defined in its stale `ForwardingState`, ignoring the config update entirely.

---

### Finding 4: Consumer Map Verification (Checks Plan §2 against Real Code)
* **Severity:** VERIFIED SAFE
* **Description:** We verified all references to tunnel ID containers and events to ensure they support sparse/large IDs (like 65000) under Path A.
  * **Rust Forwarding Table:** In `types/forwarding.rs:23`, `tunnel_endpoints` is a `FastMap<u16, TunnelEndpoint>`, which is defined as `FxHashMap` in `types/mod.rs:37`. It natively supports sparse keys and does not index by array offset.
  * **Go HA Sync & Map Sync:** In `manager_ha.go:854/867` and `maps_sync.go:1529/1551`, Go loops over `snapshot.TunnelEndpoints` slices using sequential iteration (`for _, endpoint := range ...`) rather than indexing by ID.
  * **Event Stream / Wire:** `event_stream/codec.rs:209` copies the u16 ID directly into a 2-byte slot at `buf[16:18]`, and `eventstream.go:803` parses it via `binary.LittleEndian.Uint16(payload[16:18])`.
  * **BPF maps / segmentation:** `bpf_map/mod.rs:11` only checks `decision.resolution.tunnel_endpoint_id == 0` for boolean gating; it does not map/index by ID.

---

### Finding 5: Evaluation of Paths B/C/D Kill Rationale (Checks Plan §5)
* **Verdict:** CORRECT
  * **Path B (name-keys):** Correctly killed. Changing hot-path structs like `SessionDecision` to carry strings violates zero-allocation performance invariants and introduces a versioned wire break across HA sync.
  * **Path C (Rust-side compare):** Correctly killed. Does not address wrong-tunnel encap in session tables, GRE origin threads, or HA sync drift.
  * **Path D (Tombstones):** Correctly killed. Monotonic tombstone counters depend on history, guaranteeing permanent cross-node HA sync disagreement.

---

## Required Revisions for PLAN-NEEDS-REVISION

To address these critical defects, the implementation plan must be updated with the following numbered changes:

1. **Implement Fast-Path Drop on Absent Tunnel IDs (Fixes Plaintext Leak):**
   * Update the packet transmission path in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` so that if `decision.resolution.tunnel_endpoint_id != 0` but `forwarding.tunnel_endpoints.get` returns `None` (tunnel was deleted/staled), the packet is **dropped immediately** on the fast path. It must **not** set `fallback_to_slow_path = true`, preventing plaintext leaks via `xpf-usp0`.

2. **Pre-allocate IDs Independently of Eligibility Gates (Fixes HA ID Drift):**
   * Modify the Go snapshot builder `buildTunnelEndpointSnapshots` in `pkg/dataplane/userspace/tunnels.go` to pre-calculate stable IDs for **all configured tunnels** in `cfg` in alphabetical name order. 
   * Store these name-to-ID mappings in a temporary map.
   * Only evaluate the eligibility gates (e.g. `ifaceByName` presence, source/destination validation) *after* the mapping is built. When an eligible tunnel is added to the output slice, assign it the pre-allocated stable ID from the mapping. This guarantees that link up/down states do not shift colliding tunnel IDs.

3. **Reconcile GRE Local-Origin Threads on Same-Plan Updates (Fixes Stale GRE Forwarding):**
   * Update `refresh_runtime_snapshot` in `userspace-dp/src/afxdp/coordinator/mod.rs` to reconcile GRE local-origin threads (similar to how `spawn_wg_control_threads()` reconciles WireGuard threads). It must stop and join threads for removed/updated GRE endpoints and spawn new threads for newly added/updated endpoints, passing the new `ForwardingState`.

4. **Verify Eligibility Flaps in Test Plan:**
   * Update the Go unit test plan (Plan §9) to explicitly assert ID stability when mock configurations contain a colliding pair of interfaces where one is mock-absent from the kernel (simulating a link down) and then becomes mock-present.

---

## Verdict

PLAN-NEEDS-REVISION
