I will start by listing the files in the worktree directory `/home/ps/git/bpfrx/.claude/worktrees/1881-research` to locate the plan v2 and the round-1 archives.
I will list the files in the directory `/home/ps/git/bpfrx/.claude/worktrees/1881-research/docs/research/1881-gre-frozen-state` to check the plan v2 and archive files.
I will read the contents of `/home/ps/git/bpfrx/.claude/worktrees/1881-research/docs/research/1881-gre-frozen-state/plan.md` to study Plan v2 and the open questions.
I will search the codebase using grep to locate the implementation of local-origin tunnel threads and the coordinator reconcile routines.
I will view the contents of `userspace-dp/src/afxdp/tunnel.rs` around line 1 to 200 to understand the current GRE local-origin thread structure.
I will grep for `spawn_local_tunnel_sources` to see where it is located and how it is called.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` around line 340 to 450 to see the current spawn code and context.
I will grep for `tunnel_sources` to see how it is defined in the Coordinator struct and where else it is used.
I will view the stop routines in `userspace-dp/src/afxdp/coordinator/mod.rs` around line 217 to see how resources are cleaned up during stop/tear-down.
I will grep for `WgControlEntry` and `wg_control_threads` to locate their definitions and reconcile logic.
I will search case-insensitively for `wg_control` in `userspace-dp/src/afxdp` to find where the WG control thread structures are defined.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` around line 465 to understand the WG three-pass control thread reconcile.
I will list the directory `userspace-dp/src/afxdp` to find where the reconcile code and other coordinator files are structured.
I will list the contents of the `coordinator` directory to find the layout of the reconcile routines.
I will list the contents of the `reconcile` directory to see all the reconcile modules.
I will view `userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs` to understand the current refresh logic for forwarding state and runtime snapshots.
I will search the codebase for `refresh_runtime_snapshot` using grep to locate all its definitions and call sites.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` around line 580 to see how `refresh_runtime_snapshot` handles incoming snapshots and forwarding state updates.
I will view more lines of the `refresh_runtime_snapshot` method in `userspace-dp/src/afxdp/coordinator/mod.rs` to see the rest of the refresh logic and where `self.tunnel_sources` or `wg_control` are updated.
I will view `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` around where `spawn_local_tunnel_sources` is called.
I will view lines 300 to 365 of `bringup.rs` to see where `spawn_local_tunnel_sources` or other helpers are invoked.
I will read `/home/ps/git/bpfrx/.claude/worktrees/1881-research/docs/research/1881-gre-frozen-state/codex-plan-r1.md` to see Codex's findings from Round 1.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1881-research/docs/research/1881-gre-frozen-state/codex-plan-r1.md` with the correct path.
I will read `/home/ps/git/bpfrx/.claude/worktrees/1881-research/docs/research/1881-gre-frozen-state/agy-plan-r1.md` to see the AGY findings from Round 1.
I will read `/home/ps/git/bpfrx/.claude/worktrees/1881-research/docs/research/1881-gre-frozen-state/claude-smr-plan-r1.md` to see the Claude SMR findings from Round 1.
I will search `userspace-dp/src/afxdp/gre.rs` for the owner check or endpoint check to get the exact lines and context.
I will view `userspace-dp/src/afxdp/gre.rs` from line 290 to 320 to check the endpoint check.
I will search for the definition of `resolve_tunnel_forwarding_resolution` in the codebase using grep.
I will view `userspace-dp/src/afxdp/forwarding/mod.rs` around line 1515 to inspect how `resolve_tunnel_forwarding_resolution` resolves tunnel endpoints and check for any properties we need to verify.
I will view lines 1475 to 1515 of `userspace-dp/src/afxdp/forwarding/mod.rs` to see the entire `resolve_tunnel_forwarding_resolution` implementation.
I will search `userspace-dp/src/afxdp/coordinator/mod.rs` for `self.workers` to understand how workers' handles and state are stored.
I will grep for the definition of `workers` inside the coordinator state or types to understand its fields.
I will search for the definition of `WorkerManager` in the coordinator directory to see its fields.
I will view `userspace-dp/src/afxdp/coordinator/worker_manager.rs` to see the fields of `WorkerManager`.
I will grep for `defer_workers` in the repository to understand how the worker deferring logic operates and see when `self.workers.handles` gets populated.
I will view `/home/ps/git/bpfrx/userspace-dp/src/server/handlers/snapshot.rs` around line 68 to 125 to check the `defer_workers` logic during snapshot application.
I will search for `local_tunnel_deliveries` in `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` to examine how workers access the delivery channels and handle disconnected senders.
I will view `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` around line 150 to check how `local_tunnel_deliveries` is accessed and how send failures are handled.
I will search for `refresh_fabric_links` in `userspace-dp/src/afxdp/coordinator/mod.rs` to see how it modifies forwarding state.
I will search for `fn refresh_fabric_links` using grep to locate it exactly.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` from line 570 to 590.
I will grep for `queue_warm_pass` to find all its call sites, including the RG promotion path.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` around line 880 to 900 to see what triggers `queue_warm_pass(true)`.
I will grep for `include_userspace_binding_interface` in `userspace-dp/src/server/helpers.rs` to verify the exact line numbers.
I will view `userspace-dp/src/server/helpers.rs` from line 530 to 550 to check where the tunnel interfaces are excluded from the binding plan.
# Hostile Adversarial Plan Review (Round 2) — Verdict: **PLAN-READY**

Having evaluated Plan v2 in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/docs/research/1881-gre-frozen-state/plan.md) against the actual Rust/Go sources of the working tree, I verify that **all Round 1 findings have been resolved** and **the proposed architecture is sound and ready to ship**. 

Below is the verified code-level trace analysis of the new mechanisms, followed by evaluations of the 5 open questions.

---

## 1. Trace Verification: D.1b Rotation Gate (Same-ID Mode-Flip)

### The Window and the Trace
Suppose an operator updates interface `gr-1` from GRE to WireGuard under the same name (deriving the same stable identifier `T` via name hashing).
1. **Config Apply**: Tunnel interfaces are excluded from the binding-plan hash at [helpers.rs:539-541](file:///home/ps/git/bpfrx/userspace-dp/src/server/helpers.rs#L539-L541). The Go side calls `apply_snapshot` which follows the same-plan path in [snapshot.rs:95](file:///home/ps/git/bpfrx/userspace-dp/src/server/handlers/snapshot.rs#L95), executing `refresh_runtime_snapshot`.
2. **Snapshot Refresh**: The coordinator updates `self.forwarding` to a new `ForwardingState` where endpoint `T` is in `"wireguard"` mode, and stores it in the shared worker-visible ArcSwap at [mod.rs:691](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs#L691).
3. **Thread State Load**: The GRE local-origin thread for ID `T` is still running. In its next loop iteration, it calls `load_arc_if_changed` (Plan D.1), detects the Arc swap, and updates its local `forwarding` reference.
4. **Gate Evaluation**: The thread re-evaluates `endpoint_attachment_valid(&forwarding, T, spawned_ifindex, &spawned_name)` (Plan D.1b). 
   - It performs a lookup on `forwarding.tunnel_endpoints.get(&T)`. It finds the endpoint.
   - However, `ep.mode` is `"wireguard"` (which is not in `{"gre", "ip6gre"}`).
   - The gate evaluates to `false`, setting `endpoint_attached = false`.
5. **Park Invariant**: The thread parks: it still drains `delivery_rx` and reads from the stale TUN device to prevent queue backups, but drops packets without attempting to resolve or encapsulate them ([gre.rs:306-308](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/gre.rs#L306-L308) / [tunnel.rs:159-169](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tunnel.rs#L159-L169)).
6. **Coordinator Prune**: Concurrently, the coordinator executes `reconcile_local_tunnel_sources`. Pass 2 (Stale Prune) checks the running entry `T` against `self.forwarding` and marks it stale (reason: `mode_changed`).
7. **Thread Join**: The coordinator unpublishes the delivery map key, stops the thread (`stop = true`), and joins it.
8. **WG Spawn**: The WireGuard reconcile pass runs, detects ID `T` in `wireguard` mode with no thread, and spawns the new WG control thread.

**Verdict**: The D.1b rotation gate **fully closes** the same-id mode-flip/reattachment window by forcing the thread to park instantly upon Arc rotation, preceding the coordinator's synchronous join.

---

## 2. Trace Verification: Unpublish-Before-Join Bounding

### Under a Busy Delivery Producer
Without the stop check and unpublish ordering, a worker thread executing slow-path processing could flood the `delivery_tx` channel indefinitely, blocking the coordinator thread during the synchronous `join()` call.
1. **Workers Egress**: Workers lookup and clone delivery channels *per-packet* at [slow_path.rs:159-162](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L159-L162).
2. **Pass 2 (Stale Prune)**: The coordinator first performs **Store #1** (unpublish), replacing `local_tunnel_deliveries` with a map rebuilt without the stale channels.
3. **Worker Transition**: Any worker executing slow-path processing after Store #1 gets a lookup miss (`None`) and skips writing to the stale `delivery_tx`.
4. **Drain Breakout**: The coordinator sets `stop = true` and blocks on `join()`. 
5. **Bounded Join**: The thread's inner loop draining `delivery_rx` checks `stop.load(Ordering::Relaxed)` on every chunk ([tunnel.rs:53-70](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tunnel.rs#L53-L70)). It observes `stop == true` and immediately returns, ignoring any residual packets in the channel queue.
6. **Cleanup**: The thread exits and drops its `Receiver`, disconnecting the channel. Any remaining worker holding the old map from before Store #1 gets `Disconnected` on `try_send` and handles it gracefully via exception logging at [slow_path.rs:183-195](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L183-L195).

**Verdict**: The combination of Store #1 unpublishing the channel and the inner `stop` check inside the drain loop bounds the join to a maximum of one inner loop iteration, resolving the latency hazard.

---

## 3. Trace Verification: SMR-1 Gate Predicate

During a deferred same-plan snapshot update (`defer_workers` transitioning from `true` to `true` at [snapshot.rs:109-111](file:///home/ps/git/bpfrx/userspace-dp/src/server/handlers/snapshot.rs#L109-L111)):
- No worker threads exist. `self.workers.handles` (defined in [worker_manager.rs:16](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/worker_manager.rs#L16)) is completely empty.
- If the GRE reconcile ran its spawn pass here, it would capture empty `live`, `identities`, and `worker_commands` maps, leading to a permanent exception flood during TUN reads.
- **SMR-1 Gate**: Gating spawn with `!self.workers.handles.is_empty()` successfully intercepts this, skipping the spawn pass.
- When `defer_workers` transitions to `false`, the server triggers `reconcile_status_bindings` at [snapshot.rs:114](file:///home/ps/git/bpfrx/userspace-dp/src/server/handlers/snapshot.rs#L114), which spawns the workers, populates the `handles` map, and invokes [bringup.rs:362](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs#L362) (`coord.spawn_local_tunnel_sources`), bringing up the GRE threads under a fully hydrated worker environment.

**Verdict**: The `handles.is_empty()` check is the correct and necessary predicate to evaluate worker presence.

---

## 4. Answers to Section 11 Open Questions

### Q1: Is the D.1b park sufficient while UNPARKED deliveries still flow? (Ratify)
**Ratify**. 
- Writing a decapped packet to a stale/zombie TUN fd is harmless. The fd is bound to the old `struct net_device` in the kernel; subsequent writes will either fail fatally (causing the thread to exit immediately via `local_tunnel_io_error_is_fatal` check at [tunnel.rs:62-63](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tunnel.rs#L62-L63)) or fall into a silent kernel black hole.
- Packets can never cross-talk into a recreated/remapped tunnel because Linux fd-to-device bindings are instance-locked (they do not dynamically re-bind on name or index reuse).
- Continuing to drain deliveries during the sub-millisecond park-to-join window keeps the queue clear and prevents transient `local_tunnel_delivery_queue_full` exceptions.

### Q2: Two-store reconcile (Ratify)
**Ratify**. 
Workers load `local_tunnel_deliveries` fresh *per packet* at [slow_path.rs:159-160](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L159-L160).
- If a worker loads the map between stores, it falls back cleanly to the slow-path reinjector (or drops).
- If a worker holds the sender of a pruned thread during the transition, `try_send` returns `Disconnected` which is safely caught and recorded at [slow_path.rs:183](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L183). No stronger synchronization is required.

### Q3: SMR-1 gate edge (Ratify)
**Ratify**. 
`handles.is_empty()` is the right predicate. Even if configured bindings are sparse, the presence of worker handles means the worker threads are running. Stale/empty bindings on running workers are normal operational states handled by standard slow-path drops. The gate's sole job is to shield against the zero-worker deferred window, which it does perfectly.

### Q4: Rotation-gate cost honesty (Ratify)
**Ratify**. 
BTreeMap lookups and string comparisons are only evaluated inside the `Some(new)` branch of `load_arc_if_changed` (on config update). Steady-state packet forwarding loop cost is zero.

### Q5: Anything still missed in the failure matrix? (None)
- **`refresh_fabric_links`**: This method performs a `self.ha.forwarding.store(...)` swap at [mod.rs:587](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs#L587). This triggers the rotation gate check in the GRE thread loop. Since `tunnel_endpoints` and `ifindex_to_name` are identical, the gate continues to evaluate to `true` with zero runtime disruption.
- **RG promotion**: `on_rg_promote_active` at [mod.rs:884](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs#L884) triggers `queue_warm_pass(true)` but does not rotate the forwarding state or write to `self.ha.forwarding`. The GRE thread correctly continues executing without gate re-evaluation, and reads the HAGroup active promotion state next loop iteration.

---

## Verdict Summary
*   **D.1b**: Verified. Closes same-id mode-flip/reattachment window.
*   **Unpublish-before-join**: Verified. Bounds join latency.
*   **SMR-1**: Verified. Prevents frozen empty-capture thread spawns.
*   **Open Questions**: Ratified.
*   **Verdict**: **`PLAN-READY`**
