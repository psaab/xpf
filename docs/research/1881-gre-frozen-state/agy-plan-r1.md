# Hostile Adversarial Plan Review (Round 1) — xpf Issue #1881

This is the adversarial plan review for the GRE local-origin thread lifecycle and frozen-state bug (#1881), conducted against the workspace at `/home/ps/git/bpfrx/.claude/worktrees/1881-research`.

---

## 1. Concrete Observable Failures Verification

Each of the six failures (`F1` through `F6`) is **verified as fully reachable** under the current master branch without daemon restarts or full binding plan changes:

*   **F1 (GRE endpoint edit split-brain/false keepalives)**: **REACHABLE.**
    Editing GRE tunnel endpoints (destination/source/key) updates the configuration, which hashes to the same binding plan because tunnel interfaces are excluded from the binding plan at [userspace-dp/src/server/helpers.rs:539](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/server/helpers.rs#L539). The same-plan path calls [refresh_runtime_snapshot](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs#L997), which never updates `self.tunnel_sources`. The GRE thread spawned at [userspace-dp/src/afxdp/coordinator/mod.rs:564](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs#L564) continues running with the frozen `ForwardingState` clone captured at spawn time ([userspace-dp/src/afxdp/coordinator/mod.rs:540](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs#L540)), encapsulating local-origin keepalives and routing packets with the old parameters while transit traffic follows the new ones.
*   **F2 (Underlay route change divergence)**: **REACHABLE.**
    Route modifications are processed via the same-plan apply path and do not trigger a full binding reconcile. In [userspace-dp/src/afxdp/tunnel.rs:163](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs#L163), `resolve_tunnel_forwarding_resolution` is evaluated against the thread's frozen `ForwardingState` clone. Therefore, the thread resolves to stale egress interface indexes (`tx_ifindex`) and next-hops, while workers follow the updated route table.
*   **F3 (Runtime ADD blackhole)**: **REACHABLE.**
    Adding a tunnel does not trigger a full binding plan reconcile. The same-plan snapshot refresh ignores `self.tunnel_sources`, so no reader thread is spawned for the new TUN device. Because the coordinator does not publish a `SyncSender` for the new interface index to `local_tunnel_deliveries` ([userspace-dp/src/afxdp/coordinator/mod.rs:614](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/coordinator/mod.rs#L614)), any incoming decapsulated tunnel packet hits a lookup miss at [userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:161](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L161) and is dropped.
*   **F4 (Runtime REMOVE ghost traffic)**: **REACHABLE.**
    Removing a tunnel takes the same-plan path. The local-origin thread is never stopped or joined, so it retains the open TUN file descriptor. Under UNIX semantics, even if Go invokes `LinkDel` ([pkg/routing/tunnel.go:114](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/routing/tunnel.go#L114)), the kernel keeps the TUN interface alive in a zombie state as long as userspace-dp holds the fd open. The thread continues reading from the zombie device and encapsulating traffic.
*   **F5 (CoS / shaping / owner-RG staleness)**: **REACHABLE.**
    CoS and shaper changes take the same-plan path. The local-origin thread evaluates `resolve_cos_tx_selection_at` ([userspace-dp/src/afxdp/tunnel.rs:220](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs#L220)) against the frozen `ForwardingState` and continues policing and class-assigning packets based on the old rules.
*   **F6 (Thread death)**: **REACHABLE.**
    If the thread panics or encounters a fatal I/O error (e.g., if it attempts to open the TUN device before Go finishes creating it at boot), it exits [local_tunnel_source_loop](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs#L19). There is currently no supervisor or liveness task that respawns it; the tunnel's local-origin stream is permanently broken.

---

## 2. Answers to Section 11 Open Questions

1.  **Is the per-iteration ArcSwap load placement right?**
    Yes. A `WouldBlock` or `Ok(0)` result from a non-blocking TUN read leads to a 1ms sleep ([userspace-dp/src/afxdp/tunnel.rs:129](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs#L129)). Thus, the outer loop runs at most 1000 times per second when idle. Running `load_arc_if_changed` once per outer loop iteration costs ~1-2ns (uncontended atomic read + pointer comparison), which is a negligible fraction of CPU compared to the `read(2)` syscall (which takes ~1-2µs). Restricting the reload to the sleep/idle path would mean that under a saturated TUN stream, the thread would never go idle, leaving it running on a stale state indefinitely.
    
    *Critical Revision Required:* The plan currently loads the `ha_state` ArcSwap twice per packet: once in `enforce_ha_resolution_at` ([userspace-dp/src/afxdp/tunnel.rs:159](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs#L159)) and once in `synthesized_synced_reverse_entry` ([userspace-dp/src/afxdp/tunnel.rs:214](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs#L214)). This introduces a TOCTOU window. The plan must be revised to load `ha_state` once at the top of the outer loop, and pass a reference to the loaded `BTreeMap<i32, HAGroupRuntime>` map to `build_local_origin_tunnel_tx_request`.

2.  **Attachment-identity definition:**
    Yes, `(logical_ifindex, resolved name)` is a complete and robust restart condition. Under Linux, if a TUN interface is deleted via `LinkDel` ([pkg/routing/tunnel.go:114](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/pkg/routing/tunnel.go#L114)) and recreated with the same name, any existing open file descriptor associated with the deleted link is invalidated by the kernel. Subsequent operations on the old fd fail with fatal errors (`EBADFD` / `ENODEV`). The thread will detect the failure via [local_tunnel_io_error_is_fatal](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tunnel.rs#L7), exit its loop, and be reaped by the coordinator's finished-sweep (Pass 1). The next apply or status poll (1/s) will then spawn a new thread with the new fd. This recovery window is sub-millisecond during config apply, and at most ~1s during idle, which is completely acceptable for a cold path. No fd-generation check is required.

3.  **Disarmed-leg stop:**
    Stopping GRE local-origin threads on a disarmed same-plan refresh is correct. When userspace-dp is disarmed, workers are stopped, so there is no path to transmit enqueued packets. More importantly, during In-Service Software Upgrades (ISSU) or daemon restarts, keeping the TUN file descriptor open in a disarmed helper would block the incoming daemon instance from taking exclusive ownership of the TUN device, causing bind failures and upgrade locks. Releasing these file descriptors is necessary.

4.  **Defer-workers narrow prune:**
    The narrow prune is necessary. If a tunnel is deleted from the configuration, Go immediately deletes the TUN interface in the kernel. If userspace-dp keeps the file descriptor open during the defer-workers window (which can be seconds or minutes depending on RETH MAC resolution), the kernel cannot fully destroy the interface (retaining it in a zombie state). The narrow prune stops the thread and closes the file descriptor immediately, enabling clean and prompt kernel-side device reclamation.

5.  **Delivery-channel swap race:**
    Rebuild-after-join + single store is fully sufficient. Workers retrieve the `SyncSender` dynamically *for each packet* via [local_tunnel_deliveries.load()](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L159-L162). If a thread is stopped and joined during a reconcile, its receiver is dropped. Any worker trying to send to a cloned sender during this transition will get `Err(TrySendError::Disconnected)` ([userspace-dp/src/afxdp/tx/dispatch/slow_path.rs:183](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L183)), which is handled safely by logging a `local_tunnel_delivery_unavailable` exception. Once the map is swapped, workers retrieve the new sender.

6.  **Should the loop ALSO exit when its id disappears from the loaded state (self-terminating threads)?**
    No. centralizing the lifecycle in the coordinator's three-pass reconcile is essential. If the thread self-terminated, it would create asynchronous race conditions with the coordinator's synchronous prune. Furthermore, a transient route failure or dynamic resolution drop must *not* kill the thread. It must keep reading from the TUN and dropping packets until the route returns and forwarding can resume.

7.  **Severity honesty check (Security Impact):**
    **High Severity Security Leak Identified.** The plan's claim that no security-relevant mis-encapsulation is reachable from the frozen state is **incorrect**. 
    If the operator edits the destination IP (or GRE key) of a tunnel and commits, the interface name and ifindex remain unchanged, so the binding plan is identical. 
    Because the local-origin thread runs on the frozen `ForwardingState` clone, it encapsulates local-origin traffic (including sensitive routing updates and keepalives) using the old peer destination IP.
    The #1873 owner check ([userspace-dp/src/afxdp/gre.rs:314](file:///home/ps/git/bpfrx/.claude/worktrees/1881-research/userspace-dp/src/afxdp/gre.rs#L314)) only checks if `endpoint.logical_ifindex != decision.resolution.egress_ifindex`. Since the tunnel's logical ifindex did not change, the check passes.
    Consequently, local-origin traffic is encapsulated and transmitted to the **old destination IP** over the wire, resulting in plaintext data leakage to a potentially hostile third party.
    The fix is therefore required to prevent security leaks.

---

## 3. Threat and Race Hunt

*   **Torn-State Across Reload Point**: By loading `shared_forwarding` once at the top of the outer loop iteration and passing the `Arc<ForwardingState>` by reference down to `build_local_origin_tunnel_tx_request`, the entire packet build (routing, session creation, CoS mapping, encap) uses a single, self-consistent snapshot.
*   **Worker handles (`live` / `identities` / `worker_commands`)**: These are binding-plan-scoped. Any change to physical interfaces or bindings triggers a full binding plan change, which executes `stop_inner` (tearing down the GRE threads) and rebuilds the handles. Capturing these at spawn time is structurally sound.
*   **Reconcile vs Purge Ordering**: The tunnel-session purge runs before the forwarding swap, while the GRE thread reconcile runs after. This is correct: any packet enqueued by the old GRE thread right before it is joined carries the old session key and will be safely transmitted by workers, while replies will hit the purged conntrack table and be dropped.

---

## Verdict: PLAN-NEEDS-REVISION

The overall architectural approach (Path D) is correct, but the plan requires the following revisions to address TOCTOU windows, telemetry leakage, log clarity, and coherence checks:

### Required Revisions

1.  **Refactor HA State Load**:
    To eliminate the TOCTOU window where `ha_state` is loaded twice during packet processing, change the signature of `build_local_origin_tunnel_tx_request` to accept a direct reference to the loaded map `ha_runtime: &BTreeMap<i32, HAGroupRuntime>` instead of the `Arc<ArcSwap<...>>`. Load the map once at the top of the loop in `local_tunnel_source_loop` and pass it down:
    ```rust
    let ha_runtime = ha_state.load();
    // ...
    build_local_origin_tunnel_tx_request(..., &forwarding, &ha_runtime, ...)
    ```
2.  **Filter Tombstones from Delivery Map Publication**:
    When rebuilding the `local_tunnel_deliveries` map from `tunnel_sources` entries, ensure that only entries with active handles (`handle.is_some()`) have their `delivery_tx` channel published. Senders for tombstones (`handle.is_none()`) must be excluded from publication so that workers do not waste CPU cycles attempting to send to dead channels.
3.  **Establish GRE Tombstone Coherence Gate**:
    Formulate the GRE-specific tombstone respawn coherence check. The periodic liveness task must verify that the snapshot's row matches the desired tunnel parameters (mode, destination IP, source IP, key) in the current forwarding state. If they differ, the periodic sweep must skip respawning and wait for an apply-time reconcile to prune and recreate the thread with the new config.
4.  **Differentiate Log Messages**:
    Ensure that log statements for spawning, stopping, and tombstoning GRE local-origin threads use distinct prefixing (e.g., `xpf-userspace-dp: local GRE tunnel source thread...`) to avoid confusion with WireGuard control thread log output in journald diagnostics.

---
### Summary of Work
Analyzed the codebase under `/home/ps/git/bpfrx/.claude/worktrees/1881-research` to verify the root causes and reachability of GRE local-origin thread frozen-state bugs. Evaluated all considered paths, verified security impacts (identifying a data leakage vulnerability under endpoint modifications), pressure-tested race conditions (HA State TOCTOU, channel swap races), and detailed the exact required revisions to align the plan with the codebase rules and lock-less invariants.
