I will begin by listing the contents of the worktree directory at `/home/ps/git/bpfrx/.claude/worktrees/1873-research` to locate the plan document and associated source files.
I will read the draft plan document `docs/research/1873-tunnel-ids/plan.md` to understand the details of the proposed implementation, particularly the section on the blanket R-C gate and Section 11.
I will run a command to find the locations of `wg_control.rs`, `wg.rs`, `maybe_reinject_slow_path_from_frame`, and related files mentioned in the plan, so I can inspect their contents.
I will view the contents of `userspace-dp/src/afxdp/coordinator/wg_control.rs` around lines 500-650 to verify the behavior of the control thread's TUN-read encap path and how it handles handshake initiation or session errors.
I will view the contents of `userspace-dp/src/afxdp/frame/wg.rs` around lines 95-110 to see how the worker handles the pre-handshake cold path and handshake requests.
I will read the beginning of `userspace-dp/src/afxdp/coordinator/wg_control.rs` to verify how the control thread interfaces with the kernel `wgN` TUN device and performs encapsulation.
I will view the next segment of `wg_control.rs` from lines 201 to 300 to trace the TUN-read direction and how handshake initiation is triggered.
I will search for the definition and references to `maybe_reinject_slow_path_from_frame` to confirm its location and context in the slow-path routing/reinjection flow.
I will view the `maybe_reinject_slow_path_from_frame` function and surrounding code in `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` to see how reinjection is handled.
I will locate the `gre.rs` source file to inspect the GRE encapsulation logic.
I will search for encapsulation functions in `userspace-dp/src/afxdp/gre.rs`.
I will view `userspace-dp/src/afxdp/gre.rs` around lines 290-350 to see how GRE encapsulation is implemented.
I will search for occurrences of `encapsulate_native_gre_frame` to see how its output is handled.
I will view `userspace-dp/src/afxdp/frame/mod.rs` around lines 250-300 to trace how GRE encapsulation results are handled.
I will search the codebase for calls to `build_forwarded_frame` to see how the datapath handles the `None` fallback (e.g. reinjecting to the slow-path).
I will view `userspace-dp/src/afxdp/tx/dispatch/mod.rs` around lines 490-520 to see how `build_forwarded_frame_from_frame` failure handles the packet.
I will view lines 521-580 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see what happens when the build function returns `None`.
I will view lines 581-620 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see how `fallback_to_slow_path` is handled.
I will view lines 621-680 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see how `fallback_to_slow_path` triggers reinjection.
I will view lines 681-740 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs`.
I will view lines 741-820 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs`.
I will view lines 821-865 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs`.
I will search for `fallback_to_slow_path` in `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to see where it is evaluated and what action it triggers.
I will view lines 870-930 of `userspace-dp/src/afxdp/tx/dispatch/mod.rs` to trace where `fallback_to_slow_path` is processed.
I will search for the definition of `handle_forward_build_failure` to inspect its logic.
I will view lines 25-110 of `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs` to understand the build failure handling and how it interacts with slow-path reinjection.
I will view lines 111-128 of `userspace-dp/src/afxdp/tx/dispatch/slow_path.rs`.
I will search for `record_slow_path_accept` and related slow-path counters to see if any telemetry consumers rely on slow-path accepts for tunnel-marked frames.
I will view `userspace-dp/src/afxdp/umem/mod.rs` around lines 910-950 to understand what counters are bumped by `record_slow_path_accept`.
I will search the codebase for references to `slow_path_packets` or related telemetry counters to see how they are exported to Go or telemetry dashboards.
I will search the `pkg` directory (Go side) for any references to `slow_path_packets` to verify its usage.
I will search for occurrences of `record_exception` to see how exceptions are logged and tracked.
I will view the definition of `record_exception` in `userspace-dp/src/afxdp/disposition.rs` to verify how exception statuses are stored.
I will search the `pkg` directory for references to `Exception` or `exception` fields to see if the Go control plane filters or validates specific exception reasons.
I will search for `buildTunnelEndpointSnapshots` in `pkg` to find its definition and see how endpoint IDs are currently assigned.
I will view `pkg/dataplane/userspace/tunnels.go` around lines 1-100 to inspect the current logic for building tunnel-endpoint snapshots.
I will list files in `pkg/config` to see where configuration validation rules are defined.
I will search for validation-related functions in the `pkg/config` directory to understand how config validation rules are executed.
I will view the `ValidateConfig` function in `pkg/config/compiler.go` to see what kind of validation it does and how it's called.
I will search `pkg/config/compiler.go` for the compilation function to see where hard validation errors (commit failures) are returned.
I will find files named `helpers.rs` to verify the coordinator snapshot-apply reference in the plan.
I will view `./userspace-dp/src/server/helpers.rs` around lines 525-555 to confirm that tunnel interfaces are excluded from the binding-plan key and that snapshot diffing will correctly run during both reconcile and snapshot refresh paths.
I will search for `include_userspace_binding_interface` to confirm it excludes tunnel interfaces as referenced in the plan.
I will view the definition of `include_userspace_binding_interface` in `userspace-dp/src/server/helpers.rs` to verify that tunnel interfaces are indeed excluded.
An adversarial review of **DRAFT v4** of the plan document at [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/docs/research/1873-tunnel-ids/plan.md) has been completed. 

Below are the detailed answers to the three questions listed in Section 11 of the plan, backed by file and line evidence from the repository.

---

### 1. Ratification of the Blanket R-C Gate

We ratify the blanket R-C gate at the `maybe_reinject_slow_path_from_frame` chokepoint. There is no tunnel-marked transit traffic whose delivery depends on slow-path reinjection.

*   **WireGuard Cold Path verification:**
    *   In the worker datapath, when a transit packet fails encapsulation due to a missing session, [wg.rs:100-104](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/frame/wg.rs#L100-L104) intercepts `EncapError::NoSession`, directly triggers a handshake request via the engine, and returns `None` (dropping the packet):
        ```rust
        Err(EncapError::NoSession) => {
            // Request a handshake (rate-limited relaxed atomic) and drop.
            engine.request_handshake(monotonic_nanos());
            return None;
        }
        ```
    *   If the packet were reinjected to the kernel slow path (the kernel `wgN` route), it would be read from the TUN device by the `wg_control` thread and routed to `encap_and_send`. As seen in [wg_control.rs:592-596](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L592-L596), that path receives the exact same `EncapError::NoSession` from the engine and drops the packet as well:
        ```rust
        Err(crate::afxdp::wg::EncapError::NoSession) => {
            // No confirmed session yet — request a handshake (rate-
            // limited) and drop this packet.
            engine.request_handshake(monotonic_nanos());
        }
        ```
    *   **Conclusion:** In both paths, pre-handshake transit packets are dropped and a handshake is armed. Because the worker already triggers `request_handshake`, the kernel slow path shuttle delivers no traffic and initiates nothing that isn't already handled.

*   **GRE Neighbor Cold-Start verification:**
    *   If the outer next-hop MAC for a GRE destination is unresolved, the userspace builder returns `MissingNeighbor` (leading to a packet drop). 
    *   Although the first packet is dropped, the neighbor prober (#1769) remains active. Once neighbor resolution completes, subsequent transit packets are successfully encapsulated in userspace and forwarded. Normal TCP/application retransmission recovers the initial cold-start drop.

*   **Host-Originated Traffic:**
    *   Egress packets originating from the host itself (destined for `wgN`/`grN`) never traverse the AF_XDP `xpf-usp0` redirector.
    *   As verified in [wg_control.rs:214-228](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L214-L228), host-originated traffic is read directly from the persistent `wgN` TUN device by the control thread and encapsulated/sent. It is completely out of scope of the `maybe_reinject_slow_path_from_frame` gate and unaffected.

---

### 2. Telemetry and Counter Verification

We verified the impact of the blanket drops on telemetry:
*   In [umem/mod.rs:921-950](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/umem/mod.rs#L921-L950), `record_slow_path_accept` bumps atomic counters (such as `slow_path_packets`), which are serialized to Go via JSON ([protocol.go:1379](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/protocol.go#L1379)).
*   The Go control plane uses these counters for reporting status only (e.g. [statusfmt.go:807](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/dataplane/userspace/statusfmt.go#L807)). No invariant validation or routing decisions depend on them.
*   The exception logging mechanism at [disposition.rs:23-38](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/disposition.rs#L23-L38) pushes exception metadata to a thread-safe deque which is parsed as-is on the Go side ([monitor.go:462](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/pkg/monitoriface/monitor.go#L462)). Pushing the new `"tunnel_encap_unresolved"` exception and drop counter introduces no validation breaks.

---

### 3. Implementability and Completeness

The plan is fully specified and implementable:
*   **Config Domain Assignment (R-A/R-B):** Pure hashing in `StableTunnelEndpointID` and commit-check validation over the union of all tunnel names (to prevent HA split brain) are straightforward and clear.
*   **Blanket Drop (R-C) and TX Bypass Prevention (R-E):** Enforcing the drop gate in [slow_path.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs) and keeping tunnel-marked frames out of `pending_neigh` resolves the plaintext leak entirely.
*   **Apply-time Purge (R-D):** Diffing endpoints by ID inside both the `reconcile` and `refresh_runtime_snapshot` paths is correct. As verified in [helpers.rs:533-547](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/server/helpers.rs#L533-L547) and [helpers.rs:651-657](file:///home/ps/git/bpfrx/.claude/worktrees/1873-research/userspace-dp/src/server/helpers.rs#L651-L657), tunnel interfaces are excluded from the binding-plan key, making the execution of R-D on `refresh_runtime_snapshot` essential for handling runtime tunnel configuration updates.

---

### Verdict

PLAN-READY
