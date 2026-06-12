**Findings**

1. **MAJOR: store-before-prune creates a same-id stale-thread window.**  
   The plan puts GRE reconcile after `self.forwarding = new_forwarding` and `self.ha.forwarding.store(...)`, matching current WG ordering at `userspace-dp/src/afxdp/coordinator/mod.rs:1137`, `:1155`, `:1163-1167`. A GRE thread that runs in that window would reload the new forwarding state but still read from the old TUN fd. The builder uses only `tunnel_endpoint_id`: `tunnel.rs:76-80`; resolution fetches the endpoint by id and stamps `egress_ifindex = endpoint.logical_ifindex`: `forwarding/mod.rs:1521`, `:1547-1552`; the GRE owner check then compares that same new endpoint to that same new resolution: `gre.rs:306-317`. So for temporal id re-owner, or same-interface mode flip, the #1873 owner check does **not** prove the thread is attached to the right TUN. Mode flip is especially reachable because ids are name-only: `pkg/config/tunnelid.go:9-29`, WG rows are admitted without GRE source/destination: `pkg/dataplane/userspace/tunnels.go:61-63`, and Rust WG endpoint hydration uses unspecified source/destination: `forwarding_build/tunnels.rs:20-30`. `resolve_tunnel_forwarding_resolution` and `encapsulate_native_gre_frame` do not check `mode`: `forwarding/mod.rs:1515-1557`, `gre.rs:299-306`.

2. **MAJOR: delivery-map “store after join” does not bound join latency.**  
   The plan claims stop+join is bounded by one loop iteration, but the loop checks `stop` only at the outer loop: `userspace-dp/src/afxdp/tunnel.rs:52`. Before the read path, it drains `delivery_rx` until `Empty` or `Disconnected`: `tunnel.rs:53-70`. Workers can keep obtaining the old sender while it remains published: `tx/dispatch/slow_path.rs:156-167`; send failures are only handled for full/disconnected channels: `slow_path.rs:171-183`. The queue is large enough to sustain the race: `userspace-dp/src/afxdp/mod.rs:313`. Because the plan republishes the delivery map after join, a busy inbound local-delivery stream can keep the receiver non-empty and invalidate the control-thread join budget.

3. **MEDIUM: the “whole packet torn-state-free” claim is too broad.**  
   The ForwardingState part is coherent if the loop loads one Arc and passes `&forwarding` through the build. But the packet build also reads HA runtime separately: `enforce_ha_resolution_at` calls `ha_state.load()` at `forwarding/mod.rs:539-546`, and reverse-entry synthesis gets another HA snapshot at `tunnel.rs:212-215`. HA is intentionally published independently at `ha.rs:39` and workers load it separately at `worker/loop_body/mod.rs:491`. This is not a blocker, but the invariant must say “ForwardingState coherence,” not total runtime coherence.

4. **MEDIUM: F1 overclaims the GRE keepalive path.**  
   Local-origin GRE traffic is stale as described, but the keepalive evidence does not show it “rides this path.” The keepalive uses `tc.Destination`: `pkg/routing/tunnel.go:303-305`, calls `probeICMP(state.RemoteAddr)`: `tunnel.go:557-570`, and `probeICMP` uses `net.DialTimeout` to the address, not the tunnel name or TUN fd: `tunnel.go:603-621`. Keep F1 for local-origin traffic, but remove or qualify the keepalive assertion.

**Claims Verified**

The base defect is real: `spawn_local_tunnel_sources` clones `self.forwarding` at spawn: `coordinator/mod.rs:540`; `local_tunnel_source_loop` takes it by value: `tunnel.rs:19-23`; refresh stores new worker-visible forwarding but only reconciles WG: `coordinator/mod.rs:1155-1167`.

Tunnel-only commits can take the same-plan path because tunnel interfaces are excluded from the binding-plan key: `server/helpers.rs:530-545`, `:651-657`; same-plan refresh is at `server/handlers/snapshot.rs:95-109`.

F2, F3, F4, F5, F6 are substantively reachable. Route resolution uses the frozen state: `forwarding/mod.rs:1524-1540`; local source spawn only happens at bring-up today: `coordinator/reconcile/bringup.rs:445`; delivery map entries are only published by spawn: `coordinator/mod.rs:588-615`; tunnel deletion can invalidate the fd: `pkg/routing/tunnel.go:659-667` plus fatal local TUN errors at `tunnel.rs:7-16`; CoS/RG use forwarding at `tunnel.rs:197`, `:220-226`; aux thread death has no respawn and stops that stream: `coordinator/supervisor.rs:23-26`, `:38-44`.

**Open Questions**

1. Per-iteration reload is right, not idle-only. Idle-only can stay stale under continuous local-origin traffic. Add the attachment/mode guard before using the loaded state.
2. `(logical_ifindex, resolved name)` is sound for normal anchor lifecycle. Reuse keeps the same TUN: `pkg/routing/tunnel.go:135-149`; replacement deletes/re-adds: `:151-158`; snapshots read live ifindex by name: `interfaces.go:368-375`. No fd generation is required unless you reject the existing ifindex model.
3. Disarmed stop is correct. A disarmed helper should not keep GRE readers injecting into stopped/missing bindings; same-plan disarmed refresh exists at `snapshot.rs:103-107`.
4. Defer-workers prune is needed, but broaden it: removed/mode-flipped entries are mandatory, and attachment drift should be pruned from snapshot data when available.
5. RCU sender swap is fine only after fixing publication order. No generation check is needed if stale senders are unpublished before join and the loop checks stop during delivery drain.
6. Do not make threads self-own lifecycle. But they must drop/skip packets when the loaded state no longer matches their captured attachment/mode, otherwise the store-before-prune race remains.
7. Security-relevant mis-encap is reachable in the proposed design for same-id reowner or mode flip before prune. After adding the guard or pre-publish prune ordering, the remaining bug class is mostly operational correctness.

**Required Revisions**

1. Close the same-id stale-thread window: either stop/join stale GRE threads before publishing the new forwarding Arc, or pass captured attachment into the loop and refuse to process packets unless the loaded endpoint is present, `gre`/`ip6gre`, and matches `(logical_ifindex, resolved name)`.
2. Fix delivery shutdown ordering: unpublish stale delivery senders before join and add a stop check inside the delivery-drain loop. Then republish final live entries after spawn.
3. State explicitly that periodic GRE liveness republishes `local_tunnel_deliveries` after sweep/respawn; otherwise F6 can respawn a reader without restoring inbound delivery.
4. Correct severity text: remove the unsupported keepalive-path claim and narrow “torn-state-free” to ForwardingState-owned fields.
5. Add tests for same-id `gre -> wireguard`, same-id reowner/attachment change, delivery-drain stop latency, and liveness respawn delivery-map publication.

Verdict: **PLAN-NEEDS-REVISION**.

Codex session ID: 019eb9f1-f3b6-7a20-9245-e24cb7db0027
Resume in Codex: codex resume 019eb9f1-f3b6-7a20-9245-e24cb7db0027
