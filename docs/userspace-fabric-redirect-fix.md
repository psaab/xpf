# Userspace Dataplane: Fabric Redirect Fix

**Date:** 2026-03-23
**Commits:** `efd79d7` (TTL skip), `48b7f2a` (dynamic fabric sync)

## Problem Statement

After per-RG failover in the userspace AF_XDP cluster, traffic to subnets
owned by the inactive RG was 100% dropped instead of being redirected
across the fabric link to the peer node.

**Example:** fw0 is primary for RG0 (LAN) and RG2, but secondary for
RG1 (WAN). Traffic from the LAN host to 172.16.80.200 (WAN subnet)
arrives at fw0, which should fabric-redirect it to fw1 (RG1 primary).
Instead, the packets were silently dropped.

Additionally, packets that DID traverse the fabric (from earlier
sessions) suffered double TTL decrement — the host saw TTL=62 instead
of TTL=63 for ~30% of packets.

## Root Causes

### 1. Stale Fabric State in Userspace Helper

**Problem:** The Rust helper's fabric link info (peer MAC, ifindex) was
baked into the `ForwardingState` at initial snapshot build time and
never refreshed. The snapshot is built during config apply, which may
happen before the fabric peer's ARP/NDP has resolved.

When `refreshFabricFwd` (the Go daemon's 30s periodic fabric refresh)
successfully resolved the peer MAC and updated the BPF `fabric_fwd`
map, this information was NOT pushed to the Rust helper. The helper's
`forwarding.fabrics` stayed empty.

Without fabric link data, `resolve_fabric_redirect()` returned `None`,
and `redirect_session_via_fabric_if_needed()` had nothing to redirect
to — the packet was dropped as `HAInactive`.

**Fix (`48b7f2a`):** Three-part dynamic fabric state sync:

1. **`SyncFabricState()` (Go manager + daemon)** — New method on the
   userspace Manager that builds fresh `FabricSnapshot` entries (with
   current peer MACs from the kernel neighbor table) and sends them
   to the Rust helper via an `"update_fabrics"` control request.
   Called after every successful `refreshFabricFwd`.

2. **`refresh_fabric_links()` (Rust coordinator)** — Processes the
   updated fabric snapshots, resolving peer MACs from both the
   snapshot data and `dynamic_neighbors` as fallback. Stores the
   result in `self.forwarding.fabrics` (for the coordinator) and
   `shared_fabrics` ArcSwap (for workers).

3. **`shared_fabrics` ArcSwap (Rust workers)** — Each worker checks
   `shared_fabrics` at the top of every poll cycle. If the coordinator
   has updated the fabric links, the worker rebuilds its local
   `forwarding` Arc with the new fabric data. This enables fabric
   redirect without stopping/restarting workers (no full reconcile).

### 2. Double TTL Decrement on Fabric-Ingress Packets

**Problem:** Packets forwarded across the cluster fabric link arrive
at the receiving node with TTL already decremented by the sending peer.
The Rust helper decremented TTL again in all frame rewrite paths,
causing the host to see TTL=62 instead of 63 for ~30% of packets.

**Diagnosis:** Added temporary TTL logging to `rewrite_forwarded_frame_in_place`.
All packets from `ingress_if=4` (ge-0-0-0, fabric parent) showed
`ttl_before=63` — confirming the peer had already decremented.

**Fix (`efd79d7`):** Set a fabric-ingress flag (`meta.meta_flags |= 0x80`)
early in `poll_binding` when the ingress interface is a fabric member
or has a zone-encoded fabric MAC. All four TTL decrement paths check
this flag:

- `rewrite_forwarded_frame_in_place` — in-place path
- `build_forwarded_frame_from_frame` — copy path
- `build_forwarded_frame` — segmentation path
- `apply_rewrite_descriptor` — descriptor fast path

Each path skips the TTL decrement and TTL<=1 expiry check when the
flag is set.

**Segmentation TTL-gate symmetry follow-up (#2077):** the
segmentation builders
(`frame/tcp_segmentation.rs::segment_forwarded_tcp_frames_from_frame`
and the local-owner fast-path twin
`tx/tcp_segmentation.rs::segment_forwarded_tcp_frames_into_prepared`)
honoured the fabric-ingress flag on the *decrement* but not on the
IPv4 *expiry check*: the IPv4 arm dropped unconditionally on
`packet[8] <= 1` while the IPv6 arm correctly gated the
hop-limit==1 drop on `(meta.meta_flags & 0x80) == 0`. The result was
v4/v6-asymmetric: a fabric-ingress oversized IPv4 TCP segment that
legitimately arrived with TTL==1 (the peer already decremented it)
was wrongly dropped, while the equivalent IPv6 segment was correctly
forwarded. The fabric crossing is an internal cross-chassis redirect,
not an IP hop, so neither the decrement nor the expiry drop applies.
The fix gates the IPv4 expiry drop on `(meta.meta_flags & 0x80) == 0`
in both segmentation copies, restoring symmetry with the IPv6 arm and
with the canonical `build/ipv4.rs`, `frame/mod.rs`, and
`rewrite/ipv4.rs` paths. Regression coverage lives in
`frame/tests.rs::segment_forwarded_tcp_frames_keeps_fabric_ingress_low_ttl_both_families`
(fabric-ingress TTL==1 must segment, not drop),
`..._drops_non_fabric_low_ttl_both_families` (non-fabric TTL==1 still
drops — TTL expiry preserved), and
`..._decrements_non_fabric_healthy_ttl_both_families` (normal
decrement path intact).

## Architecture: Fabric Redirect Flow (Fixed)

```
1. Host sends packet to 172.16.80.200 (WAN subnet, RG1)
2. Packet arrives at fw0 ge-0-0-1 (LAN, RG2 primary) → XDP shim → XSK
3. Helper: session lookup → FIB → egress = ge-0-0-2.80 (RG1)
4. Helper: enforce_ha_resolution_snapshot() → RG1 inactive → HAInactive
5. Helper: redirect_session_via_fabric_if_needed() →
   resolve_fabric_redirect() → FabricLink{parent=ge-0-0-0, peer_mac=...}
6. Helper: rewrite frame with fabric dst MAC, TX via ge-0-0-0 XSK
7. Packet traverses physical fabric link to fw1
8. fw1: receives on ge-7-0-0 → XDP shim → XSK
9. fw1: zone-encoded fabric ingress → meta.meta_flags |= 0x80
10. fw1: session hit (synced) → forward to ge-7-0-2.80 → 172.16.80.200
    (TTL NOT decremented — fabric-ingress flag set)
11. Reply: 172.16.80.200 → fw1 → session hit → fabric redirect to fw0
    (fw1 decrements TTL once)
12. fw0: receives on ge-0-0-0 → fabric-ingress flag → forward to host
    (TTL NOT decremented — already done by fw1)
13. Host sees reply with TTL=63 (single decrement, correct)
```

## Performance Results

| Metric | Before | After |
|--------|--------|-------|
| Split-RG ping (20 probes) | 0% received | 100% received |
| Split-RG iperf3 (4 streams) | 0 Gbps (dropped) | 16.9 Gbps |
| Warm ICMP TTL consistency | 70% TTL=63, 30% TTL=62 | 100% TTL=63 |
| Normal iperf3 (no fabric) | 23+ Gbps | 23+ Gbps (unchanged) |

## Files Changed

| File | Changes |
|------|---------|
| `userspace-dp/src/afxdp.rs` | `shared_fabrics` ArcSwap, `refresh_fabric_links()`, fabric-ingress flag, TTL skip in all rewrite paths, `FabricLink` PartialEq, worker fabric state refresh |
| `userspace-dp/src/main.rs` | `"update_fabrics"` control request handler, `fabrics` field on ControlRequest |
| `pkg/dataplane/userspace/manager.go` | `SyncFabricState()` method |
| `pkg/dataplane/userspace/protocol.go` | `Fabrics` field on ControlRequest |
| `pkg/dataplane/dataplane.go` | `SyncFabricState()` interface method, pin path helpers |
| `pkg/dataplane/maps.go` | `SyncFabricState()` no-op stub (eBPF) |
| `pkg/dataplane/dpdk/dpdk_stub.go` | `SyncFabricState()` no-op stub (retired #1525, deletion in #1528) |
| `pkg/dataplane/dpdk/dpdk_cgo.go` | `SyncFabricState()` no-op stub (retired #1525, deletion in #1528) |
| `pkg/daemon/daemon.go` | Call `SyncFabricState()` after `refreshFabricFwd` |

## Key Learnings

1. **Snapshot-time state goes stale.** The userspace helper's forwarding
   state was built once at config apply. Fabric peer MACs that resolve
   later (via ARP after the snapshot is built) were never pushed to the
   helper. Dynamic state (neighbors, fabric MACs) needs an update
   mechanism independent of full snapshot rebuilds.

2. **ArcSwap for hot-path updates.** Workers hold an `Arc<ForwardingState>`
   that's immutable. To update fabric links without stopping workers,
   we added a `shared_fabrics: Arc<ArcSwap<Vec<FabricLink>>>` that
   workers check on each poll cycle. This follows the same pattern as
   `ha_state`.

3. **Fabric-ingress TTL must be skipped.** When both nodes are in the
   forwarding path (split-RG), the sending peer decrements TTL before
   putting the packet on the fabric link. The receiving peer must NOT
   decrement again. The eBPF pipeline has the same issue but it's less
   visible because `xdp_forward.c`'s NO_NEIGH path returns XDP_PASS
   without TTL decrement.

4. **Simultaneous boot causes split-brain.** When both VMs boot at the
   same time, the heartbeat timeout (1s) fires before the peer is
   ready. Both nodes elect themselves primary. The dual-active detection
   in `electRG()` resolves this when heartbeats eventually arrive, but
   there's a window where both are primary. This is mitigated by the
   sync-hold gate but can occur if the hold timeout is shorter than
   the peer's boot time.

## Verification

```bash
# Make fw0 primary for all RGs
for rg in 0 1 2; do
  echo "request chassis cluster failover redundancy-group $rg node 0" | cli
done

# Verify normal traffic
source test/incus/cluster-env.sh   # IPERF_TARGET4: loss 172.16.80.202 (#18576)
ping -c 10 "$IPERF_TARGET4"   # expect: 0% loss, TTL=63

# Failover RG1 (WAN) to node1
echo "request chassis cluster failover redundancy-group 1 node 1" | cli

# Verify split-RG fabric redirect
ping -c 20 "$IPERF_TARGET4"   # expect: 0% loss (fabric redirect)
iperf3 -c "$IPERF_TARGET4" -P 4 -t 5   # expect: >10 Gbps through fabric

# Verify TTL consistency
ping -c 50 -i 0.1 "$IPERF_TARGET4" | grep ttl=
# expect: ALL packets TTL=63, no TTL=62
```
