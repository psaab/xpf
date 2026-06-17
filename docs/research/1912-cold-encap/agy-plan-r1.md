# AGY Adversarial Review: #1912 (Cold ENCAP Outer Next-Hop Blackhole)

We have verified the implementation direction against the userspace-dp source code on the `research/1912-cold-encap-outer-nh` branch (worktree path: `/home/ps/git/bpfrx/.claude/worktrees/1912-research`).

## Verdict: `PLAN-NEEDS-MINOR`

The plan's root cause and mechanical reasoning are **100% correct**. However, the plan needs a minor correction regarding the **Option A vs Option C tradeoff** and **HA-sync protocol representation**. The plan estimates that adding a field to `ForwardingResolution` will touch "~15 literals," but we verified there are actually **100+ literal instantiation sites** across test suites and main code. 

Furthermore, `SessionSyncRequest` (the wire protocol representation) does not carry this field. Modifying the wire protocol introduces serialization churn and version-compatibility risk. 

Instead of adding a new field (Option A) or duplicating routing lookup logic in the arm (Option C), we propose a **hybrid on-demand helper method** on [ForwardingResolution](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/types/forwarding.rs#L341-L351) that resolves the outer next-hop interface only when needed.

---

## Hostile Verification Report

### 1. Root Cause Verification
* **Confirmed** in [resolve_tunnel_forwarding_resolution](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/forwarding/mod.rs#L1515-L1558):
  * At line 1550, `egress_ifindex` is bound to the tunnel's logical interface: `egress_ifindex: endpoint.logical_ifindex`.
  * At line 1553, `next_hop` is bound to the resolved outer next-hop IP: `next_hop: outer.next_hop`.
  * `outer.egress_ifindex` (the physical/VLAN outer egress) is completely discarded and not copied.
* **Confirmed** in [MissingNeighbor arm in poll_descriptor/mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2204-L2862):
  * **Negative Cache / Resolver Keying**: At lines 2376-2377, the `neg_key` is constructed as `(decision.resolution.egress_ifindex, next_hop)`. Since `egress_ifindex` is the tunnel logical index, the key points to the wrong interface. The resolver is enqueued using this key at line 2455, mapping it to the wrong device name.
  * **Kernel ARP Probe**: At lines 2515-2522, the ARP probe checks and acquires the interface name via `ifindex_to_name.get(&decision.resolution.egress_ifindex)`. This binds the probe socket to the tunnel logical interface (e.g. `gr-0/0/1`), which has no ARP capability. No `who-has` query is emitted on the outer interface.

### 2. Neighbor Keying Analysis
* **Confirmed** in [lookup_neighbor_entry](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/forwarding/mod.rs#L1560-L1579):
  * Neighbors are keyed by `(ifindex, target)` (lines 1566 and 1572).
* **Confirmed** in [populate_egress_resolution](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/session_glue/mod.rs#L44-L63):
  * For VLANs, `tx_ifindex` maps to `bind_ifindex` (the physical parent interface, line 53), while `egress_ifindex` holds the VLAN sub-interface (line 56).
  * Because neighbor entries must be resolved and bound to the tagged VLAN interface, `outer.egress_ifindex` (the VLAN sub-interface) is indeed the correct interface to key ARP probes/resolvers, **not** `tx_ifindex`.

### 3. Packet Disposition Verification
* **Disposition Path**:
  1. The forwarding lookup for a cold outer hop returns `MissingNeighbor` (line 1548).
  2. The packet enters the `ForwardingDisposition::MissingNeighbor` arm in `poll_descriptor/mod.rs:2204`.
  3. The packet bypasses buffer admission in `pending_neigh` at lines 2781 and 2790 because `tunnel_endpoint_id != 0`. `recycle_now` remains `true`.
  4. The packet falls through to [maybe_reinject_slow_path_from_frame](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/tx/dispatch/slow_path.rs#L148-L244) at line 2888.
  5. In `slow_path.rs:231-244`, the packet is matched by `decision.resolution.tunnel_endpoint_id != 0`, increments `tunnel_encap_unresolved_drops`, and is dropped to prevent a plaintext leak.
  * *Verdict*: The packet enters the `MissingNeighbor` arm, executes the broken ARP probe, and is dropped correctly at the reinject gate. It does not die in `ForwardCandidate` or inside the encap builder.
* **Freshly-Flushed Hook**:
  * At lines 2383-2397, `neg_neigh_gate` returns `fast_fail = false` when there is no negative cache entry (i.e. fresh flush). Because `fast_fail` is `false`, the resolver enqueue block (`if fast_fail { ... }`) is skipped, and only the kernel ARP probe is triggered (which binds to the wrong device name). Thus, the resolver is never enqueued for a freshly-flushed hop.

### 4. Code Churn: Option A vs Option C vs Hybrid On-Demand
* A search for `ForwardingResolution {` in the codebase returned **100+ literal instantiation sites** (predominantly in `userspace-dp/src/session/tests.rs`, `userspace-dp/src/afxdp/session_glue/tests.rs`, and `userspace-dp/src/afxdp/tests.rs`).
* Adding `neigh_ifindex` as a new field (Option A) will break compilation across all 100+ sites.
* **Alternative Hybrid Recommendation**: Add a helper method to [ForwardingResolution](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/types/forwarding.rs#L341-L351):
  ```rust
  impl ForwardingResolution {
      pub(crate) fn neigh_ifindex(
          &self,
          state: &ForwardingState,
          dynamic_neighbors: Option<&Arc<ShardedNeighborMap>>,
      ) -> i32 {
          if self.tunnel_endpoint_id == 0 {
              self.egress_ifindex
          } else {
              state.tunnel_endpoints.get(&self.tunnel_endpoint_id)
                  .map(|endpoint| match endpoint.destination {
                      IpAddr::V4(ip) => lookup_forwarding_resolution_v4(state, dynamic_neighbors, ip, &endpoint.transport_table, 1, false).egress_ifindex,
                      IpAddr::V6(ip) => lookup_forwarding_resolution_v6(state, dynamic_neighbors, ip, &endpoint.transport_table, 1, false).egress_ifindex,
                  })
                  .unwrap_or(self.egress_ifindex)
          }
      }
  }
  ```
  This retains the "Single Source of Truth" (SSOT) benefit of Option A and encapsulation benefits of Option C, while introducing **zero compilation churn** in existing tests and keeping the hot path unaffected.

### 5. HA-Sync and Wire Protocol
* **Confirmed** in [SessionSyncRequest](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/protocol/control.rs#L661-L718):
  * `neigh_ifindex` does not exist on the wire format.
* **Confirmed** in [build_synced_session_entry](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/server/helpers.rs#L294-L404):
  * A synced session's resolution is rebuilt at line 352 without `neigh_ifindex`.
* If we use the on-demand method helper:
  * Wire representation remains untouched.
  * When a synced session for a tunnel is cold, [lookup_forwarding_resolution_for_session_with_cache](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/session_glue/mod.rs#L80-L133) calls `resolve_tunnel_forwarding_resolution` at line 121, ensuring the local node re-resolves the tunnel using local state. Stale indexes from the wire are never trusted.

### 6. R-C/R-E Preservation
* **Confirmed**: `pending_decision.resolution.tunnel_endpoint_id == 0` (lines 2781 & 2790) protects `pending_neigh` from plaintext leaks (R-E). `decision.resolution.tunnel_endpoint_id != 0` (line 231 of `slow_path.rs`) prevents slow path reinjection (R-C). Both remain fully intact.

---

## Action Plan (Minor Adjustments)

1. **Adopt Hybrid On-Demand Method**: Define `neigh_ifindex(&self, state, dynamic_neighbors)` on `ForwardingResolution` as detailed above.
2. **MissingNeighbor Arm Update**: In [poll_descriptor/mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1912-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2204), call `decision.resolution.neigh_ifindex(...)` inside the `MissingNeighbor` arm to retrieve the target interface for:
   * `neg_key` construction (line 2376).
   * Deduplication tracking via `already_probing` (line 2515).
   * Probe invocation (line 2520).
3. **Optional Enhancements**: Defer the STALE case enhancement (unconditional resolver enqueue) to keep the PR focused on resolving the fully-flushed outer hop.

I have completed the review. Please let me know how you would like to proceed.
