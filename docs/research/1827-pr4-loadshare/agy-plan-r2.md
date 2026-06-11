I will view the plan file `docs/research/1827-pr4-loadshare/plan.md` in the worktree to read its contents and understand the structure and assertions.
I will view the contents of `userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs` in the worktree.
I will view the contents of `userspace-dp/src/afxdp/session_glue/mod.rs` in the worktree.
I will search the codebase for usages of `lookup_forwarding_resolution_for_synced_session` to see where it is invoked.
I will view the file `userspace-dp/src/afxdp/session_glue/mod.rs` around line 955 to verify how synced session resolutions are handled at packet time.
I will search for `struct SyncedSessionEntry` or `SyncedSessionEntry` definition in the codebase to understand what fields it carries.
I will view `userspace-dp/src/afxdp/worker/mod.rs` around line 278 to see the struct definition of `SyncedSessionEntry`.
I will search for `SessionDecision` to see what fields it has, particularly how `resolution` is defined.
I will view `userspace-dp/src/session/entry.rs` to understand the fields of `SessionDecision`.
I will search for `struct ForwardingResolution` or `ForwardingResolution` definition to verify its fields.
I will view `userspace-dp/src/afxdp/types/forwarding.rs` around line 283.
I will search for `sessionSyncEgressLocked` in the Go codebase to see how it normalizes interface indices.
I will view the contents of `pkg/dataplane/userspace/manager_ha.go` around line 1038 to confirm the behavior of Go's receive-side normalization.
I will view lines 710 to 760 of `pkg/dataplane/userspace/manager_ha.go` to see the context of the receive side.
I will search for references to `UpsertSynced` in the Go codebase to trace the receive/import side of session synchronization.
I will search for `SetClusterSyncedSessionV4` in the codebase to find where the Go daemon receives/handles incoming sync messages from the peer.
I will view `pkg/dataplane/userspace/manager_ha.go` around line 599 to see the implementation of `SetClusterSyncedSessionV4` and trace the import/normalization of the session sync.
I will search for `SessionSyncRequest` in the Rust codebase to verify how the helper deserializes it and maps it to `SyncedSessionEntry`.
I will view `userspace-dp/src/server/helpers.rs` starting at line 220 to see how the sync request is handled by the helper process.
I will view lines 281 to 330 of `userspace-dp/src/server/helpers.rs` to see the rest of `build_synced_session_entry`.
I will search for `SetClusterSyncedSessionV6` in `pkg/dataplane/userspace/manager_ha.go` to see if it also zeroes out FIB index cache variables for IPv6.
I will view `pkg/dataplane/userspace/manager_ha.go` around line 656 to see `SetClusterSyncedSessionV6`.
I will search for references to `SetClusterSyncedSession` in `pkg/cluster` to see where the synced session values are received.
I will view the file `pkg/cluster/sync.go` around line 1390.
I will search for `SetClusterSyncedSessionV4` in `pkg` to locate all occurrences in the Go files.
I will search for references to `SetClusterSyncedSessionV4` or where the interface `SessionStore`'s `SetClusterSyncedSessionV4` is called.
I will view `pkg/dataplane/session_store.go` around line 267.
I will view lines 200 to 244 of `pkg/dataplane/session_store.go`.
I will search for `PutClusterSyncedV4` in the codebase to trace where it is called from.
I will view `pkg/cluster/sync_conn.go` around line 34 to see where the incoming network sync calls `PutClusterSyncedV4`.
I will view `userspace-dp/src/protocol/snapshot.rs` around line 128 to verify the `RouteSnapshot.next_hops` type.
I will view `pkg/dataplane/userspace/protocol.go` around line 503 to verify the Go type counterpart.
I will view `pkg/dataplane/userspace/routes.go` around line 46 to verify how next-hops are constructed in the Go builder.
I will view `userspace-dp/src/afxdp/forwarding_build/fib.rs` around lines 162 and 196 to verify that route snapshots flatten multi-nexthops to a single next-hop.
I will view `userspace-dp/src/afxdp/types/forwarding.rs` around line 123 to verify the route entry structs.
I will view `userspace-dp/src/afxdp/worker/mod.rs` around line 237 to verify the scope and implementation of `fabric_queue_hash`.
I will view `userspace-dp/src/afxdp/types/forwarding.rs` around lines 396-405 to verify how `fabric_queue_hash` is consumed.
I will view `pkg/dataplane/userspace/routes.go` around line 143 to verify the route sorting logic.
I will view `docs/multi-wan.md` around line 3-9 to verify what is currently there.
I will search for `SetSessionV4` in `pkg/dataplane/userspace/manager_ha.go` to see if it zeroes out `FibIfindex` on local sessions.
I will view `pkg/dataplane/userspace/manager_ha.go` around line 569.
I have completed a hostile review of the material updates in research plan v2.1 (`docs/research/1827-pr4-loadshare/plan.md`) against the current source code tree. 

Below are the numbered findings detailing verification of code paths, race/HA invariants, and the correctness of the proposed Path D (PLAN-KILL) recommendation.

---

### Numbered Findings

#### 1. Synced Session Re-Resolution & Go Normalization Nuance (§3.3)
In **§3.3 (Step 1)**, the plan asserts that Go receive-side normalization looks up the wire `FibIfindex` against the receiving node's own snapshot. 

A code walk reveals a slight variance that actually **strengthens** the plan's conclusion:
* In [pkg/dataplane/userspace/manager_ha.go:600-605](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/manager_ha.go#L600-L605) (and [manager_ha.go:657-662](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/manager_ha.go#L657-L662) for IPv6), the standby node's manager explicitly zeroes out `FibIfindex` on the incoming session value before passing it to `syncSessionV4Locked` / `syncSessionV6Locked`:
  ```go
  installVal := val
  installVal.FibIfindex = 0
  ```
* Consequently, when [manager_ha.go:744](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/manager_ha.go#L744) calls `sessionSyncEgressLocked`, it passes `0` as the first argument. 
* As seen in [manager_ha.go:1043-1048](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/manager_ha.go#L1043-L1048), `sessionSyncEgressLocked` immediately skips interface snapshot lookup when `fibIfindex <= 0`, returning `0` for egress and tx indices, and only normalizes `OwnerRGID` via the egress zone:
  ```go
  if fibIfindex <= 0 {
      return fibIfindex, fibIfindex, resolveOwnerRGFromZone(snapshot, egressZone)
  }
  ```
* Therefore, the receiving node's manager does *not* resolve the wire interface index. Instead, it deliberately forwards an `egress_ifindex = 0` to the helper. 
* In the Rust helper, [userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:39-44](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L39-L44) resolves the session on receipt. Because the incoming `egress_ifindex` is `0`, [userspace-dp/src/afxdp/session_glue/mod.rs:25-27](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/session_glue/mod.rs#L25-L27) triggers a cache miss in `cached_session_resolution` (since `egress_ifindex <= 0`). 
* This cache miss guarantees that the receipt-time lookup falls through to a full, local route lookup via `lookup_forwarding_resolution_with_dynamic` ([mod.rs:113](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/session_glue/mod.rs#L113)). 

**Conclusion:** The plan's claim that receipt-time re-resolution uses local egress is correct, but the Go manager achieves this by stripping the remote index to force a clean local lookup, rather than mapping the index. This guarantees no stale interface references bypass local routing.

#### 2. Synced Session Packet-Time Lookup-First (§3.3)
At packet-processing time, the dataplane must lookup-first without caching for synced sessions:
* [userspace-dp/src/afxdp/session_glue/mod.rs:954-960](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/session_glue/mod.rs#L954-L960) invokes `lookup_forwarding_resolution_for_synced_session` when the hit session is peer-synced.
* This wrapper calls `lookup_forwarding_resolution_for_session_with_cache` with `allow_cached_fast_path = false` ([mod.rs:122-134](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/session_glue/mod.rs#L122-L134)). 
* Skipping cache evaluation forces a local lookup at packet-time. If it fails, the fallback to the carried resolution is correctly structured in [mod.rs:114-117](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/session_glue/mod.rs#L114-L117):
  ```rust
  match resolved.disposition {
      ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
          cached_session_resolution(forwarding, decision.resolution).unwrap_or(resolved)
      }
      _ => resolved,
  }
  ```

#### 3. Scope of Single Next-Hop Selection & Flattening (§3.1)
The negative scopes and structural constraints in **§3.1** are fully accurate:
* The route snapshot on both sides carries a vector ([userspace-dp/src/protocol/snapshot.rs:128-129](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/protocol/snapshot.rs#L128-L129) and [pkg/dataplane/userspace/protocol.go:503](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/protocol.go#L503)), and the Go builder populates it in order ([pkg/dataplane/userspace/routes.go:46-55](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/routes.go#L46-L55)).
* The dataplane builder flattens this vector to the first element only: [userspace-dp/src/afxdp/forwarding_build/fib.rs:161-163](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/forwarding_build/fib.rs#L161-L163) (IPv4) and [fib.rs:195-197](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/forwarding_build/fib.rs#L195-L197) (IPv6) resolve only `next_hops.first()`.
* The downstream entry types in [userspace-dp/src/afxdp/types/forwarding.rs:123-140](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/types/forwarding.rs#L123-L140) only carry a single optional next-hop address.
* The only flow-hashing in the dataplane is for fabric queue-spreading: `fabric_queue_hash` in [userspace-dp/src/afxdp/worker/mod.rs:237-274](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/worker/mod.rs#L237-L274) is consumed by `fabric_target_index` in [types/forwarding.rs:396-405](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/userspace-dp/src/afxdp/types/forwarding.rs#L396-L405) to balance packet distribution across queues of the single fabric link.

#### 4. Route Sorting Nondeterminism (§10)
In **§10**, the plan notes the sorting stability edge:
* [pkg/dataplane/userspace/routes.go:143-151](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/pkg/dataplane/userspace/routes.go#L143-L151) uses `sort.Slice` to order route snapshots. Since `sort.Slice` is unstable, identical keys (VRF Table, Family, Destination) have nondeterministic relative ordering. If two different sources (e.g. static route and PBR inter-VRF leak) overlap on the same prefix destination, they could result in different default active egress selections across nodes.

#### 5. Documentation Cleanup Gaps (§5)
The close-out plan in **§5** is necessary:
* [docs/multi-wan.md:8-9](file:///home/ps/git/bpfrx/.claude/worktrees/1827-pr4-research/docs/multi-wan.md#L8-L9) still references a future delivery: `"Health-gated load-sharing is a later PR (§5 of the plan)."`. To avoid publishing dead contract promises, a micro-PR to clear this line must follow the decision to abort the stage.

#### 6. Earned Kill Verdict (Path D)
Path D is fully earned and correct. Since local route re-resolution runs dynamically on packet reception, load sharing via flow hashing would require both nodes to run a strictly symmetric hashing algorithm. This would introduce complex invariants on cross-node weight-epoch synchronization and hash inputs (excluding local interfaces/IDs). Given that session pinning is required to protect SNAT mappings (established in PR-3), traffic would not dynamically re-converge on weight updates for active sessions anyway. 

The Rust implementation effort required to rebuild single-next-hop routing into per-flow multi-next-hop forwarding (~1.5–2.5k LOC) does not justify the marginal benefit at 2 uplinks when FBF per-policy steering and failover are already merged.

PLAN-READY
