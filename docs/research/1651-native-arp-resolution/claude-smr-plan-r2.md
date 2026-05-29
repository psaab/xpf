# Claude SMR hostile plan-review — #1651 r2

**Reviewer framing**: kernel-networking / AF_PACKET / ARP-NDP / AF_XDP / HA
domain expert. **Target**: plan v2.2 (commit pending). **Verdict**:
**PLAN-READY** for Gate-M + the §6 ifindex fix; **PLAN-KILL-leaning** for the
native resolver as written, conditional on Gate-M.

## Round-2 convergence check

All three reviewers now agree on the shape:
- **Claims 1, 3, 4 verified** (3-way). Codex r2 added a cleaner VLAN-80 cite
  (`loss-userspace-cluster.env:33,41`) and the sharp HIGH-3 finding that the
  cold-start doc is internally self-contradictory on AF_PACKET bind+send
  (line 94 worked vs line 101 failed) — which I accept and which
  *strengthens* the measurement-first thesis: that doc is not kill-grade
  proof, so AF_PACKET-on-VLAN viability must be measured.
- **The ifindex key-mismatch (Root cause A′)** is the lead hypothesis,
  converged independently by all three. v2 promotes it to §6 + matrix row 1.
- **v1's AF_PACKET-RX-dead overclaim is retracted** (my SMR-1 self-correct +
  Codex CRITICAL-1). The native path is NOT presupposed dead; matrix rows
  4/6 keep it live and Gate-M tests it.

## AGY r2's two design corrections — I concur, both verified

1. **Reject netlink-side dual-insert.** Verified: `neigh_monitor_thread` is
   spawned at `coordinator/reconcile/bringup.rs:338` with only
   `(stop, dynamic_neighbors, neighbor_generation)` — no `ForwardingState`.
   `parse_neighbor_msg` literally cannot map parent→logical. AGY is right;
   v2.2 marks Option 2 REJECTED.
2. **Put the fallback in `lookup_neighbor_entry`, not retry-only.** Verified:
   `lookup_neighbor_entry` (`forwarding/mod.rs:1529`) is the shared
   fast-path lookup (static → dynamic → None) and already has
   `state: &ForwardingState`. A retry-only fallback would force every NEW
   flow to a VLAN neighbor through the `pending_neigh` ~1ms queue even after
   resolution; the shared-lookup fallback keeps 0ms fast-path and gives
   correct `RTM_DELNEIGH` invalidation via the single parent-keyed entry.
   `resolve_tx_binding_ifindex` (`tx/dispatch/shared_recycle.rs:189`) is the
   exact logical→parent mapping needed and is in scope. This is a genuine
   improvement over my r1 framing and AGY's own r1 retry-side sketch.

## Residual hostile checks (none blocking)

- **SMR-r2-1 (note, not blocker)**: the `lookup_neighbor_entry` fallback
  must NOT mask a legitimately-different-subnet neighbor. Because
  `resolve_tx_binding_ifindex` only returns the parent when an egress
  mapping exists and the parent ≠ logical, and the lookup is keyed by
  `(parent, target_ip)` where `target_ip` is the specific next-hop, a
  cross-subnet false hit would require the same IP resolved on two ifaces —
  no worse than the existing `(ifindex, target)` exact-match semantics.
  Acceptable; flag for the /engineer test matrix (add a
  two-VLAN-same-subnet-IP negative test).
- **SMR-r2-2 (note)**: Gate-M remains the hard gate. If A′ is confirmed, the
  §6 fix is the deliverable and #1651-as-written (native resolver) is
  PLAN-KILL; #1648 must NOT be closed as superseded (orthogonal). If Gate-M
  shows row 4/6, the native §4 (prefer Path B shim-redirect over Path A
  AF_PACKET) earns its complexity. Either way the plan now routes correctly.

## Recommendation

Converged. PLAN-READY to run Gate-M. The expected outcome (A′) yields a
~5–15-line `lookup_neighbor_entry` parent-fallback and a PLAN-KILL of the
native-resolver scope — but that conclusion is now reached via verified
mechanism (ifindex mismatch + the structural fast-path-lookup placement),
not the partly-wrong v1 argument.
