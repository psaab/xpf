# AGY adversarial plan review — round 7 (#1636)

**Job ID**: adversarial-review-mpptjf39-5ajzfe
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v7 @ `3f9aecc700c9`

## VERDICT: PLAN-READY

The v7 plan is exceptionally well-researched, mathematically sound, and architecturally robust. All four findings from our Round 6 review have been addressed and folded into the plan with high-fidelity designs. No new fatal flaws have been introduced. We can confidently declare convergence and proceed to the `/engineer` phase.

## Findings (low-severity doc nits — for /engineer phase, not blocking)

### Finding 1 [SEVERITY: LOW (Doc Nit)] Path access to `rg_runtime`

In §7 pseudocode, `self.ha_rg_runtime.load()` was used. Real codebase access path: `rg_runtime` resides on `HaState`, exposed as `Coordinator.ha`. Use `self.ha.rg_runtime.load()` during /engineer phase.

### Finding 2 [SEVERITY: LOW (Doc Nit)] Access path and duplicate mention for `last_warm_sweep_ns`

§8 mentioned `Coordinator gains last_warm_sweep_ns: u64` but §7 correctly places it on `NeighborManager` as `Arc<AtomicU64>`. `Coordinator` accesses via `self.neighbors.last_warm_sweep_ns`. Drop the §8 mention.

### Finding 3 [SEVERITY: LOW (Doc Nit)] Interface index resolution for `FabricLink`

When iterating `fabrics`, pass `f.parent_ifindex` as `egress_ifindex` and `f.peer_addr` as `hop`. Pseudocode should make this explicit.

## Recommendation

ship as-planned

The mitigation strategy is fully qualified and sequenced perfectly:
1. PR-1: Low-risk sysctl drop-in (B) to verify baseline and lower kernel solicit intervals.
2. PR-2: Proactive neighbor warm pass (C) — single long-lived queue-fed warmer worker thread with snapshot-level and key-level rate limiters, per-RG state tracking, full generation-collapse protection.
3. PR-3: Dynamic fallback-safe PENDING_NEIGH_TIMEOUT_NS reduction to 800ms (D), computed dynamically per snapshot in `build_forwarding_state_with_policy_counters_and_previous()` with zero hot-path overhead.

Declare 3-of-3 convergence and ship it.
