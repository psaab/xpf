# AGY adversarial plan review — round 6 (#1636)

**Job ID**: adversarial-review-mpptbh1g-iqbqdj
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v6 @ `268fb607243a`

## VERDICT: PLAN-NEEDS-MINOR

## Findings (verbatim from AGY)

### Finding 1 [SEVERITY: MEDIUM] Type mismatch in warmer_loop signature and ha.rg_runtime.load()

The pseudocode uses `Arc<HaSnapshot>` but the real type in `bringup.rs:199` is `Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>`. Pseudocode is a docstring artifact; implementation must use real types.

**Mitigation**: Change `warmer_loop` to take `rg_runtime: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>` directly.

### Finding 2 [SEVERITY: MEDIUM] Missing proactive warm pass trigger on Routing Group promotion

`Coordinator::on_rg_promote_active()` only clears `last_probed_at` but does not trigger `queue_warm_pass()`. Without this, no proactive probes fire on promotion, leaving the first user flow on a newly active RG to experience the cold delay.

**Mitigation**: Integrate the map clear AND warm pass trigger:
```rust
if let Ok(mut map) = self.neighbors.last_probed_at.lock() {
    map.clear();
}
self.queue_warm_pass(true); // force=true bypasses 1s sweep limit
```

### Finding 3 [SEVERITY: LOW] 1-second snapshot rate limit blocks promotion warming

If a snapshot apply occurs right before HA promotion (common during daemon startup or cluster failover), `queue_warm_pass()` called on promotion returns early due to rate-limit. Newly promoted RG's neighbors remain cold.

**Mitigation**: Add `force: bool` parameter to `queue_warm_pass()`. Pass `force=true` from `handle_activated_rgs`, `force=false` from `refresh_runtime_snapshot`. Convert `last_warm_sweep_ns` to `AtomicU64` so `queue_warm_pass` can take `&self`.

### Finding 4 [SEVERITY: LOW] OnceLock limitation for PENDING_NEIGH_TIMEOUT_NS

`OnceLock` for `PENDING_NEIGH_TIMEOUT_NS` has architectural limits:
1. Daemon init does not know configured dataplane interfaces (received via snapshots).
2. Cannot be re-evaluated on snapshot change.

**Mitigation**: Store `pending_neigh_timeout_ns: u64` as field on `ForwardingState`. Re-evaluate during snapshot build in `build_forwarding_state_with_policy_counters_and_previous()`. Workers atomically load `forwarding` and read field directly — zero hot-path cost.

## R5 check-list responses

1. r5 #1 Per-RG HA: adequate with Finding 1 (type) and Finding 2 (trigger missing).
2. r5 #2 Cached: adequate; Finding 4 offers superior architectural placement.
3. r5 #3 + Codex r5 #1 Dual-stack: Fully Adequate.
4. New fatal in v6: None. All findings are refinements.

## Recommendation

iterate to v7. Once Findings 1-4 are folded, plan is fully ready for `/engineer 1636`.
