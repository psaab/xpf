# #1741 plan v2 — AGY adversarial review (round 2)

Job: adversarial-review-mq91os4y-mkv4iw — verdict PLAN-READY (review-only, no writes)

    }
    ```
*   Because this returns `false`, no entries are ever added to `scratch_rst_teardowns` at [poll_descriptor/mod.rs:L1905-L1911](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1905-L1911).
*   Consequently, `rst_teardowns` at [worker/lifecycle.rs:L227-L235](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/worker/lifecycle.rs#L227-L235) is always empty. The RST-teardown eviction path is dead in production. Eviction relies solely on stale-stamp lookup, HA invalidation, and LRU collision.

#### 4. Path A Implementation Shape
*   The reference patch [agy-impl-reference.patch](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/docs/research/1741-flow-count/agy-impl-reference.patch) compiles cleanly.
*   By copying `self.current_epoch` to a local variable `current` and inlining the age computation inside the loop over `self.entries.iter_mut()`, the borrow checker has no conflicts.
*   The mutability changes (`&self` to `&mut self` for `active_flow_debug_entries` and `count_active_flows`) compile cleanly because all unit tests already declare `mut cache` ([flow_cache_tests.rs:L177](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/flow_cache_tests.rs#L177)) to perform lookups/inserts.

#### 5. 3-of-6 Per-Scrape Attribution
*   The hedge is correct: verifying that the ghost wrap mechanism is capable of causing the observed spikes is sufficient. A full historical reconstruction of the exact network state during those 3 scrapes is unnecessary.

---

### Part 2: Deep-Dive and Pressure Testing

#### Are there any tick-without-scan paths?
The only call site of `tick_advance_epoch` in production code is in [umem/debug_state.rs:L230](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/umem/debug_state.rs#L230):
```rust
binding.flow.flow_cache.tick_advance_epoch();
let (active_flow_count, flow_debug_entries, cos_counts, flow_map_truncated) = binding
    .flow
    .flow_cache
    .active_flow_debug_entries(FLOW_WORKER_MAP_MAX_PER_BINDING);
```
Since it is immediately followed by the debug scan (which runs the proposed clamp), every single epoch increment is guaranteed to scan the cache and clear any entry that has just transitioned to the stale state (age $\ge 10$). An entry is clamped to `0` immediately upon leaving the active window, preventing it from ever being caught in a wraparound.

Even if a tick-without-scan path existed or occurred (e.g. in test code), the clamp is safe. Since a wrap cycle takes $65535$ ticks (~71 minutes), a scan only needs to execute once per 71 minutes on any given cache entry to clamp it before it could resurrect. With scans occurring every 65 ms, this margin of safety is extremely high.

#### Does any consumer rely on ghost-able stamps?
*   **Scheduler / Packet Path:** We searched the Class of Service (CoS) admission and shaper logic under [userspace-dp/src/afxdp/cos/](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/cos/). The shaper uses `active_flow_buckets` (from `FlowFairState`) to track active queues inside the scheduling algorithm. It does not reference `FlowCache`'s `active_flow_count` or the epoch stamps.
*   **Go-side Telemetry:** As verified in [dataplane/userspace/fairness.go:L90-L92](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/pkg/dataplane/userspace/fairness.go#L90-L92), all derived statistics are purely telemetry/status math:
    ```go
    // CoSFairnessRSSSummaries derives the production/operator RSS-structure
    // view from the low-frequency per-CoS active-flow snapshot. It is status
    // math only: no packet-path state, no locks, no scheduler feedback.
    ```
    Similarly, [metrics_userspace.go:L1228-L1247](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/pkg/api/metrics_userspace.go#L1228-L1247) exposes this strictly as Prometheus metrics (`xpf_userspace_cos_active_flow_count`). 
    
    No consumer depends on the presence of ghost entries. Correcting the telemetry to show the real active flow count aligns with all system invariants.

#### Does clamping impact slow/bursty live traffic?
Clamping an entry's `last_used_epoch` to `0` does not evict it. The entry remains in the cache and stays valid. 
*   If a packet for a slow flow (e.g., sending every 2 seconds) arrives after its entry was clamped to `0`, it will hit the cache.
*   `lookup_with_observed_bytes` will locate the entry, validate its generations/lease, and then update `entry.last_used_epoch = current_epoch` ([flow_cache.rs:L668](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/flow_cache.rs#L668)).
*   The flow immediately resumes being counted as active.
*   Thus, there is no impact to slow/bursty traffic other than correctly excluding it from the "active flow count" metric during its idle periods.

#### Are there any concurrency/race conditions with `&mut self`?
The `BindingWorker` struct is strictly worker-thread-owned and does not employ cross-core synchronization or concurrent map mutations ([worker/mod.rs:L139-L140](file:///home/ps/git/bpfrx/.claude/worktrees/1741-research-flow-count/userspace-dp/src/afxdp/worker/mod.rs#L139-L140)). Clamping the `last_used_epoch` field inside the debug scan is fully thread-safe and free of data races.

---

### Conclusion
The v2 plan is **ready**. Clamping the activity stamp on scan (Path A) is the correct fix:
1. It has **zero hot-path overhead**.
2. It restores the active-flow metric invariant by eliminating epoch-wrap resurrections.
3. The borrow-mut shape is clean and compiler-compliant.
4. It resolves the problem at the telemetry source without changing the packet path or cache lookup semantics.
