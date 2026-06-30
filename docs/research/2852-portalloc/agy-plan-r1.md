Verdict: PLAN-NEEDS-MAJOR

## Findings

### F5 (FATAL/MAJOR, correctness/deadlock) — Lock-Ordering Deadlock in Sharded Release/Rollback Paths
* **File**: [userspace-dp/src/nat/allocator.rs:613](file:///home/ps/git/bpfrx/.claude/worktrees/2852-research/userspace-dp/src/nat/allocator.rs#L613) (`release_flow`) and [userspace-dp/src/nat/allocator.rs:654](file:///home/ps/git/bpfrx/.claude/worktrees/2852-research/userspace-dp/src/nat/allocator.rs#L654) (`rollback_flow`) vs [userspace-dp/src/nat/allocator.rs:336](file:///home/ps/git/bpfrx/.claude/worktrees/2852-research/userspace-dp/src/nat/allocator.rs#L336) (`allocate_translation`).
* **Description**: The recommended design (§5.2 item 4) mandates a lock hierarchy of `PersistShard` before `FlowShard` during allocation. However, both `release_flow` and `rollback_flow` are called with only the 5-tuple (`SourceNatFlowKey`) and do not know the persistent lease key (`PersistentSourceKey`) beforehand. They must lock the `FlowShard` first to look up the flow in `live_by_flow`. If they subsequently acquire the `PersistShard` lock to update the lease, the acquisition order becomes `FlowShard -> PersistShard`. This is the exact inverse of the allocation path, causing a fatal deadlock under concurrent allocate/release churn.
* **Mitigation**: Globally invert the lock hierarchy to `FlowShard -> PersistShard`. In `allocate_translation`, lock the `FlowShard` first, determine lease status, and lock the `PersistShard` second. Because a thread never holds multiple locks of the same tier, this stratified hierarchy is deadlock-free.

### F6 (MINOR, performance) — False Sharing on Contiguous Shard Mutex Arrays
* **File**: [userspace-dp/src/nat/allocator.rs:166](file:///home/ps/git/bpfrx/.claude/worktrees/2852-research/userspace-dp/src/nat/allocator.rs#L166) (added fields `flow_shards: [Mutex<FlowShard>; N]` and `persist_shards: [Mutex<PersistShard>; N]`).
* **Description**: Declaring adjacent `Mutex` instances contiguously in an array will cause them to share cache lines (a standard cache line is 64 bytes, while a mutex is typically 40 bytes). Parallel workers locking different shards will cause severe cache-line bouncing (false sharing), severely degrading throughput under high-churn concurrent connection setups.
* **Mitigation**: Wrap the shard structures or mutexes in a newtype aligned/padded to cache line boundaries using `#[repr(align(64))]`.

### F7 (MINOR, correctness) — Static IP-to-Address Index Lookup vs Duplicate Pool IPs
* **File**: [userspace-dp/src/nat/allocator.rs:566](file:///home/ps/git/bpfrx/.claude/worktrees/2852-research/userspace-dp/src/nat/allocator.rs#L566) (`release_translated_locked`) vs [userspace-dp/src/nat/source.rs:259-260](file:///home/ps/git/bpfrx/.claude/worktrees/2852-research/userspace-dp/src/nat/source.rs#L259).
* **Description**: The recommended design (§5.2 item 3) replaces the dynamic `addr_index_by_translated` map with a static IP-to-index lookup. This assumes each `IpAddr` in the pool maps to a unique index. If the configuration contains duplicate IP addresses (e.g., for weighted allocation profiles), a static IP-to-index lookup will resolve to the first matching index, which may differ from the actual index from which the port was allocated, leading to incorrect bitmap clear indices.
* **Mitigation**: Store the allocated `addr_index` inside the `LiveAllocation` struct and pass it to `release_flow` and `release_translated_locked` rather than relying on a static IP lookup.

### Validation of Claude SMR Findings (F1-F4)
* **F1 (ABA Hazard on Unconditional Clear)**: **VALIDATED (Agree)**. Double/late release calls must not unconditionally clear the bitmap bit. The clear must be conditional on the successful matching removal of the flow record (non-persistent) or lease teardown (persistent) under the shard lock.
* **F2 (Cursor-Wrap != FIFO Recycle)**: **VALIDATED (Agree)**. A simple wrapping cursor does not spread reuse across the 2MSL window equivalent to FIFO. A lock-free FIFO queue (e.g. `crossbeam::queue::SegQueue` or a lock-free recycle ring) must be used.
* **F3 (Phased Staging)**: **VALIDATED (Agree)**. Phase 1 (lock-free bitmap + single mutex for maps) is highly recommended. It avoids the deadlock surface of F5 entirely in the initial step and captures the bulk of the win. Map sharding (Phase 2) should be deferred until Phase 1 lab metrics justify it.
* **F4 (Global Cap Reserve/Rollback)**: **VALIDATED (Agree)**. `AtomicUsize` global cap requires a CAS-style reservation loop and rollback on downstream allocation failure.

### Verification of Existing Behaviors
* **HA-synced NAT tuples (§7.5)**: The plan's correction is **VALIDATED**. Synced NAT tuples are not reserved in the allocator on master today (verified by grep across `ha.rs` and `ha_state.rs`). The standby-turned-active does not run allocator reservations. Keeping HA reservation out of scope is correct.
* **White-box Test Churn**: Verified that exactly 32 of the 185 test functions in `userspace-dp/src/nat/tests.rs` access white-box allocator internals (`owner_by_translated`, `addr_index_by_translated`, `recycled_ports_by_addr`, etc.).

## Disposition
The plan cannot proceed as written due to the fatal deadlock hazard F5 in the sharded design. The plan must be revised to flipped lock ordering (`FlowShard -> PersistShard`) and adopt the F1-F4 corrections.
Phasing the work (bitmap first) is highly recommended to bypass the two-lock complexity entirely in Phase 1.
Gating the final merge on connection-rate generator benchmark results (PLAN-KILL if unmeasurable) remains the correct business disposition.
