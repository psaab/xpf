# #2852 — Sharded / lock-free SNAT PortAllocator (research plan)

## 1. Status

`DRAFT v1 — pending adversarial plan review` (Claude SMR + Codex + AGY).

Reviewed against `origin/master` **9d00d219c** (worktree
`.claude/worktrees/2852-research`, branch `research/2852-portalloc`).
This is **design-only**: no production code is touched, no PR is opened.
The deliverable is this plan + the three reviewer verdicts + the issue
comment. Implementation begins only on an explicit `/engineer 2852`.

A prior campaign-8 plan-of-action lives in the #2852 comment thread (it
converged a "two-tier sharding + lock-free bitmap" design after two
hostile reviews of an earlier striped-slice draft). This document
re-verifies that design against current master, **corrects one
overstatement** in it (HA-synced NAT tuples are NOT reserved in the
allocator today — see §7/§10), and re-subjects the design to a fresh
hostile round so it can carry a current `reviewer-ids.md` ledger.

## 2. Issue framing

The pool-mode SNAT port allocator keeps all live allocation state behind
**one global mutex per pool**:

```
userspace-dp/src/nat/allocator.rs:166   live: Mutex<PortAllocatorLiveState>,
```

`allocate_translation` locks it for the full critical section on every
**new** SNAT flow:

```
allocator.rs:336   let mut live = self.shared.live.lock()...;   // held 336..475
```

and `release_flow` (619), `rollback_flow` (660), and `snapshot` (700)
take the same lock. Every worker thread shares the **same**
`Arc<PortAllocatorShared>` (see §6 confirmation), so at high new-flow
rates all workers serialize on this one lock during SNAT connection
setup. The issue asks: shard / lock-free the allocator while preserving
address-persistence, PAT correctness, reverse-NAT lookup, HA behavior,
and exhaustion accounting; **validate the new-flow ceiling on the loss
userspace cluster**.

## 3. Honest scope / value framing — and the PLAN-KILL line

What this is and is NOT:

- **It is a per-NEW-FLOW lock, NOT a per-packet lock.** Confirmed: the
  allocate path is reached only inside the session-miss block
  (`poll_descriptor/mod.rs:815`, `telemetry.counters.session_misses`).
  Established flows hit the session table and never touch the allocator.
  So contention scales with **connections/sec**, not packets/sec or
  Gbps. A 100 Gbps elephant-flow workload puts **zero** load on this
  lock. The win shows up only under high connection *churn* (the issue's
  "hundreds of thousands of new flows/sec").

- The critical section is small but not trivial: a budgeted GC sweep
  (`gc_expired_locked`, ALLOCATION budget 8), a `live_by_flow` hash
  lookup, the persistent-lease decision, a forward-probe port claim with
  two hash inserts (`owner_by_translated`, `addr_index_by_translated`),
  and the `live_by_flow` insert. Order ~hundreds of ns under the lock.
  At 6 workers a single mutex caps new-flow throughput near
  `1 / hold_time` ≈ low-single-digit million/sec **best case**, far less
  under cache-line bouncing and lock-handoff latency, and tail latency
  (p99/p999) degrades sharply as workers queue.

- **Explicit PLAN-KILL line:** *PLAN-KILL is acceptable if the
  contention is not measurable in practice (i.e. the lab cannot drive a
  new-flow rate high enough for the single mutex to be the dominant
  bottleneck before another limit — RX queue, session-table insert,
  conntrack-map publish, or NIC — saturates first), or if the measured
  win does not justify the churn.* This is why the design carries a
  **mandatory lab gate** (§9): we ship the redesign only if the
  loss-cluster new-flow ceiling demonstrably rises with worker count
  after the change. If the lab shows the mutex is not the dominant
  new-flow bottleneck at achievable rates, the correct outcome is
  PLAN-KILL (or PLAN-DEFER pending a connection-rate generator), not a
  speculative rewrite of correctness-critical NAT state.

The value, if the lab confirms it: near-linear new-flow scaling to the
worker count (6 on the loss cluster), lower tail latency on connection
setup under churn, and headroom for higher core counts on bigger
appliances.

## 4. What's already shipped / partially batched

- Round-robin **address** selection and per-address **port cursors** are
  already lock-free atomics (`addr_counter_v4/v6`, `counters[]`,
  `try_next_port`). Only the *live ownership* state
  (`PortAllocatorLiveState`) is behind the mutex.
- `sticky_pool_index(src_ip)` (allocator.rs:836) — the
  address-persistent address-selection hash — is already a pure,
  lock-free function. **Address-persistence does not touch the mutex**,
  so sharding cannot break it (it only chooses *which pool address*; the
  port claim within that address is the locked part).
- `#3047` forward-probe-past-collision and `#3011` FIFO recycle spreading
  already exist in `claim_free_port_locked` (allocator.rs:481-545) and
  must be preserved (or subsumed) by any redesign.
- `PersistentNatPermit` (`source.rs:115`) and `persistent_source_key`
  (`source.rs:172`) are wired on master: `AnyRemoteHost→remote=None`,
  `TargetHost→Some((dst,0))`, `TargetHostPort→Some((dst,dst_port))`. The
  `remote` field is already part of `PersistentSourceKey`.
- Allocator-reuse across config refresh is via
  `parse_source_nat_rules_with_previous` (source.rs:473) keyed by
  `SourceNatPoolAllocatorKey`; it Arc-clones the live `PortAllocator`,
  preserving state across a commit that does not change the pool. Any
  redesign keeps state behind `Arc<PortAllocatorShared>` so this is
  unchanged.
- `benches/` already has `session_table.rs`, `prefix_set_lookup.rs`,
  `tx_kick_latency.rs` (criterion, `harness=false`) — the template for a
  new `snat_allocator.rs` microbench.

## 5. Concrete design

### 5.1 Path options considered

**Option A — Per-worker / per-CPU sharded port sub-ranges.**
Partition the port space into N disjoint slices, one per worker; each
worker allocates from its own slice under its own lock (or lock-free).
- Pro: zero cross-worker contention on the common path.
- Con (fatal): **fragments the pool**. A worker whose slice is full
  reports exhaustion while another slice has free ports → *premature
  exhaustion*. A narrow pool (e.g. 64 ports) cannot be sliced N ways.
  Address-persistence + a fixed worker→slice map interact badly (a
  persistent source's flows can land on different workers). Rejected.
  *(This is the family the campaign-8 first draft tried as "striped
  slices + cross-shard steal"; both prior hostile reviewers rejected the
  steal — it degrades worse than the single mutex at high occupancy and
  can falsely exhaust.)*

**Option B — Per-(pool, external-IP) striping.**
One lock per pool address. Helps when a pool has many addresses, but the
loss cluster's typical SNAT pool is 1–few addresses → collapses back to
one lock. Doesn't address the single-address-pool hot case. Insufficient
alone.

**Option C — Two-tier map sharding + lock-free occupancy bitmap
(RECOMMENDED).** Shard the *maps* by hash (so map mutation contention
drops ~1/N) and make the *port claim* lock-free via a per-address atomic
occupancy bitmap (so the genuinely-shared resource — the port space —
has no mutex at all). This is the campaign-8 converged design; details
below.

**Option D — Replace the whole structure with a concurrent map crate**
(`dashmap`, `flurry`). Adds a dependency, still needs a separate
free-port-selection mechanism, and gives less control over the
GC/persistent-lease state machine. The bitmap (Option C) is simpler for
the port-claim core and dependency-free. Rejected in favor of C.

### 5.2 Recommended design (Option C — two-tier sharding + lock-free bitmap)

N = fixed power-of-two **map** shard count (default 16, tunable). N sizes
the *maps only* and is independent of the port range, so a narrow pool is
unaffected.

1. **`live_by_flow` sharded by `hash(SourceNatFlowKey full 5-tuple)`**
   into `flow_shards: [Mutex<FlowShard>; N]`. Mode-independent: the same
   shard is reached at allocate, `release_flow`, and `rollback_flow` from
   the 5-tuple alone (no need to know persistence at release). A single
   source opening many short-lived connections to many *distinct
   destinations* (the issue's high-churn shape) distributes across shards
   because the destination varies the hash.

2. **`persistent_by_source` + per-shard `lease_expirations`(+`_by_addr`)
   sharded by `hash(protocol, src_ip, src_port)`** = the persistent key
   **minus `remote`** into `persist_shards: [Mutex<PersistShard>; N]`.
   This is the load-bearing correctness choice: every flow that can
   *share* one persistent lease has the same `(proto, src_ip, src_port)`
   and so co-locates, for **all three** permit modes (permit-any
   `remote=None` AND target-host `remote=Some(...)`). Including `remote`
   in the shard key would split a permit-any lease across shards —
   forbidden.

3. **Port ownership becomes lock-free.** Per pool **address** keep an
   atomic occupancy bitmap (`Vec<AtomicU64>`) sized to the inclusive
   range `port_high - port_low + 1` bits, plus the existing atomic
   per-address cursor. Claim = forward-probe from the cursor, CAS a clear
   bit (subsumes the `#3047` forward-probe-past-collision); free = atomic
   clear; cursor advance preserves the `#3011` 2MSL/TIME_WAIT reuse
   spreading. This deletes `owner_by_translated`,
   `addr_index_by_translated`, `next_port_offset_by_addr`, and
   `recycled_ports_by_addr` from under any lock. **The occupancy bit IS
   the ownership token**: a held bit cannot be re-claimed (CAS fails), so
   the per-tuple owner-identity check is unnecessary and ABA-safe — the
   bit is cleared exactly once, by the legitimate owner, via the
   `live_by_flow`/lease record that points at the translated tuple.
   - `translated.ip → addr_index` becomes a **static** lookup over the
     fixed pool-address list (built at allocator construction), replacing
     the dynamic `addr_index_by_translated` map.
   - `recycled_ports_by_addr` (the FIFO 2MSL spreader) is replaced by the
     advancing cursor: the cursor walks forward and wraps, so a
     just-freed port is the *last* to be re-probed within one wrap — the
     same anti-immediate-reuse property `#3011` wanted, without a queue.
     *(Open question Q3: confirm the cursor-wrap reuse distance is
     equivalent to the FIFO queue for the 2MSL window; if not, keep a
     lock-free recycle ring. Lab/regression decides.)*

4. **Tracked-flow cap = one global `AtomicUsize`** (exact RMW), not a
   per-shard approximation, so the `MAX_SOURCE_NAT_POOL_TRACKED_FLOWS`
   (262 144) and per-pool capacity caps stay exact.

**Hot path (non-persistent new flow):** 1 flow-shard lock (insert
`live_by_flow`) + atomic cursor `fetch_add` + a few bitmap CAS + 1 global
cap RMW. No global mutex.

**Persistent new flow:** lock the persist-shard (lease reuse/expiry
decision + claim the bitmap bit atomically with the lease decision, so
two distinct 5-tuples sharing one lease cannot both claim a port — the
second finds the lease and reuses), THEN lock its own flow-shard to
insert `live_by_flow`. Two locks, **fixed global order (persist-shard
before flow-shard)** → deadlock-free. Persistent NAT is the colder path.

**Release / rollback:** flow-shard from the 5-tuple; if the
`LiveAllocation.persistent_key` is present, also take the persist-shard
(same fixed order) for lease accounting; clear the bitmap bit (lock-free)
for non-persistent flows and on lease teardown.

**Exhaustion:** a per-address bitmap full → try the next pool address
(existing round-robin loop) → all addresses full ⇒ `AllocatorExhausted`.
**True pool-full, never premature**: there is no per-shard port
partition, so no shard can starve while another has free ports (this is
exactly why Option A was rejected).

**GC:** each persist-shard keeps its own `lease_expirations` + the
existing budgets (ALLOCATION 8 / RELEASE 64 / PRESSURE 64), driven by
that shard's own call rate; a lease lives in exactly one persist-shard,
so per-shard budgets are correct and aggregate GC throughput scales ×N.
Expiry clears the bitmap bit for the lease's recorded translated tuple
(lock-free), under the persist-shard lock that already gates
`active_flows == 0`.

### 5.3 Implementation sketch (types / signatures)

```rust
struct PortAllocatorShared {
    counters: Vec<AtomicU32>,        // unchanged (per-address cursor)
    addr_counter_v4: AtomicU32,      // unchanged
    addr_counter_v6: AtomicU32,      // unchanged
    flow_shards: [Mutex<FlowShard>; N],        // live_by_flow, sharded
    persist_shards: [Mutex<PersistShard>; N],  // persistent_by_source + lease idx
    occupancy: Vec<AddressBitmap>,   // one per pool address (Vec<AtomicU64> + cursor)
    live_flow_count: AtomicUsize,    // exact global cap
    allocations_total: AtomicU64, reuses_total: AtomicU64, exhaustion_total: AtomicU64,
    max_tracked_flows: usize,
    addr_of_ip: /* static Ip->index map */,
}
struct FlowShard    { live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation> }
struct PersistShard { persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
                      lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
                      lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>> }
struct AddressBitmap { words: Vec<AtomicU64>, cursor: AtomicU32 }
```

- `allocate_translation`: branch persistent vs non-persistent at shard
  selection. Non-persistent: flow-shard lock → cap RMW → bitmap claim →
  insert. Persistent: persist-shard lock (lease decision + bitmap claim)
  → flow-shard lock (ordered) → insert.
- `snapshot`: sum per-shard lens (cold, 1/s poll); `used_ports` =
  popcount over bitmaps OR a separate `AtomicU64` used counter; totals
  from atomics.
- Public signatures of `allocate_translation` / `release_flow` /
  `rollback_flow` / `snapshot` / `try_next_port` / `address_index`
  **unchanged** (they already take `&self`; the internals change).
- Add `benches/snat_allocator.rs` (criterion, `harness=false`).

## 6. Public API preservation

- `PortAllocator` stays `#[derive(Clone)]` wrapping
  `Arc<PortAllocatorShared>`; `.clone()` continues to share inner state
  (so all workers share one allocator and config-refresh reuse via
  `parse_source_nat_rules_with_previous` is unchanged). **Confirmed
  sharing:** `forwarding: Arc<ArcSwap<ForwardingState>>`
  (`coordinator/ha_state.rs:14`) → every worker loads the same
  `Arc<ForwardingState>` → the same `SourceNatRule.pool_allocator`
  (`source.rs:261`) → the same `Arc<PortAllocatorShared>`.
- `pub(super)` method set unchanged: `address_index`, `try_next_port`,
  `allocate_translation`, `release_flow`, `rollback_flow`, `snapshot`.
- `PortAllocatorSnapshot` fields unchanged (`live_flows`, `used_ports`,
  `persistent_leases`, `max_tracked_flows`, `allocations_total`,
  `reuses_total`, `exhaustion_total`).
- White-box test seams (`debug_live`, `debug_seed_owner`,
  `debug_clear_owner`, and the `pub(super)` live-state fields the tests
  read) must be re-expressed against the new layout — the existing 185
  `nat/tests.rs` assertions are the regression contract (§9). This is the
  largest churn surface: those tests inspect `owner_by_translated`,
  `addr_index_by_translated`, `recycled_ports_by_addr`,
  `next_port_offset_by_addr` directly. Replacing them with
  bitmap-occupancy queries is mechanical but broad.

## 7. Hidden invariants the change must preserve

1. **PAT correctness:** no two live flows ever get the same external
   `(ip, port, proto)`. The bitmap CAS is the single arbiter — a set bit
   cannot be re-claimed. Must hold across the lock-free claim under
   concurrency (loom/stress test, §9).
2. **Address-persistence:** same `src_ip` → same pool *address* across
   sessions. Preserved by `sticky_pool_index` (already lock-free,
   untouched).
3. **Persistent-NAT lease sharing:** all flows that may share one lease
   co-locate in one persist-shard (shard key excludes `remote`). A
   permit-any lease must never be split. Cross-checked for all three
   permit modes.
4. **Reverse-NAT lookup is unaffected:** reverse translation is resolved
   from the **session table** (the synced/established session carries the
   NAT decision), *not* from the allocator. The allocator only mints the
   forward mapping at flow birth. So sharding the allocator cannot break
   reverse lookup. (Confirmed: reverse path uses
   `reverse_session_key(&entry.key, entry.decision.nat)`,
   `ha.rs:420`.)
5. **HA sync of NAT bindings — CORRECTION to the campaign-8 plan:** synced
   sessions carry `entry.decision.nat` (`ha.rs:332/366`) but **the HA
   path does NOT reserve the translated tuple in the allocator today** —
   there is no production `assign_owner`/reserve call outside the
   allocator's own allocate path (verified by grep across
   `ha.rs`/`ha_state.rs`). The `#3047` comment's "HA-synced install
   sitting at the cursor's port" is a *modeled/defensive* scenario, not a
   wired reservation. Therefore the redesign's obligation is **preserve
   current behavior**: it does NOT need to add a synced-tuple reservation
   step. (Adding one — reserving inherited synced tuples in the bitmap on
   failover to prevent the standby-turned-active from re-minting an
   in-use port — is a *separate latent hardening* that should be filed as
   its own issue, OUT OF SCOPE here; see §10.) `make test-failover` is
   still a merge gate to prove no failover regression.
6. **Exhaustion accounting is exact pool-full**, never per-shard
   premature (Option A's failure mode). Global cap is an exact atomic.
7. **`#3047` forward-probe** and **`#3011` reuse-spreading** semantics
   preserved (subsumed by bitmap CAS + advancing cursor; Q3 verifies the
   2MSL distance equivalence).
8. **Config-refresh state reuse** (`parse_source_nat_rules_with_previous`)
   preserved by keeping state behind one `Arc<PortAllocatorShared>`.
9. **Deadlock freedom:** the only two-lock path (persistent) acquires
   persist-shard before flow-shard, always, with no other nested order.

## 8. Risk assessment

| Class | Risk | Likelihood | Mitigation |
|-------|------|-----------|------------|
| **Correctness** | Lock-free bitmap claim double-allocates a port under race | Low | CAS is the sole arbiter; loom model + concurrent stress test (§9) RED-on-revert |
| **Correctness** | Persistent lease split across shards (wrong shard key) | Med if key chosen wrong | Shard key = persistent key MINUS `remote`; unit test all 3 permit modes share/​isolate correctly |
| **Correctness** | `#3011` 2MSL reuse regresses (cursor-wrap ≠ FIFO) | Med | Q3 lab/regression; fall back to a lock-free recycle ring if not equivalent |
| **Correctness** | Two-lock deadlock | Low | Fixed global lock order; loom test |
| **Perf (the whole point)** | Mutex not actually the dominant new-flow bottleneck → no measurable win | **Med** | **Lab gate (§9) — PLAN-KILL if unmeasurable** |
| **Perf** | Bitmap CAS contention near a hot cursor at high worker counts | Low–Med | Advancing atomic cursor distributes; add per-worker cursor hints only if lab shows it |
| **HA** | Failover regression | Low | `make test-failover` gate; HA reservation behavior preserved (§7.5) |
| **Churn** | ~185 white-box tests inspect old fields; broad mechanical rewrite | **High churn** | Re-express test seams against bitmap; this is the dominant cost and a PLAN-KILL input if the win is marginal |

## 9. Test plan (RED-on-revert)

**Microbench (`benches/snat_allocator.rs`, model on
`benches/session_table.rs`):** M threads {1,2,4,6,8} calling allocate at
max rate; report allocs/sec AND p99/p999 for OLD single-mutex vs NEW.
Profiles (mandatory): (a) uniform low occupancy, (b) **85–98 % pool
occupancy**, (c) **skew: 80 % traffic from 10 % of sources**, (d)
**narrow range (64 ports)**. Gate: near-linear scaling to 6 threads AND
no p99 regression in any profile.

**Unit / regression (must be RED on revert of the fix):**
1. **Concurrent no-collision:** N threads allocate disjoint flows
   simultaneously; assert every returned `(ip,port)` is unique and the
   used count == allocation count. RED if a global lock is reintroduced
   *and* the bitmap arbiter removed (this is the core proof the issue
   asks for: concurrent allocation across workers without collision).
2. **Address-persistence preserved:** same `src_ip`, many flows → same
   pool address; across the sharding boundary.
3. **Persistent lease sharing:** permit-any (`remote=None`) flows from
   one `(proto,src,sport)` to different destinations share ONE lease and
   ONE translated tuple; target-host/target-host-port isolate correctly.
4. **Pool-exhaustion correctness:** fill a narrow pool fully → next
   allocate returns `AllocatorExhausted`; freeing one → next allocate
   succeeds; assert NO premature exhaustion while any address has a free
   port.
5. **All 185 existing `nat/tests.rs` assertions pass** (re-expressed
   white-box seams).
6. **loom model:** the two-lock persistent path (ordered) + the
   lock-free bitmap claim/free under interleavings.
7. `cargo test` full NAT suite + `cargo build` clean + clippy.

**Cluster (REQUIRED merge gate — the issue explicitly requires it):**
new-flow ceiling on `loss:xpf-userspace-fw0/fw1` (6 workers). Pool-mode
SNAT rule; drive a high NEW-CONNECTION rate (distinct sources + many
distinct destinations, short-lived connects). **Note:** the `perf-test`
skill measures bulk throughput, not connection rate — a
connection-rate generator must be added (e.g. a many-short-flow loop or
a SYN/connect storm tool). Measure conns/sec at allocator saturation
BEFORE vs AFTER via `PortAllocatorSnapshot.allocations_total` delta/sec +
per-core `perf` (confirm the allocate path is no longer single-core
bound). Success = new-flow/sec scales with worker count until another
bottleneck dominates; zero correctness regressions. `make test-failover`
must pass (HA gate).

## 10. Out of scope (explicitly)

- **Adding HA reservation of inherited synced NAT tuples** (reserving the
  standby's inherited translated tuples in the bitmap on failover so a
  standby-turned-active does not re-mint an in-use port). This is a
  pre-existing latent gap (synced tuples are not reserved today, §7.5) —
  file as its own issue; do NOT bundle it here.
- DNAT / static-NAT allocators (the issue is specifically the SNAT
  pool-mode `PortAllocator`).
- Interface-mode SNAT (address-only, no port allocation — already returns
  before the allocator).
- Changing the `sticky_pool_index` hash or `MAX_SOURCE_NAT_POOL_TRACKED_FLOWS`.
- Per-worker cursor hints — added only if the lab demands them.

## 11. Open questions for adversarial review

1. **Is the mutex actually the dominant new-flow bottleneck on this
   hardware?** If the loss cluster cannot drive enough conns/sec for the
   single mutex to dominate before RX-queue / session-table-insert /
   conntrack-publish saturates, this should PLAN-KILL or PLAN-DEFER
   pending a connection-rate generator. Is the lab capable of generating
   the required new-flow rate at all?
2. **Bitmap memory:** `port_high-port_low+1` bits per pool address — for
   the default 1024–65535 range that's ~8 KiB/address. Acceptable? Any
   pool with many addresses? (Default full range × many addresses could
   be MiBs — is that fine, or do we need a sparse representation?)
3. **`#3011` 2MSL reuse:** is an advancing-cursor wrap genuinely
   equivalent to the FIFO recycle queue for spreading reuse across the
   upstream TIME_WAIT window, or do we still need a lock-free recycle
   ring? (Q3 in §5.2.)
4. **Shard count N=16 default:** right for 6 workers? Too many (wasted
   memory / false-sharing of shard locks) or too few? Should N derive
   from worker count?
5. **Persistent two-lock path:** is acquiring persist-shard then
   flow-shard genuinely deadlock-free against every other path
   (release/rollback also take both in that order)? Any path that takes
   flow-shard first?
6. **`used_ports` snapshot:** popcount over all bitmaps each 1/s poll vs
   a maintained `AtomicU64` — which, given snapshot is cold but bitmaps
   can be large?
7. **Is the simpler Option C-minus enough?** i.e. shard ONLY
   `live_by_flow` (the hottest, non-persistent path) and keep the
   persistent-lease + port-claim state under a *smaller* second mutex —
   would that capture most of the win at a fraction of the churn? (A
   deliberately smaller-scope alternative to weigh against the full
   bitmap rewrite.)
8. **Churn vs win:** ~185 white-box tests + a correctness-critical NAT
   rewrite. If the lab win is < ~2× new-flow scaling, does churn outweigh
   it (PLAN-KILL)?
