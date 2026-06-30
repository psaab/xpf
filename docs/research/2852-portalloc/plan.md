# #2852 — Sharded / lock-free SNAT PortAllocator (research plan)

## 1. Status

`v3 — Claude SMR + Codex + AGY folded. Design firm → terminal
PLAN-DEFER (plan-deferred-research): /engineer-able, but merge is gated
on the loss-cluster new-flow-ceiling lab measurement, with PLAN-KILL the
correct outcome if contention is not measurable.`

Reviewed against `origin/master` (re-verified at **b3b8b6029**; the
`userspace-dp/src/nat/` tree is byte-identical to the v1 base
**9d00d219c**, so all file:line anchors below still hold — confirmed by
`git diff --stat 9d00d219c..b3b8b6029 -- userspace-dp/src/nat/` = empty).
Worktree `.claude/worktrees/2852-research`, branch
`research/2852-portalloc`. This is **design-only**: no production code is
touched, no PR is opened. The deliverable is this plan + the three
reviewer verdicts + the issue comment. Implementation begins only on an
explicit `/engineer 2852`.

**v2 changelog (Claude SMR round-1 fold, verdict PLAN-NEEDS-MINOR):**
- F1 (correctness, MAJOR-leaning): the occupancy bit-clear is now an
  explicit *conditional* invariant — cleared exactly once, by the path
  that successfully removes the owning record under its shard lock, never
  unconditionally (§5.2 item 3, §7.1, §9 test 1b).
- F2 (correctness): the advancing-cursor-wrap is **NOT** asserted
  equivalent to the FIFO `#3011` recycle queue; the design **keeps a
  lock-free recycle ring by default**, cursor-wrap-only is a lab-gated
  alternative with a dedicated regression test (§5.2 item 3, §9 test 8).
- F3 (sequencing / churn — adopted): the work is now **phased** —
  Phase 1 = lock-free per-address bitmap claim + a single *tiny* mutex
  around just the map insert/remove; Phase 2 = shard the maps, gated on
  Phase-1 lab measurement still showing the residual mutex as the
  bottleneck (§5.4). This captures the dominant win at roughly half the
  churn and defers the two-lock persistent-ordering complexity.
- F4 (correctness): the global tracked-flow cap now has an explicit
  reserve/rollback discipline (`fetch_add`-reserve → `fetch_sub` on any
  later failure; CAS-style over-cap check, never racy load-then-add)
  (§5.3, §7.6).
- Churn correction: the white-box test surface is **~32 of the 185
  `nat/tests.rs` functions** (the ones touching `owner_by_translated` /
  `addr_index_by_translated` / `recycled_ports_by_addr` /
  `next_port_offset_by_addr` / `debug_*`), not all 185 — the other ~153
  are behavioral (public-API allocate/release/snapshot) and survive the
  refactor unchanged. This materially lowers the churn side of the
  churn-vs-win PLAN-KILL axis (§6, §8). (AGY independently re-verified the
  exact count: 32 of 185.)

**v3 changelog (Codex + AGY round-1 fold; both returned PLAN-NEEDS-MAJOR,
converging on one shared correctness gap):**
- **F5 (MAJOR — lock-ordering deadlock; found INDEPENDENTLY by Codex AND
  AGY; missed by the plan and by Claude-SMR r1):** the Phase-2 sharded
  release/rollback path as sketched acquired flow-shard→persist-shard, the
  inverse of allocate's persist→flow → AB/BA deadlock. Resolved (§5.2 F5,
  §7.9): every two-lock path acquires persist→flow unconditionally, with
  both shard indices computed up front from the 5-tuple (the persist key
  `(proto,src,sport)` is a subset of the flow key, so release need not read
  `live_by_flow` first). Phase 1 has no two-lock path, so it sidesteps F5
  entirely. The §9 test 6 loom must race a persistent allocate against a
  release to prove it.
- **F6 (MINOR perf — AGY):** adjacent shard mutexes share a 64 B cache
  line → false sharing. Pad each shard cell (`CachePadded` /
  `#[repr(align(64))]`) — §5.3, §8.
- **F7 (MINOR correctness — AGY):** the static `translated.ip→addr_index`
  reverse lookup is wrong if a pool carries the same IP at two indices;
  store `addr_index` in `LiveAllocation`/`PersistentLease` and pass it to
  release instead — §5.2 item 3, §5.3, §8.
- **F-BODY (Codex) is a review-race artifact, NOT a real gap:** Codex read
  `plan.md` after the §1 v2 changelog was written but before the §5.2 item
  3 / §5.3 / §5.4 / §7.6 / §8 / §9-test-1b body edits committed. The body
  edits are all present in this v3 (verified). No action — recorded here
  so the ledger is honest.
- Codex + AGY both **AGREE** with all four Claude-SMR findings (F1-F4) and
  both **VALIDATE** the §7.5 HA-reservation correction (no production
  reserve caller; `debug_seed_owner`/`debug_clear_owner` are
  `#[cfg(test)]`). The architecture (bitmap ownership, two-tier shard
  keys, phased delivery, FIFO recycle ring, global atomic cap) is judged
  sound; the only blockers were F5 (now resolved in design) and the lab
  gate. Both reviewers explicitly endorse the mandatory lab gate +
  PLAN-KILL line and say it must NOT be weakened.

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
   `addr_index_by_translated`, and `next_port_offset_by_addr` from under
   any lock (`recycled_ports_by_addr` → see F2 below). **The occupancy
   bit IS the ownership token**: a held bit cannot be re-claimed (CAS
   fails), so the per-tuple owner-identity check is unnecessary — PROVIDED
   the bit-clear is conditional per **F1** below.
   - **F1 invariant (MAJOR — the ABA guard): the occupancy bit is cleared
     exactly once, by the code path that *successfully* removes the
     owning record under that record's shard lock; NEVER
     unconditionally.** Concretely:
     - *Non-persistent free:* `release_flow`/`rollback_flow` removes
       `live_by_flow[flow]` under the flow-shard lock and clears the bit
       **iff** the removed entry's `translated` matches (this preserves
       today's `existing.translated != translated` guard at
       allocator.rs:623/664). A duplicate or late `release_flow` for an
       already-gone 5-tuple MUST NOT clear the bit — otherwise it frees a
       port a *different* flow has since CAS-claimed at the same offset →
       silent PAT double-allocation.
     - *Persistent free:* the bit is owned by the LEASE and shared by many
       flows. A per-flow persistent `release_flow` only decrements
       `active_flows` and MUST NOT clear the bit; the bit clears ONLY at
       lease teardown (`release_expired_lease_locked` / rollback
       `remove_lease`) under the persist-shard lock with
       `active_flows == 0` — mirroring today's
       `release_translated_locked` call sites.
   - **F7 (AGY, correctness) — store `addr_index` in the live/lease
     record; do NOT reverse-lookup the IP.** The v1/v2 sketch replaced
     `addr_index_by_translated` with a *static* `translated.ip →
     addr_index` lookup over the pool-address list. That is wrong if the
     pool can carry the **same IP at two indices** (e.g. a weighted pool,
     or a range that expands a duplicate): a static first-match lookup
     would clear the bit in the wrong address bitmap. Fix: record the
     allocated `addr_index` in `LiveAllocation` (and in `PersistentLease`)
     at claim time and pass it to `release`/teardown — strictly safer and
     it deletes the reverse map entirely. (Verify whether duplicate pool
     IPs are reachable from the Go builder; even if not today, storing the
     index is the robust choice and costs one `usize`.)
   - **F2 (#3011 reuse spreading) — keep a lock-free recycle ring by
     default.** The plan does NOT delete `recycled_ports_by_addr` on the
     strength of the cursor. Today's cursor is a one-shot sweep
     `0..range` (allocator.rs:502-503 `if next_offset >= range break`),
     after which ALL reuse is drained front-first from the FIFO
     `recycled_ports_by_addr` (allocator.rs:530-542) — strict
     oldest-freed-first, the `#3011` anti-immediate-reuse property. A
     *wrapping* bitmap cursor does NOT reproduce FIFO: a port freed just
     ahead of the cursor is re-probed almost immediately while one freed
     just behind waits a full wrap → position-dependent reuse latency, a
     `#3011` regression (a just-freed port handed back inside the
     upstream's 2MSL/TIME_WAIT window). Default design: replace the
     `VecDeque` FIFO with a **lock-free recycle ring** (e.g. an MPMC ring
     / per-address `SegQueue`) drained before forward-probing — preserves
     FIFO without a lock. Cursor-wrap-only (dropping the ring) is a
     *lab-gated alternative*, accepted only if §9 test 8 proves the reuse
     distance is equivalent (Q3).

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
before flow-shard)** → deadlock-free *only if every two-lock path obeys
the same order* — see the F5 invariant below. Persistent NAT is the
colder path.

**F5 — lock-ordering deadlock (MAJOR, found independently by Codex AND
AGY; missed by the plan and Claude-SMR r1). RESOLUTION:** the v1/v2
release sketch ("flow-shard first; *if* `persistent_key` present, then
persist-shard") acquires **flow→persist**, the *inverse* of allocate's
**persist→flow** — a classic AB/BA deadlock under concurrent
allocate+release churn (worker A holds persist[i] waiting flow[j];
worker B holds flow[j] waiting persist[i]). The fix relies on a fact the
sketch overlooked: **the persist-shard key `(proto, src_ip, src_port)`
is a strict SUBSET of the 5-tuple `SourceNatFlowKey`**, so
`release_flow`/`rollback_flow` can compute the persist-shard index
**directly from their 5-tuple argument** — no need to read
`live_by_flow` first to learn it. Therefore **every two-lock path
acquires persist-shard BEFORE flow-shard, unconditionally**, with both
indices computed up front from the 5-tuple. A non-persistent release
takes the persist-shard lock briefly and no-ops (it finds no lease) —
trivial cost on the colder release path, and it keeps one global order.
(Codex's resolution (A); equivalent to AGY's "stratified hierarchy" with
the direction pinned to persist→flow. The two-lock loom test, §9 test 6,
MUST exercise concurrent allocate+release on the persistent path to prove
this. Phase 1 (§5.4) has NO map sharding — a single tiny mutex — so F5
**does not arise in Phase 1 at all**; it is a Phase-2-only obligation.)

**Release / rollback:** compute BOTH the flow-shard and persist-shard
indices from the 5-tuple up front; acquire **persist-shard then
flow-shard** (the F5 fixed order). Read/remove `live_by_flow` under the
flow-shard; do lease accounting under the persist-shard; clear the bitmap
bit (lock-free) **conditionally per F1** (only on the successful matching
record removal for non-persistent, or lease teardown with
`active_flows == 0` for persistent). Use the `addr_index` recorded in the
live/lease record (F7) — not a reverse IP lookup — to find the bitmap.

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
    // F6: cache-line-padded shard cells — adjacent mutexes on one 64B line
    // bounce between cores (a Mutex is ~40B), so wrap each in a padded newtype.
    flow_shards: [CachePadded<Mutex<FlowShard>>; N],       // live_by_flow, sharded
    persist_shards: [CachePadded<Mutex<PersistShard>>; N], // persistent_by_source + lease idx
    occupancy: Vec<AddressBitmap>,   // one per pool address (Vec<AtomicU64> + cursor)
    live_flow_count: AtomicUsize,    // exact global cap (F4 reserve/rollback)
    allocations_total: AtomicU64, reuses_total: AtomicU64, exhaustion_total: AtomicU64,
    max_tracked_flows: usize,
    // NB: no static addr_of_ip reverse map — addr_index lives in the record (F7).
}
// F6: crossbeam_utils::CachePadded (or a #[repr(align(64))] newtype) — avoids
// false sharing of the per-shard locks under concurrent multi-shard traffic.
struct FlowShard    { live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation> }
struct PersistShard { persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
                      lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
                      lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>> }
struct AddressBitmap { words: Vec<AtomicU64>, cursor: AtomicU32 }
// LiveAllocation / PersistentLease each carry the allocated `addr_index: usize`
// (F7) so release/teardown clears the correct bitmap without a reverse lookup.
```

- `allocate_translation`: branch persistent vs non-persistent at shard
  selection. Non-persistent: flow-shard lock → cap reserve → bitmap claim
  → insert. Persistent: persist-shard lock (lease decision + bitmap
  claim) → flow-shard lock (ordered) → insert.
- **F4 — global cap reserve/rollback discipline (`live_flow_count:
  AtomicUsize`):** reserve a slot with a single `fetch_add(1)`; if the
  post-increment value exceeds `max_tracked_flows`, immediately
  `fetch_sub(1)` and return `AllocatorExhausted` (over-cap). If any
  *later* step fails (bitmap full → exhaustion, or a persistent-lease
  pressure abort), `fetch_sub(1)` to release the reservation before
  returning. Never a racy load-then-add. This keeps the count exact (no
  drift up → no premature exhaustion, no admit-over-cap) even with the
  insert no longer under one global lock.
- `snapshot`: sum per-shard lens (cold, 1/s poll); `used_ports` =
  popcount over bitmaps OR a separate `AtomicU64` used counter; totals
  from atomics.
- Public signatures of `allocate_translation` / `release_flow` /
  `rollback_flow` / `snapshot` / `try_next_port` / `address_index`
  **unchanged** (they already take `&self`; the internals change).
- Add `benches/snat_allocator.rs` (criterion, `harness=false`).

### 5.4 Phasing (F3 — adopted)

The two changes in §5.2 are **not equally load-bearing**, so the
implementation is phased to capture the dominant win first at the lower
churn, and to make the churn-vs-win PLAN-KILL decision on Phase-1
measurement rather than up front. Decompose the locked critical section:

1. **the port claim** — cursor advance + `owner_by_translated` insert +
   `addr_index_by_translated` insert: the bulk of the locked work and the
   genuinely cross-worker-shared resource (the port space);
2. **the map insert** — `live_by_flow` / `persistent_by_source`: a couple
   of hash ops.

**Phase 1 (essential): lock-free per-address occupancy bitmap + recycle
ring for the port claim, keeping a SINGLE now-tiny mutex around just the
map insert/remove + lease state.** This removes the dominant contention
(every allocate stops serializing on the port-claim arithmetic and the
two ownership-map inserts) without introducing any shard-key correctness
surface or the two-lock ordered persistent path. Measure on the loss
cluster (§9). This is ~half the churn of the full design and zero new
deadlock surface.

**Phase 2 (incremental, gated): shard the maps** (`flow_shards[N]` +
`persist_shards[N]`, the §5.2 two-tier design with the
persistent-key-minus-`remote` shard key and the ordered two-lock path),
**only if** the Phase-1 lab measurement still shows the residual tiny
mutex as a material new-flow bottleneck. If Phase-1 already scales
near-linearly to 6 workers, Phase 2 is not built.

**Why not "Option C-minus" (shard maps WITHOUT the lock-free claim):**
explicitly rejected because the port claim (cursor + two ownership-map
inserts) stays serialized under whatever lock guards the port space, so
sharding only the `live_by_flow` map removes a couple of hash ops while
the genuinely-shared resource stays contended — almost no win for real
churn. The lock-free claim is the load-bearing half; map sharding is the
incremental half. (This corrects the v1 framing, which dismissed
C-minus without the reason.)

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
  read) must be re-expressed against the new layout. **Churn correction
  (Claude SMR):** of the **185 `#[test]` functions** in `nat/tests.rs`,
  only **~32 touch the white-box fields** (`owner_by_translated`,
  `addr_index_by_translated`, `recycled_ports_by_addr`,
  `next_port_offset_by_addr`, `debug_*`) and need re-expressing against
  bitmap-occupancy queries — mechanical. The other ~153 are **behavioral**
  (they drive `allocate_translation` / `release_flow` / `snapshot` via the
  public API) and survive the refactor unchanged; they are the regression
  contract (§9). So the white-box rewrite surface is ~32 tests, not 185 —
  the churn is real but bounded, and Phase 1 (§5.4) touches only the
  port-claim subset of it.

## 7. Hidden invariants the change must preserve

1. **PAT correctness:** no two live flows ever get the same external
   `(ip, port, proto)`. The bitmap CAS is the single arbiter — a set bit
   cannot be re-claimed. **This holds only with the F1 conditional clear
   (§5.2 item 3): the bit is cleared exactly once, by the path that
   successfully removes the owning record under its shard lock, never
   unconditionally** — otherwise a stale/duplicate free clears a port a
   different flow has since claimed → silent double-allocation. Must hold
   across the lock-free claim under concurrency (loom/stress test, §9).
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
   premature (Option A's failure mode). The global tracked-flow cap is an
   exact `AtomicUsize` with the F4 reserve/rollback discipline (§5.3):
   `fetch_add`-reserve, `fetch_sub` on any later failure, CAS-style
   over-cap check — never racy load-then-add, so the count never drifts
   (no false exhaustion, no over-cap admit).
7. **`#3047` forward-probe** and **`#3011` reuse-spreading** semantics
   preserved (subsumed by bitmap CAS + advancing cursor; Q3 verifies the
   2MSL distance equivalence).
8. **Config-refresh state reuse** (`parse_source_nat_rules_with_previous`)
   preserved by keeping state behind one `Arc<PortAllocatorShared>`.
9. **Deadlock freedom (F5):** EVERY two-lock path —
   `allocate_translation` (persistent), `release_flow`, `rollback_flow`,
   and lease teardown — acquires **persist-shard BEFORE flow-shard,
   unconditionally**, with both indices computed up front from the
   5-tuple (the persist-shard key `(proto, src_ip, src_port)` is a subset
   of the 5-tuple, so release does NOT read `live_by_flow` first to learn
   it). A non-persistent release takes-and-noops the persist-shard lock to
   preserve the single global order. No path acquires flow-shard first.
   Phase 1 (single tiny mutex, no map sharding) has no two-lock path at
   all. Proven by the §9 test 6 loom model exercising concurrent
   allocate+release on the persistent path.

## 8. Risk assessment

| Class | Risk | Likelihood | Mitigation |
|-------|------|-----------|------------|
| **Correctness** | Lock-free bitmap claim double-allocates a port under race | Low | CAS is the sole arbiter; loom model + concurrent stress test (§9) RED-on-revert |
| **Correctness** | Persistent lease split across shards (wrong shard key) | Med if key chosen wrong | Shard key = persistent key MINUS `remote`; unit test all 3 permit modes share/​isolate correctly |
| **Correctness** | `#3011` 2MSL reuse regresses (cursor-wrap ≠ FIFO) | Med | **F2: keep a lock-free recycle ring by default** (preserves FIFO); cursor-wrap-only is lab-gated by §9 test 8 |
| **Correctness** | Stale/duplicate free clears a live flow's port (ABA) | Low | **F1: conditional clear** — bit cleared only on successful matching record removal under the shard lock; §9 test 1b RED-on-revert |
| **Correctness** | Global cap drifts (premature exhaustion / over-cap admit) | Low | **F4: `fetch_add`-reserve + `fetch_sub`-rollback**, CAS-style over-cap check |
| **Correctness** | **F5: two-lock AB/BA deadlock** (release locks flow→persist, allocate persist→flow) | **Med (was a real design gap — Codex+AGY both caught)** | All two-lock paths acquire persist→flow unconditionally; persist index computed from the 5-tuple subset, no flow-shard-first read; §9 test 6 loom on concurrent allocate+release. Phase 1 has no two-lock path |
| **Perf** | **F6: false sharing** of adjacent shard mutexes on one cache line | Med | Pad each shard cell to 64B (`CachePadded` / `#[repr(align(64))]`) |
| **Correctness** | **F7: wrong bitmap cleared** when pool has a duplicate IP (static IP→index first-match) | Low–Med | Store `addr_index` in `LiveAllocation`/`PersistentLease`; no reverse IP lookup |
| **Perf (the whole point)** | Mutex not actually the dominant new-flow bottleneck → no measurable win | **Med** | **Lab gate (§9) — PLAN-KILL if unmeasurable** |
| **Perf** | Bitmap CAS contention near a hot cursor at high worker counts | Low–Med | Advancing atomic cursor distributes; add per-worker cursor hints only if lab shows it |
| **HA** | Failover regression | Low | `make test-failover` gate; HA reservation behavior preserved (§7.5) |
| **Churn** | ~32 of 185 `nat/tests.rs` fns inspect old white-box fields (the other ~153 are behavioral, survive unchanged); Phase 1 touches only the port-claim subset | **Med churn** | Re-express the ~32 white-box seams against bitmap-occupancy queries (mechanical); F3 phasing front-loads only the port-claim slice; a PLAN-KILL input only if the lab win is marginal |

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
   **1b. F1 stale/duplicate-free does NOT free a live port:** allocate
   flow A→port P; free A; allocate flow B which CAS-claims the same offset
   P; issue a *second* (stale) `release_flow` for A; assert B still owns P
   (the bit stays set) and a fresh allocate does not hand out P. For
   persistent: a per-flow `release_flow` with `active_flows>0` must NOT
   clear the bit. **RED on revert** if the clear is made unconditional.
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
6. **loom model (F5 deadlock + ABA):** the two-lock persistent path
   (Phase 2 only) under interleavings — MUST exercise a persistent
   `allocate_translation` racing a `release_flow`/`rollback_flow` whose
   persist-shard and flow-shard indices land such that a flow→persist
   acquisition would deadlock; assert the fixed persist→flow order is
   deadlock-free. Also model the lock-free bitmap claim/free (the F1
   conditional clear) under interleavings.
7. `cargo test` full NAT suite + `cargo build` clean + clippy.
8. **F2 `#3011` reuse-distance:** free a known sequence of N ports, then
   allocate N+1; assert the FIRST reused port is the *oldest-freed*
   (FIFO), matching today's `recycled_ports_by_addr` behavior. This test
   is the gate that decides cursor-wrap-only vs the lock-free recycle
   ring (§5.2 F2): with the default ring it passes; it is the proof
   obligation before any cursor-wrap-only simplification.

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
