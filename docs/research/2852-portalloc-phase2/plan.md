# #2852 — SNAT PortAllocator residual serialization (Phase-2 evaluation) — research plan

- **Revision:** r2 (Claude-SMR r1 folded: F4 wording softened per Attack 2; F5
  release-path lock-order inversion in Option A surfaced per Attack 5; follow-up
  issue made an explicit CLOSE deliverable. Codex r1 pending.)
- **Base:** origin/master `b4f2ddb2f` (re-verified: `userspace-dp/src/nat/allocator.rs`
  = 1796 LOC, Phase 1 `6cbb10615` + #4676 `c7194b2af` both landed)
- **Branch:** `research/2852-portalloc-phase2` (docs only; no production source touched)
- **Scope:** decide the TERMINAL disposition of #2852 now that Phase 1 (lock-free
  bitmap claim) and #4676 (chunked GC) are merged. Either (A) PLAN-READY a Phase-2
  map-sharding design, or (B) PLAN-KILL Phase 2 + CLOSE #2852 as substantially
  resolved. This supersedes the prior PLAN-DEFER (which the campaign flags as a
  work queue, not a terminal state).
- **Reviewers:** Claude-SMR (hostile) + Codex. AGY infra-down this session →
  2-of-3 per `feedback_codex_infra_must_retry`.

---

## 0. TL;DR recommendation (challenge this)

**Recommended disposition: CLOSE #2852 as substantially-resolved (Phase 1
`6cbb10615` + #4676 `c7194b2af`); PLAN-KILL the Phase-2 map-sharding follow-on as
an architecturally-bounded, unproven, correctness-risking optimization.** File a
narrow follow-up issue
to build a connection-rate generator + measure the loss-cluster new-flow ceiling,
and revisit Phase-2 ONLY if that measurement shows the residual `live` mutex is
the dominant real-world bottleneck.

The issue's headline defect — *"PortAllocator serializes ALL fast-path SNAT
allocation on one global Mutex — destroys multi-core scaling"* — is **no longer
true on master**: the port CLAIM (cursor + owner map + collision probe + FIFO
drain — the bulk of the old critical section) is now lock-free, GC no longer
holds the lock across a sweep, and the reuse-lookup is a single `get`.
Multi-core scaling went from **negative** (2.87M→0.62M allocs/s, M=1→8, the
mutex-collapse the issue describes) to **positive** (1.4–1.6× at M=6/8, lower
tail). What remains under the mutex is a single `FxHashMap` insert/remove.

Phase 2 (shard that map) would carry a real cost — it **puts at risk the exact
global-cap property Phase 1 deliberately achieved** (see §3.3, §6.4) and shards
correctness-critical NAT state — for a win that is **architecturally bounded** and
has **never been measured on real hardware**. The new-flow path already takes two
co-resident all-workers locks for EVERY new flow — `publish_shared_session` (a
global Mutex) and `replicate_session_upsert` (N−1 Mutexes) —
(`poll_descriptor/mod.rs:3136,3157`), taken by MORE flows than the NAT allocator
mutex (§2.2, §3.0). Sharding the NAT allocator alone therefore cannot restore
linear new-flow scaling: publish + N-way replication serialize every new flow
first. The prior three reviewers unanimously gated Phase 2 behind a cluster
connection-rate measurement that does not exist and was never run; that gate is
now not just unmet but shown to be the WRONG lock to optimize in isolation. Per
the task's own criterion ("if the perf win is unproven → PLAN-KILL/CLOSE"), Phase
2 should be killed.

This document nonetheless designs Phase-2 fully (§5) so the reviewers can judge
the trade on its merits, and presents the PLAN-READY path (Option A) as the
alternative if the reviewers disagree.

---

## 1. Status of the code on current master

`git log origin/master -- userspace-dp/src/nat/allocator.rs`:

| commit | what |
|--------|------|
| `6cbb10615` | **#2852 Phase 1** — lock-free SNAT port claim (`AddressOccupancy` atomic bitmap + atomic cursor; a `fetch_or` CAS is the ownership token). Tiny mutex kept only around the `live_by_flow` insert/reuse/exact-cap CS. |
| `c7194b2af` | **#4676** — chunked NAT GC: `gc_expired_chunked` drops the `live` mutex between reclaim chunks and frees ports lock-free on the bitmap, so a sweep no longer blocks a concurrent allocate for its full duration. |
| `b68eb8ee6` | persistent-lease reuse extracted from `allocate_translation`. |

Both landed **after** the last research round (which was reviewed against a tree
"byte-identical to the v1 base"). The premise of the prior plan — "ONE mutex
serializes every new-flow allocation, GC sweep, and reuse-lookup" — is **stale**.

The merged microbench (`docs/research/2852-portalloc/microbench-results.md`,
gate for Phase 1) is the authoritative measurement and is quoted throughout.

---

## 2. What serialization ACTUALLY remains (quantified)

### 2.1 The one remaining shared lock on the SNAT new-flow path

`PortAllocatorShared.live: Mutex<PortAllocatorLiveState>` (`allocator.rs:610`).
`PortAllocatorLiveState` (`allocator.rs:388`) now holds ONLY:

- `live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>` — the hot map.
- `persistent_by_source` + `lease_expirations` + `lease_expirations_by_addr` —
  persistent-NAT lease lifecycle (COLD path; touched only when
  `persistent_nat`/`address-persistent` is configured).
- `gc_counter: u32`.

The **hot-path critical section** (non-persistent new flow,
`allocate_translation` lines 912–943) is, with the port already claimed
lock-free:

```
lock(live)
  live_by_flow.get(&flow)      // reuse check — 1 hash probe
  live_by_flow.len() >= cap    // exact cap (F4) — O(1)
  live_by_flow.insert(...)     // 1 hash insert
unlock
```

That is ~2 `FxHashMap` operations. Everything expensive (cursor probe, bit CAS,
FIFO recycle drain, collision handling) already ran OUTSIDE the lock on the
lock-free `AddressOccupancy` bitmap (lines 890–911). The amortized GC
(`gc_expired_chunked`, budget 8) also runs OFF this CS (line 911) and is chunked.

`release_flow` / `rollback_flow` take the same mutex for the paired
`live_by_flow.remove` + the (cold) persistent-lease accounting.

### 2.2 The allocator mutex is NOT the only cross-worker lock on the new-flow path — this is decisive

The forwarding SessionTable is per-worker (`session/install.rs:34`: "per-worker,
single-threaded, and `&mut`-exclusive during packet"; `session/README.md:325,589,
927`), so session INSTALL has no cross-worker lock. The PortAllocator IS shared
(`nat/source.rs:287` `pool_allocator: PortAllocator` = `Arc<PortAllocatorShared>`,
one `live` mutex for all workers).

**But the allocator mutex is one of SEVERAL per-new-flow cross-worker locks, and
not the most-traveled one.** On the transit new-flow install block
(`afxdp/poll_descriptor/mod.rs:3136–3160`), EVERY new forward flow —
unconditionally, whether or not it matches a source-NAT rule — also runs:

- **`publish_shared_session(...)`** (`:3136`) → locks the HA shared-session mirror,
  `Arc<Mutex<FastMap>>` × 3 (synced / nat / forward_wire) + the owner-RG index
  (`coordinator/session_manager.rs:13–16`, lock helper `afxdp/shared_ops.rs:31`).
  This is a **single global mutex set, contended by ALL workers, taken once per
  new flow.**
- **`replicate_session_upsert(worker_ctx.peer_worker_commands, …)`** (`:3157`;
  impl `session_glue/mod.rs:731–741`) → for each of the N−1 sibling workers, locks
  that worker's `Arc<Mutex<VecDeque<WorkerCommand>>>` and pushes an `UpsertSynced`
  replica. This is **N−1 mutex acquisitions per new flow**, always on (it is the
  mechanism that lets the reply — which RSS may hash to a different worker — find
  the session), and each queue is contended by up to N−1 producers.

So every new flow already pays: 1 global publish-mutex set + (N−1) replication
mutexes, PLUS the event-stream mpsc + delta-buffer mutex + atomics (§2.4). The
NAT allocator `live` mutex is taken by a **subset** of new flows (only pool-mode
SNAT matches, §5-gated) and is O(1). **Therefore sharding the NAT allocator in
isolation cannot restore linear new-flow scaling: the publish + N-way replication
locks serialize EVERY new flow first.** This is precisely the reviewers'
PLAN-KILL condition — "if another limit (session-install / conntrack publish /
…) saturates first" — now located in code, not hypothesized. The NAT mutex is
demonstrably NOT the dominant new-flow bottleneck.

### 2.3 The measured contention (from the merged Phase-1 gate)

Isolated microbench, threads M = {1,2,4,6,8}, 16-core host, uniform-low profile
(aggregate successful allocate()/sec; NEW = shipped Phase-1 shape):

```
 M      CUR a/s      NEW a/s   speedup |  CUR p99   NEW p99
 1    2,868,506    3,950,589    1.38x  |     300      177
 2      955,130    1,386,382    1.45x  |    8948     1675
 4      803,664    1,152,502    1.43x  |   16203    10344
 6      657,194    1,029,144    1.57x  |   23468    16425
 8      623,612    1,001,846    1.61x  |   31385    21982
```

Two facts matter:

1. **Phase 1 fixed the collapse the issue reported.** CUR (pre-#2852) negative-
   scales — throughput DROPS as cores are added (2.87M→0.62M) and p99 explodes
   ~100×. That is exactly "destroys multi-core scaling". NEW does not collapse:
   it is positive and 1.4–1.6× faster at the cluster's 6-worker scale with lower
   tail.
2. **Phase 1 alone is NOT linear.** NEW also falls off (3.95M→1.00M, M=1→8)
   because the residual `live_by_flow` insert/remove mutex is now the
   serialization point. This is the ENTIRE remaining defect, and it is what a
   Phase-2 shard would attack.

**Caveat on the microbench (reviewer-acknowledged, not my claim):** it
*reimplements* the allocator shape in the bench crate and runs `allocate()` in a
tight loop with nothing else. It is an **upper bound on contention**, not a
representative of the real dataplane, where each new flow also runs parse +
screen + zone + policy-match + session-install + HA-enqueue + forward BETWEEN
allocator calls. That inter-arrival work lowers the CS duty cycle and therefore
lowers real contention below the microbench worst case. The prior reviewers were
unanimous: the microbench does **not** establish the mutex is the *dominant*
real-world bottleneck — only the cluster new-flow-ceiling measurement does, and
that measurement is the PLAN-KILL gate.

### 2.4 Full inventory of per-new-flow cross-worker synchronization

From the concurrency sweep of the transit new-flow commit block
(`afxdp/poll_descriptor/mod.rs:3046–3160`):

| # | Mechanism | Kind | Scope | file:line |
|---|-----------|------|-------|-----------|
| a | per-worker `SessionTable` insert | none (worker-owned) | all new flows | `poll_descriptor/mod.rs:3046` |
| b | BPF `session_map` / `dnat_table` update | kernel map syscall | all new flows | `:3123,:3147` |
| **c** | **HA shared-session publish** (3× `Arc<Mutex<FastMap>>` + owner-RG) | **global Mutex set** | **all new flows** | `:3136`; `shared_ops.rs:31` |
| **d** | **sibling replication** (push into every peer worker queue) | **N−1 Mutexes** | **all new flows** | `:3157`; `session_glue/mod.rs:731` |
| e | event-stream deltas | bounded mpsc | all new flows | `event_stream/mod.rs:369` |
| f | recent-delta CLI buffer | Mutex | all new flows | `session_delta.rs:71` |
| g | diagnostic counters | atomics | all new flows | `shared_ops.rs:64` |
| h | NAT rule hit-counters | atomics | matched flows | `:3103` |
| **X** | **NAT allocator `live` mutex** | **global Mutex** | **pool-mode-SNAT flows ONLY** | `allocator.rs:912` |

The lock under study (**X**) is taken by a strict subset of the flows that take
(**c**) and (**d**), and is O(1). Deterministic-CGNAT / persistent-NAT take the
same `live` mutex but are cold/config-gated.

---

## 3. Why the win is unproven and the residual is small

### 3.0 The scaling win is architecturally bounded — whack-a-mole is proven, not speculated

The strongest kill argument, from §2.2/§2.4: the new-flow path has co-resident
all-workers locks — `publish_shared_session` (global Mutex, ALL new flows) and
`replicate_session_upsert` (N−1 Mutexes, ALL new flows) — taken by MORE flows
than the NAT allocator mutex and at least as contended. Any config with N>1
workers that contends the NAT mutex ALSO contends these. So even a perfectly
lock-free NAT allocator leaves every new flow serialized on publish + N-way
replication. Sharding the NAT allocator in isolation therefore **cannot** deliver
the issue's promised "restore multi-core scaling at high new-flow rates" — the
aggregate new-flow ceiling is set by whichever of {publish mutex, replication
mutexes, session-install, RX queue, NIC} saturates first, and the NAT mutex is
not uniquely nor even primarily that. This is the reviewers' exact PLAN-KILL
condition, now confirmed in code.

### 3.1 The realistic new-SNAT-flow ceiling is unmeasured — and probably below the mutex cap

For the residual mutex (Phase-1 NEW caps ~1.0M allocs/s at M=6) to be the *real*
bottleneck, the box must sustain a NEW pool-mode-SNAT flow rate approaching
~1M/sec across 6 workers (~167K/worker/sec of brand-new, distinct 5-tuples that
match a port-translating source-NAT rule). Established flows never touch the
allocator (they hit the per-worker session table). That is a very high sustained
connection-setup rate for a 6-worker mlx5-VF userspace dataplane whose per-new-
flow pipeline (policy match + session install with secondary indices + HA
enqueue) is on the order of 1–5 µs/flow. If the pipeline caps a worker below
~167K new-SNAT-flows/sec, the mutex is never the aggregate cap and Phase 2 buys
nothing. **This has never been measured** — no connection-rate generator exists
(the `perf-test` skill measures bulk throughput; grep of `test/incus/` finds no
conn-rate harness), and building one is /engineer-scale work.

### 3.2 SYN-flood / DoS is not a Phase-2 justification

The obvious "high new-flow rate" scenario — a SYN flood — is handled BEFORE
session/NAT state is created: screen syn-flood + SYN-cookie generation short-
circuit the pipeline and do NOT call `allocate_translation`. So the allocator
mutex is not on the flood-resilience path. The workloads that do reach it
(CGNAT churn, connection storms from legitimate many-short-connection apps) are
real but niche, and their sustained rate on this platform is exactly the
unmeasured quantity.

### 3.3 Phase 2 puts the F4 exact-cap property at risk (mitigable only via premature exhaustion or a fallback mode)

Phase 1's design note (`allocator.rs:24–31`) is explicit: the global tracked-flow
cap is `live_by_flow.len()` re-checked **under the insert mutex**, where the map
length is authoritative — so it is **EXACT and never overshoots**, and a tiny
pool near capacity is never falsely exhausted. This is strictly better than the
microbench's atomic `fetch_add`-reserve model, which the gate doc itself found
overshoots by up to M in-flight and **failed 71–79% of allocations at M=6/8 on a
narrow 64-port pool** (`microbench-results.md:141–154`).

Sharding `live_by_flow` puts the cheap exact `len()` at risk. Every avoidance
path has a cost: (a) a global cap across N shards via `AtomicUsize`
reserve/rollback overshoots by up to M (the microbench data above); (b) static
per-shard sub-caps (`max/N`) avoid the atomic but cause *premature exhaustion*
under skewed flow-key hashing (one shard hits its sub-cap while other shards —
and the port bitmap — have room), the exact failure that killed Option C; (c) a
serialized exact-path fallback for small pools preserves exactness but adds a
mode split + a size threshold to tune. So Phase 2 trades away, or adds complexity
to preserve, a correctness property (exact NAT-pool cap, no false exhaustion when
the pool has room) that Phase 1 was engineered to obtain — for an unproven
throughput win. For NAT, "never falsely reject a connection when the pool has
room" is a real operator-visible guarantee.

### 3.4 The residual is small and the risk surface is large

Sharding correctness-critical NAT state introduces: (a) a per-shard-vs-global
cap accounting problem (§3.3), (b) a lock-ordering surface for the persistent-NAT
path (the prior plan's F5 deadlock, independently found by two reviewers),
(c) HA `reserve_flow` must reach the correct shard for a peer-synced port,
(d) per-shard GC/exhaustion accounting, (e) false-sharing tuning. All to remove
~2 hashmap ops from a lock whose real-world duty cycle is unmeasured.

---

## 4. Design options

### Option A — PLAN-READY: shard `live_by_flow` only (Phase-2-lite)

The prior plan's two-tier scheme (shard the persistent maps too, with the
`(proto,src_ip,src_port)` key) is over-built: the HOT path is only the
NON-persistent `live_by_flow` insert. So the minimal, lowest-risk Phase 2 is:

- `live_by_flow` → `N` striped shards, each `Mutex<FxHashMap<…>>`, shard =
  `hash(SourceNatFlowKey) % N`. Reached identically at allocate / `release_flow`
  / `rollback_flow` / `reserve_flow` from the 5-tuple alone.
- **Persistent-lease maps + expiration indexes + `gc_counter` stay under ONE
  separate mutex** (cold). The hot non-persistent path never touches it, so it
  is uncontended in the target workload. This sidesteps the two-tier shard-key
  correctness surface AND the F5 deadlock entirely (the hot path takes exactly
  ONE shard lock; the persistent path takes the cold lease-mutex, then a flow
  shard, in that fixed order).
- Global cap → `AtomicUsize` with `fetch_add`-reserve / `fetch_sub`-rollback
  (accepts the §3.3 overshoot; mitigate with a per-shard soft cap + a small-pool
  fallback to a serialized exact path, OR document the up-to-M overshoot as
  acceptable on large pools and fall back to serialized alloc when
  `max_tracked_flows` is small).
- Occupancy bitmap, cursor, recycle ring: UNCHANGED (already lock-free /
  per-address).

Zero-alloc on the hot path: yes (striped mutex is a fixed `Vec<Mutex<…>>`; insert
into a pre-sized shard map; no per-flow allocation beyond the existing map
growth, same as today).

**PLAN-READY merge gate:** microbench extended to show near-linear scaling of NEW
to 6 threads AND no p99 regression AND no narrow-pool false-exhaustion;
`make test-failover` (HA `reserve_flow`); the cluster new-flow-ceiling
measurement as a NICE-TO-HAVE (see §8), with PLAN-KILL retained if a conn-rate
generator materializes and shows the mutex is not the real cap.

### Option B — PLAN-KILL Phase 2 + CLOSE #2852 (recommended)

Close the issue: its severe defect is fixed (§0/§2.3). Kill Phase 2 as unproven
(§3.1), correctness-regressing (§3.3), and high-risk (§3.4). File a narrow
follow-up to build a conn-rate generator + run the cluster new-flow ceiling, and
reopen Phase-2 with data if the residual mutex is shown to be the real cap.

### Option C — REJECTED: striping / per-worker port pools

Partition the port range per worker/shard. Rejected by all prior reviewers and
re-rejected here: fragments the pool → *premature exhaustion* (a worker's slice
full while another has free ports), breaks narrow pools, and degraded WORSE than
the single mutex at high occupancy in the prior analysis. The lock-free bitmap
(already shipped) is strictly better.

### Option D — REJECTED: prior two-tier shard scheme

Shard both `live_by_flow` (5-tuple) and the persistent maps
(`proto,src_ip,src_port`). More correctness surface (two-tier keys, the F5
lock-ordering deadlock) than Option A for no extra hot-path benefit — persistent
NAT is cold. If Phase 2 ships at all, Option A is the right shape.

---

## 5. Concrete design (Option A, for the reviewers to judge)

### 5.1 Data structures

```rust
struct PortAllocatorShared {
    // ... counters / addr_counter_* / occupancy unchanged (lock-free) ...
    flow_shards: Box<[Mutex<FxHashMap<SourceNatFlowKey, LiveAllocation>>]>, // N, pow2
    leases: Mutex<LeaseState>,   // persistent_by_source + lease_expirations(+_by_addr) + gc_counter
    live_flow_count: AtomicUsize,        // global cap accounting
    allocations_total / reuses_total / exhaustion_total: AtomicU64, // unchanged
    max_tracked_flows: usize,
}
```

`N` = fixed power-of-two (default 16, `CachePadded` cells to avoid false sharing);
sized for the flow MAP, independent of the port range (narrow pools unaffected —
the bitmap already handles those).

### 5.2 Hot path (non-persistent new flow)

1. Claim a port on the lock-free `AddressOccupancy` bitmap (UNCHANGED, no lock).
2. `let s = &flow_shards[hash(flow) % N]; let mut m = s.lock();`
3. reuse check: `m.get(&flow)` → if present, drop lock, free the just-claimed
   port, return existing (idempotent re-entry, unchanged).
4. cap: `live_flow_count.fetch_add(1, AcqRel)`; if the pre-value `>= cap`,
   `fetch_sub(1)` rollback, free the port, return `AllocatorExhausted`
   (reserve/rollback — the §3.3 overshoot lives here).
5. `m.insert(flow, LiveAllocation{…})`; `allocations_total += 1`; return.

Only ONE shard lock is held, for one `get` + one `insert`. GC
(`gc_expired_chunked`) stays off this path (takes `leases`, not a flow shard).

### 5.3 Persistent / deterministic / pressure paths

Take `leases` (cold mutex) for the lease decision + claim atomicity, THEN the
flow shard for the `live_by_flow` insert — fixed order `leases → flow_shard`,
so no deadlock on allocate.

**F5 hazard on the release path (found in SMR Attack 5 — must be resolved before
Option A is PLAN-READY).** A naïve release reads the flow-shard record first to
learn whether it has a `persistent_key`, then takes `leases` — i.e. `flow_shard →
leases`, the INVERSE of allocate's `leases → flow_shard`. That is an ABBA
deadlock (the prior plan's F5, resurfacing in the "simpler" Option A). Resolution:
either (i) release takes `leases` UNCONDITIONALLY first (a non-persistent release
takes+noops it) to keep the one global `leases → flow_shard` order, or (ii) the
persistent key is re-derived from the 5-tuple + rule WITHOUT reading the record
(`PersistentSourceKey` = proto/src_ip/src_port/remote is a pure function of the
flow key + permit mode), so release can decide up front and always order `leases
→ flow_shard`. This must be nailed and loom-tested before any Option-A code.

### 5.4 Snapshot / cap / GC

`snapshot` sums shard `len()`s (cold, 1/s). `live_flow_count` is the cap source
of truth. GC unchanged except it locks `leases` instead of `live`.

---

## 6. Hidden invariants (must hold in EITHER option)

1. **No double-allocation.** The occupancy bit CAS is the sole ownership arbiter
   and is UNCHANGED by sharding — a set bit cannot be re-claimed. Sharding the
   flow map cannot cause two flows to share a port because the port is owned by
   the bit, not the map. ✔ preserved.
2. **HA session-sync port portability.** `reserve_flow` (`allocator.rs:1465`)
   sets the bit + inserts `live_by_flow` keyed by the synced flow's 5-tuple, so a
   peer-synced port is reserved in THIS node's allocator and freed by the SAME
   teardown path. Sharding keys `reserve_flow` by the same 5-tuple → reaches the
   right shard trivially. ✔ preserved (Option A). Must be gated by
   `make test-failover`.
3. **Correct release on GC.** `gc_expired_chunked` reclaims idle persistent
   leases; the bit stays SET from lease-removal until the deferred free, so a
   concurrent claim cannot re-hand-out the port in the gap. Sharding moves the
   lease map behind `leases` (Option A) but the bit-as-token discipline is
   unchanged. ✔ preserved.
4. **Exact global cap (F4).** Phase 1 guarantees NO overshoot / no false
   exhaustion. **Option A cannot fully preserve this** (§3.3) — the AtomicUsize
   reserve overshoots by up to M. This is the single hardest invariant and the
   strongest argument for Option B.
5. **Zero-alloc hot path.** Both options keep the hot path allocation-free
   (fixed `Vec<Mutex<…>>`, pre-sized maps). ✔.
6. **Address-persistence unchanged.** `sticky_pool_index` is a pure lock-free
   function, untouched by sharding. ✔.

---

## 7. Risk table (4-class)

| Class | Risk | Option A | Option B |
|-------|------|----------|----------|
| **Correctness** | Exact-cap regression → false exhaustion on small pools (§3.3) | REAL (AtomicUsize overshoot; needs small-pool fallback + concurrency test) | NONE (Phase 1's exact cap kept) |
| **Correctness** | Double-alloc / HA port reuse | LOW (bit-token unchanged; `test-failover` gate) | NONE |
| **Correctness** | Persistent-path lock-ordering deadlock (F5) | REAL in Option A — the release path naïvely inverts to `flow_shard→leases` (§5.3); resolvable (unconditional `leases`-first or re-derive key) + loom test, but must be fixed before PLAN-READY | NONE |
| **Perf** | Win never materializes | HIGH→CERTAIN — architecturally bounded by co-resident publish (c) + replication (d) locks on every new flow (§3.0); unmeasured on top of that | NONE |
| **Perf** | False sharing of shard mutexes | LOW (`CachePadded`) | NONE |
| **Perf** | p99 regression on narrow/low-concurrency pools | MED (microbench showed NEW ~par at M=1–2 narrow) | NONE |
| **Ops/complexity** | Sharding correctness-critical NAT state; larger review surface, ongoing maintenance | MED–HIGH | NONE (net −complexity) |

Option B's risk profile is strictly dominated-favourable: it removes an unproven
optimization from the backlog and preserves every Phase-1 correctness property.

---

## 8. Validation plan

### 8.1 Microbench (exists, merge-gated for Phase 1; extend for Option A)

`userspace-dp/benches/snat_allocator.rs` — add a SHARDED shape alongside CUR/NEW.
Pass criteria for Option A: near-linear scaling of the sharded shape to 6 threads,
no p99 regression vs NEW in any of the four AGY-5 profiles (uniform-low, high-occ
92%, skew 80/20, narrow-64), and **zero false-exhaustion on the narrow pool at
high occupancy** (the §3.3 F4 regression guard).

### 8.2 Loss-cluster SNAT-under-load smoke (the missing gate)

On `loss:xpf-userspace-fw0/fw1` (6 workers, mlx5 VF), with a pool-mode SNAT rule
on the WAN egress path, drive **many concurrent short-lived NEW connections**
(distinct sources × many distinct destinations) — a connection-rate generator,
NOT the bulk-throughput `perf-test` skill. Measure new-flows/sec at allocator
saturation BEFORE vs AFTER via `PortAllocatorSnapshot.allocations_total`
delta/sec + per-core `perf` (is the allocate path single-core-bound?).

**This is the decision gate.** If the cluster cannot drive a new-SNAT-flow rate
where the residual mutex is the dominant limit (before RX-queue / session-install
/ NIC saturates), the correct outcome is Option B (PLAN-KILL), NOT a speculative
rewrite. The generator does not exist today; building it is the follow-up issue.

### 8.3 Regression (Option A only)

Full `cargo test` nat suite (add concurrent no-double-alloc / no-leak /
exact-cap-under-shard / narrow-pool-false-exhaustion tests), a loom test for the
`leases→shard` ordered path, and `make test-failover`.

---

## 9. Phasing

Phase 1 (lock-free claim) + #4676 (chunked GC): DONE, merged. Any Phase 2 is a
single self-contained follow-on (Option A shape). Recommended: do NOT start
Phase 2 until §8.2 justifies it.

---

## 10. Disposition

**Recommend Option B: CLOSE #2852 (substantially resolved by `6cbb10615` +
#4676); PLAN-KILL Phase-2 map-sharding as architecturally-bounded + unproven +
correctness-risking.** Two deliverables accompany the close:

1. **File a narrow follow-up issue** for a connection-rate generator + a
   loss-cluster new-flow-ceiling measurement (§8.2). Phase 2 (correctly scoped as
   "shard ALL per-new-flow cross-worker state — publish + replication + NAT",
   since NAT alone is architecturally insufficient, §3.0) is reopenable there ONLY
   if that measurement shows new-flow scaling is a real, lock-bound target.
2. The Phase-2 design (§5) is preserved on this research branch, reopenable.

Adopt Option A (PLAN-READY the Phase-2-lite shard) ONLY if the reviewers overrule
the kill — in which case BOTH the F4 exact-cap risk (§3.3, §6.4) AND the F5
release-path lock-order inversion (§5.3) must be resolved in the design first, and
it still would not deliver end-to-end new-flow scaling without also addressing the
co-resident publish/replication locks (§3.0).

## 11. Open questions for reviewers

- Q1. Is the merged microbench (isolated, reviewer-acknowledged as an upper
  bound) + the architectural proof that the allocator mutex is the SOLE shared
  lock on the SNAT new-flow path (§2.2) sufficient to call the Phase-2 win
  "proven", or does the never-run cluster measurement remain a hard gate (→ B)?
- Q2. Is trading Phase 1's EXACT global cap (no false exhaustion) for a sharded
  AtomicUsize cap (up-to-M overshoot) an acceptable cost for a NAT pool? (I say
  no → B.)
- Q3. If Phase 2 proceeds, is Option A (shard `live_by_flow` only, leases under a
  separate cold mutex) agreed to be strictly better than the prior two-tier
  scheme (Option D)?
- Q4. Does closing #2852 + a narrow follow-up issue correctly capture the
  residual, or should #2852 stay open as the Phase-2 tracker?
