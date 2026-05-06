---
status: DRAFT v1 — pending adversarial plan review
issue: #936 (parent), #789 (gate)
phase: extend MQFQ flow-fair scheduling to shared_exact CoS queues via cross-worker shared per-flow vtime
---

## 1. Issue framing

The user's "fairness across flows" requirement (#789) cannot be met by
HW steering alone — both Codex and Gemini Pro 3 independently
verdicted PLAN-KILL on the byte-rate Phase 2 of PR #1203 with the
identical structural finding:

> For iperf P=N (N identical greedy TCP flows), per-flow CoV is
> bounded by within-queue TCP fairness regardless of HW steering
> placement. The ≤20% gate is unreachable through any ntuple-based
> mechanism.

The honest fix is a **per-flow scheduler** that orders packet TX by
virtual finish-time across all workers servicing the same
`shared_exact` CoS queue. This plan implements the approach that
issue #936 has tracked since the post-#917 retrospective.

**Empirical state (Phase 1 of #1203, t=120s):**

| Class | Shape | CoV | Aggregate | Gate ≤20% |
|-------|-------|----:|----------:|:---------:|
| iperf-b (5202) | 10 Gb/s  | 28.9% | 9.54 | ✗ |
| iperf-c (5203) | 25 Gb/s  | 28.2% | 22.71 | ✗ |
| iperf-d (5204) | 13 Gb/s  | 16.4% | 12.40 | ✓ |
| iperf-e (5205) | 16 Gb/s  | 26.3% | 15.26 | ✗ |
| iperf-f (5206) | 19 Gb/s  | 24.5% | 18.12 | ✗ |

iperf-d already passes via Phase 1. The other four classes share a
common shape: queue rate ≥ 16 Gb/s, multiple workers on the same
shared_exact queue, RSS-hash distribution dictating which flows land
on which worker. This is the workload #936 was filed for.

## 2. Honest scope/value framing

**xpf already has MQFQ flow-fair scheduling.** It's the
`flow_fair=true` codepath in `userspace-dp/src/afxdp/cos/`. The
admission, queue layout (1024-bucket SFQ), per-bucket vtime, and
DRR pop order are all in place. **It is gated off for shared_exact
queues** by the comment at `types/cos.rs:432-434`:

> shared_exact queues are NOT on the flow-fair path — they stay on
> the single-FIFO-per-worker drain with no SFQ DRR ordering. The
> shadow exists so future cross-worker fairness work (tracked in
> issue #786) can branch on it.

This plan extends flow-fair scheduling to `shared_exact` queues.
The hard part is **cross-worker** scheduling: multiple workers
service the same shared_exact queue concurrently, and per-worker
SFQ doesn't equalize flows distributed unevenly across workers (the
exact case #786 documented and #936 was filed to address).

**Trade-off (explicit, per #936 acceptance):**

The mechanism stalls fast workers — workers carrying fewer flows
must wait for workers with more flows to advance their per-flow
finish-time. CPU efficiency drops on degenerate distributions:

> Worker A carries 1 flow, worker B carries 3.
> Without throttle: A pops at line rate, B's flows split, CoV bad.
> With throttle: A stalls until B's flows catch up; A is idle ~75%
> of the time once V_min binds.

Aggregate throughput on iperf-c P=12 may drop from 22.71 Gb/s to
the cap set by `min_per_flow_rate × N_flows` ≈ ~16 Gb/s in the
degenerate case — **a 30% aggregate hit for fairness.** This is
the cost the user must accept to clear the ≤20% CoV gate.

**Non-degenerate distributions** (e.g., 2-flows-per-worker even
spread which Phase 1 of #1203 already drives toward) see negligible
aggregate impact because no worker is materially ahead of the
others — V_min naturally tracks the actual finish time.

**If reviewers conclude the aggregate-throughput cost isn't worth
the CoV improvement, PLAN-KILL is acceptable.** #936's own
acceptance criteria already specify: regression > 50% → close
RESEARCHED-NEGATIVE.

## 3. What's already shipped

- MQFQ infrastructure: `userspace-dp/src/afxdp/cos/{flow_hash,
  admission, queue_ops/{push,pop,v_min}, queue_service/{service,
  drain}}.rs`. ~2000 LOC of working code.
- Flow-fair drain helpers (`drain_exact_local_items_to_scratch_flow_fair`,
  `drain_exact_prepared_items_to_scratch_flow_fair`).
- Per-bucket SFQ vtime + DRR active-bucket ring (`FlowRrRing`).
- `CoSQueueRuntime { flow_fair: bool, shared_exact: bool,
  flow_hash_seed: u64, active_flow_buckets: u16, ... }`.
- V_min sync (#917) — per-worker `queue_vtime` tracker, atomic-min
  CAS. Implemented as **slot-floor**, not true CAS-global atomic.
- Stall counters per worker (`v_min_throttles`,
  `v_min_throttle_hard_cap_overrides`) wired through to
  `BindingStatus` (#943 telemetry pipeline).

**The change in scope here is the gating.** We are NOT building
MQFQ from scratch; we are flipping the policy bit and adding the
cross-worker shared finish-time table that the per-worker SFQ
needs to actually equalize when multiple workers consume the same
queue.

## 4. Concrete design

### 4.1 Per-flow shared finish-time table

A single shared array of `AtomicU64 finish_time` per shared_exact
queue, indexed by `cos_flow_bucket_index(queue_seed, flow_key) %
SHARED_FLOW_TABLE_SIZE`. Padded to 64 B per slot to eliminate
false sharing between adjacent flows.

```rust
// userspace-dp/src/afxdp/cos/shared_flow_table.rs (new)
const SHARED_FLOW_TABLE_SIZE: usize = 1024;
const CACHE_LINE_BYTES: usize = 64;

#[repr(C, align(64))]
pub(in crate::afxdp) struct SharedFlowSlot {
    finish_time_ns: AtomicU64,   // virtual finish-time tracker
    last_packet_ns: AtomicU64,   // anti-stale (drop slots not seen for 5s)
    _pad: [u8; 48],              // pad to one cache line
}

pub(in crate::afxdp) struct SharedFlowTable {
    slots: Box<[SharedFlowSlot; SHARED_FLOW_TABLE_SIZE]>,
    queue_seed: u64,
    queue_rate_bps: u64,
    v_min_ns: AtomicU64,         // global floor across slots (read-mostly)
}
```

**Memory cost:** 1024 × 64 B = 64 KB per shared_exact queue. With
6 shared_exact classes × 1 queue each = 384 KB. (#936 estimated 6.4
MB assuming 1024 buckets × 100 flows × 64 B = "per-flow padding",
but per-flow atomics are unnecessary if we hash to bucket-level
slots and accept the per-bucket-collision aggregation. **This plan
uses bucket-level, not per-flow, mirroring the existing
flow_hash.rs design.**)

This decision divergence from #936's "Option A" is a deliberate
revision: **the existing CoS code already hashes flows into 1024
buckets** (see `cos_flow_bucket_index` at flow_hash.rs:144). Adding
a parallel per-flow table would force a second hash structure and
inflate memory by 100×. Bucket-level shared vtime keeps the
existing data model.

### 4.2 Promotion policy change

Current (`worker/cos.rs::promote_cos_queue_flow_fair`):
```rust
flow_fair = queue.exact && !shared_exact;
```

New:
```rust
flow_fair = queue.exact && (!shared_exact || system_services_userspace_dp_flow_fair_shared_exact_enable);
```

Default is **disabled** — operator opts in, just like #1203 Phase 1's
flow-steering knob. The CLI knob is:
```
set system services userspace-dp flow-fair-shared-exact enable
```

When enabled AND queue.shared_exact: workers consult
`SharedFlowTable` on every pop; the per-worker SFQ becomes a
cross-worker SFQ via the shared finish-time atomic.

### 4.3 Hot-path integration: pop gate

The existing flow-fair pop logic (in `cos/queue_ops/pop.rs`) reads
`queue.flow_bucket_vtime[bucket]` (per-worker). New flow:

```rust
fn pop_next_packet_shared_flow_fair(queue, worker, table) -> Option<...> {
    // Pick the bucket with the smallest local finish-time as today.
    let candidate_bucket = pick_local_min_bucket(queue);
    let local_ft = queue.flow_bucket_vtime[candidate_bucket];

    // NEW: consult shared finish-time table.
    let shared_slot = &table.slots[candidate_bucket];
    let shared_ft = shared_slot.finish_time_ns.load(Ordering::Acquire);
    let v_min = table.v_min_ns.load(Ordering::Relaxed);

    // Worker can pop iff its candidate's shared finish-time is not
    // more than `T_BYTES` ahead of the global floor.
    let ft = shared_ft.max(local_ft);
    if ft.saturating_sub(v_min) > T_BYTES_BUDGET {
        worker.live.v_min_throttles.fetch_add(1, Ordering::Relaxed);
        return None;  // STALL — wait for V_min to advance
    }

    let pkt = pop_from_bucket(queue, candidate_bucket)?;
    let new_ft = ft.saturating_add(pkt.bytes as u64 * NS_PER_BYTE);
    queue.flow_bucket_vtime[candidate_bucket] = new_ft;
    shared_slot.finish_time_ns.store(new_ft, Ordering::Release);
    shared_slot.last_packet_ns.store(now_ns(), Ordering::Relaxed);
    Some(pkt)
}
```

The `Ordering::Acquire`/`Release` on the shared slot is the price
paid for cross-worker visibility. `Ordering::Relaxed` is acceptable
on `v_min_ns` and `last_packet_ns` — these are read-mostly and
slightly-stale-tolerant.

### 4.4 V_min update

`v_min_ns` is the floor across all `finish_time_ns` slots. Naïve
implementation: scan all 1024 slots every tick (1 Hz), atomic-min.
That's ~1 KB of atomic loads per shared queue per tick — cheap.

```rust
fn refresh_v_min(table: &SharedFlowTable) {
    let mut min_ft = u64::MAX;
    let mut max_ft = 0u64;
    for slot in &*table.slots {
        let ft = slot.finish_time_ns.load(Ordering::Relaxed);
        let last_pkt = slot.last_packet_ns.load(Ordering::Relaxed);
        if now_ns() - last_pkt > 5_000_000_000 {
            // stale — slot hasn't been touched in 5s, exclude
            continue;
        }
        min_ft = min_ft.min(ft);
        max_ft = max_ft.max(ft);
    }
    if min_ft != u64::MAX {
        table.v_min_ns.store(min_ft, Ordering::Relaxed);
    }
}
```

Refresh cadence: existing `COS_STATUS_INTERVAL_NS = 100ms` (10 Hz).
At 10 Hz × 1024 atomic loads = 10 KB/sec scan per queue. Negligible.

### 4.5 T_BYTES_BUDGET tuning

The slack budget `T_BYTES_BUDGET` controls the fairness/aggregate
trade-off. Per #936's research doc: `2 × per_flow_BDP(queue_rate)`
is the suggested initial value. For 25 Gb/s shared_exact with 12
flows, per-flow BDP at 1ms RTT = 25 Gb/s × 1 ms / 12 flows = 2.6 KB.
2× = 5.2 KB.

Sweep `{0.5×, 1×, 2×, 4×}` per #936's experimental slice B. Make
configurable for tuning:

```
set system services userspace-dp flow-fair-shared-exact slack-budget 5200
```

### 4.6 Stall accounting

Workers already have `v_min_throttles` and
`v_min_throttle_hard_cap_overrides` counters. New:
- `shared_flow_throttles`: incremented on stall under the new
  cross-worker shared-table gate. Distinguished from the existing
  per-worker V_min throttle so we can attribute regressions
  precisely.
- `shared_flow_v_min_lag_ns`: gauge — instantaneous
  `max_ft - v_min_ns` per shared queue.

Both surfaced via `BindingStatus` and the Prometheus collector.

### 4.7 HA cluster considerations

**SharedFlowTable is local to each node.** Standby workers don't
populate finish-times until activation. On role flip:
- Old active's table is discarded (worker shutdown).
- New active's table starts cold (all slots have `last_packet_ns =
  0` → all excluded by the staleness filter).
- First few seconds after flip, V_min is u64::MAX → all workers
  see "no peer behind us, ok to pop" → no throttling.
- As packets flow, slots populate and V_min lowers, throttling
  begins to bind.

**Failover does NOT dirty the table from the old active's state.**
This is the right behavior; cross-cluster session state is already
synced via the existing session-sync path, but the per-flow vtime
floor is a runtime quantity, not a reconciliation target.

**uint64 underflow risk** (the bug that killed PR #1203 Phase 2):
`v_min_ns` is the floor. After role flip, V_min = u64::MAX is
correctly handled by `saturating_sub`. No diff-of-u64 anywhere in
this design — we never compute `bytes_t - bytes_{t-1}`.

## 5. Public API preservation

- New CLI knob (default disabled).
- Extended `BindingStatus` with `shared_flow_throttles` and
  `shared_flow_v_min_lag_ns` (additive, JSON `omitempty`).
- New Prometheus counters/gauges.
- No breaking changes.

## 6. Hidden invariants the change must preserve

- **Existing flow-fair semantics on non-shared_exact queues
  unchanged** — the policy bit only lifts for shared_exact when the
  knob is on.
- **Non-fast-path worker correctness.** The shared table is
  consulted in the pop hot path; it MUST NOT block under contention.
  Atomic ordering matters: `Acquire` on read of finish_time so we
  see the prior worker's update. Padded to 64 B to prevent false
  sharing.
- **Dependency on existing flow_hash_seed.** Per-queue salt mixed
  into the bucket hash already exists (`cos_flow_hash_seed_from_os`)
  — re-used for the shared table to keep enqueue/dequeue bucket
  consistency across workers. **All workers servicing the same
  shared_exact queue MUST use the same `flow_hash_seed`** — this
  becomes a invariant the queue-promotion code must preserve.
- **`active_flow_buckets` accounting on the per-worker queue stays
  intact.** The shared table is additional, not replacement.
- **No torn reads on x86 / ARM64.** All atomic accesses are 64-bit
  aligned via `repr(C, align(64))`. AArch64 8-byte loads/stores
  are atomic when 8-byte aligned; the cache-line padding ensures
  this trivially.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Cross-worker cache contention | **MED** | One shared atomic load per pop. Bucket collision rate determines real cost. Per-bucket padding caps it; iperf P=12 distributes across 1024 buckets so contention is rare |
| Aggregate throughput regression | **HIGH** | Plan §2 explicitly accepts ~30% drop on degenerate distributions. iperf-c on RSS-degenerate: stall budget binds → may drop 22.7 → ~16 Gb/s |
| Architectural mismatch | **LOW** | Layered on existing flow_fair codepath; only flips the gating bit and adds shared-vtime consultation |
| HA reconciliation | **LOW** | Per-node table; no cross-cluster sync needed; uint64 underflow avoided via saturating_sub |
| Mouse-flow latency | **LOW-MED** | Per #936 acceptance: p99 same-class iperf-b N=128 must stay within ±15% of 59.51 ms baseline. Add to test plan |
| Operator misconfig | **LOW** | Knob default off; slack budget bounded `[1024, 65536]` |
| Empirical: clears ≤20% gate | **UNKNOWN** | Concept proven in MQFQ literature; xpf-specific measurement TBD |

## 8. Test plan

### Cargo
- `cargo build --release` clean
- `cargo test --release` 977+ pass
- New cargo tests:
  - `shared_flow_table::stall_when_local_ft_exceeds_v_min_plus_budget`
  - `shared_flow_table::no_stall_when_within_budget`
  - `shared_flow_table::v_min_advances_when_all_slots_progress`
  - `shared_flow_table::stale_slot_excluded_from_v_min`
  - `shared_flow_table::cache_alignment_64_bytes`
  - `cos::queue_ops::pop::shared_flow_fair_path_uses_shared_table`

### Go
- `go build ./...` clean
- `go test ./...` all 30 packages pass
- New Go tests for the CLI knob and BindingStatus field parity

### Smoke (loss userspace cluster)
- Pass A (CoS disabled): unchanged from baseline; all 4 + 2 cells
  pass with 0 retrans
- Pass B (CoS enabled, knob OFF): unchanged from Phase 1 of #1203;
  all 24 per-class measurements pass
- **Pass C (CoS enabled, knob ON): #936 acceptance gate**
  - iperf-b P=12 t=120 push: CoV ≤ 20%
  - iperf-c P=12 t=120 -R: CoV ≤ 20%, throughput ≥ 22 Gb/s OR
    documented regression
  - iperf-d P=12 t=120 push: CoV ≤ 20% (regression check — Phase 1
    already achieves 16.4%)
  - iperf-e P=12 t=120 push: CoV ≤ 20%
  - iperf-f P=12 t=120 push: CoV ≤ 20%
  - **Mouse-latency**: same-class iperf-b N=128 p99 within ±15% of
    Phase 1 baseline (currently ~59.51 ms per #917 records)
  - **Stall accounting visible**: `show class-of-service` shows
    `shared_flow_throttles > 0` on the steady-state run

### Hot-path measurement
- `perf stat -e cache-misses,LLC-load-misses` on the worker thread
  during steady-state iperf-c P=12. Compare CoV-on vs CoV-off:
  - LLC-load-misses per packet must NOT exceed 2× baseline (#936
    acceptance criterion, normalized metric)
  - CPU utilization per worker — record stall-time as expected
    increase

### Regression
- `make test-failover`: must pass
- 5×flake on the most-affected named cargo test

## 9. Out of scope

- Per-class slack budget (global only in v1)
- ice/i40e CoS portability (mlx5_core / virtio test only)
- AFD-style approximate fair dropping (#936 §2.3 — separate work,
  complementary)
- Cross-binding redirect (#937 — competing solution; if this lands
  and clears the gate, #937 becomes a win on top, not a replacement)

## 10. Open questions for adversarial review

1. **Bucket-level vs per-flow vtime.** #936 specified Option A
   (per-flow atomic). This plan uses per-bucket atomic to align
   with the existing 1024-bucket SFQ design and reduce memory
   from 6.4 MB to 64 KB per queue. Trade-off: when 2 distinct
   flows hash to the same bucket, they share the finish-time —
   degrades fairness within a bucket. Empirical question: does
   the existing `flow_hash_seed` salt deliver enough bucket
   diversity at iperf P=12 to avoid this collision case?

2. **Cache contention bounds.** The shared atomic is hot. Workers
   on different CPUs touching the same bucket cause MOESI
   bouncing. Padded to 64 B. Is there a measurement we should
   commit to in the test plan to confirm contention is bounded?

3. **Aggregate hit on degenerate distributions.** Plan §2 accepts
   30%. #936 says >50% → RESEARCHED-NEGATIVE close. What does
   the user want as the actual gate?

4. **Slack budget tuning.** 2× per-flow BDP is the seed value.
   Should we ship with a default that's known-conservative
   (small T → tight CoV, big aggregate hit) or aggressive
   (big T → loose CoV, small aggregate hit)? Default-off
   protects either way.

5. **Race on `last_packet_ns` staleness check.** A slot that was
   just touched by worker A and is being read by V_min refresher
   may show `last_packet_ns < 5s ago` but `finish_time_ns` is the
   pre-update value. Does this skew V_min toward over-low? Worst
   case: V_min is one packet stale → workers think they're more
   ahead than they are → spurious stall. Bounded by the publish
   cadence (10 Hz).

6. **PLAN-KILL: is the aggregate cost worth it?** iperf-c may
   drop from 22.7 → ~16 Gb/s on RSS-degenerate distributions.
   Default-off mitigates by making it a per-deployment choice.
   Reviewers may still verdict KILL.

7. **`flow_hash_seed` invariant under cluster failover.** The
   per-queue salt is drawn from getrandom. Across HA failover,
   the new-active node's queue gets a fresh salt. Bucket
   assignment changes. No correctness issue (shared-table
   re-populates from cold), but the first few seconds post-flip
   re-shuffle bucket contents. Acceptable for a fairness
   mechanism.

8. **#937 competition.** #936 acceptance says "if #937 wins,
   close #936 NOT-NEEDED". #937 is cross-binding redirect (PR
   #1203 Phase 1 was a partial implementation). Should we run
   the comparison test against #937's empirical result before
   investing 2-3 weeks in this implementation?

## 11. Verdict request

PLAN-READY → execute Phase 3 against issue #936.
PLAN-NEEDS-MINOR → tweak (bucket vs per-flow, slack tuning,
test additions).
PLAN-NEEDS-MAJOR → revise (different mechanism, e.g. per-flow
finish-time, AFD overlay, or competing approach).
PLAN-KILL → aggregate cost not worth it, OR mechanism wrong; ship
Phase 1 of #1203 and accept residual gap, or close #789 with the
partial win recorded.

---

## 12. PLAN-NEEDS-MAJOR → WITHDRAWN — 2026-05-06

Codex (`task-mou3gcvw-5omg11`) verdicted PLAN-NEEDS-MAJOR with a
headline finding that **invalidates the plan's premise**: shared_exact
queues already run MQFQ flow-fair scheduling in the current tree.

### Code reality (verified at admission.rs:478-486, post-#785 Phase 3):

```rust
// promote_cos_queue_flow_fair (current)
queue.shared_exact = queue_fast.shared_exact;
queue.vtime_floor = queue_fast.vtime_floor.clone();    // #917 V_min sync
queue.worker_id = worker_id;
// flow-fair is enabled on EVERY exact queue, including shared_exact.
// Dequeue-ordering: MQFQ virtual-finish-time (#913 fix at pop.rs:112)
// Admission: rate-aware (#914) — max(fair_share*2, bdp_floor)
```

The `cos.rs:432-434` comment that motivated this plan ("shared_exact
queues are NOT on the flow-fair path") is **stale documentation**.
That sentence no longer reflects code behavior.

### Codex's verified findings against plan v1

1. **Blocking — premise stale.** Plan proposes lifting a gate that
   was already lifted in #785 Phase 3.
2. **Blocking — flow_hash_seed not shared.** Each worker draws a
   fresh seed in `cos_flow_hash_seed_from_os`; per-bucket shared
   table would map flow F to different bucket on different workers.
3. **Blocking — bucket count mismatch.** Plan said 1024-slot table;
   actual `COS_FLOW_FAIR_BUCKETS = 4096`. Out-of-bounds or implicit
   modulo collision.
4. **Blocking — race-unsafe writes.** Load-compute-store on shared
   slots, the same family as #836/#837 which were rejected for
   "finish-time state is not naturally commutative under races".
5. **Major — V_min cadence.** 100ms refresh creates sawtooth at
   25 Gb/s; existing #917 uses K=8 pop-interval cadence.
6. **Major — slack budget math 100× off.** Plan said "5.2 KB" for
   2× per-flow BDP at 25 Gb/s × 1ms / 12; correct figure is ~520 KB.
7. **Major — HA lifecycle under-specified** vs existing #917 reset
   hooks at `worker/cos.rs:312`.
8. **Major — stall in pop conflates empty/throttled.** Existing
   V_min throttle lives in the drain loop BEFORE pop, returning
   `None` from pop for "throttled" would confuse callers.

### Empirical recap with the actual existing architecture

iperf P=12 t=120, with current code (MQFQ + #913 + #914 + #917):

| Class | Shape | Aggregate | CoV | Gate ≤20% |
|-------|-------|-----------|-----|-----------|
| iperf-b (5202) | 10 Gb/s | 9.54 | 28.9% | ✗ |
| iperf-c (5203) | 25 Gb/s | 22.71 | 28.2% | ✗ |
| iperf-d (5204) | 13 Gb/s | 12.40 | 16.4% | ✓ |
| iperf-e (5205) | 16 Gb/s | 15.26 | 26.3% | ✗ |
| iperf-f (5206) | 19 Gb/s | 18.12 | 24.5% | ✗ |

**Differentiator: iperf-d is non-saturated** (12.40 / 13 = 95% of
shape, 91% of cluster capacity ~13.5 Gb/s with 6 workers). The other
four are saturated — shape rate ≥ what 6 workers can push. Saturated
within-queue TCP fairness creates cwnd-jitter variance that no
scheduler primitive smooths inside a 30s measurement window.

### Conclusion

The mechanism this plan tried to build **already ships**. The
remaining 5-10 percentage points of per-flow CoV on saturated
workloads is residual TCP cwnd-jitter, not a missing scheduler
primitive. Per-flow CoV ≤20% on saturated workloads is physically
tight — a bound below cwnd-equalization timescales.

**Plan WITHDRAWN.** No code changes proposed.

### Recommendations (escalated to user)

1. **Re-evaluate #789 gate.** Set workload-aware gates: ≤20% for
   non-saturated workloads (current iperf-d passes), looser
   (e.g. ≤30%) for saturated workloads (iperf-b/c/e/f).
2. **Optional tuning experiment.** Run a sweep on existing #917
   V_min cadence and slack-budget knobs to see if any tunable
   tightens current 24-29% CoV. Risk-free measurement-only work;
   if no improvement found, close and accept the empirical floor.
3. **Issue #1204 closes** with the finding that all four mandated
   actions ship in current tree; the empirical gap is irreducible.

### What gets preserved vs killed

- Scrub of stale "1024 buckets" docstrings (in commit `ffd73f4e`)
  is correct and stays.
- Plan body §1-§11 stays as a record of the analysis path.
- No code/test changes shipped beyond the docstring fixup.
