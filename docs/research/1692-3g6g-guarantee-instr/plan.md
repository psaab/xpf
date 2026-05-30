# #1692 — Path A: instrument-first isolation of the 3g/6g guarantee-rate under-protection (§3.B)

Revision: v2 (Codex r1 + Claude-SMR r1 folded)
Branch: research/1692-3g6g-guarantee-instr
Base: origin/master @ ea0a670bd (#1628 counters live; #1643 fence live)
Status: PLAN-READY candidate — INSTRUMENT-FIRST measurement design, NOT a
fix. Explicit PLAN-KILL exit if the disambiguating data shows ~52% is
structurally inherent.

> v2 CHANGE LOG: Codex r1 + Claude-SMR r1 both PLAN-NEEDS-MAJOR with a
> shared CRITICAL: §4 v1's `Σ share_i vs class_rate` discriminator is
> mathematically CONSTANT (`Σ my_share_i = cap` by construction —
> `total_flows = Σ my_count`, so the per-worker shares sum to the full cap
> every epoch regardless of distribution; `rotate_epoch_v8.rs:306-312`).
> That column could never be `< class_rate`, so v1 could not separate
> L1-by-design from L1-fixable, and §8 KILL-exit #1 was unreachable.
> v2 DELETES that column and rebuilds §4 around `granted_i vs share_i` +
> per-worker BACKLOG (`queued_bytes_i`) + per-worker DEMAND. Other folded
> findings: (Codex F4 / SMR F5) L2 root-FCFS is DEAD not provisional —
> aggregate `park_root=0` over a monotonic saturating-add sum proves every
> per-worker term is 0; (Codex F2 / SMR F3) `share_i` is a 200µs epoch
> gauge, must be windowed-integrated, bank depth is sub-noise; (Codex F3 /
> SMR F4) the `my_share` read must use the seqlock pattern
> (`mod.rs:1561`), NOT a bare Relaxed load; (SMR F2) v1's table was blind
> to per-worker DEMAND and aliased a gated worker with a cwnd-starved one
> — the #1630 cause-2 transport-physics floor, a FOURTH (PLAN-KILL)
> outcome now added as decision precedence-0.

> This is a `/research` deliverable. It STOPS at PLAN-READY/PLAN-KILL. No
> production source is modified by `/research`. The instrumentation
> described here is the FIRST `/engineer` deliverable (a throwaway,
> diagnostic-only counter set), gated behind this plan's review.

---

## 0. Scope and the standing PLAN-KILL hazard

This is Path A of the #1614 research (`docs/research/1614-simul-load-diagnosis/plan.md`
v3 @ `e672bb821`, §3.B + §4). The #1614 research converged 3-of-3
PLAN-READY with §3.B reframed as a **CONFIRMED defect SIGNAL with an
UNRESOLVED mechanism**. Three mechanisms were already eliminated:

1. **single-owner per-class CPU funnel** — REFUTED: 18g pushed 14.25 G
   from ONE owner worker (q8/worker 2), `park_root=0`. One worker is not
   the ~4 G limiter.
2. **per-worker `quantum_sum` miscompute** — code-FALSIFIED by Codex r1:
   `quantum_sum` (`queue_service/mod.rs:794-797`) is summed over
   `root.exact_queues_by_rate_ascending`, the GLOBAL ascending vector
   built over ALL configured exact queues at config-apply
   (`builders.rs:80-83`), with no owner/eligible filter. With small4+24g
   quanta, 100m+1g+3g+6g fit well inside `0.7 × quantum_sum`.
3. **Phase-2 epoch lock-in** — telemetry-REFUTED: interface
   `waterfill_epochs` climbed 7.68M → 9.41M (~52K/s) DURING the run, and
   `phase1_admit` is the DOMINANT path for every class (incl 24g at 84%).
   A wedged-Phase-2 worker would show flat epochs + ~0 phase1_admit.

**This space is the most PLAN-KILL-prone in the repo.** The
#1211/#1236/#1237/#1239/#936/#937 lineage all PLAN-KILLED, and the #1220
CoV finding showed an apparent "47% unfairness" was actually BELOW the
structural ceiling — no bug. The #1630 chain falsified FOUR derived
mechanisms before landing on transport physics. PLAN-KILL is a fully
expected and valid outcome of this research. The deliverable here is a
**measurement design that decides between three remaining candidate
gating layers**, NOT a fix and NOT a mechanism assertion.

## 1. The defect SIGNAL being isolated (verbatim from #1614 §3.B)

Decisive scenario: `small4 + 24g` push, `-P 12`, `guarantee-rate 0.7`,
`shaping-rate 25g`, all classes backlogged:

| class | shape G | recv G | %shape | phase2_admit% | park_root |
|------|--------:|-------:|-------:|--------------:|----------:|
| 100m | 0.1 | 0.094 | 94 | 0.0 | 0 |
| 1g | 1 | 0.94 | 94 | 0.2 | 0 |
| 3g | 3 | 1.62 | **54** | 0.1 | 0 |
| 6g | 6 | 3.06 | **51** | 0.2 | 0 |
| 24g | 24 | 12.6 | 52 | 16.0 | 0 |
| SUM | | 18.2 | | | |

The scenario achieved 18.2 G aggregate — there was ~6 G of headroom under
the ~24 G push ceiling (§3.A) left UNUSED while 3g/6g sat at ~52%,
exactly tracking the unguaranteed priority-low 24g. The small4 sum-shape
(10.1 G) fits comfortably under 18.2 G, so a working `guarantee-rate`
small-first contract SHOULD have lifted 3g/6g to ~95% (like 100m/1g) at
the cost of 24g. It did not. `park_root=0` rules out the root token
bucket. `phase2_admit ≤ 0.2%` for 3g/6g rules out simple Phase-2
relegation: 3g/6g ARE admitted via the guaranteed Phase-1 path, yet under-
delivered. **That is the surprise this instrumentation must explain.**

## 2. The three candidate gating layers (code-walked this research)

The decisive architectural fact the #1614 §2.2 "owner worker" table
OBSCURED: the shared-exact threshold. From `worker/cos/mod.rs:31,168`:

```rust
COS_SHARED_EXACT_MIN_RATE_BYTES = 2_500_000_000 / 8  // 2.5 Gbps
fn queue_uses_shared_exact_service(...) -> bool {
    queue.transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES
}
```

- **100m, 1g** (< 2.5 G): SINGLE-OWNER. One worker drains the whole
  class, one FIFO arbitration domain. These are the two classes that
  ARE protected (94%).
- **3g, 6g, 9g…24g** (≥ 2.5 G): SHARED-EXACT, **sharded across ALL 6
  workers** (`cross_binding.rs:69` Step1 bail when
  `shared_exact && tx_owner_live.is_some()` → each worker drains its OWN
  RSS-placed flows locally). Each worker's per-class token bucket
  (`queue.hot.tokens`) is gated by the **v8 per-worker fair-share
  lease**.

So #1614 §2.2's "queue X owned by worker Y" is true only for 100m/1g.
For 3g/6g/24g the queue runs on every worker that has a flow for it.
**The defect is in the under-protected SHARED-EXACT tier — the exact tier
the v8 lease governs.** That single fact reorganizes the candidate set.

The under-delivery of a shared-exact class is gated by exactly one of
three serial layers a frame must clear to ship (each frame: queue
selected by the per-worker waterfill selector → token granted by v8
lease → token granted by root pool):

### Layer L1 — v8 per-worker fair-share lease (`acquire_v8`)

`types/shared_cos_lease/mod.rs:1152` + `rotate_epoch_v8.rs:308`. Each
200µs epoch the rotation winner computes, per worker `i`:

```
cap     = class_rate × elapsed_epoch         // the class's full rate
my_share[i] = cap × active_flow_buckets[i] / Σ_j active_flow_buckets[j]
```

`acquire_v8`'s PRIMARY path hard-caps worker `i`'s grant at `my_share[i]`.
The SURPLUS path (`surplus_open = bypass && !equal_flow_enforced`,
`mod.rs:1320`) opens ONLY when the rotation armed `bypass_grace`
(`rotate_epoch_v8.rs:188`: `any_active_worker_signaled &&
aggregate_underuse && any_peer_cpu_bound_under_util`). For
**shaper-bound** (not CPU-bound) 3g/6g traffic, the `any_peer_cpu_bound_
under_util` gate (`5 × prev_grant < 3 × share`, util < 60%) is the most
likely NON-firing condition: shaper-bound peers consume ~90% of share.
**Candidate failure mode:** with 3g flows on a SUBSET of the 6 workers
(RSS multinomial leaves some idle), the per-worker `my_share` divides the
3g rate by `Σ active_flow_buckets`, but if a worker's local
backlog/demand exceeds `my_share` while OTHER workers with the same class
are idle (no flows → 0 share, not "spare"), the busy worker is capped at
its proportional slice and surplus never opens → the class delivers
`Σ_i min(demand_i, my_share_i) < class_rate`. This is the
"strict per-flow fairness leaves headroom idle" trade the #1304/Cstruct
work intentionally chose — and it would mean §3.B is BY DESIGN, a
PLAN-KILL.

### Layer L2 — root FCFS pool ordering (root token bucket / `SharedCoSRootLease`) — CONFIRMED DEAD

`token_bucket.rs:54` `maybe_top_up_cos_root_lease` + the per-worker
`select_*` walk consuming `root.tokens` (`queue_service/mod.rs:856`,
`:1034`). The root pool is the 25 G shaping rate, shared across all
classes on the interface. **`park_root = 0` everywhere** (#1614 §2.1 +
§2.4).

v1 kept L2 alive "on the narrow chance the aggregate masks a per-worker
imbalance." **Codex r1 + Claude-SMR r1 both REFUTED that** and they are
correct: `drain_park_root_tokens` is a monotonic non-negative counter
bumped per-(queue,worker) at `queue_service/mod.rs:856-861`, then folded
to the per-class number by SATURATING-ADD (`worker/cos/queue_row.rs:228`,
`coordinator/mod.rs:1039`). A saturating-add sum of non-negative terms is
zero IFF every term is zero. So aggregate `park_root=0` already PROVES no
worker hit root starvation — the SUM cannot hide a per-worker imbalance
because there is nothing to hide. **L2 is dead, not provisional.** The
instrument emits the per-worker `park_root_i` for completeness only; it is
a confirmation column, not a live discriminator. This tightens the live
candidate set to: the demand-bound null (precedence-0), L3 (per-worker
budget), and L1 (v8 share-cap).

### Layer L3 — per-worker waterfill Phase-1 budget (selector)

`queue_service/mod.rs:777` `select_exact_cos_guarantee_queue_waterfill`.
Each worker runs its OWN waterfill epoch over its OWN `CoSInterfaceRuntime`.
Phase-1 budget = `(quantum_sum × 0.7).floor()` (`:804`), consumed
ascending by `phase1_cost = min(tokens, quantum) ≥ head_len` (`:911`).
Codex r1 falsified the v2 "owner-local-eligible quantum_sum" theory —
`quantum_sum` is global. BUT the selector's CONSUMPTION walk (`:817-959`)
SKIPS empty/non-runnable queues, and `phase1_cost` is bounded by the
queue's CURRENT `hot.tokens` — which L1 (the v8 lease) just gated. So L3
and L1 are COUPLED: if L1 starves a worker's 3g `hot.tokens`, L3 sees
`phase1_cost = head_len` (one frame) and the budget is spent elsewhere.
**Candidate failure mode:** the per-worker Phase-1 budget split, computed
from a GLOBAL `quantum_sum` but consumed against L1-gated tokens, causes
each worker to honor 3g for only one frame per epoch before its budget
moves to a larger ascending queue — i.e. a budget-accounting fault that
is distinct from L1's share cap.

### Why these three produce DISTINCT signatures — the consumer success criterion

**The instrumentation PASSES its consumer test iff it produces a counter
signature that uniquely identifies L1, L2, or L3 (or proves the ~52% is
inherent → PLAN-KILL).** A counter set that is internally clean but
cannot separate the three is a STRUCTURAL FAILURE of this plan (per
`feedback_review_scaffolding_against_consumer`). The discriminating
question for each layer, expressed in counters, is in §5. Worked
distinct-signature table in §4.

## 3. Why the live #1628 + production counters CANNOT disambiguate (the gap)

Verified this research against master @ ea0a670bd:

1. **Per-class waterfill counters are SUMMED across workers.**
   `coordinator/mod.rs:1048-1053`: `q.waterfill_phase1_admissions +=
   queue.waterfill_phase1_admissions` folds all 6 workers' counts into
   one per-class number. For a shared-exact class on 6 workers, the live
   `phase1_admit%` cannot show whether worker 4's 6g shard is starved
   while worker 1's 6g shard is fine. (Confirms Codex r1 finding 3 over
   AGY r1 §5: AGY's "each queue is single-owner so per-class IS
   per-owner" is FALSE for the ≥2.5G shared-exact tier — that tier is the
   one under-protected.)

2. **`cos_queue_lease_acquire_v8_granted_bytes` is per-WORKER but NOT
   per-class.** `coordinator/status.rs:382-383` reads a per-worker scalar
   (`s.cos_queue_lease_acquire_v8_granted_bytes`) that
   `worker/mod.rs:1031-1036` summed across ALL v8 queues that worker
   services. Worker 4 owns BOTH 6g and 24g shards (#1614 §2.2). Its v8
   grant total mixes the two. We cannot read "how many bytes did the v8
   lease grant worker 4 FOR 6g this window" — exactly the L1 question.

3. **`drain_park_root_tokens` / `drain_park_queue_tokens` are per-queue
   but folded to per-class** via `merge_cos_queue_owner_profile_sum`
   (`worker/cos/mod.rs:481-486`). For L2 (root) the aggregate `park_root=0`
   is conclusive (monotonic-sum, §2-L2); for L3 (queue-token) the
   per-worker `park_queue_i` split is still informative.

4. **`drain_sent_bytes` is per-queue, summed across workers.** We have
   the class total but not the per-worker split, so we cannot compute
   per-worker `delivered_i` vs `share_integral_i` (the L1 deciding ratio).

5. **No per-worker BACKLOG (DEMAND) signal is exported at all.**
   `queue.hot.queued_bytes` is worker-local and never surfaced
   per-(class,worker). Without it, an under-delivering worker that is
   simply cwnd/generator-bound (the #1630 cause-2 transport floor) is
   indistinguishable from one the lease or selector is gating (SMR r1 F2).
   This is the SINGLE most important new column — it is the precedence-0
   demand-bound discriminator (§4 outcome 0).

The gap is uniform: **everything is per-class-summed; nothing is
per-(class, worker), and DEMAND is invisible entirely.** The shared-exact
tier needs per-(class, worker) visibility — including backlog — to decide
which of {demand-bound, L1, L3} explains a specific worker's 3g/6g shard.
That is the single instrumentation deliverable.

## 4. Worked distinct-signature table (the disambiguation proof) — REBUILT v2

The v1 table is discarded: its `Sum share_i vs class_rate` discriminator
was a CONSTANT (`Sum my_share_i = cap` always — see v2 CHANGE LOG), and it
had no DEMAND column, so it aliased a gated worker with a cwnd-starved
one. v2 rebuilds around columns that are actually independent.

**All comparisons are over the WINDOWED steady-state (bytes / 30 s), NOT
instantaneous** (Codex r1 F2 / SMR F3): `share_i` is recomputed every
200us epoch (`rotate_epoch_v8.rs:293`), so the instrument accumulates a
per-worker `share_integral_i` = the lease's TOTAL grant CEILING the worker
was entitled to over the window, in bytes (sum over epochs of
my_share x epoch_elapsed). The N-frame token bank
(`COS_EXACT_QUEUE_LEASE_BANK_BYTES`, N=8 ~= 12 KB, `token_bucket.rs:196`)
lets `granted` and `delivered` diverge by <= bank-depth instantaneously,
which is sub-noise against a 3 G x 30 s window — stated explicitly so it
is not re-flagged.

Per-(class,worker) columns (defined in section 5), for each worker `i`
with >=1 active flow of the class, over the 30 s window:
- `backlog_i` — per-worker class backlog presence
  (`queue.hot.queued_bytes` > 0 for a sustained fraction of the window).
  The DEMAND proxy: a worker with persistent backlog has offered load it
  could not ship; a worker with ~0 backlog is demand-bound
  (cwnd/generator-limited), not gated.
- `granted_i` — per-(class,worker) v8 `acquire_v8` granted bytes (NEW).
- `share_integral_i` — windowed lease entitlement ceiling (NEW).
- `delivered_i` — per-(class,worker) `drain_sent_bytes`.
- `p1_admit_i`, `p2_admit_i`, `eligible_visits_i` — per-(class,worker)
  waterfill admits/visits (split out of the existing SUM-fold).
- `park_root_i` — confirmation only (L2 dead, section 2-L2).
- `bypass_arms` — v8 `bypass_grace_arm_count` (per-lease, already exists).

| Outcome | `backlog_i` (busy workers) | `granted_i` vs `share_integral_i` | `delivered_i` vs `granted_i` | `p1_admit_i` vs `eligible_visits_i` | `park_root_i` |
|---|---|---|---|---|---|
| **(0) DEMAND-BOUND null -> PLAN-KILL** | **~0 on the under-delivering workers** (no backlog; #1630 cause-2 transport floor) | `granted_i < share_integral_i` (lease WILLING, worker did not ask) | `delivered_i ~= granted_i` | `p1_admit_i ~= eligible_visits_i` (visits + admits, but queue empties) | 0 |
| **(L1) v8 share-cap** | **> 0 sustained** on workers whose `delivered_i ~= share_integral_i` (capped WITH backlog) AND >=1 OTHER worker has `granted_i < share_integral_i` (idle slice the capped worker cannot borrow) | `granted_i ~= share_integral_i` on busy workers (lease grants exactly the ceiling, my_room->0) | `delivered_i ~= granted_i` | `p1_admit_i ~= eligible_visits_i` | 0 |
| **(L3) Phase-1 budget fault** | **> 0 sustained** | `granted_i < share_integral_i` (lease willing, selector under-requests) | `delivered_i ~= granted_i` | **`p1_admit_i << eligible_visits_i`** — selector VISITS 3g every epoch but Phase-1 budget exhausts before honoring it past <=1 frame | 0 |

The three live outcomes are DISTINCT on independent columns:
- **`backlog_i ~= 0`** uniquely fingerprints outcome (0): no other outcome
  leaves the under-delivering busy workers with empty queues.
- **`p1_admit_i << eligible_visits_i`** uniquely fingerprints (L3): the
  selector visits but does not honor (budget fault). (0) and (L1) both
  admit on every visit.
- **`granted_i ~= share_integral_i` WITH backlog AND a peer with
  `granted_i < share_integral_i`** uniquely fingerprints (L1): the lease
  is binding and there is idle peer slice the capped worker cannot reach
  (surplus bypass-gated, shaper-bound -> `bypass_arms ~= 0`).

Decision rule (consumer criterion, ordered so a multi-signal read is still
decidable from ONE scrape):
1. If the under-delivering busy workers have `backlog_i ~= 0` ->
   **DEMAND-BOUND** -> not a CoS defect -> **PLAN-KILL** (#1630 cause-2 /
   #1220). Confirm with `p1_admit_i ~= eligible_visits_i`.
2. Else if `p1_admit_i << eligible_visits_i` on a backlogged worker ->
   **L3** Phase-1 budget fault. FIXABLE (re-derive the Phase-1 boundary
   from configured guarantee RATES rather than `quantum x fraction` —
   #1614 Path A candidate 4).
3. Else (`granted_i ~= share_integral_i` WITH backlog, some peer under its
   ceiling, `bypass_arms ~= 0`) -> **L1** v8 share-cap. Sub-decide:
   - if the desired behavior is "let the backlogged worker borrow the idle
     peer's slice" — that is a non-work-conserving -> work-conserving
     policy change (the surplus path), a SEPARATE design issue (#1211
     warns this space is hard) -> **PLAN-KILL #1692**, file the policy
     issue;
   - the strict-per-flow-fairness floor is the #1304/Cstruct/#1220
     precedent and is BY-DESIGN -> PLAN-KILL.

`park_root_i` is a sanity confirmation that L2 is dead (must be 0;
non-zero would mean the section 2-L2 monotonic-sum argument is wrong and
the model is incomplete — a #1630-style "add a candidate" finding, not a
fix).

## 5. Instrumentation design — Multiple Path Options

All options are **diagnostic-only, throwaway** counters added in the
`/engineer` round, never in `/research`. None feed the scheduler. Each is
independently invitable to PLAN-KILL. The shared requirement: produce
per-**(class, worker)** rows for the shared-exact tier, exported through
the existing status snapshot → Prometheus path so the harness can scrape
them in the same window as iperf3.

### Option A (RECOMMENDED) — extend the existing per-queue waterfill counters to carry a per-worker dimension via the existing per-(class,worker) snapshot key

The status path ALREADY emits `cos_active_flow_count{ifindex, queue_id,
worker_id}` (`coordinator/status.rs:195` keys on
`(ifindex, queue_id, worker_id)`). Option A adds, to that SAME
per-(ifindex,queue_id,worker_id) row, four fields the worker already
holds locally on its `CoSQueueRuntime`/`CoSInterfaceRuntime`:

1. `phase1_admissions_i`, `phase2_admissions_i`, `eligible_visits_i` —
   already exist per-queue on `queue.telemetry.waterfill_counters`
   (`queue_service/mod.rs:851,948,1058`); Option A stops the coordinator
   SUM-fold (`coordinator/mod.rs:1048-1053`) for the shared-exact tier
   and keys them by worker instead. Net new code: emit per-worker, not
   sum.
2. `drain_sent_bytes_i` — already per-queue on the owner profile; key by
   worker (stop the `merge_cos_queue_owner_profile_sum` fold for this
   tier).
3. `v8_granted_bytes_i_per_class` — NEW: the only genuinely new counter.
   `acquire_via_lease` (`token_bucket.rs:101`) already returns the grant
   per call; today it accumulates into the per-WORKER (all-class) scalar.
   Option A also accumulates it into a per-(queue,worker) field on the
   `CoSQueueLeaseAcquireTelemetry` → `queue.telemetry`. ~1 u64 add per
   top-up, no new atomics on `acquire_v8` (the worker-local accumulator
   pattern from `token_bucket.rs:27-35` is preserved).
4. `share_integral_i` — NEW: the windowed lease entitlement ceiling.
   `worker_fair_share[worker_id]` is recomputed every 200µs epoch
   (`rotate_epoch_v8.rs:293,308`), so a single end-of-window gauge read is
   NOT comparable to 30 s `granted`/`delivered` deltas (Codex r1 F2 / SMR
   F3). The instrument instead accumulates, on the OWNING worker (the only
   writer of `queue.hot.tokens`/`telemetry`), `share_integral_i +=
   my_share` each epoch its lease rotates — yielding the total bytes the
   worker was ENTITLED to over the window. The per-epoch `my_share` read
   must use the existing seqlock snapshot path (`snapshot_epoch_v8`,
   `mod.rs:1561`), NOT a bare Relaxed load (Codex r1 F3 / SMR F4): the
   worker already calls `acquire_v8` → `snapshot_epoch_v8` on the hot path,
   so the integral can piggyback that snapshot's `share` field at zero
   extra synchronization cost — no new seqlock read is introduced. All new
   per-(queue,worker) counters are single-writer (owning worker) /
   single-reader (status path) → Relaxed accumulator + the status path's
   existing ArcSwap publish boundary suffices; no new atomic on
   `acquire_v8`.

- **Pros:** reuses the per-(class,worker) snapshot key that already
  works for `cos_active_flow_count`; minimal new hot-path code (one u64
  add); the `backlog` + `share_integral` + `granted` + `delivered` set is
  exactly the §4 decision columns; `bypass_arms` already exists per-lease.
- **Cons:** widens the per-queue status row by 6 u64 × workers; must not
  break the existing SUM-fold for the single-owner tier (100m/1g) that
  operators already read. Mitigation: keep the per-class SUM AND add the
  per-worker breakdown as a sibling repeated field, gated to the
  shared-exact tier (queue_id whose `transmit_rate ≥ 2.5G`).
- **PLAN-KILL trigger:** if review shows the per-queue status row is
  already truncation-prone (`cos_active_flow_counts_truncated` exists),
  adding 6×workers fields per shared-exact queue could push the snapshot
  past its bound on an 11-class × 6-worker interface (66 rows × 6 fields).
  Must verify the snapshot cap headroom before committing.

### Option B — a dedicated throwaway per-(class,worker) "guarantee trace" control-socket dump, NOT through Prometheus

Add a one-shot `cli -c "show class-of-service guarantee-trace reth0.80"`
that walks every worker's `CoSInterfaceRuntime` for the target interface
and dumps the per-(queue,worker) `{backlog (queued_bytes), phase1_admit,
phase2_admit, eligible_visits, drain_sent, v8_granted, share_integral,
park_root, park_queue}` set as a table — the §4 columns plus the DEMAND
proxy (`backlog`) added per SMR r1 F2. Bypasses the Prometheus
truncation/cardinality concern entirely; it is a debug RPC, run pre/post
the iperf window like the #1614 `diag_*.sh` scripts.

- **Pros:** zero Prometheus cardinality cost; no per-queue-status-row
  widening; the dump is a snapshot of state the worker ALREADY holds, so
  the only new code is the RPC serializer + a CLI formatter; trivially
  throwaway (delete the RPC after diagnosis).
- **Cons:** a single pre/post snapshot pair, not a time-series — cannot
  see WITHIN-window dynamics (e.g. a worker that oscillates between
  starved/fine). But §1's signal is steady-state (30 s window, stable
  ~52%), so a pre/post delta is sufficient for the §4 decision rule.
  Per `feedback_control_socket_contention`, a 1-shot debug RPC at run
  boundaries does NOT contend with the 1/s status poll.
- **PLAN-KILL trigger:** if the worker cannot read its per-(queue,worker)
  `my_share` without racing rotation. It CAN, but ONLY via the seqlock
  snapshot (`snapshot_epoch_v8`, `mod.rs:1561`), which the worker already
  performs every `acquire_v8` call — the `share_integral_i` accumulator
  piggybacks that snapshot, adding zero new synchronization (Codex r1 F3 /
  SMR F4). A bare Relaxed load of `worker_fair_share[worker_id]` would tear
  against the rotation's cross-epoch write and is explicitly NOT used.
  `v8_granted` is worker-local accumulated (single-writer).

### Option C — REJECTED: add the disambiguation as production Prometheus gauges feeding nothing

Considered making the per-(class,worker) grant/share/delivered a
permanent `xpf_fairness_*` production gauge set. REJECTED: this is a
one-time diagnosis; permanent gauges add cardinality
(`11 classes × 6 workers × N interfaces`) for a measurement we run once.
The #1247 `max-worker-flow-share` precedent shows production fairness
gauges should be DERIVED scalars, not raw per-(class,worker) dumps.
Option C is the gold-plating anti-pattern; named only to reject it.

### Recommended path

**Option B (control-socket guarantee-trace dump) as the primary, with
Option A's single genuinely-new field (per-(queue,worker) v8 granted
bytes accumulator) folded in if Option B's pre/post snapshot proves
insufficient.** Rationale: Option B avoids the Prometheus
cardinality/truncation hazard (the one real risk in Option A), needs the
least new hot-path code (`backlog`/`phase1/2_admit`/`eligible_visits`/
`park_*`/`drain_sent` all ALREADY exist on worker-local state; only
`v8_granted` per-class needs a 1-u64-add accumulator and `share_integral`
needs a per-epoch add that piggybacks the existing `snapshot_epoch_v8`
seqlock read), and the §1 signal is steady-state so a pre/post delta
satisfies the §4 decision rule. The harness wraps it exactly like the
#1614 `diag_gr2.sh` script: snapshot → 30 s iperf → snapshot → diff.

## 6. Measurement protocol (the `/engineer` STEP 0 deliverable)

On the loss userspace cluster (`loss:xpf-userspace-fw0`, node 0 primary):

```bash
# deploy WIPES CoS — re-apply guarantee-rate 0.7 fixture first
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env make cluster-deploy
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0   # guarantee-rate 0.7, shaping 25g
# decisive falsifier scenario from #1614 §2.4
cli -c "show class-of-service guarantee-trace reth0.80"   # PRE snapshot
# small4 + 24g: ports 5200(100m) 5201(1g) 5202(3g) 5203(6g) 5210(24g), push, -P12, 30s
#   v4 172.16.80.200 AND v6 2001:559:8585:80::200
cli -c "show class-of-service guarantee-trace reth0.80"   # POST snapshot
```

Per-(class,worker) deltas for 3g (q with transmit-rate 3g) and 6g across
all 6 workers, then apply the §4 decision rule. Also re-run the full
11-class scenario (#1614 §2.1) to confirm the same layer lights up under
full contention. Run v4 AND v6 per `feedback_smoke_v4_and_v6` (v6 header
overhead can shift the per-worker share math).

**Coordination:** the cluster is shared (one job at a time,
`feedback_smoke_serialized_single_agent`). This is a DIAGNOSIS run, not a
smoke; it still queues behind any active smoke. Post
`<!-- AWAITING-DIAG -->` or coordinate with #1694 if it wants the cluster.

## 7. Disambiguation success criterion (the consumer contract)

The instrumentation is ACCEPTED at `/engineer` STEP 0 iff the post-run
data satisfies the §4 decision rule UNAMBIGUOUSLY — i.e. exactly one of
the four outcomes {(0) demand-bound, (L1) v8 share-cap, (L3) Phase-1
budget fault, (L2-confirm) park_root non-zero ⇒ model incomplete} is
selected by the §4 fingerprint columns. The columns were chosen to be
INDEPENDENT: `backlog_i≈0` uniquely picks (0), `p1_admit_i≪
eligible_visits_i` uniquely picks (L3), and `granted_i≈share_integral_i`
with backlog + an under-ceiling peer uniquely picks (L1). A counter set
that produces all-zero or all-equal columns across the three live
outcomes — unable to decide — is a FAILED instrument and must be
redesigned, NOT papered over with a fix. This is the explicit guard
against the `feedback_review_scaffolding_against_consumer` failure: the
counters are judged by whether they DECIDE, not by whether they are
individually correct. If `park_root_i > 0` anywhere (contradicting the
§2-L2 monotonic-sum proof) the three-layer model is incomplete → file a
"add a 4th candidate" follow-up, do NOT ship a fix against an undecided
model (#1630 four-mechanism-falsification discipline).

## 8. PLAN-KILL exits (all expected, all valid)

1. **DEMAND-BOUND (§4 outcome 0):** the under-delivering busy workers
   have `backlog_i ≈ 0` AND `p1_admit_i ≈ eligible_visits_i`. The 3g/6g
   flows simply do not offer the bytes on the workers they RSS-landed on —
   the #1630 cause-2 transport-physics floor (single-flow-bundle,
   ACK-clocked, worsens at low per-worker parallelism), NOT a CoS defect.
   PLAN-KILL #1692. This is the SINGLE MOST LIKELY outcome given #1630's
   prior finding that mid-rate classes sit on a transport floor.
2. **L1 v8 share-cap, BY-DESIGN (§4 outcome L1):** `granted_i ≈
   share_integral_i` WITH sustained `backlog_i`, ≥1 peer under its
   ceiling, `bypass_arms ≈ 0`. The lease holds each worker to its
   active-flow-proportional slice and refuses to let a backlogged worker
   borrow an idle peer's slice (surplus bypass-gated, shaper-bound never
   arms it). This is the #1304/Cstruct strict-per-flow-fairness trade and
   the #1220 precedent. PLAN-KILL #1692; a work-conserving surplus policy
   is a SEPARATE design issue with its own plan (the #1211 race-safe-AFD
   kill warns that space is hard).
3. **Model incomplete:** `park_root_i > 0` anywhere (contradicting the
   §2-L2 proof) OR the fingerprint columns are mutually contradictory
   (e.g. backlog>0 AND p1_admit≈visits AND granted<share_integral with no
   peer slack). The three-layer model is wrong; file a follow-up to add
   the missing candidate, do NOT ship a fix against an undecided model
   (#1630 four-mechanism-falsification discipline).
4. **Snapshot/cardinality blocker** (Option A): if the per-queue status
   row cannot carry the per-worker breakdown without truncation, fall to
   Option B; if Option B's control-socket dump also can't read
   `share_integral` via the seqlock snapshot, the instrument is infeasible
   → re-scope.

The ONLY non-KILL outcome is **(L3) Phase-1 budget fault** (`p1_admit_i ≪
eligible_visits_i` on a backlogged worker): the selector visits 3g every
epoch but the `quantum × fraction` Phase-1 budget exhausts before honoring
it past ≤1 frame. That is the one genuinely fixable layer, and even then
the fix (re-derive the Phase-1 boundary from configured RATES — #1614
Path A candidate 4) is bounded by §3.A's ~24 G ceiling and trades 24g for
3g/6g, the documented `guarantee-rate` intent.

## 9. What this plan explicitly does NOT do

- Does NOT choose or design a fix. The #1614 Path A fix candidates
  (eligibility-gated Phase-1, Phase-2 epoch hardening, v8-lease fairness,
  rate-derived Phase-1 boundary) are all GATED behind this
  instrumentation naming the layer. Picking one now would repeat the v2
  mistake (code-falsified pre-chosen mechanism).
- Does NOT touch the default `proportional` oversubscription mode
  (bit-for-bit preserved per `docs/fairness-regimes.md`).
- Does NOT add per-flow-CoV work — that is PLAN-KILL by #1220/#1244
  precedent (#1614 §3.2), out of scope.
- Does NOT modify production source during `/research`.

## 10. Acceptance criteria for the `/engineer` STEP 0 (instrument-only)

- [ ] Per-(class, worker) `{backlog (queued_bytes), phase1_admit,
      phase2_admit, eligible_visits, drain_sent, v8_granted,
      share_integral, park_root, park_queue}` is observable for the
      shared-exact tier (≥2.5G classes) on reth0.80. `backlog` (the DEMAND
      proxy) and `share_integral` (windowed lease ceiling) are the two
      load-bearing additions; the rest split out of the existing SUM-fold.
- [ ] Hot-path cost: ≤ 1 u64 add per lease top-up (`v8_granted`) + a
      per-epoch `share_integral` add that piggybacks the EXISTING
      `snapshot_epoch_v8` seqlock read (no new seqlock read, no new atomic
      on `acquire_v8`); all other columns reuse existing worker-local
      state read on the 1/s or on-demand path.
- [ ] The §4 decision rule selects exactly one of {(0) demand-bound, (L1)
      v8 share-cap, (L3) Phase-1 budget fault} on the `small4+24g`
      falsifier (v4 AND v6), confirmed on the full 11-class scenario.
- [ ] If the rule selects (0) demand-bound or (L1) by-design → PLAN-KILL
      #1692 with the data. Only (L3) leads to a fix.
- [ ] `make test` green; `make test-failover` ≤ 60 ms unchanged
      (instrument-only, no scheduler change).
- [ ] Default proportional mode unchanged bit-for-bit.

## 11. Reproducibility / references

- #1614 converged research: `docs/research/1614-simul-load-diagnosis/plan.md`
  v3 @ `e672bb821` (§3.B + falsified hypotheses + Path A charter).
- #1628 live counters: `queue_service/mod.rs:809,851,948,1058` (per-queue);
  `coordinator/mod.rs:1048-1053` (the SUM-fold this instrument splits).
- v8 lease: `types/shared_cos_lease/mod.rs:1152` (`acquire_v8`),
  `rotate_epoch_v8.rs:308` (`my_share` formula), `:188` (bypass arm gate).
- shared-exact threshold: `worker/cos/mod.rs:31,168`.
- cross-binding sharding: `cos/cross_binding.rs:69`.
- root pool: `token_bucket.rs:54`.
- contract: `docs/fairness-regimes.md` (#1217 Cstruct, #1304 equal-flow,
  #1630 cause-1/cause-2 floors).
- KILL lineage: #1211 #1236 #1237 #1239 #936 #937 #1220 #1244.
