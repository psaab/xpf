# #1692 — Path A: instrument-first isolation of the 3g/6g guarantee-rate under-protection (§3.B)

Revision: v1 (DRAFT — pre-review)
Branch: research/1692-3g6g-guarantee-instr
Base: origin/master @ ea0a670bd (#1628 counters live; #1643 fence live)
Status: PLAN-READY candidate — INSTRUMENT-FIRST measurement design, NOT a
fix. Explicit PLAN-KILL exit if the disambiguating data shows ~52% is
structurally inherent.

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

### Layer L2 — root FCFS pool ordering (root token bucket / `SharedCoSRootLease`)

`token_bucket.rs:54` `maybe_top_up_cos_root_lease` + the per-worker
`select_*` walk consuming `root.tokens` (`queue_service/mod.rs:856`,
`:1034`). The root pool is the 25 G shaping rate, shared across all
classes on the interface. **But `park_root = 0` everywhere** (#1614 §2.1
+ §2.4): the root token bucket NEVER throttled any class in any scenario.
So L2 is PROVISIONALLY ruled out by existing telemetry — BUT the #1614
data is per-class SUMMED-across-workers (see §3 below). A per-WORKER
`drain_park_root_tokens` split could still reveal a single worker hitting
root starvation that the SUM hides. L2 stays a candidate only on the
narrow chance that the aggregate `park_root=0` masks a per-worker
imbalance; the instrumentation must be able to confirm or kill it
per-worker.

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
   (`worker/cos/mod.rs:481-486`). The aggregate `park_root=0` cannot
   confirm no SINGLE worker hit root starvation (L2).

4. **`drain_sent_bytes` is per-queue, summed across workers.** We have
   the class total but not the per-worker split, so we cannot compute
   per-worker delivered-vs-`my_share` (the L1 deciding ratio).

The gap is uniform: **everything is per-class-summed; nothing is
per-(class, worker).** The shared-exact tier needs per-(class, worker)
visibility to decide which of L1/L2/L3 gates a specific worker's 3g/6g
shard. That is the single instrumentation deliverable.

## 4. Worked distinct-signature table (the disambiguation proof)

For the `small4+24g` scenario, on each worker `i` that has ≥1 active 3g
flow, the proposed per-(class,worker) counters (defined in §5) would read
as follows under each hypothesis. `delivered_i` = per-worker 3g
`drain_sent_bytes`; `share_i` = per-worker v8 `my_share` snapshot;
`granted_i` = per-worker-per-class v8 `acquire_v8` granted bytes;
`p1_admit_i` = per-worker 3g Phase-1 admissions; `bypass_arms` = v8
`bypass_grace_arm_count` (already exists, per-lease).

| Hypothesis | `delivered_i` vs `share_i` | `granted_i` vs `share_i` | `p1_admit_i` | `park_root_i` | `bypass_arms` | Σ`share_i` vs class_rate |
|---|---|---|---|---|---|---|
| **L1 v8-lease cap (BY-DESIGN, PLAN-KILL)** | `delivered_i ≈ share_i` (each worker delivers its full share, no more) | `granted_i ≈ share_i` (lease grants exactly the share; primary path hits `my_room=0`) | high (admitted every epoch) | 0 | ~0 (surplus never armed; shaper-bound) | **Σ`share_i` < class_rate** because idle-worker shares (0 flows → 0 share) leave the rate undistributed; busy workers capped at their slice | 
| **L1 v8-lease cap (FIXABLE: share misallocation)** | `delivered_i ≈ share_i` | `granted_i ≈ share_i` | high | 0 | ~0 | **Σ`share_i` ≈ class_rate** (rate IS fully allocated across workers) but `delivered < Σshare` → workers leave granted tokens unspent → look at L3/drain |
| **L2 root FCFS** | `delivered_i < share_i` | `granted_i ≈ share_i` (queue lease grants, but…) | high | **>0 on ≥1 worker** | any | n/a | 
| **L3 Phase-1 budget fault** | `delivered_i < share_i` AND `delivered_i < granted_i` | `granted_i ≈ share_i` (v8 willing to grant) | **LOW relative to eligible_visits_i** — the selector visits 3g but the Phase-1 budget is spent before honoring it past one frame | 0 | any | n/a |

Decision rule (the consumer criterion, made operational):
- **`granted_i ≈ share_i` AND `delivered_i ≈ granted_i` AND
  Σ`share_i` < class_rate AND `bypass_arms ≈ 0`** → **L1 by-design →
  PLAN-KILL** (strict per-flow fairness leaving idle-worker share
  unclaimed; the #1304/Cstruct trade, the #1220 precedent). The fix
  would be a non-work-conserving→work-conserving policy change, a
  different issue.
- **`granted_i ≈ share_i` AND `delivered_i ≈ granted_i` AND
  Σ`share_i` ≈ class_rate** → L1 share-allocation is correct but the
  bytes are not delivered; recurse into L3 drain accounting (selector
  not requesting enough / dropping sub-budget). FIXABLE.
- **any worker `park_root_i > 0`** → **L2** root FCFS contention hidden
  by the SUM. FIXABLE (root pool ordering / per-worker root reservation).
- **`p1_admit_i` low vs `eligible_visits_i` AND `granted_i > delivered_i`**
  → **L3** Phase-1 budget spends before honoring 3g past one frame.
  FIXABLE (re-derive Phase-1 boundary from configured rates — #1614
  Path A candidate 4).

If two layers light up together (e.g. L1 share correct + L3 low admit),
the table's columns still order them: L2 (park) is checked first because
it is a hard stop; then L3 (admit vs visit) because it gates whether the
v8 grant is even requested; then L1 (granted vs share + Σshare) as the
residual. The instrumentation produces all columns in ONE scrape so the
ordering is decidable post-hoc, not by re-running.

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
4. `v8_my_share_snapshot_i` — NEW: sample `worker_fair_share[worker_id]`
   for this queue's lease at status-snapshot time (a single Relaxed load
   off the Arc the worker already holds in `queue.queue_lease_v8`). No
   hot-path cost; read only on the 1/s status path.

- **Pros:** reuses the per-(class,worker) snapshot key that already
  works for `cos_active_flow_count`; minimal new hot-path code (one u64
  add); the `my_share` + `granted` + `delivered` triple is exactly the
  L1 decision columns; `bypass_arms` already exists per-lease.
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
and dumps the per-(queue,worker) `{phase1_admit, phase2_admit,
eligible_visits, drain_sent, v8_granted, my_share, park_root,
park_queue}` octuple as a table. Bypasses the Prometheus
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
- **PLAN-KILL trigger:** if the worker does NOT actually hold a
  per-(queue,worker) `my_share` readable without racing the rotation —
  but it does: `worker_fair_share[worker_id]` is a Relaxed-loadable
  AtomicU64 (`shared_cos_lease/mod.rs:409`, read via the seqlock-free
  accessor pattern), and `v8_granted` is worker-local accumulated.

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
least new hot-path code (the `my_share`, `phase1/2_admit`,
`eligible_visits`, `park_*`, `drain_sent` octuple all ALREADY exist on
worker-local state; only `v8_granted` per-class needs a 1-u64-add
accumulator), and the §1 signal is steady-state so a pre/post delta
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
{L1-by-design, L1-fixable, L2, L3} is selected, OR the data is
internally contradictory (which would itself be a finding: the three-
layer model is incomplete and a fourth candidate must be added before any
fix). A counter set that produces all-zero or all-equal columns across
L1/L2/L3 — unable to decide — is a FAILED instrument and must be
redesigned, NOT papered over with a fix. This is the explicit guard
against the `feedback_review_scaffolding_against_consumer` failure: the
counters are judged by whether they DECIDE, not by whether they are
individually correct.

## 8. PLAN-KILL exits (all expected, all valid)

1. **L1 by-design** (§4 row 1): if `granted_i ≈ share_i ≈ delivered_i`
   AND `Σ share_i < class_rate` AND `bypass_arms ≈ 0`, the ~52% is the
   strict per-flow-fairness floor leaving idle-worker share unclaimed —
   the #1304/Cstruct trade, the #1220 precedent. PLAN-KILL #1692; if a
   work-conserving surplus policy is desired it is a SEPARATE design
   issue with its own plan (and the #1211 race-safe-AFD kill warns that
   space is hard).
2. **Σ share_i ≈ class_rate but instrument can't separate L1/L3** — the
   three-layer model is wrong; file a follow-up to add the fourth
   candidate, do NOT ship a fix against an undecided model
   (#1630 four-mechanism-falsification discipline).
3. **Snapshot/cardinality blocker** (Option A): if the per-queue status
   row cannot carry the per-worker breakdown without truncation, fall to
   Option B; if Option B's control-socket dump also can't read
   `my_share` race-free, the instrument is infeasible → re-scope.

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

- [ ] Per-(class, worker) `{phase1_admit, phase2_admit, eligible_visits,
      drain_sent, v8_granted, my_share, park_root, park_queue}` octuple is
      observable for the shared-exact tier (≥2.5G classes) on reth0.80.
- [ ] Hot-path cost: ≤ 1 u64 add per lease top-up (the only new counter);
      all others reuse existing worker-local state read on the 1/s or
      on-demand path.
- [ ] No new atomic on `acquire_v8` (worker-local accumulator preserved).
- [ ] The §4 decision rule selects exactly one layer on the `small4+24g`
      falsifier (v4 AND v6), confirmed on the full 11-class scenario.
- [ ] If the rule selects L1-by-design → PLAN-KILL #1692 with the data.
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
