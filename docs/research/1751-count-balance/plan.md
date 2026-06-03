# #1751 — count-balancing selection for the #1748 ntuple rebalance controller

- **Status**: **PLAN-DRAFT v1** — pre-review. Awaiting Codex + AGY + Claude-SMR
  hostile rounds. `/research` mode: STOP at PLAN-READY / PLAN-KILL. No PR, no
  production code touched.
- **Issue**: #1751
- **Mode**: `/research`
- **Branch (docs only)**: `research/1751-count-balance` (off `origin/master`
  @ `ecdc16f2e`)
- **Predecessors / required reading**:
  - PR #1749 / `engineer/1748-ntuple-rebalance` — the controller machinery this
    plan re-uses verbatim (barriered ownership transfer, ntuple ioctl,
    RebalancedOut/Owner suppression set, budget/cap). Plan: `docs/pr/1748-ntuple-rebalance/plan.md` (PLAN-READY v7).
  - `docs/pr/1748-ntuple-rebalance/r1-spike-findings.md` — R1 existence proof:
    manual COUNT-balance re-pin took per-flow CoV 16.8% → 2.3–4.2%, aggregate
    preserved/up, on `loss:xpf-userspace-fw0`, CoS OFF / clean fixture.
  - #1750 (`research/1750-reliable-flow-feed/plan.md`, PLAN-READY v4) — the
    reliable per-worker feed this plan's data source depends on (precise
    dependency stated in §2).
  - `docs/fairness-regimes.md` — the structural CoV ceiling `Cstruct` (a
    `2,2,2,2,2,2` count partition has `Cstruct = 0%`).
  - #1203 / `docs/pr/789-fairness-via-ntuple/plan.md` — the prior COUNT-based
    controller that reached only 49–55% CoV. The §5 KILL-risk analysis turns on
    why #1203 stalled and whether v2 avoids it.

---

## 1. Issue framing

The #1748 reactive ntuple rebalance controller is infrastructurally **complete
and correct**: the ownership-transfer protocol is miri-clean and survived 9
review rounds; the `ethtool_rxnfc` ioctl is fixed against the mlx5 driver
(mask DIRECT, `GRXCLSRLALL` driver-select skip, `fs.location = RX_CLS_LOC_ANY`);
live activate/teardown works; the slot-vs-worker_id id-space join is fixed
(`coordinator/rebalance.rs:207-256`). But across 6 live-deploy cycles it
installed **0 rules** because `select_move`
(`rebalance/controller.rs:484-641`) is **byte-rate-aware**, and the per-flow
byte-rate signal is unreliable under load: `FlowCacheEntry.observed_bytes`
resets to one packet's length on flow-cache eviction (`flow_cache.rs:370`), and
entries evict within the 1 s eval window at line rate, so the per-flow rate
reads ~0, the magnitude/epsilon guards never admit a move, and the worker-rate
fallback alone is not enough to clear the gate.

R1 proved the **mechanism** works without any byte-rate signal at all: a manual
COUNT-balance (force a `2,2,2,2,2,2` flow→queue partition by round-robin exact
re-pin) drove per-flow CoV 16.8% → 3.8% with aggregate preserved. The reliable
signals to do that automatically already exist:
- **per-worker flow COUNT** — `xpf_userspace_binding_active_flow_count`
  (proven reliable live), and equivalently derivable by *counting rows per
  `worker_id`* in the `flow_worker_map` snapshot the controller already loads;
- **the per-worker 5-tuple list** — the now-fixed `flow_worker_map` rows
  (post id-space fix), each carrying `worker_id`, `ifindex`, `session_key`,
  `observed_bytes`.

**This plan redesigns `select_move` to COUNT-balancing**: move a flow from the
highest-flow-COUNT worker to the lowest-flow-COUNT worker, converging toward an
even count partition, gated by a count-delta threshold + per-flow cooldown +
dwell/hysteresis + a count-based overshoot guard — with **no per-flow
byte-rates on the decision path**. Every piece of the reviewed move machinery
(barriered ownership transfer, ntuple ioctl, RebalancedOut/Owner suppression,
budget/cap, second-move unwind, teardown reverse-barrier) is re-used unchanged.

## 2. Data source + the #1750 dependency (PRECISE)

The controller already consumes the `flow_worker_map` rows in
`coordinator/rebalance.rs:273` (`let (rows, _truncated) = self.flow_worker_map()`)
and groups them per-`(ifindex, worker_id)`. **Count-balancing needs only those
rows** — it counts them per `worker_id`, and the same rows carry the 5-tuples to
write ntuple rules. It does **not** need `observed_bytes` on the decision path.

### 2.1 What the feed must guarantee

Count-balancing has a sharper data-integrity requirement than byte-balancing
had: **the per-worker COUNT used to choose the source/destination worker MUST be
the count of the SAME row set the candidate 5-tuple is drawn from.** If the
controller reads a worker COUNT from one instant (or from the separate
Prometheus `binding_active_flow_count` AtomicU32) and the ROWS from another, a
**count-vs-rows skew** makes it (a) pick the wrong hottest/coolest worker, or
(b) find the chosen source worker has zero rows to move (`NoEligibleFlow`),
exactly the #1748 live symptom. #1750 §2 documents that today the count
(`active_flow_count` AtomicU32, `umem/debug_state.rs:223`) and the rows
(`FlowWorkerMapSnapshot`, `umem/mod.rs:817`) are **two independent atomic
publishes from one scan** → a reader can observe a fresh count with stale/empty
rows.

### 2.2 The dependency, stated three ways (pick at §5)

There are **three** ways to source the count, with different #1750 coupling:

1. **Count rows from the same snapshot the controller already loads
   (NO #1750 dependency).** Derive the per-worker count by counting
   `flow_worker_map` rows per `worker_id` *in the same `flow_worker_map()`
   return value* the controller uses for candidates. Count and rows are then
   the same object by construction — **the count-vs-rows skew is structurally
   impossible** because there is only one snapshot. This is the key insight that
   **decouples #1751 from #1750**: count-balancing does not need the separate
   `binding_active_flow_count` atomic at all; it counts the rows it is about to
   choose from. (Caveat: this count is the *row* count, which can differ from
   the Prometheus count under row truncation — see 2.3.)

2. **Path-1-of-#1750 atomic bundle (SOFT dependency, RECOMMENDED long-term).**
   #1750 Path 1 bundles `active_flow_count` + `published_ns` INTO
   `FlowWorkerMapSnapshot`. If #1750 lands first, the controller reads count +
   rows + freshness from one `ArcSwap` load and additionally gets the
   snapshot-AGE staleness defer (avoids acting on a stale snapshot under publish
   lag). #1751 is *better* with #1750 but does **not require** it: option 1
   already gives count==rows atomicity from the existing snapshot.

3. **Prometheus `binding_active_flow_count` AtomicU32 (REJECTED for the
   decision).** Reading the separate atomic re-introduces exactly the
   count-vs-rows skew #1750 §2 describes. Use it only for operator-facing
   metrics/logging, never to choose the move.

### 2.3 Row-count vs Prometheus-count: the truncation caveat

`flow_worker_map()` caps at `FLOW_WORKER_MAP_MAX_ROWS = 4096` total and
per-binding `FLOW_WORKER_MAP_MAX_PER_BINDING = 256` (`flow_cache.rs:18`). On the
6-worker loss cluster at P12 (≤24 forward+reverse entries) truncation **cannot**
fire (24 ≪ 256). So the row-count equals the true active count for the target
regime. The plan MUST assert this precondition (and degrade gracefully — treat a
`truncated` snapshot as a defer, not a decision) so a future high-flow-count
workload does not silently feed a truncated count into the balancer.

**Verdict on the dependency:** **#1751 can land INDEPENDENTLY of #1750** by
sourcing the count from the same row snapshot (option 1). #1750 remains the
*recommended* companion because its atomic bundle + snapshot-age defer hardens
the feed against publish-cadence skew and gives a principled staleness gate, but
it is **not a hard blocker**. Land #1751 with the option-1 self-consistent count
and the truncation/staleness guards; adopt #1750's bundle when it ships.

## 3. select_move v2 — count-balancing design

### 3.1 Inputs (re-uses the existing `RebalanceTickInput`)
The tick already assembles, per ifindex:
- `workers: Vec<WorkerByteRate>` — keyed by the REAL `worker_id` (post id-space
  fix), carrying `queue_id` (the ntuple `ring_cookie` target). Byte-rate is
  retained ONLY for the metric gauge + optional heterogeneous tiebreak (§3.6),
  NOT for the count decision.
- `flows: Vec<FlowSample>` — each `{key, worker_id, byte_rate}`, one per
  `flow_worker_map` row. **v2 adds a derived per-worker count** = number of
  `flows` whose `worker_id == w`. (No new wire field; counted from `flows`.)

### 3.2 The decision (replaces the byte-rate hottest/coolest + project_move)
```
counts[w] = |{ f in flows : f.worker_id == w }|         // from the rows
hi = argmax_w counts[w]   (tie-break: higher byte_rate, then lower worker_id)
lo = argmin_w counts[w]   (tie-break: lower  byte_rate, then lower worker_id)

if counts[hi] - counts[lo] < K        -> SkipReason::Balanced   (count-delta threshold)
if hi == lo                            -> SkipReason::Balanced
// overshoot guard (replaces the byte-rate magnitude guard):
if counts[lo] + 1 >= counts[hi]        -> SkipReason::Magnitude  // moving one would
                                          //   not reduce max-min (would make lo the new max)
pick a flow F on hi, not in cooldown   -> else SkipReason::NoEligibleFlow / Cooldown
move F: hi -> lo  (queue = workers[lo].queue_id)
```
- **`K` (count-delta threshold), default 2.** A move is worthwhile only if the
  max worker carries at least `K` more flows than the min. `K = 2` means
  "don't bother for a 1-flow imbalance" (moving one flow off a `3` to a `2`
  leaves `2,3→3,2` — no net improvement; the overshoot guard below also catches
  this). `K = 2` converges `[2,2,1,1,4,2]` → `[2,2,2,2,2,2]` in the minimum
  number of moves and stops cleanly at an even partition.
- **Overshoot guard (count-based, replaces magnitude `≤ gap`).** Reject the move
  if moving one flow would make `lo` the new max, i.e. require
  `counts[hi] - counts[lo] >= 2` (equivalently `counts[lo] + 1 < counts[hi]`).
  This is the count analogue of "don't make the destination the new hottest
  worker" and needs NO rates. It guarantees each admitted move strictly reduces
  `max - min` (the convergence potential, §3.4).
- **Candidate flow choice on `hi`.** Homogeneous (equal-rate) traffic: any
  non-cooldown flow on `hi` is equally good — pick deterministically (e.g.
  lowest `session_key`) for reproducibility. Heterogeneous: §3.6 optional
  tiebreak.

### 3.3 Gating (all re-used unchanged from v1)
- **Dwell / hysteresis** (`DWELL_TICKS_REQUIRED = 2`): the count imbalance must
  persist `≥ 2` consecutive ticks before the first move (avoids reacting to a
  one-tick RSS-count blip). v1's `is_over_threshold` becomes
  `is_count_imbalanced` (`max_count - min_count >= K`).
- **One move per `rebalance_interval`** (default ≥ 1 s) — bounds the R3 reorder
  burst (R1's 7601 retransmits came from moving 12 flows at once; incremental
  one-per-interval amortizes it).
- **Per-flow cooldown** (`COOLDOWN_INTERVAL_MULTIPLIER = 5` intervals): a flow
  re-pinned cannot thrash back for several intervals.
- **Budget/cap** (`max_rules`, STOP-on-exhaustion, NO eviction) — unchanged.

### 3.4 Convergence / anti-thrash (formal)
Define the potential `Φ = max_w counts[w] - min_w counts[w]`. The overshoot
guard admits a move only when `counts[hi] - counts[lo] >= 2`, and a move
decrements `counts[hi]` by 1 and increments `counts[lo]` by 1, so post-move
`max - min` is `≤ Φ - 1` for the (hi,lo) pair (other workers unchanged ⇒ global
`Φ` is non-increasing and strictly decreases whenever the (hi,lo) pair was the
unique extremal pair). `Φ` is a non-negative integer bounded by `N` (flow count)
⇒ the process **terminates** in `≤ Φ₀` admitted moves at `Φ ≤ 1` (an even
partition up to ±1). The per-flow cooldown plus the `Φ ≥ 2` overshoot guard make
**oscillation impossible**: once balanced, no move passes the `K`-threshold; a
moved flow is in cooldown and cannot be re-chosen as the immediate next move, so
the controller cannot ping-pong a flow between two equal-count workers. This is
the count analogue of v1's ε-band monotone-objective termination argument, but
on an integer potential (no floating-point ε needed) — strictly cleaner.

### 3.5 What is REMOVED vs v1
- `project_move` (byte-rate vector projection) — gone from the decision.
- `byte_rate_cov` epsilon-band gate (`EPSILON_COV_IMPROVEMENT`) — gone from the
  decision; replaced by the integer `Φ`-decrease guarantee. (CoV gauge retained
  for the metric.)
- `fallback_per_flow_rate` (hottest/candidate_count estimate) — gone; the count
  is now the primary signal, no estimate needed.
- The byte-rate magnitude guard `move_rate > gap` — replaced by the count
  overshoot guard.

### 3.6 Heterogeneous traffic — the honest limitation
Equal-COUNT ≠ equal-RATE. For **homogeneous** traffic (iperf `-P12`, all flows
≈ equal rate) count-balancing is **exact**: a `2,2,2,2,2,2` partition gives
`Cstruct = 0%` and R1 measured 3.8% (implementation margin). For
**heterogeneous** traffic (one elephant + several mice on a worker), an even
COUNT partition does **not** flatten per-flow rate — moving a mouse off a worker
dominated by an elephant leaves the elephant's queue-mates slow. Count-balancing
**cannot** fix heterogeneous skew on its own.

Two honest stances, decided at §5:
- **(a) Count-balancing is sufficient for the stated symptom + gate.** The
  measured problem (`docs/fairness-regimes.md`, #1333, #1748 framing) is the
  *homogeneous* RSS count-imbalance on iperf `-P` ports. The live gate is
  iperf (equal-rate). Ship count-balancing; document the heterogeneous
  limitation as a known follow-up. This is the R1-validated scope.
- **(b) Optional rate-aware tiebreak IFF a reliable feed exists.** When the
  hottest-count worker has flows of clearly unequal rate (detectable only with a
  reliable per-flow byte signal, i.e. #1750 Path 2's cold-path eviction
  side-table OR an ordinal "heaviest flow" signal), break the
  which-flow-to-move tie toward the heavier flow. This is **purely a tiebreak
  among already-count-eligible candidates** — it never changes the
  source/destination *worker* choice (still count-driven), so it cannot
  re-introduce the byte-rate-stall that blocked #1748. It is gated behind a
  reliable feed and is **explicitly out of scope** for the first increment
  unless §5 says otherwise.

**Recommendation: ship (a); document (b) as a #1750-gated follow-up.** Honesty:
the controller's name is "count-balance"; it will leave heterogeneous within-
worker rate skew on the table, and that is acceptable because (i) it is strictly
better than today (0 installs), (ii) it matches the validated symptom, and (iii)
the rate-aware lever has no reliable feed yet (#1750 open).

## 4. The #1203 KILL-RISK analysis (CRITICAL)

**The danger:** #1203 was *also* a COUNT-based reactive controller on *this
exact cluster* and reached only **49–55% CoV** at P=12 — the gate (≤20%) was
not met, and it was closed with the verdict *"per-flow CoV is bounded by
within-queue scheduling, not placement."* R1's MANUAL count-balance on the same
cluster hit **3.8%**. If count-balancing is provably floor-bound at ~50%
regardless of controller quality, **#1751 is a PLAN-KILL.** This section
resolves the contradiction with code-grounded evidence.

### 4.1 What #1203 actually did, and its own root-cause statement
#1203 (`docs/pr/789-fairness-via-ntuple/plan.md`; PR body; close comment) was a
Go-side closed-loop controller that **flattened the per-queue flow COUNT** via
sticky placement (K=4 rules/tick, round-robin to least-loaded queues). It
*succeeded* at the count goal — its own PR body: *"you successfully flattened
the flow count across RX queues, but your TCP flows are still seeing 49% CoV."*
The close comment is explicit about WHERE the residual lived:

> "HW flow steering can't drive per-flow CoV under 20% … because per-flow CoV is
> bounded by **within-queue scheduling, not placement**. For `shared_exact` CoS
> queues — which are what the test fixture uses — the within-queue path is
> currently **single-FIFO-per-worker** (the MQFQ flow-fair codepath … is gated
> to `exact && !shared_exact`)."

So #1203's residual 49–55% was **NOT a placement failure and NOT a count-balance
failure** — it flattened the count fine. The residual was the **within-queue
scheduler**: under `shared_exact` CoS, two flows sharing one worker were served
by a single FIFO, and TCP cwnd dynamics let one flow dominate the FIFO → per-flow
unfairness *within* the queue that placement cannot touch.

### 4.2 Why R1 hit 3.8% where #1203 hit 55% — the decisive variable
R1 ran on **CoS OFF / clean fixture** (`r1-spike-findings.md`: "post-#1745,
equal-flow-enforcement OFF / clean fixture"). #1203 ran on **`shared_exact` CoS
classes**. With CoS off, the within-queue path is the #1183 best-effort fast
path, and with two equal-rate flows on a worker the per-flow service is fair
(the FIFO serves them round-robin-ish at equal cwnd). With `shared_exact` CoS
**at the time of #1203**, the within-queue MQFQ flow-fair path was gated OFF, so
the same two flows were single-FIFO'd and TCP let one win. **Same count
partition, different within-queue scheduler → 3.8% vs 55%.** The variable is the
within-queue scheduler, exactly as #1203's own close comment said.

### 4.3 The within-queue scheduler has been STRUCTURALLY FIXED since #1203
This is the load-bearing finding that flips the KILL risk. Post-#1203, the
within-queue scheduler was rebuilt:
- **#913** (served-finish MQFQ): `queue_vtime = max(vtime, served_finish)`
  replaced the broken aggregate-bytes accumulation that caused temporal
  inversion (`cos/queue_ops/pop.rs:112`). #913 is the exact bug #1203's
  adversarial reviewer pointed at ("the temporal inversion bug, Issue #913").
- **#911 / #914**: same-class HOL fix + shared_exact per-flow share cap.
- **#1735** (current master, `cos/README.md:50-66`): **"Per-flow MQFQ runs on
  ALL shaped queues, not just exact."** `promote_cos_queue_flow_fair` now marks
  every queue (exact AND non-exact) `flow_fair_eligible`; exact/`shared_exact`
  queues promote EAGERLY at build and allocate `FlowFairState` immediately. The
  `flow_fair() == flow_fair_state.is_some()` invariant means a `shared_exact`
  queue now dispatches the **per-flow MQFQ** branch, NOT the single-FIFO branch
  #1203 was bounded by.

**So the precise thing #1203's close comment blamed — "the within-queue path …
is single-FIFO-per-worker … gated to `exact && !shared_exact`" — is no longer
true on master.** The within-queue scheduler that bounded #1203 to 55% has been
replaced by per-flow MQFQ on shared_exact since #911/#913/#914/#1735.

### 4.4 Does count-balance v2 avoid #1203's failure? — verdict + the residual risk
**Yes, with one honestly-stated live precondition.** v2 avoids #1203's failure
mode along three axes:
1. **Count-balance is the part #1203 got right** (it flattened the count). v2
   does the same, more cleanly (integer-`Φ` convergence vs #1203's K=4 thrash +
   the sticky-cooldown bug that put 50+ rules on the NIC). The convergence/anti-
   thrash machinery (§3.4) is strictly better than #1203's.
2. **The within-queue floor that bounded #1203 is fixed** (§4.3) — the residual
   #1203 could not touch is now handled by per-flow MQFQ on shared_exact.
3. **R1 is the existence proof on this hardware** that a count partition →
   3.8% CoV is reachable; R1 did it CoS-off, and the §4.3 fixes bring the
   CoS-on path's within-queue scheduler up to the same per-flow-fair behavior.

**The residual KILL risk, stated honestly:** R1 validated the count→CoV link
**CoS OFF**. The live gate at `-P12 -p5210` routes through the
**`iperf-24g` `shared_exact`** class (`test/incus/cos-iperf-config.set` term 10:
dst-port 5210 → forwarding-class iperf-24g, scheduler `transmit-rate 24g
exact`). So the CoS-ON validation exercises the post-#1735 shared_exact MQFQ
within-queue path that has **not yet been measured in combination with
count-balanced placement**. The plan therefore makes the **live A/B gate the
acceptance criterion in BOTH CoS modes** (§9): if count-balanced placement +
post-#1735 shared_exact MQFQ does NOT reach R1-class CoV (~3-4% homogeneous), the
residual is the within-queue scheduler and #1751 reduces to #1203's wall — that
outcome is a documented PLAN-OUTCOME (ship CoS-off where it works + file a
shared_exact within-queue follow-up), NOT necessarily a full kill, because the
CoS-off path is the R1-validated win and the controller is default-OFF/opt-in.

**Net #1203 verdict: NOT a kill.** #1203's 55% was a *within-queue* floor on a
scheduler that has since been fixed (#913/#1735), not a *count-balance* or
*placement* floor. R1 is the on-hardware proof the floor is ~3.8% once
within-queue scheduling is fair. The one thing not yet measured — count-balanced
placement under the post-#1735 *shared_exact* MQFQ — is the live gate's job, and
even a partial result (CoS-off win) is shippable for a default-OFF knob. PLAN-KILL
is reserved for the case where the live trace shows the post-#1735 shared_exact
MQFQ still single-FIFOs count-balanced flows (i.e. the #1735 README claim does
not hold at runtime) AND CoS-off also fails to reproduce R1 — improbable given
R1.

## 5. Multiple Path Options

### Path A — Count-balance v2, count sourced from the same row snapshot, ship (a) homogeneous (RECOMMENDED)
- `select_move` v2 per §3; per-worker count = rows-per-worker from the existing
  `flow_worker_map()` load (no #1750 hard dependency, §2.2 option 1); `K=2`,
  count overshoot guard, integer-`Φ` convergence; truncation/staleness guards
  (§2.3); reuse ALL existing move machinery. Heterogeneous tiebreak documented as
  a #1750-gated follow-up.
- **Pros:** unblocks installs with NO byte-rate signal; smallest change to a
  heavily-reviewed controller (swaps the `select_move` body, keeps the barrier /
  ioctl / suppression / teardown verbatim); decouples from #1750; integer
  convergence is cleaner than v1's float ε; R1 is the existence proof.
- **Cons:** leaves heterogeneous within-worker rate skew on the table;
  CoS-on (shared_exact) within-queue interaction unproven until the live gate.

### Path B — Path A but HARD-depend on #1750 (atomic count+timestamp bundle)
- Same v2 selection, but source count + rows + freshness from #1750's bundled
  `FlowWorkerMapSnapshot` and add the snapshot-age defer.
- **Pros:** principled staleness gate; future-proof against publish-cadence
  skew at high flow counts.
- **Cons:** serializes #1751 behind #1750; unnecessary for the P12 gate where
  the same-snapshot row count (Path A) is already self-consistent. Over-coupled.

### Path C — Path A + heterogeneous rate-aware tiebreak in the FIRST increment
- Add §3.6(b)'s heaviest-flow tiebreak now, requiring #1750 Path 2's cold-path
  eviction side-table for a reliable per-flow byte signal.
- **Pros:** handles elephant+mice in one shot.
- **Cons:** drags in #1750 Path 2 (new cold-path state), expands scope and
  review surface for a benefit with no current live gate (no heterogeneous
  fixture). Premature.

### Path D — PLAN-KILL
- Only if §4's #1203 analysis is wrong: i.e. the post-#1735 shared_exact MQFQ
  does NOT actually run per-flow within-queue (README claim false at runtime)
  AND a CoS-off count-balance also fails to reproduce R1's 3.8%. Code + R1
  evidence make this improbable.

**Recommendation: Path A.** It is the minimal, R1-validated, #1750-decoupled
increment that unblocks the controller. Run the pre-code `--features debug-log`
`REBALANCE_EVAL`/`REBALANCE_FLOW` trace FIRST (confirm per-worker row counts
match `binding_active_flow_count`), then the live A/B gate in BOTH CoS modes
decides whether the homogeneous win extends to shared_exact or whether the
shared_exact within-queue follow-up (§11) is needed. Defer Path B's #1750
coupling and Path C's heterogeneous lever to follow-ups.

## 6. Concrete design (Path A)

### 6.1 `select_move` v2 (`rebalance/controller.rs`)
Replace the body of `select_move` (lines 484-641) per §3.2. Keep the function
signature, the `MoveCandidate` struct, the `SkipReason` enum (re-purpose
`Magnitude` as the count-overshoot reject; `Balanced` as the `K`-threshold
reject; `NoEligibleFlow`/`Cooldown`/`Epsilon` semantics: `Epsilon` becomes
unused on the decision path — keep the variant for metric ABI stability but it
is no longer recorded, OR rename to a `CountConverged` reject; reviewer Q). Add a
private `per_worker_counts(flows) -> HashMap<u32,u32>` helper. Retain
`byte_rate_cov` ONLY to refresh the `worker_byterate_cov` gauge in `tick`.
`tick`'s structure (dwell, dwell-ticks, interval gate, budget gate, second-move
unwind, forward barrier, install) is **unchanged** — only `is_over_threshold` →
`is_count_imbalanced` and `select_move` change.

### 6.2 Tick assembly (`coordinator/rebalance.rs`)
- The per-worker rate aggregation (slot→worker_id join, lines 207-256) stays —
  it feeds the CoV gauge + tiebreak only.
- The per-flow loop (lines ~256-330) stays, but the controller no longer needs
  the per-flow `byte_rate` for the decision; keep populating `FlowSample.byte_rate`
  for the gauge/tiebreak (cheap; already computed) but the decision counts rows.
- Add a **truncation/staleness guard**: if `flow_worker_map()` returns
  `truncated == true`, record a defer skip and do NOT run the balancer this tick
  (the row count would understate the true count, §2.3).

### 6.3 Config knob (`pkg/config/schema.go`) — unchanged from #1748
Same `class-of-service flow-rebalance` leaf. v2 re-interprets sub-leaves:
`imbalance-threshold` (was a byte-rate ratio) becomes the integer count-delta
`K` (or add a new `count-delta` sub-leaf and deprecate the ratio — reviewer Q;
default `K=2`). `rebalance-interval`, `max-rules` unchanged. Default-OFF
byte-identical path unchanged.

### 6.4 Metrics — re-use #1748's surfaces
`xpf_userspace_flow_rebalance_{rules_active, installs_total, deletes_total,
moves_skipped_total{reason}, worker_byterate_cov}`. Add a derived
`worker_flowcount_cov` (or reuse the existing CoV gauge computed on counts) so
operators see the count imbalance the controller is acting on.

## 7. Public API / behavior preservation
- **Default-OFF is byte-identical** — unchanged from #1748; no controller, no
  ioctl socket, no per-tick work when the knob is unset.
- No Rust pub-fn signature changes beyond the `select_move` body and the
  `is_count_imbalanced` rename (both `pub(in crate::afxdp)`, internal).
- `flow_worker_map()` consumer is unchanged (Path A does not require #1750's API
  change); the status/wire consumer (`server/helpers.rs:124`) is untouched.
- The barriered ownership-transfer protocol, RebalancedOut/Owner suppression
  set, ntuple ioctl, second-move unwind, teardown reverse-barrier — **all
  re-used verbatim**, so #1748's 9 rounds of correctness review carry forward
  unchanged. v2 changes only WHICH flow is chosen and WHEN, never HOW the move
  is executed.

## 8. Hidden invariants to preserve
- **No per-packet/per-poll cost** (CLAUDE.md): the decision is coordinator-
  cadence (~1 Hz); counting rows-per-worker is O(rows) on the ≤4096-row snapshot
  the controller already loads. No new hot-path work.
- **Control-socket contention** (CLAUDE.md): no new >1 Hz control-socket caller;
  the feed is the already-collected `flow_worker_map` ArcSwap snapshot.
- **Count==rows atomicity**: the count MUST be derived from the same snapshot the
  candidate rows come from (§2.2 option 1) — never the separate Prometheus
  atomic.
- **Truncation safety**: a `truncated` snapshot must defer, not feed an
  understated count into the balancer (§2.3).
- **Move-eligibility / ownership-transfer invariants** (#1748 §4.5): unchanged —
  the move still requires the target worker hold a peer-synced replica, the
  barrier still serializes promote→demote, RebalancedOut still suppresses every
  shared-state release. v2 does not touch any of this.

## 9. Risk assessment
| Class | Level | Note |
|---|---|---|
| Behavioral regression | LOW (OFF) | default-OFF byte-identical; ON re-uses reviewed move machinery |
| #1203 within-queue floor recurs on CoS-on (shared_exact) | **MED** | §4 argues fixed by #913/#1735; UNPROVEN with count-balanced placement until live A/B in BOTH CoS modes; documented PLAN-OUTCOME if it recurs |
| Count-vs-rows skew | LOW | structurally avoided by same-snapshot count (§2.2 option 1) |
| Truncation feeds bad count | LOW | guarded (§2.3); cannot fire at P12 |
| Heterogeneous traffic unfair | MED (documented) | count-balance cannot fix within-worker rate skew; §3.6 follow-up gated on #1750 |
| Hot-path perf | NONE | coordinator-cadence O(rows) count; no per-packet work |
| Live gate still 0 installs | LOW | count signal is reliable (proven); the byte-rate stall that caused 0 installs is removed entirely |

## 10. Test plan (for the eventual `/engineer` increment)
- **Pre-code live trace:** `--features debug-log` deploy on loss cluster, P12
  -p5210; capture `REBALANCE_EVAL` and confirm per-worker ROW counts match
  `xpf_userspace_binding_active_flow_count` (proves the same-snapshot count is
  the reliable signal) and that `flows_per_worker` is non-empty on the hottest
  worker.
- **Unit (`controller_tests.rs`):**
  - `count_balance_converges_to_even_partition` (drive `[2,2,1,1,4,2]` →
    `[2,2,2,2,2,2]` over N ticks, assert `Φ` monotone-decreasing, terminates).
  - `count_overshoot_guard_blocks_1_delta` (`3,2` → no move).
  - `count_delta_threshold_K` (imbalance `< K` → Balanced).
  - `cooldown_prevents_immediate_thrash` (moved flow not re-chosen next move).
  - `truncated_snapshot_defers` (no decision on truncated rows).
  - `slot_ne_worker_id_still_selects` (keying regression, carried from #1748).
  - the existing second-move-chain + budget-exhaustion + barrier-order tests
    pass UNCHANGED (move machinery untouched).
- cargo build + full suite + 5× flake of the controller tests; go suite (schema
  leaf label).
- **Live A/B CoV gate (acceptance) in BOTH CoS modes:** enable knob, `-P12
  -p5210` (CoS-on shared_exact) AND a CoS-off run, v4+v6, push + `-R`: confirm
  `installs_total > 0`, per-worker count → even (`2,2,2,2,2,2`), per-flow CoV →
  R1-class (~3-4% CoS-off; measure CoS-on), aggregate not regressed, bounded
  retransmits (incremental moves). Default-OFF control run unchanged.
- Full Pass A/B smoke matrix (v4+v6 × push+reverse × CoS-off/on).
- **`make test-failover`** — MANDATORY (the move machinery touches HA session
  ownership; unchanged from #1748 but must stay clean).

## 11. Out of scope / follow-ups
- **Heterogeneous rate-aware tiebreak** (§3.6(b)) — gated on a reliable per-flow
  byte feed (#1750 Path 2 cold-path eviction side-table or ordinal signal); no
  current heterogeneous live gate. Documented follow-up.
- **#1750 atomic bundle adoption** — recommended hardening; adopt when #1750
  ships (Path B becomes free).
- **shared_exact within-queue follow-up** — IFF the live A/B gate shows
  count-balanced placement + post-#1735 shared_exact MQFQ does not reach
  R1-class CoV on the CoS-on path, file a within-queue scheduler issue (the
  #1203 residual, on the now-different #1735 scheduler) — distinct from this
  placement controller.
- R2 reverse-direction rules, R4 HA peer rule-mirroring — already #1748 §9
  follow-ups, unchanged.
