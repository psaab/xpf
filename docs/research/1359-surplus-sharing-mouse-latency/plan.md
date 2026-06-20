# #1359 — surplus-sharing fails p99.9 mouse-latency gate while strict-exact passes

**Status: DRAFT v1 (draft-fanout, no reviewers run yet)**
Branch: `research/1359-surplus-sharing-mouse-latency`
Author: Claude (research draft)
Disposition (see §11): **LIKELY-DEFER-LAB** — the diagnosis and the gate
itself are LAB-bound, and the upstream measurement path is blocked by
**#1365** (high-rate 100E100M cells fail cwnd-settle before the mouse
probe even runs). A scheduler-tuning code increment is *plausible* but
must not be merged before a lab artifact reproduces the tail and a
second artifact proves the fix.

---

## 1. Issue framing

Under the reduced 100-elephant / 100-mouse (`100E100M`) latency matrix:

- **Strict exact** (`transmit-rate exact`, no surplus): loaded
  `N=100,M=100` p99.9 mouse latency ≈ **7.4–7.6 ms**, idle ≈ 6.6–6.9 ms,
  ratio ≈ 1.1 (gate threshold ≤ 2.0). **PASS.**
- **Surplus-sharing** (`MOUSE_COS_SURPLUS_SHARING=1`, the diagnostic
  fixture that flips `surplus-sharing` on the elephant scheduler): loaded
  p99.9 mouse latency jumps to **29–51 ms** on the *valid* reps, with
  invalid reps showing per-coroutine progress collapse
  (`degenerate-coroutine`: `min_attempts` 66–303 vs median ≈ 2890, p99.9
  spikes to ~1 s). **FAIL → INSUFFICIENT-DATA after #1361.**

The elephant queue under surplus borrows more root rate (q4 ≈ 1.22–1.30
Gbps vs ≈ 825 Mbps strict exact), confirming surplus *is* doing its job —
but at a steep best-effort/mouse tail-latency cost. The issue owner's own
framing: "this is a real work-conserving tradeoff problem, not just a
harness preflight failure."

The current gate verdict for surplus is **INSUFFICIENT-DATA** (not FAIL),
because after the #1361 fail-closed reducer fix the loaded surplus cell
cannot produce ≥ the required valid-rep count. The *product signal*
survives that reframing: the valid loaded samples that do exist show tail
latency ~4–7× the strict-exact baseline.

### Acceptance criteria (verbatim from the issue)

1. Explain *why* surplus-sharing creates 30–50 ms p99.9 mouse latency
   while strict-exact stays ~7–8 ms under the same 100E100M shape.
2. Add telemetry / artifact fields that pin the cause to one of: queue
   residence, worker-scheduling starvation, timer-wheel wake delay, root
   surplus arbitration, or CPU contention.
3. **Either** change surplus behavior so the reduced `N=100,M=100` p99.9
   gate passes, **or** explicitly document that surplus-sharing is not
   compatible with the 100E100M mouse-latency contract.

Note the acceptance is satisfiable by *documentation alone* (option 3) —
this is important for scope discipline (see §3).

### Dependency: #1365 (BLOCKING for high-rate validation)

#1365 is the reason this is lab-deferred rather than directly engineerable.
At the default 5201 / 1 Gbps elephant class, strict-exact reaches the
probe and surplus reproduces the tail — that evidence is real. But at
5202 / 10 Gbps (and presumably higher classes), the loaded 100-elephant
cell fails the 20 s cwnd-settle gate in 15/15 reps (`INVALID-cwnd-not-
settled`), so the harness never starts the mouse probe. We therefore
**cannot** today claim surplus passes or fails at high rate; the
measurement is blocked *upstream of the mouse window*. Any "fix verified"
claim that rests only on the 1 Gbps class is incomplete by construction.

---

## 2. Blast radius (code walked)

The surplus scheduler is entirely in the Rust AF_XDP dataplane
(`userspace-dp/`). The Go control plane only carries the config flag.

**Hot path (per-tick TX drain), single-writer per worker:**

- `userspace-dp/src/afxdp/cos/queue_service/mod.rs`
  - `drain_shaped_tx()` (line ~159) — the per-binding drain loop. **Does
    exactly ONE batch per call**, in this priority order:
    1. `service_exact_guarantee_queue_direct_with_info()` (exact queues'
       guarantee pass — strict priority over everything below),
    2. `build_nonexact_cos_batch()` → `select_nonexact_cos_guarantee_batch()`
       (non-exact guarantee pass),
    3. → `select_cos_surplus_batch_filtered()` (the surplus DRR pass).
  - `select_cos_surplus_batch_filtered()` (line ~1311) — the heart of the
    bug surface. Walks `queue_indices_by_priority[0..6]` in **strict
    priority order**, round-robin within a priority via
    `rr_index_by_priority`. Per queue it: (a) skips empty/non-runnable,
    (b) skips exact queues unless `surplus_sharing` is set (the #915
    gate), (c) parks on root-token starvation, (d) runs **deficit
    round-robin (DRR)**: tops up `surplus_deficit` by
    `cos_surplus_quantum_bytes(queue)` and skips if still under head_len.
  - `cos_surplus_quantum_bytes()` (line ~1770) =
    `COS_SURPLUS_ROUND_QUANTUM_BYTES (1500) × surplus_weight.max(1)`. **A
    surplus-sharing elephant and a best-effort mouse default to the same
    1500 B quantum and the same priority band unless config separates
    them.**
- `userspace-dp/src/afxdp/cos/tx_completion.rs`
  - `CoSServicePhase` enum (Guarantee | Surplus), `ParkReason`,
    `park_cos_queue()`, the timer wheel (`COS_TIMER_WHEEL_TICK_NS =
    50_000` ns; 256 × 256 slot wheel, ~3.28 s horizon).
  - Surplus debit: `apply_cos_*_result` debits `surplus_deficit` (not
    `tokens`) in the Surplus phase (line ~801).
- `userspace-dp/src/afxdp/cos/fairness.rs` — per-bucket EWMA rate
  accounting + `bucket_target_bps()` cap-aware MQFQ selector input.
- `userspace-dp/src/afxdp/tx/drain/mod.rs` — constants
  (`COS_SURPLUS_ROUND_QUANTUM_BYTES = 1500`, `COS_GUARANTEE_VISIT_NS =
  200_000`, quantum min/max).
- Telemetry struct: `userspace-dp/src/afxdp/types/cos.rs`
  (`root_token_starvation_parks`, `queue_token_starvation_parks`,
  `drain_surplus_sent_bytes`, `drain_park_root_tokens`,
  `drain_park_queue_tokens`).

**Slow path / config (Go):**

- `pkg/config/types_cos.go` — `SurplusSharing bool` (+ `surplus_weight`).
- `pkg/config/parser_class_of_service_test.go` — flat-set + hierarchical
  surplus-sharing tests; note **equal-flow-enforcement cannot be combined
  with surplus-sharing** (already rejected at compile).

**Test harness (bash, lab-only):**

- `test/incus/test-mouse-latency-matrix.sh` — `MOUSE_COS_SURPLUS_SHARING`
  fixture switch, the `degenerate-coroutine` validity guard, the
  `cwnd-not-settled` settle gate (the #1365 blocker), and the per-rep
  `INVALID-*` marker reducer.

**NOT in blast radius:** HA/failover (no cluster-state code touched),
boot-class, byte-order, dual-AST parsing (the config flag is already
parsed both ways and tested), and the conntrack/forwarding path. This is
a *scheduler-internal* concern on the TX drain hot path of a single
worker. A code increment, if any, is hot-path-allocation-sensitive
(per-tick, single-writer) but HA-neutral.

---

## 3. Honest scope & value

The surplus-sharing feature exists to make a class **work-conserving** —
let an exact-capped elephant borrow idle root rate. That is a legitimate
and desirable WAN-SQM property. The mouse-latency contract (#1321) is the
*counter-constraint*: best-effort/interactive mice must keep a bounded
tail under load.

The blunt truth is that **these two goals are in direct tension and the
issue may have no "free" fix.** Work-conservation hands the elephant more
in-flight bytes; more in-flight bytes means a deeper standing queue at the
shaper/NIC; a deeper standing queue means a longer worst-case wait for the
next mouse packet. This is textbook bufferbloat-vs-utilization. A
scheduler tweak can *shift* the operating point but cannot make both the
elephant's borrow AND the mouse's tail strictly better than strict-exact
simultaneously — strict-exact achieves its 7 ms tail precisely *because*
it refuses the elephant the extra bytes.

So the realistic outcomes are, in increasing order of churn:

- **(D) Document-only**: accept that surplus-sharing trades mouse tail for
  throughput, document the incompatibility with the 100E100M latency
  contract, and tell operators to use strict-exact when interactive tail
  matters. This *fully satisfies acceptance option 3* with near-zero risk.
- **(C) Telemetry-only**: add the diagnostic fields (acceptance item 2)
  so the cause is attributable in the artifact, then choose D or B with
  data. Low risk, high information value.
- **(B) Bounded scheduler tuning**: give the best-effort/mouse queue a
  *strict-priority lane over surplus* (it largely has this already — see
  §5 option B1), and/or cap the elephant's per-round surplus borrow so the
  standing queue cannot grow unbounded (B2/B3). Medium churn, must be
  lab-validated, fairness-sensitive.

> **If reviewers conclude the perf gain / scope is too small to justify
> the churn, PLAN-KILL is acceptable.** Given that acceptance is
> satisfiable by documentation alone and the fundamental tradeoff may be
> irreducible, a reviewer could reasonably land C+D and close, treating
> any B-class scheduler change as out of scope or a separate increment.

---

## 4. What's already shipped (do not re-invent)

- **#915 surplus opt-in gate**: exact queues are excluded from surplus by
  default; `surplus_sharing` lifts the skip (`select_cos_surplus_batch_
  filtered` line ~1346). The exact queue's per-queue rate cap stays a
  *guarantee-phase* concept; in surplus it spends `root.tokens +
  surplus_deficit + shared_root_lease`.
- **Strict-priority surplus**: surplus already walks
  `queue_indices_by_priority` in strict priority order. A
  higher-priority best-effort queue is already serviced before a
  lower-priority elephant *within the surplus pass* (see §5 B1 caveat:
  this is only true if config puts the mouse at a higher priority band).
- **Residual-rate clamp under exact demand** (`nonexact_surplus_budget_
  under_exact_demand`): non-exact surplus is capped to `shaping_rate −
  Σ backlogged-exact-guarantee-rate`, so a backlogged exact queue's
  guarantee is reserved before best-effort surplus runs. This is the
  existing fairness backstop — but it caps the *non-exact* borrower, not
  the *surplus-sharing exact* elephant, which is the #1359 actor.
- **#1630 per-visit frame-count cap** (`cos_guarantee_visit_cap_bytes` =
  `TX_BATCH_SIZE × frame` = 64 frames): bounds a single guarantee visit.
  **Note: surplus visits are NOT capped by this** — surplus is bounded by
  `surplus_deficit` (DRR) and `root.tokens` only.
- **#1782 timer-wheel O(slots) snap**: cold-start / catch-up wake delay
  is already addressed; the wheel horizon is 65,536 ticks (~3.28 s).
- **#1361 fail-closed reducer**: insufficient valid reps → INSUFFICIENT-
  DATA, not a silent PASS. This is why the surplus verdict is now
  INSUFFICIENT-DATA.
- **#1364 drain-timeout branch**: bounds probe `writer.drain()`.
- Park-reason telemetry (`root_token_starvation_parks`,
  `queue_token_starvation_parks`) and surplus-sent-bytes counters already
  exist — a telemetry increment *extends* these, it does not start cold.

---

## 5. Concrete design — multiple path options

The acceptance has three independent deliverables (explain / telemetry /
fix-or-document). The *explain* and *telemetry* parts are common to all
paths; the *fix-or-document* part is where the path options diverge.

### 5.0 Common: the leading hypothesis for the tail (the "explain")

`drain_shaped_tx` emits **one batch per call** and surplus is the *last*
phase. Under 100E100M with surplus on:

1. The elephant (exact + surplus_sharing) is backlogged and runnable.
2. In the surplus DRR pass it accumulates `surplus_deficit` in 1500 B
   quanta and spends `root.tokens` — borrowing the idle root rate the
   mouse is not using moment-to-moment.
3. The borrowed bytes form a **standing queue at the shaper/NIC TX ring**.
   The mouse packet that arrives next must wait behind that standing
   queue's drain time. At ~1.3 Gbps borrow, a few-ms standing queue is
   exactly the 29–51 ms p99.9 we see once tail events stack.
4. The `degenerate-coroutine` collapse (min_attempts 66 vs median 2890)
   is the smoking gun for *episodic* starvation: during a borrow burst,
   some mouse coroutines get zero forward progress for a window, not just
   elevated average latency. This points at **root-surplus arbitration +
   queue residence**, not CPU contention (probe error rate stayed low)
   and not timer-wheel wake delay (the wheel snap shipped in #1782).

The telemetry (§5.1) is designed to *confirm or refute* this hypothesis
before any scheduler change — the worst failure mode here is "fixed" the
wrong layer (cf. the project's repeated lesson about chasing the wrong
layer in #1921/#1961).

### 5.1 Common: telemetry / artifact fields (acceptance item 2)

Add per-queue, owner-only (single-writer, no atomics needed on the hot
path; published via the existing snapshot) counters that distinguish the
five candidate causes:

- `surplus_borrow_bytes` (already partly via `drain_surplus_sent_bytes`)
  attributed **per queue** — how much each queue borrowed.
- `surplus_standing_queue_max_bytes` / EWMA — peak `queued_bytes` on the
  elephant during the loaded window (queue residence proxy).
- `mouse_park_ticks` — sum of ticks a best-effort queue spent parked on
  `RootTokenStarvation` vs `QueueTokenStarvation` (already have park
  *counts*; add the *duration*).
- `surplus_round_skips` — DRR rounds where the elephant consumed the
  quantum and the mouse was skipped (root-surplus arbitration signal).
- harness-side: emit per-rep elephant `q4` borrow Gbps, mouse-queue park
  duration, and standing-queue peak into the artifact JSON so the
  validity reducer and a human can attribute the tail.

These are **diagnostic outputs only** — no behavior change — so they can
land first as a low-risk increment and immediately make the lab artifact
self-explaining.

### 5.2 Path A — Document-only (acceptance option 3)

Write `docs/cos-surplus-mouse-latency.md` (or extend
`docs/cos-validation-notes.md` / `docs/fairness-regimes.md`) stating that
surplus-sharing is a throughput/work-conservation feature that trades
best-effort tail latency, is **not** compatible with the 100E100M p99.9
contract, and that operators who need bounded interactive tail must use
`transmit-rate exact` without `surplus-sharing`. Mark the surplus
100E100M gate as `EXPECTED-INCOMPATIBLE` rather than FAIL.

- **Pros**: satisfies acceptance, near-zero risk, honest about the
  irreducible tradeoff, no hot-path change.
- **Cons**: leaves a real WAN-SQM use case (borrow idle rate *and* keep
  VoIP/interactive snappy) unserved. Junos `excess-rate`/`excess-priority`
  schedulers *do* offer this; we'd be documenting a capability gap.

### 5.3 Path B — Bounded scheduler tuning (acceptance option "change")

Three sub-mechanisms, mix-and-match, each independently lab-gateable:

**B1 — Mouse strict-priority lane over surplus (mostly already present).**
Ensure the best-effort/mouse queue sits at a *higher priority band* than
the surplus-sharing elephant so `select_cos_surplus_batch_filtered` always
offers the mouse its bytes first. *Caveat*: the diagnostic fixture may put
both in the same band; the real fix might be **config/fixture**, not code.
If the mouse is already higher-priority and still starves, B1 is
insufficient and the cause is standing-queue residence (→ B2/B3).

**B2 — Cap the elephant's per-round surplus borrow (anti-bufferbloat).**
Introduce a surplus *visit* cap analogous to #1630's guarantee
`cos_guarantee_visit_cap_bytes`, but tuned *down* for surplus-sharing
exact queues so a single borrow burst cannot push a multi-ms standing
queue ahead of the next mouse packet. Trades elephant borrow throughput
for mouse tail — directly moves the operating point. Tunable
`surplus_visit_cap_bytes`.

**B3 — Reserve a best-effort surplus floor (symmetric to residual-rate
clamp).** Today `nonexact_surplus_budget_under_exact_demand` reserves
*exact-guarantee* rate before *non-exact* surplus. Add the dual: reserve a
small best-effort floor before a *surplus-sharing exact* queue may borrow,
so the mouse always retains a slice of root rate even while the elephant
borrows. This is the most principled but the most invasive (new shared
budget, must be HA/worker-safe and single-writer-clean).

- **Pros**: actually serves the borrow-and-stay-interactive use case;
  moves the gate toward PASS.
- **Cons**: every B variant is a fairness-sensitive hot-path change that
  MUST be lab-validated against BOTH the mouse gate AND the existing
  fairness CoV floor (`docs/fairness-regimes.md`, 6-worker denominator) —
  a fix that passes the mouse gate but regresses elephant fairness or the
  strict-exact baseline is a net loss. B3 touches shared budget state and
  needs the same single-writer / no-hot-path-alloc discipline as the
  existing residual-rate clamp.

### 5.4 Recommended sequencing

1. **Increment 1 (telemetry + doc framing)**: §5.1 + §5.2 draft. Low
   risk, makes the artifact self-explaining, satisfies acceptance items 1
   and 2 and *conditionally* 3 (document). **This is the shippable first
   increment if B is pursued at all.**
2. **Increment 2 (only if a B-class fix is desired AND #1365 is resolved
   enough to reach the probe)**: pick ONE B mechanism, gate it on the lab.
   Do not bundle B1+B2+B3 in one PR.

Recommended path: **A+telemetry first (§5.1 + §5.2)**, then re-evaluate B
with data. Treat B as a separate, lab-gated, multi-increment effort.

---

## 6. Public API preservation

- **Go config flag** `surplus-sharing` (and `surplus-weight`): unchanged.
  Both flat-set and hierarchical parse paths already exist and are tested
  (`parser_class_of_service_test.go`). No new commit-time grammar.
- **gRPC / REST / CLI**: no new RPCs or commands for telemetry — extend
  the existing CoS snapshot / `show class-of-service`/`show system
  buffers` surfaces (additive fields only; no field renames, no wire-type
  changes — see the #1961 `[]uint8` base64 lesson, not applicable here as
  these are scalar `u64` counters but the additive-only rule stands).
- **Snapshot wire (Go↔Rust)**: any new telemetry fields are scalar
  numerics — encode as plain integers, never `[]uint8` (the #1976/#1977
  `WireUint8List` trap). Additive struct fields with serde defaults so a
  newer Rust helper decodes an older Go snapshot and vice versa.
- **No behavior change in Path A / telemetry-only**: identical scheduling
  decisions; counters are write-only diagnostics.

---

## 7. Hidden invariants to preserve

- **Hot-path allocation**: `drain_shaped_tx` / `select_cos_surplus_batch_
  filtered` run per-tick on the TX drain. New telemetry must be plain
  field increments on owner-only state — **no `Vec`/`Box`/`String`/map
  insert in the surplus loop** (cf. #1755 probestack-elimination lesson).
- **Single-writer discipline**: FlowFairState and per-queue hot state are
  owner-only (the worker that drains the queue). Telemetry that another
  thread reads must use the existing snapshot-publish path
  (`AtomicU64` only where already atomic), not a new cross-worker mutation.
- **DRR fairness invariant**: `surplus_deficit` is topped up by quantum
  and debited by actual sent bytes (`tx_completion.rs:801`). Any B2 visit
  cap must keep the deficit/debit accounting exact so long-run rate is
  still metered by tokens, not by the cap (the #1630 invariant: cap bounds
  a *visit*, not the *rate*).
- **#915 exact-cap semantics**: surplus-sharing must not turn into an
  uncapped firehose — the per-queue rate cap stays a guarantee-phase
  concept; surplus spends root tokens + deficit only. B-class changes must
  not leak the elephant past `root.tokens`.
- **Residual-rate clamp**: B3 must compose with `nonexact_surplus_budget_
  under_exact_demand` without double-reserving or starving.
- **HA / failover**: none of this touches cluster state, session sync, or
  VRRP. **No `make test-failover` dependency for Path A / telemetry.** A
  B-class change does not touch HA code either, but per project rule any
  CoS change that could affect the dataplane should still smoke on the
  cluster (which IS the lab here).
- **Boot-class / byte-order / dual-AST**: not in scope (config flag
  already parsed both shapes; no new typed leaf; no IP/`__be32` fields).
- **Timer-wheel correctness**: do not alter `park_cos_queue` /
  `advance_cos_timer_wheel` (the #1782 O(slots) snap is provably behavior-
  identical and fragile to touch).

---

## 8. Risk table (4-class)

| Class | Risk | Likelihood | Impact | Mitigation |
|-------|------|-----------|--------|------------|
| **Correctness** | B2 visit cap breaks DRR rate metering (cap mistaken for rate) | Med | High (rate regression) | Keep deficit/debit exact; cap bounds visit only; unit test long-run rate == tokens, not cap |
| **Correctness** | B3 shared best-effort floor double-reserves or starves elephant | Med | High | Compose with existing residual-rate clamp; oracle test budget conservation |
| **Performance** | New telemetry adds per-tick alloc/atomic to surplus hot path | Low | Med (throughput regression) | Owner-only field increments; publish via existing snapshot; objdump/perf check |
| **Performance** | B-class fix passes mouse gate but regresses elephant fairness CoV or strict-exact baseline | **High** | High (net-negative) | Lab gate BOTH mouse p99.9 AND fairness CoV (`docs/fairness-regimes.md`) AND strict-exact baseline before/after |
| **Compat/Wire** | New snapshot field decoded wrong across Go↔Rust version skew | Low | Med | Scalar `u64` only, serde default, additive; never `[]uint8` |
| **Lab/Process** | "Fix verified" claimed from 1 Gbps class only, while #1365 blocks high-rate | **High** | High (false confidence) | Block any B-merge until #1365 lets exact reach the high-rate probe; require both a repro artifact and a fix artifact |
| **Lab/Process** | Degenerate-coroutine guard misattributed (harness defect vs real starvation) | Med | Med | Telemetry must independently confirm dataplane standing-queue/park before trusting harness validity verdict |
| **Scope** | B-class churn lands for a tradeoff that's arguably irreducible | Med | Med | Telemetry+doc first; PLAN-KILL B if reviewers judge gain too small |

---

## 9. Test plan — and what it needs

This is **fundamentally a lab issue**. The metric (p99.9 mouse latency
under 100E100M) only exists on the loss userspace cluster via
`test/incus/test-mouse-latency-matrix.sh`. There is no unit-test
substitute for the gate verdict.

**Unit-testable (CI, no lab):**
- Telemetry counters increment correctly (synthetic surplus DRR rounds).
- B2: long-run drained bytes == token-metered rate, NOT the visit cap
  (regression oracle — must FAIL if the cap is mistaken for the rate).
- B3: shared best-effort floor budget conservation (oracle over random
  rings, cf. `fused_diff_tests.rs` style).
- Snapshot encode/decode round-trip of new fields (Go↔Rust).

**Lab-only (loss userspace cluster — BLOCKED layering):**
- Reproduce the 1 Gbps surplus tail (already done by the issue owner —
  reuse the artifact shape).
- **#1365 gate**: confirm strict-exact reaches the mouse probe at the
  target class before claiming any surplus fix. At 10 Gbps this is
  *currently impossible* (cwnd-not-settled 15/15).
- After a B fix: re-run the 100E100M matrix under surplus AND under strict
  exact (baseline must not regress) AND the fairness CoV check.
- `make test-failover`: **NOT required** — no HA/cluster/VRRP/session-sync
  code is touched. (Stated explicitly per project rule.)

**Multi-increment?** Yes. Telemetry+doc is increment 1 (CI + a single lab
repro). Any B fix is increment 2, lab-gated, and itself should be ONE B
mechanism per PR. Do not attempt B1+B2+B3 in one change.

---

## 10. Out of scope

- **#1365 itself** (high-rate cwnd-settle harness fix). It is a *blocking
  dependency* for high-rate validation but a separate issue with its own
  acceptance. This plan does not fix the settle gate.
- Full Junos `excess-rate` / `excess-priority` scheduler model — a much
  larger feature; documenting the gap (Path A) is in scope, implementing
  it is not.
- Cross-worker / shared-NIC fairness redesign (`docs/cross-worker-flow-
  fairness-research.md`) — orthogonal.
- The `equal-flow-enforcement` × surplus-sharing interaction (already
  rejected at compile).
- Any change to the timer wheel (#1782) or the #1630 guarantee visit cap.

---

## 11. Open questions (for adversarial review)

1. **Is the tail irreducible?** Can ANY scheduler change make the
   surplus-sharing elephant's borrow AND the mouse p99.9 both ≤ strict-
   exact, or is this a hard utilization-vs-latency Pareto front where the
   only honest answer is Path A (document)? If irreducible, B-class work
   is wasted churn → PLAN-KILL B.
2. **Is the mouse already higher-priority than the elephant in the
   diagnostic fixture?** If yes, B1 is a no-op and the cause is purely
   standing-queue residence (B2/B3 territory). If no, the "fix" may be a
   fixture/config change, not dataplane code — which would shrink this to
   telemetry + doc + harness.
3. **Is `degenerate-coroutine` measuring a real dataplane starvation, or
   a harness/probe artifact under load?** The issue notes probe error
   rate stayed low and it's "not the old port-7 accept storm" — but we
   must independently confirm via dataplane telemetry (park duration,
   standing-queue peak) before trusting the validity verdict. Misattribut-
   ing a harness defect as a scheduler bug would send a B fix at the wrong
   layer (the project's recurring failure mode).
4. **Does the existing residual-rate clamp already half-solve this for
   non-exact borrowers, leaving only the surplus-sharing-EXACT case
   (#1359's actor) unprotected?** If so, B3 is "extend the existing clamp
   to also reserve a best-effort floor against surplus-sharing exact
   queues" — a small, principled delta rather than new machinery.
5. **Can we validate a fix AT ALL given #1365?** If high-rate classes
   can't reach the probe, a B fix is only validatable at 1 Gbps. Is a
   1 Gbps-only validation acceptable to merge, or must #1365 land first?
   (This is the crux of the LIKELY-DEFER-LAB disposition.)
6. **What is the right surplus visit cap (B2) magnitude?** Too small kills
   the borrow throughput (defeats the feature); too large doesn't move the
   mouse tail. Is there a principled value (e.g. one shaper-RTT of bytes)
   or is it pure empirical tuning that only the lab can set?
7. **Does B2/B3 regress the fairness CoV floor** (`docs/fairness-
   regimes.md`, 6-worker mlx5 VF denominator)? A mouse-gate pass that
   breaks elephant inter-flow fairness is a net regression.

---

## 12. Claude self-SMR (hostile)

**Strongest objection to this plan:** *It is over-engineered for an issue
whose acceptance is satisfiable by a paragraph of documentation.* The
issue explicitly allows "explicitly document that surplus-sharing is not
compatible with the 100E100M mouse-latency contract" as a complete
resolution. The tradeoff between work-conservation and tail latency is a
well-understood, arguably irreducible Pareto front (bufferbloat 101): the
elephant borrows idle rate → standing queue grows → mouse tail grows.
Strict-exact gets 7 ms *because* it forbids the borrow. Spending a
fairness-sensitive, lab-gated, multi-increment B-class scheduler change to
chase a gate PASS — when (a) the change can only be validated at 1 Gbps
until #1365 lands, (b) it risks regressing the fairness CoV floor and the
strict-exact baseline, and (c) it may be physically impossible to satisfy
both constraints — is a poor bet.

**Second objection:** the high-rate evidence does not even exist yet
(#1365), so we are reasoning about a tail we can only measure at one rate.
Committing to a code fix before the measurement is reachable is exactly
the "verify-before-trust" failure the project keeps relearning.

**Counter-argument (why not pure PLAN-KILL):** acceptance item 2
(telemetry) is genuinely useful regardless of the fix decision — it makes
every future surplus artifact self-explaining and lets a human (or
reviewer) decide doc-vs-fix *with data* instead of speculation. And Junos
*does* offer borrow-and-stay-interactive via excess-rate scheduling, so a
B-class fix is a real (if larger) capability, not a fiction. Telemetry +
doc is low-risk and high-value; it should land.

**Explicit disposition: LIKELY-DEFER-LAB.**

- The diagnosis (acceptance item 1) and any fix verification require the
  loss userspace cluster, and high-rate verification is **blocked by
  #1365**. Nothing here is mergeable on CI alone.
- **Shippable first increment (if anyone proceeds): the telemetry +
  doc-framing increment (§5.1 + §5.2)** — CI-testable counters plus a
  doc that records the tradeoff and marks the surplus 100E100M gate
  `EXPECTED-INCOMPATIBLE`. This satisfies acceptance items 1, 2 and
  conditionally 3.
- The B-class scheduler change is **DEFER-LAB and arguably PLAN-KILL**:
  do not pursue it unless (1) telemetry confirms the cause is standing-
  queue residence (not a harness artifact, OQ #3), (2) #1365 is resolved
  enough to validate at the target class (OQ #5), and (3) a reviewer
  judges the borrow-and-stay-interactive capability worth the fairness
  risk (OQ #1, #7). If the tail proves irreducible, **PLAN-KILL B and
  ship Path A only.**

Recommended path: **§5.4 sequencing — telemetry + doc first
(DEFER-LAB for the repro artifact), B-class deferred/PLAN-KILL pending the
open questions and #1365.**
