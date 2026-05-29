# #1630 — v8 rotation credit-carry: seqlock-safe bounded deficit to fix small-class shape loss

- Issue: #1630
- Branch: `research/1630-v8-credit-carry` (off `origin/master` @ `dbfbf680c`)
- Mode: `/research` — plan only; NO production code touched; STOP at PLAN-READY.
- Author: Claude SMR (CoS-scheduler / WFQ-DRR / token-bucket / seqlock-concurrency / AF_XDP multi-worker-shaper / HA-failover domain)
- Rev: **v3** (r1+r2+r3 reviews folded). **Status after r3:
  PLAN-NEEDS-MAJOR, converged on a measurement-gated fork (§12).** r3:
  Codex PLAN-NEEDS-MAJOR (3 BLOCKING — regime-2 draw rule undefined,
  global burst cap re-introduces #1614 via FCFS starvation, ResetCoSEpochs
  not retag-correct); Claude SMR self-corrected to concur; AGY r3 result
  infra-blocked (investigation aligned). The §3.6 SOLO A/B is the pivot:
  Fork A (small-K+P2 clears Gate 1 → simple, burst-safe fix; r3 blockers
  dissolve) vs Fork B (only large-K clears it → architecturally blocked
  by the small-class-first-allocator constraint). **Run §3.6 first.**

> This round does **not** re-derive the root cause. Three prior diagnosis
> rounds converged; the third is measurement-proven (engineer log on
> `fix/1630-cos-lease-watermark` @ `b29fdb344`). This plan designs the
> **seqlock-safe, burst-bounded, HA-safe credit carry** that the prior
> converged plan explicitly deferred as "Path B — out of scope, seqlock-
> risky" (`docs/research/1630-cos-equalize-rootcause/plan.md` §5 row B,
> §9). The deferral is now the work.

---

## 0b. v3 changelog (round-2 review response)

Both r2 reviewers (Codex + AGY) returned PLAN-NEEDS-MAJOR on v2; I
self-corrected my too-lenient r2 PLAN-READY. v3 fixes:

- **[Codex r2 B1 / AGY r2 F3 — aggregate cap unsound] FIXED (§3.5.1).**
  v2's thread-local `C_agg` only bounded per-worker burst → `N × C_agg`
  aggregate across N≈6 workers (leases are Arc-cloned to every worker,
  `acquire_v8(worker_id,…)` is multi-worker). v3 moves the budget to a
  single shared atomic `carry_release_budget` on `SharedCoSRootLease`
  (already shared by all workers), refilled once per root epoch, drawn
  via atomic CAS by all workers → genuinely global, independent of N.
- **[AGY r2 F1 — `else` branch clamps to 1 epoch] FIXED (§5.3).** v2's
  `raw_elapsed.min(EPOCH_DURATION_NS)` made mechanism A inert; v3 regime
  1 uses `raw_elapsed` (bounded by the K guard).
- **[Codex r2 B2 / AGY r2 F2 — self-heal cliff at K×EPOCH] FIXED
  (§5.3 + §5.3.1).** v2 reused `K×EPOCH` as both the rate-recovery width
  AND the cold-resume cutoff, so a legitimate 12-epoch lag (§3.4's own
  example) hit an 8× cliff and dropped its carry. v3 introduces a
  **decoupled `STALL_THRESHOLD` (≈256 epochs)** and THREE regimes:
  normal (≤K), bank-residual (K<lag≤STALL, no cliff, mechanism B), and
  cold-resume (>STALL). STALL sized between the §3.6 legitimate-tail p99
  and the ≥500-epoch failback gap.
- **[AGY r2 F4 — punted ResetCoSEpochs fallback] FIXED (§5.3.2).** The
  fallback command is now fully designed: enum variant, producer routing
  (`ha.rs` demote+promote), consumer handler (`loop_body` →
  seqlock-safe `reset_epoch_state()`), visibility invariant, idempotency.

---

## 0. v2 changelog (round-1 review response)

All three r1 reviewers returned **PLAN-NEEDS-MAJOR** with a strongly
overlapping finding set. v2 addresses each:

- **[BLOCKING, all 3] Loss model inconsistent / K=8 does not clear the
  gate.** v1 claimed "A alone clears Gate 1" while citing probe numbers
  94.5/95.3/**84.9 (3g)**/94.4% against a "each ≥95%" gate. **v2 retracts
  that claim.** The primary production mechanism is NOT pre-decided; it is
  selected by a *mandatory discriminating measurement* (§3.6) that
  resolves the heavy-tail-vs-P2 ambiguity BEFORE /engineer commits a
  mechanism. P2 is promoted from "likely prerequisite" to
  **load-bearing-pending-A/B** (§6).
- **[BLOCKING, Codex F4 — decisive] HA "fresh lease" proof was FALSE.**
  v1 §5 claimed leases are rebuilt at `start==0` on failover. Codex
  proved (and I verified) that leases are **reused** when config matches
  (`coordinator/mod.rs:1106-1116` `matches_config_v8` →
  `out.insert(key, lease.clone())`), and HA demotion only queues
  `VacateAllSharedExactSlots` (V_min slots) + `DemoteOwnerRGS`
  (`ha.rs:48-55`), which does **not** reset the queue lease's
  `epoch_start_ns`. On same-node failback with unchanged config the same
  lease Arc survives with a stale `start`, so the first post-reactivation
  `acquire_v8` sees `lag ≈ demotion_duration` and mechanism A grants a
  `K×rate×EPOCH` burst (B preserves stale carry too). v2 adds an
  **explicit stale-`start` self-heal** to the rotation (§5, the decisive
  fix) plus a re-promotion epoch reset.
- **[BLOCKING/HIGH, all 3] Aggregate simultaneous-resume burst
  unbounded.** v1 bounded only single-class burst. Codex showed the 10
  named exact rates sum to 109.1 G → aggregate K=8 release ≈ 21.8 MB,
  and the **root lease uses raw elapsed** (`mod.rs:853`
  `elapsed_ns = now_ns - last_refill_ns`, NOT epoch-clamped) with a
  default burst floor of only 1% of rate (`forwarding_build/cos.rs:66`).
  The root shaper therefore does NOT absorb the aggregate burst. v2 adds
  an **aggregate burst invariant + global per-tick release cap** (§3.5).
- **[MINOR, Codex F5 + Claude MAJOR-5] Seqlock writer wording / carry
  enforcement.** v2 downgrades payload stores to `Relaxed` (matching the
  `cold_path_hist.rs:572` reference), keeps the single `Release` publish,
  and adds an **enforced carry-reader-private guard** (§4.0).

---

## 1. Problem statement

`cos-iperf-config.set` on `loss:xpf-userspace-fw0/1`, `reth0.80`:
`shaping-rate 25g`, `oversubscription-policy guarantee-rate 0.7`, 11
exact classes (`transmit-rate {100m..24g} exact`), best-effort q0,
uncapped q11.

Documented contract (`docs/fairness-regimes.md`): under guarantee-rate,
small-rate exact classes whose aggregate fits the Phase-1 budget should
each reach ~100% of configured rate first.

**Proven floor (measurement-established, not hypothesis):** even SOLO
(one class, one port, zero competition, 12 streams, push, v4) the small
exact classes cannot reach their shape:

| Class | Shape | SOLO % of shape (master) |
|-------|------:|-------------------------:|
| iperf-100m | 0.1 G | 81.4 % |
| iperf-1g   | 1.0 G | 83.7 % |
| iperf-3g   | 3.0 G | 89.9 % |
| iperf-6g   | 6.0 G | ~85 % |

Efficiency rises with rate. This is a **per-class rate-metering floor**
in the v8 epoch rotation, independent of cross-class competition. The
diagnostic probe (relax the rotation clamp to `8 × EPOCH_DURATION_NS`)
lifted the solo ceilings to 94.5 / 95.3 / 84.9(noisy) / 94.4 %,
isolating the rotation clamp as the dominant loss. The probe is unsafe
(unbounded burst after a stall — "Gate-4 risk"); this plan replaces it
with a bounded carry.

---

## 2. Verified root cause (confirmed against origin/master)

### 2.1 The clamp

`userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs`,
STEP 6 of `maybe_rotate_epoch_v8` (verified lines, origin/master
`dbfbf680c`):

```rust
// rotate_epoch_v8.rs:214-223
let elapsed_ns = if start == 0 {
    EPOCH_DURATION_NS
} else {
    (now_ns - start).min(EPOCH_DURATION_NS)        // <-- line 218: the clamp
};
let new_cap_raw =
    ((self.config.rate_bytes as u128) * (elapsed_ns as u128) / 1_000_000_000u128) as u64;
let new_cap = new_cap_raw.min(u32::MAX as u64);
v8.epoch.epoch_total_grant_cap.store(new_cap, Ordering::Release);   // line 224
...
v8.epoch.epoch_start_ns.store(now_ns, Ordering::Release);          // line 237
v8.epoch.epoch_seq.store(seq + 2, Ordering::Release);              // line 239 (ODD->EVEN publish)
```

The confirmed mechanism (I re-derived it; it matches the engineer log):

1. `EPOCH_DURATION_NS = 200_000` (200 µs), confirmed
   `shared_cos_lease/mod.rs:241`.
2. Rotation is **purely lazy**: the only non-test call site is
   `acquire_v8` (`mod.rs:1042`). There is no timer thread forcing a
   rotation every 200 µs. Rotation happens only when a worker calls
   `maybe_top_up_cos_queue_lease` → `acquire_via_lease` → `acquire_v8`
   for that queue (`cos/token_bucket.rs:101`).
3. A low-rate class is **visited intermittently**. At 100 Mbit
   (`rate_bytes = 12.5e6 B/s`), one 200 µs epoch's full cap is
   `12.5e6 × 200e-6 = 2500 bytes` — below one 4096-byte TX frame
   (`tx_frame_capacity()`). The exact-queue top-up watermark is
   `lease_bytes.max(tx_frame_capacity)=4096` (`token_bucket.rs:188`),
   so the queue can only usefully act every ~2 epochs. Under the
   scheduler's round-robin across 11+ classes the gap between two
   `acquire_v8` calls for the *same* low-rate queue routinely exceeds
   one epoch.
4. On the next visit at `now`, with `lag = now − start > EPOCH`,
   rotation runs **once** and computes
   `elapsed = min(lag, EPOCH) = EPOCH`, so
   `new_cap = rate × EPOCH = 2500 B` — even though `lag` worth of rate
   credit (`rate × lag`) accrued in wall-clock.
5. The discard is **permanent**: `epoch_start_ns := now_ns`
   (line 237), NOT `start + EPOCH`. The interval
   `[start + EPOCH, now]` of wall-clock is erased from the rate budget
   forever. The class's achievable throughput is therefore
   `rate × EPOCH / lag_avg` — strictly below `rate` whenever
   `lag_avg > EPOCH`. This is the exact shape of the SOLO efficiency
   curve (rises with rate, because higher-rate classes are visited more
   often → smaller `lag/EPOCH`).

**Confirmed:** the engineer's line reference (`:214`/`:218`) and
mechanism are correct. The clamp at line 218 plus the
`epoch_start_ns := now_ns` reset at line 237 together discard
`rate × (lag − EPOCH)` bytes of grant per lagged rotation.

### 2.2 Why the watermark/bank approach (Path A) was inert

Confirmed independently: the binding limiter is `epoch_total_grant_cap`
(the rate-metered per-epoch grant), not the per-queue bucket ceiling.
A saturated class drains its bucket below one frame every visit
(`park_queue ≫ 0`, `park_root = 0`), so raising the bucket watermark or
`max_total_leased` changes nothing — the grant the bucket is allowed to
draw is already the bottleneck. The fix must enlarge the **grant**, not
the bucket.

### 2.3 Why the naive un-clamp is unsafe (the design constraint)

The clamp bounds burst. If a worker (or the whole RG) stalls for
seconds — GC pause, HA failover hold, scheduler starvation under DDoS —
an unclamped `elapsed` computes `new_cap = rate × seconds`, a single
multi-megabyte one-shot grant. That violates the shaper's burst bound:
the class would emit a burst far above its configured rate over the
window immediately following the stall. The diagnostic probe
(`× 8`) is a hard-capped relaxation, not a true fix; even `× 8` admits
an 8-epoch (1.6 ms) burst, and an unbounded relax is a Gate-4
violation. **The carry must be bounded.**

---

## 3. Design: bounded rotation credit carry (DRR-style deficit)

### 3.1 The invariant we must preserve

Define the shaper contract over any window `[t0, t1]` of length
`W = t1 − t0`:

> Total grant issued over `[t0, t1]` ≤ `rate × W + B_max`, where `B_max`
> is the configured burst bound.

Today's clamp enforces a *stronger* (over-tight) bound by also forbidding
`rate × W` to be reached after a lag (it floors grant at
`rate × Σ min(lag_i, EPOCH) ≤ rate × W`). We want to relax to *exactly*
`rate × W + B_max` — recover the lagged rate, but never exceed the
burst.

### 3.2 Mechanism (chosen): carry deficit on `epoch_total_grant_cap`

Add one `AtomicU64` to `SharedCoSEpochState`:
`epoch_carry_bytes` — the unbanked rate credit owed to the class,
written **only by the rotation winner** (single-writer, inside the
seqlock ODD critical section), read only by the rotation winner.

Rotation STEP 6 changes from:

```rust
let elapsed_ns = (now_ns - start).min(EPOCH_DURATION_NS);   // OLD
let new_cap = (rate * elapsed_ns / 1e9).min(u32::MAX);
```

to:

```rust
// NEW — bounded carry
let raw_elapsed_ns = now_ns - start;                         // unclamped wall-clock
let clamped_ns     = raw_elapsed_ns.min(EPOCH_DURATION_NS);
let overshoot_ns   = raw_elapsed_ns - clamped_ns;            // == raw - EPOCH (or 0)

// rate-bytes that the clamp would have discarded this rotation:
let new_owed = (rate as u128 * overshoot_ns as u128 / 1e9) as u64;

// accumulate into a *bounded* carry deficit:
let prev_carry = epoch_carry_bytes.load(Acquire);            // single-writer read
let carry = prev_carry.saturating_add(new_owed).min(MAX_CARRY_BYTES);

// this epoch's cap = base (rate*clamped) + a bounded *slice* of carry:
let base_cap   = (rate as u128 * clamped_ns as u128 / 1e9) as u64;     // == old new_cap when lag<=EPOCH
let carry_draw = carry.min(MAX_CARRY_DRAW_PER_EPOCH);                   // bounded per-epoch release
let new_cap    = base_cap.saturating_add(carry_draw).min(u32::MAX as u64);

epoch_carry_bytes.store(carry - carry_draw, Release);        // remaining owed
epoch_total_grant_cap.store(new_cap, Release);
```

Two independent bounds, each defending a different failure mode:

- **`MAX_CARRY_BYTES`** caps the *reservoir*: no matter how long the
  stall, the class can never owe more than this. This is the burst-bound
  guard. Set `MAX_CARRY_BYTES = K_res × rate × EPOCH` with small
  `K_res` (proposed `K_res = 4` → ≤ 800 µs of rate, i.e. ≤ 4 frames'
  worth for 100m, ≤ ~2.4 MB for 24g). The reservoir is the *total* extra
  bytes a class can ever burst after an arbitrarily long stall.
- **`MAX_CARRY_DRAW_PER_EPOCH`** caps the *drain rate*: how fast the
  reservoir converts to grant. This bounds the instantaneous burst
  *immediately after resume* and guarantees the deficit drains
  smoothly over several epochs (DRR semantics). Proposed
  `MAX_CARRY_DRAW_PER_EPOCH = base_cap` (i.e. at most double the
  per-epoch rate while draining → recovery at ≤ 2× rate, classic DRR
  catch-up, bounded). With this choice the post-stall burst over any
  window is ≤ `2 × rate × W` until the reservoir empties, then exactly
  `rate × W`.

### 3.3 Why this fixes Gate 1 (worked numeric trace — low-rate, lagging)

100m class, `rate = 12.5e6 B/s`, `EPOCH = 200 µs`,
`rate × EPOCH = 2500 B`. Choose `K_res = 4` →
`MAX_CARRY_BYTES = 10 000 B`; `MAX_CARRY_DRAW_PER_EPOCH = base_cap`.

Suppose the scheduler visits this queue once every `1 ms` (5 epochs of
lag) under load. **NOTE (v2):** the scalar loss model `eff = EPOCH /
mean_lag` inverts the measured 81.4% SOLO to a *mean* lag of only
~1.23 epochs, which would predict K=8 reaches ~100% — yet the probe
measured 94.5%. The 5-epoch figure here is an illustrative trace, NOT
the measured mean; the true lag distribution is heavy-tailed (§3.6),
which is exactly why the mean-based model and the probe disagree. The
trace below is kept only to motivate the constant-derivation that
follows; the *binding* analysis is §3.6.

| Visit | lag (ns) | overshoot (ns) | new_owed | carry (pre-draw, ≤10k) | base_cap | carry_draw (≤base) | new_cap | reservoir after |
|------:|---------:|---------------:|---------:|-----------------------:|---------:|-------------------:|--------:|----------------:|
| t1 | 1.0e6 | 0.8e6 | 10000 | 10000 | 2500 | 2500 | 5000 | 7500 |
| t2 | 1.0e6 | 0.8e6 | 10000 | 10000 (clip) | 2500 | 2500 | 5000 | 7500 |
| t3 | 1.0e6 | 0.8e6 | 10000 | 10000 (clip) | 2500 | 2500 | 5000 | 7500 |

Steady state: each visit grants `base_cap + carry_draw = 5000 B` over a
1 ms interval → effective rate `5000 / 1e-3 = 5e6 B/s = 40 Mbit`. The
class only reaches `2×rate` while draining, but the reservoir is
**clipped at 10 000 B**, so the long-run grant per ms is capped at
`base_cap + MAX_CARRY_DRAW = 2 × base_cap` and the *owed* beyond the
reservoir (`new_owed − accepted`) is genuinely dropped. **This trace
shows the chosen constants are too tight for a 5-epoch lag** — at 40
Mbit the class only reaches 40% of shape, not 95%.

**This is the key design tension, surfaced honestly:** to reach ≥95% the
**drain rate** must keep up with the lag, i.e. `MAX_CARRY_DRAW_PER_EPOCH`
must be large enough that `base_cap + carry_draw ≈ rate × lag`. With
`lag = L × EPOCH`, we need `carry_draw ≈ (L−1) × base_cap`, i.e.
`MAX_CARRY_DRAW_PER_EPOCH ≈ L_max × base_cap`. And the reservoir must
hold one visit's worth: `MAX_CARRY_BYTES ≈ L_max × base_cap`.

So the two constants are really **one** physical quantity:
`L_max × EPOCH` = the maximum lag the carry fully compensates. **This is
identically the diagnostic probe's `K × EPOCH` clamp** — but expressed
as a reservoir+drain so that lags *beyond* `L_max` are bounded (the
reservoir clips) instead of unbounded. The corrected design:

- `MAX_CARRY_BYTES = L_max × rate × EPOCH`
- `MAX_CARRY_DRAW_PER_EPOCH = (L_max − 1) × rate × EPOCH`
  (so a single on-time visit after a full-reservoir lag emits
  `base_cap + (L_max−1)×base_cap = L_max × base_cap = rate × L_max ×
  EPOCH` in one grant — **this is the burst**, bounded by `L_max`).

This collapses the "DRR slow-drain" story: because a low-rate queue is
visited *once* per long interval, it must receive the full lagged credit
*in that one visit* or it can never catch up (there is no subsequent
near-term visit to drain into). So the carry is **not** drained over
many epochs for a low-rate class — it is released in the single visit,
capped by `L_max`. **The honest mechanism is a bounded `elapsed`, i.e.
`elapsed = min(lag, L_max × EPOCH)`, which is mathematically identical
to the probe with `K = L_max`.** The carry reservoir adds value ONLY for
the case where a class is visited *more often than once per lag window*
(higher-rate classes), where it smooths multi-visit catch-up.

### 3.4 Re-framed mechanism (what the design actually reduces to)

Given §3.3, the minimal core fix is `elapsed = min(lag, K×EPOCH)` with
`K = MAX_ROTATION_LAG_EPOCHS`. **NOTE (v3):** the production form is NOT
this two-branch snippet — it is the **three-regime** rotation of §5.3
(normal recovery / bank-residual / cold-resume), which fixes the v2
`else`-branch bug and the cold-resume cliff. The snippet below is the
*conceptual* core; read §5.3 for the actual code:

```rust
// CONCEPTUAL ONLY — see §5.3 for the production three-regime form.
const MAX_ROTATION_LAG_EPOCHS: u64 = 8;   // K, from the §3.6 sweep
let elapsed_ns = if start == 0 {
    EPOCH_DURATION_NS
} else {
    (now_ns - start).min(EPOCH_DURATION_NS * MAX_ROTATION_LAG_EPOCHS)
};
```

with the burst bound now `rate × K × EPOCH` of rate — a hard, configured
ceiling. The "credit carry" reservoir of §3.2 is the *generalization*
that also handles the residual `lag − K×EPOCH` by banking it (clipped at
`MAX_CARRY_BYTES`) for the next visit, so a class lagging at 12 epochs
with `K=8` recovers 8 now + 4 next visit instead of dropping the 4.

**v2 recommendation (REVISED — no longer "ship A, B optional"):** the
primary production mechanism is **NOT pre-decided**. v1 claimed bounded-
`elapsed` at K=8 "clears Gate 1"; all three r1 reviewers proved that is
false on the cited data (94.5/95.3/**84.9**/94.4% vs a "each ≥95%"
gate). The choice between {A at larger K} vs {A+B carry} vs {A+P2} is
**contingent on the §3.6 discriminating measurement**, which /engineer
MUST run first. The plan commits to a *decision rule*, not a mechanism:

1. If `K=64` SOLO reaches ≥95% on 100m AND 3g but `K=8` does not →
   the loss is the heavy lag tail; ship **A with K sized to the
   measured tail** (and re-check the aggregate burst bound at that K,
   §3.5). Carry reservoir B only if K large enough to clear the gate
   also violates the aggregate burst invariant — then B's bounded drain
   is required to spread the tail recovery.
2. If `K=8 + P2` reaches ≥95% but `K=8` alone does not → the residual
   is the sub-frame selector discard; **P2 is the co-fix** (§6) and K
   stays small (preserving the burst bound).
3. If neither reaches ≥95% on 3g specifically → the 3g loss is NOT the
   rotation clamp; re-open root-cause for that class (the probe's
   "3g=84.9% noisy" is then a mis-attribution, not noise).

### 3.5 Worked burst-bound trace (stalled-then-resumed worker)

Worker stalls 2 s (GC / failover hold), then resumes. `rate = 12.5e6`
(100m). Without any clamp: `new_cap = 12.5e6 × 2 = 25 MB` one-shot →
catastrophic burst. With bounded `elapsed` (`K=8`):
`elapsed = min(2e9, 8 × 2e5) = 1.6e6 ns`, `new_cap = 12.5e6 × 1.6e-3 =
20 000 B`. The post-stall burst is **≤ 20 KB** for 100m (≤ `8 ×
rate × EPOCH` for any class — for 24g: `3e9 B/s × 1.6e-3 = 4.8 MB`,
which is 8 epochs of 24g, still a bounded transient that the downstream
root shaper and NIC ring absorb). **Burst bound holds: no class can
ever emit more than `K × EPOCH` worth of rate in one rotation.**

With the carry-reservoir variant the burst is identical (`MAX_CARRY_DRAW`
≤ `(K−1)×base_cap` enforces the same per-rotation ceiling); the
reservoir only changes whether the residual beyond `K×EPOCH` is dropped
(bounded-elapsed) or banked-and-clipped (reservoir). Either way the
single-rotation grant is `≤ K × rate × EPOCH` **per class**.

### 3.5.1 Aggregate simultaneous-resume burst (v2 — Codex F3 / AGY / Claude MAJOR-4)

The per-class bound above is necessary but NOT sufficient. The real
hazard is **all classes resuming in the same tick** after a poll-loop
stall (the worker loop services every queue in one pass, so a stall that
delays the loop lags *every* queue's rotation simultaneously). Codex's
worked counter-example: the 10 named exact rates sum to **109.1 G**, so
the aggregate one-tick release at K=8 is

```
Σ_i (rate_i × K × EPOCH) = K × EPOCH × Σ rate_i
                         = 8 × 200µs × 109.1e9 B/s / 8  (bytes)
                         ≈ 21.8 MB   in a single worker-loop pass.
```

v1 hand-waved that "the root shaper absorbs it." **That is false** — two
verified repo facts:

1. The root lease refills on **raw elapsed**, NOT epoch-clamped:
   `mod.rs:853` `let elapsed_ns = now_ns - last_refill_ns;`. After a
   stall the root *also* refills its full stalled-duration credit (up to
   its own burst cap), so it does not throttle the aggregate class burst
   the way an epoch-clamped meter would.
2. The default root burst is only **1% of rate floored at 64×1500**:
   `forwarding_build/cos.rs:66`. At 25 G that is ~31 MB — so a 21.8 MB
   aggregate class burst fits *inside* the root burst and is NOT
   throttled. The root is not the backstop.

**v3 aggregate burst invariant + fix (corrected — Codex r2 B1 / AGY r2
F3).** v2's thread-local `C_agg` was UNSOUND: the dataplane runs N≈6
workers (`forwarding_build/cos.rs`), each Arc-clones the same queue
leases (`coordinator/cos_state.rs:8-14`; `acquire_v8(worker_id, …)` is
explicitly multi-worker). A system-wide stall resumes all N workers, each
resetting its OWN thread-local budget → aggregate burst `N × C_agg`,
overrunning the ~31 MB root burst; dividing by N starves a single-owner
queue to 1/N. A thread-local cannot bound a global constraint.

**v3 fix — a true global per-epoch carry-release budget on the SHARED
root lease.** The root lease (`SharedCoSRootLease`) is already the
interface-wide arbiter shared by all workers. Add ONE atomic to it:

```rust
// on SharedCoSRootLease (the existing shared, all-workers object):
carry_release_budget: AtomicU64,   // bytes of carry/over-grant still
                                   // releasable this ROOT epoch
```

- **Refill (single writer per root epoch):** the worker that rotates the
  root epoch (root already has its own epoch/refill at `mod.rs:853`)
  resets `carry_release_budget = C_agg` once per root epoch, where
  `C_agg = min(root_burst_bytes / 2, nic_tx_ring_depth × frame)` — sized
  to BOTH the root burst AND the physical NIC TX ring depth (AGY r2 NIT:
  the burst lands in the ring, not only the root).
- **Draw (all workers, atomic):** each queue lease's carry/over-grant in
  `acquire_v8` does a `fetch_sub`-with-floor (CAS loop) against the
  shared `carry_release_budget`; when it hits 0 the carry is withheld
  that epoch (recovered next epoch). One atomic on an already-shared
  object — low contention because the draw fires only on the *carry/
  over-grant* path (lagged classes), not every acquire.

This makes the aggregate genuinely global: `Σ over all workers and all
classes (carry released this root epoch) ≤ C_agg`, independent of N.

**Gate 5c (aggregate burst) — corrected assertion:** lag ALL leases by
2 s, resume all N workers in one root epoch, assert **total** carry
released across all workers ≤ `C_agg` (NOT per-worker). The test must
exercise N>1 workers to catch the v2 thread-local flaw.

(Alternative (ii) — per-lease K scaled by class share so `Σ rate_i ×
K_i × EPOCH ≤ C_agg` — remains a fallback if the shared-atomic
contention proves measurable; rejected as primary because it couples K
to config and complicates the §3.6 sweep.)

### 3.6 MANDATORY discriminating measurement (v2 — resolves the loss model)

Before /engineer commits a mechanism, run on SOLO (one class, one port,
12 streams, push, v4, `guarantee-rate 0.7`) for **both 100m AND 3g**:

| Variant | 100m % | 3g % | Interpretation |
|---------|-------:|-----:|----------------|
| master (K=1 clamp) | 81.4 | 89.9 | baseline |
| A: K=8 | ? | ? | probe said 94.5 / 84.9(noisy) |
| A: K=64 | ? | ? | if ≈100% → loss is heavy lag tail |
| A: K=8 + P2 | ? | ? | if ≥95% but K=8 alone <95% → P2 is co-fix |
| A: K=64 + P2 | ? | ? | belt-and-suspenders ceiling |

This A/B is the load-bearing experiment; the §3.4 decision rule consumes
its result. The plan does **not** declare a mechanism until this table is
filled. (This is legitimate /research output: the plan specifies the
*decision procedure* and the gate; the mechanism falls out of one
measurement at /engineer time. A throwaway local build A/B during this
research round MAY pre-fill it if the loss cluster is free and the
parallel #1636 / full-review agents are not mid-smoke.)

---

## 4. Seqlock-safety argument (folds in #1643 — pre-existing acquire-fence bug)

The v8 epoch state is published via a seqlock: writer CASes
`epoch_seq` EVEN→ODD (claim), mutates state, stores ODD→EVEN (publish);
readers in `snapshot_epoch_v8` read `seq_before` (must be EVEN), read
`{cap, share, grace, tag}`, re-read `seq_after`, retry if changed.

### 4.0 #1643 — the reader is missing `fence(Acquire)` (VERIFIED, fold in)

A parallel full-codebase review filed **#1643** against this exact
reader. I verified it against origin/master `dbfbf680c`:
`snapshot_epoch_v8` (`mod.rs:1427-1455`) loads the payload with
independent `Acquire` loads and then re-reads `seq_after` with a plain
`Acquire` load — with **no `std::sync::atomic::fence(Ordering::Acquire)`
between the data loads and the trailing seq re-read**. An `Acquire` load
only prevents *later* ops from being hoisted above it; it does NOT pin
the *prior* data loads above the `seq_after` read. On a weakly-ordered
CPU (ARM/POWER) `seq_after` can be observed *before* the payload loads
retire, so the even-equal validation can pass against torn cross-epoch
data. **Confirmed:** there are zero `fence(...)` calls in
`shared_cos_lease/mod.rs`, and the writer
(`rotate_epoch_v8.rs:239`) uses a plain `Release` store. This is the
#1619 seqlock-tearing class. Latent on the x86-TSO i40e deploy target
(TSO forbids load-load reordering) but a real hazard if the dataplane
ever runs on a weakly-ordered CPU.

**The correct reference pattern** is the cold-path histogram seqlock,
which the parallel review verified as correct
(`cold_path_hist.rs:556-595` `snapshot()`):

```rust
let s1 = gen.load(Ordering::Acquire);          // even-check
if s1 & 1 != 0 { backoff; continue; }
// ... payload loads with Ordering::Relaxed ...
std::sync::atomic::fence(Ordering::Acquire);   // SEAL the Relaxed loads
let s2 = gen.load(Ordering::Relaxed);          // re-read
if s2 == s1 { return Some(payload); }
```

**Fold the #1643 fix into this plan** rather than ship it as a separate
PR — a second PR touching the same seqlock would collide and double the
review. The fix to `snapshot_epoch_v8`:

```rust
let seq_before = v8.epoch.epoch_seq.load(Ordering::Acquire);   // even-check (Acquire OK here)
if seq_before & 1 == 1 { ...spin... continue; }
let cap   = v8.epoch.epoch_total_grant_cap.load(Ordering::Relaxed);   // payload -> Relaxed
let share = ...load(Ordering::Relaxed);
let grace = v8.epoch.epoch_grace_expires_ns.load(Ordering::Relaxed);
std::sync::atomic::fence(Ordering::Acquire);                   // NEW: seal payload loads
let seq_after = v8.epoch.epoch_seq.load(Ordering::Relaxed);    // re-read (Relaxed after fence)
if seq_after == seq_before { return Some((cap, share, grace, tag)); }
```

**Writer side (v2 — precise wording, Codex F5 / Claude MAJOR-5).** The
correctness comes from three facts, not from "Release orders prior
Release stores" (which is imprecise — a `Release` store does not order
*other* locations' prior `Release` stores for a *different* reader):

1. **Single writer in program order.** Only the rotation winner is in
   the ODD section (`compare_exchange(AcqRel, Acquire)` at
   `rotate_epoch_v8.rs:46` admits one winner). All payload stores happen
   before the ODD→EVEN publish *in that one thread's program order*.
2. **One Release publish.** The `epoch_seq.store(seq+2, Release)` at
   `:239` is the single release the reader's fenced-Acquire re-read
   synchronizes-with.
3. **Reader fenced-Acquire** (the §4.0 fix) pins the payload reads above
   the `seq_after` read.

Given (1)+(2)+(3), the payload stores **can and should be downgraded to
`Relaxed`** (currently `Release` at `:224` etc.) — matching the
`cold_path_hist.rs:572` reference writer, which stores payload `Relaxed`
under `fetch_add(AcqRel)` claim + `fetch_add(Release)` publish. Keeping
them `Release` is harmless but redundant; the downgrade is part of the
#1643 fix for clarity and parity with the verified-correct reference.

**This sibling bug strengthens, not complicates, the carry design:** the
new carry field MUST observe the *same* fence discipline. Because the
carry is rotation-private (read/written only by the rotation winner
inside the ODD section, never read by `snapshot_epoch_v8` or
`acquire_v8`), it adds nothing to the reader payload and needs no new
reader fence — it rides inside the writer's existing
`compare_exchange(AcqRel)` → `store(Release)` brackets.

**ENFORCED carry-reader-private guard (v2 — Codex F5 / Claude MAJOR-5).**
"Reader-private" must be *enforced*, not asserted, or a future edit
silently reintroduces #1643 for the carry. Required:
- The carry atomic is a private field accessed only via two
  `#[inline]` rotation-internal helpers in `rotate_epoch_v8.rs`; no
  `pub`/`pub(super)` accessor.
- A `#[cfg(test)]` test that greps the crate (or a
  `compile_fail`/visibility test) asserting no `acquire_v8`,
  `snapshot_epoch_v8`, or `coordinator/status.rs` path references
  `epoch_carry_bytes`. (Cheap CI insurance; Gate 5b sibling.)
- If a future variant must surface the carry to status/Prometheus, it
  joins the §4.0 fenced payload region — a documented invariant in the
  struct doc comment.

`Closes #1643` belongs on the /engineer PR alongside the #1630 fix.

`Closes #1643` belongs on the /engineer PR alongside the #1630 fix.

**Both mechanisms (bounded-elapsed and carry-reservoir) are seqlock-safe
by construction:**

1. **Bounded-`elapsed` (§3.4):** changes only the *value* written to
   `epoch_total_grant_cap` at line 224 — it adds no new published field,
   no new atomic read in the reader path. The seqlock contract is
   byte-for-byte unchanged; `snapshot_epoch_v8` reads the same four
   fields. **Zero seqlock surface change.** This is the decisive
   argument for preferring §3.4: it cannot introduce the #1619
   seqlock-tearing class because it touches no publication shape.

2. **Carry-reservoir (§3.2):** `epoch_carry_bytes` is written and read
   **only by the rotation winner**, entirely inside the ODD critical
   section (between the EVEN→ODD CAS at `rotate_epoch_v8.rs:44` and the
   ODD→EVEN store at line 239). It is **never read by acquirers** —
   `snapshot_epoch_v8` does not read it; `acquire_v8` does not read it.
   Therefore it is *not part of the published payload*; it is rotation-
   private mutable state that happens to live in the shared struct. Only
   one thread is ever in the ODD section (the CAS guarantees a single
   winner; line 44-51). Hence the carry read/modify/write is a
   single-threaded RMW with no concurrent reader → no torn read, no new
   seqlock invariant. The `Acquire`/`Release` on the carry atomic are
   redundant (the surrounding seqlock CAS already fences) but harmless
   and self-documenting.

   **The one hazard to verify in review:** the carry must be read/written
   only after the EVEN→ODD CAS succeeds and before the ODD→EVEN store —
   i.e. it must NOT be touched on the early-return paths (peer rotating,
   CAS lost). Confirmed: all early returns (`mod.rs`-extracted lines
   33-35, 39-41, 45-51) precede the critical section; placing the carry
   RMW alongside the existing STEP 6 cap computation satisfies this.

   **Reader-side cap range:** the published `cap` already varies epoch to
   epoch; readers treat it as opaque. Adding `carry_draw` only widens the
   value range of an existing field, which the reader and `acquire_v8`
   primary/surplus loops already tolerate (they compare `class_granted <
   cap` with a tag-checked CAS; a larger `cap` simply admits more grant
   that epoch, still tag-fenced). No new tearing path.

**Conclusion:** §3.4 has zero seqlock risk; §3.2's carry is rotation-
private and does not extend the published seqlock payload. Neither
introduces the #1619 class. (#1619 was a *reader-visible* field added to
the payload without widening the seq-guarded read; the carry is
deliberately *not* reader-visible.)

---

## 5. HA-failover-safety argument (v2 — CORRECTED; Codex F4 was decisive)

> **v1 was wrong here.** v1 claimed leases are rebuilt fresh
> (`start==0`) on every failover, so the standby's first grant is
> harmless. Codex's Finding 4 (which I verified against origin/master)
> falsifies that: **leases are REUSED when the config matches.**

### 5.1 The actual lease lifecycle (verified)

`coordinator/mod.rs:1106-1116` reuses an existing lease when
`matches_config_v8(transmit_rate, burst, active_shards, max_worker_id,
rate_mode)` holds:

```rust
if let Some(lease) = existing.get(&key).filter(|lease| {
    lease.matches_config_v8(...)
}) {
    out.insert(key, lease.clone());   // SAME Arc survives
    continue;
}
out.insert(key, Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode(...)));
```

HA demotion (`ha.rs:48-55`) queues only `DemoteOwnerRGS` +
`VacateAllSharedExactSlots`; the latter vacates **V_min slots only**
(`worker/cos/mod.rs:305 vacate_all_shared_exact_slots_for_binding`), NOT
the queue lease's epoch state. Re-promotion (`ha.rs:119`) queues
`RefreshOwnerRGS`. **Nothing in the demote→promote cycle resets
`epoch_start_ns`.**

### 5.2 The worked counter-example (the bug v2 must fix)

1. Node A active; lease L for the 100m queue has `epoch_start_ns = t0`.
2. A demotes for 2 s (peer takes over). Config unchanged on A.
3. A re-promotes. Reconcile finds L matches config →
   `out.insert(key, L.clone())`: **the same Arc, `start` still = t0**.
   `ensure_v8_lease_attached` sees the same Arc (ptr_eq) → no re-attach,
   no reset.
4. First post-promotion `acquire_v8(now = t0 + 2s)` →
   `maybe_rotate_epoch_v8`: `lag = now − start ≈ 2 s`.
   - Mechanism A: `elapsed = min(2s, K×EPOCH) = K×EPOCH` →
     `new_cap = rate × K × EPOCH` = a **`K`-epoch burst on the first
     post-failback grant**, exactly the burst the clamp was protecting
     against, now re-introduced by the K relaxation on a stale `start`.
   - Mechanism B: the carry reservoir *also* survived in L (it is
     per-lease, never reset) → it adds its banked `MAX_CARRY_BYTES` on
     top. Worse.

This is the HA double-grant the charter's constraint #4 demanded be
ruled out. v1 missed it because v1 assumed a fresh lease.

### 5.3 The fix: THREE-regime rotation with a DECOUPLED stall threshold (v3)

> **v3 corrects two v2 defects** (Codex r2 B2 / AGY r2 F1+F2): (1) the v2
> `else` branch `raw_elapsed.min(EPOCH_DURATION_NS)` clamped to ONE epoch,
> making mechanism A inert — a literal code bug; (2) the v2 cold-resume
> cutoff at `K×EPOCH` collided with the legitimate heavy-tail visit lag
> (§3.4's own 12-epoch example), causing an 8× step-function drop and
> dropping the very carry B was meant to recover. v3 **decouples** the
> stall threshold from `K` and uses three regimes:

```rust
// K = MAX_ROTATION_LAG_EPOCHS (rate-recovery width, e.g. 8..64 from §3.6)
// STALL = STALL_THRESHOLD_EPOCHS (cold-resume cutoff, DECOUPLED from K,
//         sized below a failback gap and ABOVE any legitimate tail; see
//         §5.3.1). e.g. STALL = 256 epochs ≈ 51.2 ms.
debug_assert!(STALL_THRESHOLD_EPOCHS > MAX_ROTATION_LAG_EPOCHS);

let raw_elapsed = now_ns - start;
let lag_epochs = raw_elapsed / EPOCH_DURATION_NS;

let elapsed_ns = if start == 0 || lag_epochs > STALL_THRESHOLD_EPOCHS {
    // REGIME 3 — cold start / stall / failback gap:
    // grant exactly one epoch, bank NOTHING, drop stale carry.
    if start != 0 { epoch_carry_bytes.store(0, Release); }
    EPOCH_DURATION_NS
} else if lag_epochs > MAX_ROTATION_LAG_EPOCHS {
    // REGIME 2 — legitimate heavy-tail lag beyond K but below stall:
    // grant the full K-epoch width NOW (mechanism A ceiling) and BANK
    // the residual (lag − K) into carry for the next visit (mechanism B).
    // No cliff: a 12-epoch lag at K=8 grants 8 now, banks 4. (matches §3.4)
    let overshoot_ns = raw_elapsed - EPOCH_DURATION_NS * MAX_ROTATION_LAG_EPOCHS;
    let new_owed = (rate as u128 * overshoot_ns as u128 / 1e9) as u64;
    let carry = epoch_carry_bytes.load(Acquire)
        .saturating_add(new_owed)
        .min(MAX_CARRY_BYTES);
    epoch_carry_bytes.store(carry, Release);   // drained next visit, capped
    EPOCH_DURATION_NS * MAX_ROTATION_LAG_EPOCHS
} else {
    // REGIME 1 — normal recovery: lag within K. (FIX: bound by K*EPOCH,
    // NOT 1*EPOCH — this was the v2 bug.)
    raw_elapsed   // == raw_elapsed.min(K*EPOCH) since the guard bounds it
};
```

Properties:
- **Regime 1 (lag ≤ K):** mechanism A fully active — recovers the common
  intermittent-visit lag. (v2's `.min(EPOCH)` bug is fixed.)
- **Regime 2 (K < lag ≤ STALL):** NO cliff. The legitimate heavy tail
  gets the full K-epoch grant now plus banked residual (B), drained next
  visit and capped at `MAX_CARRY_BYTES`. This is where mechanism B earns
  its keep and where the v2 cliff is eliminated.
- **Regime 3 (lag > STALL, or start==0):** cold-resume — one epoch, drop
  carry. Bounds the post-failback/stall burst to `rate × EPOCH`,
  identical to today's `start==0` grant. The carry drop prevents B
  double-grant across the gap.
- Per-rotation grant is `≤ max(K×EPOCH, 1×EPOCH) × rate = K×rate×EPOCH`
  in all regimes (regime 2 grants exactly K, banks the rest) → the
  §3.5.1 global cap still bounds the aggregate.

### 5.3.1 Sizing STALL_THRESHOLD (the decoupling — Codex r2 B2 / AGY r2 F2)

`STALL` must satisfy `legitimate_tail_p99 < STALL × EPOCH < failback_gap`.

- **Lower bound (legitimate tail):** the §3.6 sweep measures the visit-
  lag distribution; `STALL` must exceed its p99 so regime 2 (not regime
  3) handles real heavy-tail visits. If §3.6 shows the tail p99 is, say,
  ~30 epochs, `STALL = 256` has a 8× margin.
- **Upper bound (failback / stall gap):** a planned failback is ≥100 ms
  (daemon start + dataplane load + sync hold, per CLAUDE.md "Failback
  timing ~130 ms") = ≥500 epochs; a GC pause that should reset is ≥ tens
  of ms. `STALL = 256 epochs ≈ 51 ms` sits below a failback gap and above
  the tail.
- **If the bounds overlap** (legitimate tail p99 ≳ failback gap — very
  unlikely given 500-epoch failback vs single/double-digit-epoch visits),
  the lag-magnitude heuristic is unsafe → use the §5.3.2 explicit reset
  command INSTEAD. §3.6 decides; the plan now specifies BOTH paths fully.

### 5.3.2 Fallback: explicit `WorkerCommand::ResetCoSEpochs` (fully designed — AGY r2 F4)

If §5.3.1 shows the heuristic bounds overlap, replace the regime-3
lag-magnitude trigger with an explicit reset driven by the HA lifecycle:

- **New variant:** `WorkerCommand::ResetCoSEpochs` in the existing worker
  command enum (sibling of `DemoteOwnerRGS`/`VacateAllSharedExactSlots`/
  `RefreshOwnerRGS`).
- **Routing (producer):** `ha.rs` enqueues it on the **re-promotion**
  path (alongside `RefreshOwnerRGS` at `ha.rs:119`) AND on the
  **demotion** path (alongside `VacateAllSharedExactSlots` at
  `ha.rs:55`) — demotion reset is cheap insurance so a reused lease is
  clean before the gap, not only after.
- **Handler (consumer):** the worker poll loop (where
  `VacateAllSharedExactSlots` is handled, `loop_body/mod.rs:579`) calls a
  new `lease.reset_epoch_state()` on each attached v8 queue lease:
  `epoch_start_ns.store(0)`, `epoch_carry_bytes.store(0)`,
  `epoch_total_grant_cap.store(0)`, and bump `epoch_seq` to an even value
  via the seqlock claim/publish so concurrent readers see a consistent
  reset (NOT a bare store — must go through the EVEN→ODD→EVEN protocol to
  preserve the §4.0 seqlock invariant).
- **Visibility invariant:** the reset is single-writer (the owning
  worker), goes through the seqlock, and zeroes exactly the fields the
  `start==0` first-rotation branch already handles — so a post-reset
  `acquire_v8` takes the identical `start==0` cold path. No new reader
  surface.
- **Idempotent + race-safe:** resetting an already-reset lease
  (`start==0`) is a no-op; the seqlock claim serializes against a
  concurrent rotation.

**Recommendation:** ship the §5.3 three-regime heuristic as primary (it
also covers non-HA stalls — GC, scheduler starvation — that no command
catches), and add §5.3.2 ResetCoSEpochs as belt-and-suspenders on the HA
demote/promote path (cheap, removes any dependence on the heuristic
margin for the HA case specifically). §3.6's measured tail decides
whether the heuristic margin alone is sufficient or the command is
required.

### 5.4 Cross-node safety (unchanged from v1, still valid)

The carry/epoch state is per-lease, per-node, in-process heap state,
never serialized into session-sync, config-sync, or heartbeat (verified:
no `carry`/lease reference in `protocol.rs`/`protocol.go`; only sessions
and config are synced). A failover cannot transfer carry between nodes.
The standby builds/reuses its OWN lease locally. ✓

### 5.5 Empirical gate

`make test-failover` (mandatory for any TX-shaping change) PLUS a new
assertion: after a deliberate demote→promote cycle on the loss cluster,
the newly-active node's first-epoch grant for each class ≤ `rate × EPOCH`
(no `K`-epoch failback burst). The §5.2 counter-example becomes a unit
test in `shared_cos_lease_tests.rs`: `acquire_v8(0, t0, huge)` then
`acquire_v8(0, t0 + 2e9, huge)` on a REUSED lease (not a fresh one) →
assert the second grant ≤ `rate × EPOCH`, proving the self-heal fires.

**Conclusion (v3):** the carry/clamp cannot double-grant across a
failback because (a) the regime-3 cold-resume (§5.3, lag > STALL or
start==0) collapses an implausible lag to a single-epoch grant and drops
stale carry, with STALL decoupled from K so legitimate heavy-tail visits
(regime 2) are NOT penalized, and (b) the §5.3.2 `ResetCoSEpochs`
command provides an explicit seqlock-safe reset on the HA demote/promote
path as belt-and-suspenders. This is the fix v1 missed and the v2 cliff
defect corrected.

---

## 6. Compose with prior work (P2 + watermark)

`fix/1630-cos-lease-watermark` @ `b29fdb344` retains:
- **P2** (per-visit FRAME-count cap at the selectors) — removes the
  sub-frame-remainder discard at the selector.
- **P1 watermark** (`lease_bytes.max(bank)`) — raises the bucket ceiling.

**Assessment — are these prerequisites?**

- **P2 is LOAD-BEARING-pending-A/B (v2 — promoted from "likely").** The
  §3.6 measurement explicitly tests `K=8 + P2` vs `K=8` alone. If the
  residual loss is the sub-frame selector discard (BLOCKING-1 branch
  (b)), P2 is the co-fix and a low `K` suffices — which is *strongly
  preferable* because it preserves the burst bound. Mechanism: once the
  v8 fix grants the lagged credit, the per-queue bucket receives more
  bytes, but a low-rate class whose per-visit grant is < 1 frame
  (100m = 2500 B < 4096 B frame) still cannot emit a frame at the
  selector without P2's frame-count cap. **The /engineer fix folds P2 in
  by default**, and the §3.6 A/B confirms whether it is the residual
  lever or merely harmless. This is the cheapest path to ≥95% that keeps
  K small.

- **P1 watermark is likely NOT required and possibly inert.** The
  engineer proved the watermark sweep (N=8→64) is flat: the bucket
  ceiling was never the binding limiter. Once the carry enlarges the
  *grant*, the bucket fills faster, but the watermark only sets how full
  the bucket is *allowed* to get before top-up stops — it does not gate
  the grant. **Recommendation: drop P1 from the eventual fix unless
  measurement shows the carry over-fills and the bucket clips.** Keep it
  only if it is provably harmless and helps (engineer says it is rate-
  safe / Gate-4-holds, so it is harmless; the question is whether it
  helps — measure).

**Explicit statement for the return contract:** P2 is load-bearing-
pending-A/B (fold in, confirm via §3.6); P1 watermark is independent and
probably unnecessary (measure before keeping). Neither is THE fix; the
fix is the v8 bounded-`elapsed` (§3.4) + the stale-`start` self-heal
(§5.3) + the aggregate burst cap (§3.5.1), with P2 as the selector-side
co-fix.

---

## 7. Acceptance gate (canonical) + new burst & HA gates

Primary: `test/incus/cos-gate1-small-four-alone.sh` (100m/1g/3g/6g,
alone, 12 streams, push, v4, `guarantee-rate 0.7`). Each ≥ **95% of
configured shape**. Today: 81/84/90/~85% SOLO. **The probe's K=8 numbers
(94.5/95.3/84.9/94.4%) do NOT clear this gate — see §3.6; the mechanism
that clears it is selected by measurement, not pre-assumed.**

Full matrix (per memory feedback: v4+v6 × push+`-R` × CoS-off+CoS-on):
- **Gate 1 (small-class SOLO ≥ 95%)** — the primary fix gate.
- **Gate 1b (full simul-load)** — small-class starvation (#1614) must
  improve; small classes ≥ 95% under the 5-class and 11-class simul.
- **Gate 2 (priority-low ≥ 5% of cluster ceiling)** — must not regress.
- **Gate 3 (per-class retransmits ≤ 100/30 s)** — must not regress.
- **Gate 4 (aggregate ≥ ~19.5 G)** — no throughput regression.
- **NEW Gate 5 — burst bound:** stalled-then-resumed worker must not
  emit a grant > `K × rate × EPOCH`. **Test design:** a Rust unit test
  in `shared_cos_lease_tests.rs` that calls
  `acquire_v8(0, T, huge)` then `acquire_v8(0, T + 2_000_000_000, huge)`
  (a 2 s lag) and asserts the second grant ≤ `K × rate × EPOCH` (not
  `rate × 2 s`). Plus a cluster check: after a deliberate worker stall
  (or the failover hold), the instantaneous post-resume rate over the
  first 10 ms ≤ shape × small constant.
- **NEW Gate 5b — #1643 fence regression:** unit test pins the
  `fence(Acquire)` between the payload loads and the `seq_after` re-read
  in `snapshot_epoch_v8` + the carry-reader-private guard (§4.0).
- **NEW Gate 5c — aggregate simultaneous-resume burst (§3.5.1, v3):** lag
  ALL leases by 2 s and resume **N>1 workers** in one root epoch; assert
  the **total carry released across all workers** ≤ `C_agg` (≤ root
  burst). MUST use N>1 to catch the v2 thread-local flaw (a single-worker
  test would pass the broken design). HARD gate.
- **NEW Gate 5d — no-cliff regime-2 (§5.3, v3):** a lag of `K+1` epochs
  must grant `K×rate×EPOCH` + bank residual (NOT drop to `1×EPOCH`); a
  lag of `STALL+1` epochs must cold-resume to `1×EPOCH`. Two unit tests
  pinning the regime boundaries, guarding against the v2 cliff regression.
- **NEW Gate 6 — HA failover/failback safety (§5):** `make test-failover`
  passes (zero-drop) AND the §5.2 reused-lease unit test passes (second
  acquire after a 2 s gap on a REUSED lease grants ≤ `rate × EPOCH`,
  proving the §5.3 self-heal fires) AND no post-failback throughput spike
  above shape on the newly-active node's first epoch.

---

## 8. Candidate mechanisms — tradeoff table

All variants now **require** the §5.3 stale-`start` self-heal (HA) and
the §3.5.1 aggregate burst cap, regardless of A-vs-B. Those are not
optional; the table compares only the *credit-recovery core*.

| # | Mechanism | Clears Gate 1 (each ≥95%)? | Burst-bounded? | Seqlock surface | HA surface | Complexity | Verdict (v2) |
|---|-----------|---------------|----------------|-----------------|------------|------------|---------|
| A | **Bounded `elapsed = min(lag, K×EPOCH)`** (§3.4) | **UNPROVEN at K=8** (probe 94.5/95.3/**84.9**/94.4 — three <95%). Possibly at larger K (§3.6) | YES per-class `≤ K×rate×EPOCH`; aggregate needs §3.5.1 | **NONE** (changes a value, not payload) | needs §5.3 self-heal (stale `start` on reused lease) | Lowest (+self-heal+agg-cap) | **Candidate; selected only if §3.6 shows it clears the gate** |
| A+P2 | A + per-visit frame cap (§6) | likely, if residual is sub-frame discard (BLOCKING-1 branch b) — keeps K small | YES (small K) | NONE | §5.3 | Low | **Preferred if §3.6 confirms P2 is the residual lever** |
| B | **Carry reservoir on `epoch_total_grant_cap`** (§3.2, DRR deficit) | recovers `lag > K×EPOCH` residual (heavy tail, BLOCKING-1 branch a) | YES — `MAX_CARRY_DRAW`/rotation + `MAX_CARRY_BYTES` reservoir | one rotation-private atomic, NOT in payload (enforced §4.0) | §5.3 must also `store(0)` carry on resume | Medium | **Required if §3.6 shows loss is the heavy lag tail and a gate-clearing K violates §3.5.1 aggregate cap** |
| C | `last_rotation_ns` tracked separately | == A (`start` already IS last_rotation_ns; verified `:237`) | YES | NONE | §5.3 | Low | **Redundant with A** |
| D | Per-worker carry | double-counts class-wide lag; needs per-worker published field → #1619 risk | — | adds reader-visible per-worker field | — | High | **REJECT** |

**Mechanism selection is data-driven (v2):** v1's "A clears Gate 1, B
optional" claim is RETRACTED — it was false on the cited probe data
(three of four classes <95%, 3g 10 pts under). The §3.6 table decides:
A+P2 if the residual is the sub-frame discard (keeps K small, best burst
posture); B if the loss is the heavy lag tail AND the gate-clearing K
would violate the §3.5.1 aggregate burst cap (then B's bounded drain
spreads the tail recovery without a giant aggregate burst). Either way
§5.3 + §3.5.1 are mandatory.

**On D (the prompt's "per-worker vs per-lease" question):** the carry
MUST be per-lease (class-wide). The lagged credit is a property of the
*class* rate-meter (`epoch_total_grant_cap` is class-wide), not of any
worker. A per-worker carry would (i) require a new per-worker published
field → exactly the #1619 seqlock-tearing surface, and (ii)
double-count, since N workers would each bank the same class-wide lag.
The single rotation winner (one thread, holding the ODD seq) is the
correct and only safe owner.

---

## 9. Choice of K (constrained by TWO gates, not one)

`K` is bounded below by "large enough to recover the visit-lag tail to
clear Gate 1" (§3.6) and above by "`K × EPOCH` of *aggregate* rate fits
the §3.5.1 aggregate burst cap" — NOT, as v1 claimed, by the root
shaper (which uses raw elapsed and does not throttle the aggregate
burst, §3.5.1). The probe's K=8 reached only 94.5/95.3/84.9/94.4% (does
not clear Gate 1), so K=8 is a *lower* bound at best. The §3.6 sweep
`K ∈ {8, 16, 64}` finds the smallest K that clears Gate 1 on 100m AND
3g; the §3.5.1 cap then bounds the aggregate burst at that K. **If the
gate-clearing K makes `Σ rate_i × K × EPOCH` exceed `C_agg`, K cannot be
raised further — mechanism B (bounded drain) is then required** to
recover the tail without a giant aggregate one-tick burst. K is a named
`const MAX_ROTATION_LAG_EPOCHS` doubling as the §5.3 cold-resume cutoff.

---

## 10. Risks & residuals

- **R1 — K too small under heavier class counts.** With 11+ classes the
  per-queue visit lag may exceed 8 epochs, so K=8 under-recovers in the
  full simul. Mitigation: Gate 1b (full simul) is a gate; if it fails,
  raise K or add mechanism B's residual-banking. Measured at /engineer.
- **R2 — root shaper does NOT re-bound the aggregate burst (v2
  CORRECTED).** v1 wrongly claimed the root throttles the aggregate. The
  root lease refills on **raw elapsed** (`mod.rs:853`), so after a stall
  it refills its full stalled credit too; its default burst is 1% of
  rate (`forwarding_build/cos.rs:66`, ~31 MB at 25 G) which is *larger*
  than the ~21.8 MB aggregate class burst — so the root does not gate it.
  The §3.5.1 global per-tick carry-release cap is the actual backstop.
  Gate 5c is the hard test.
- **R3 — interaction with the bypass-grace / surplus path.** The carry
  enlarges `cap`; the surplus path and bypass detector read `cap` and
  `class_granted`. Larger `cap` means `aggregate_underuse =
  prev_granted + slack < prev_cap` fires differently. Must re-run the
  iperf-c/iperf-e regimes (the bypass calibration cases) to confirm no
  fairness regression. Owed at /engineer.
- **R4 — `u32::MAX` cap saturation.** `new_cap.min(u32::MAX)` still
  applies; for 24g, `8 × 3e9 × 2e-4 = 4.8e6 < u32::MAX`. Safe. But the
  carry-reservoir variant must also clip its intermediate sums at
  u32/u64 boundaries (`saturating_add`). Noted in §3.2.
- **R5 — P2 dependency unproven.** §6 asserts P2 is load-bearing from
  the engineer's reasoning, not from an A/B. §3.6 measures it directly
  (`K=8 + P2` row) before /engineer declares P2 required.
- **R6 — 3g=84.9% may be a mis-attributed root cause (Codex F1 / Claude
  BLOCKING-2).** If §3.6's `K=64` does not lift 3g to ≥95% SOLO, the 3g
  loss is NOT the rotation clamp and the root cause for that class is
  re-opened. The plan does not assume 3g is fixed by this work until the
  §3.6 table shows it.
- **R7 — STALL_THRESHOLD tuning (v3 — decoupled from K).** §5.3.1 sizes
  `STALL` between the §3.6 legitimate-tail p99 and the ≥500-epoch
  failback gap. Measured at /engineer; if (very unlikely) the tail p99
  and a failback gap overlap, switch the regime-3 trigger from the
  lag-magnitude heuristic to the explicit §5.3.2 `ResetCoSEpochs` command
  (fully designed). No longer the K-cutoff cliff of v2.
- **R8 — shared root-budget ordering starvation (Claude r3 MINOR-1).**
  `carry_release_budget` (§3.5.1) is drawn FCFS; a high-rate class could
  drain it before a low-rate Gate-1-victim class releases its carry,
  re-introducing small-class starvation through the burst cap. By design
  the cap fires only on the pathological all-stall path, so steady-state
  carry release should not hit it. Confirm via Gate 1b that the cap does
  not starve small classes in steady state (it must bound only the
  stall-resume transient). If it does, reserve a per-class minimum slice.
- **R9 — root-vs-queue epoch skew (Claude r3 MINOR-2).** The budget
  refills on the root epoch; carry is owed on the queue epoch
  (independent timelines, both ~200µs). /engineer must confirm the root
  refill fires at least as often as queue carry-release so the budget is
  replenished; otherwise a slow root refill throttles legitimate carry.

---

## 11. Plan of action (for /engineer, NOT this round)

0. **FIRST: run the §3.6 discriminating measurement** (`K∈{8,64} ×
   {±P2}` SOLO on 100m AND 3g). This selects the mechanism (§3.4
   decision rule). Do NOT commit a mechanism before this table is filled.
1. Implement the credit-recovery core selected by step 0: bounded
   `elapsed = min(lag, K×EPOCH)` (A) in `rotate_epoch_v8.rs` STEP 6, with
   K from the sweep; add carry reservoir (B) only if step 0 + §3.5.1
   require it.
2. **Mandatory regardless of A/B: the §5.3 THREE-regime rotation**
   (normal recovery ≤K / bank-residual K<lag≤STALL / cold-resume >STALL),
   with `STALL_THRESHOLD_EPOCHS` decoupled from K and sized per §5.3.1.
   This is the HA fix + the cliff fix; NOT optional. Add the §5.3.2
   `ResetCoSEpochs` command on the `ha.rs` demote+promote path as
   belt-and-suspenders (and as the primary regime-3 trigger if §3.6 shows
   the tail/failback bounds overlap).
3. **Mandatory regardless of A/B: the §3.5.1 GLOBAL aggregate per-root-
   epoch carry-release budget** — a single shared `carry_release_budget`
   atomic on `SharedCoSRootLease` (NOT thread-local), refilled once per
   root epoch, drawn by all workers via CAS. Prevents the `N × C_agg`
   simultaneous-resume burst.
4. **Fold in #1643** — fix `snapshot_epoch_v8` to the §4.0 fenced
   pattern; downgrade payload stores to `Relaxed`. PR `Closes #1643`.
5. Fold in **P2** (per-visit frame cap) from `b29fdb344` by default;
   drop P1 watermark unless §3.6 shows it helps.
6. Tests: Gate 5 (single-class burst), **Gate 5c (aggregate burst,
   N>1 workers)**, **Gate 5d (regime boundaries — no cliff at K+1,
   cold-resume at STALL+1)**, Gate 5b (#1643 fence + carry-private
   guard), **Gate 6 reused-lease failback unit test** (§5.2
   counter-example → regime-3 asserts ≤ `rate×EPOCH`).
7. Build, full `cargo test`, deploy to `loss:xpf-userspace-fw0/1`,
   re-apply CoS config (deploy wipes CoS).
8. Full smoke matrix: Gate 1 (SOLO each ≥95%), Gate 1b (simul), Gates
   2/3/4, Gate 5c (aggregate burst), Gate 6 (`make test-failover` +
   failback no-spike). v4+v6 × push+`-R` × CoS-off+CoS-on.
9. Quad-review (Codex + AGY + Claude SMR + Copilot on the PR).

---

## 12. Convergence (after r3) — PLAN-NEEDS-MAJOR + the fork

Three review rounds uncovered escalating design depth. v3 fixed the
literal r2 bugs but Codex r3 (+ Claude SMR r3-corrected; AGY r3 result
infra-blocked, investigation aligned) found three new blockers. The
decisive one is **Codex r3 BLOCKING-3**: the global aggregate-burst cap
(§3.5.1, mandated to fix Codex/AGY r2's `N×C_agg` flaw) and the
small-class-first guarantee (Gate 1, the whole point) **structurally
conflict**. A global cap allocated FCFS lets high-rate classes drain it
and re-starve the low-rate class — re-introducing #1614 — while Gate 5c
still passes (total ≤ C_agg). Eliminating that requires a *global
small-class-first allocator across AF_XDP queue-bound workers*, a class
of mechanism this codebase has repeatedly PLAN-KILLED (MEMORY:
per-5-tuple fairness — AF_XDP ZC queue-binding makes cross-worker
small-class-first allocation infeasible without per-flow XDP_REDIRECT).

Plus: regime-2 has no defined draw rule for the single-visit low-rate
case (BLOCKING-1, contradicts §3.3's own conclusion); `ResetCoSEpochs`
doesn't retag `packed_granted`/`worker_grants` so stale acquirers can
grant post-reset, and loses the EVEN→ODD CAS race (BLOCKING-5).

### The fork — what /research must resolve BEFORE the next plan revision

The §3.5.1 aggregate cap is ONLY needed if the gate-clearing `K` is large
enough that `Σ rate_i × K × EPOCH` exceeds the root/NIC burst. **This
makes the §3.6 measurement the pivot:**

- **FORK A — small-K + P2 clears Gate 1 (the hoped-for branch).** If
  §3.6 shows `K=8 + P2` (or even `K=8` alone) reaches ≥95% SOLO on 100m
  AND 3g, then K is small, the per-class burst is ≤8 epochs, and the
  *aggregate* burst at small K is `8 × 25G × EPOCH / 8 = 25G × EPOCH` —
  one root epoch's worth, which the existing root meter DOES absorb. In
  this branch **the §3.5.1 global cap is unnecessary**, BLOCKING-3
  dissolves, mechanism B is not needed, and the fix collapses to:
  bounded `elapsed = min(lag, K×EPOCH)` (small K) + P2 + the §5.3
  cold-resume (regime 3 only, no regime-2 banking) + #1643 + the
  retag-correct ResetCoSEpochs. That is a tractable, gate-clearing,
  burst-safe, HA-safe fix. **This is the most likely successful path and
  the §3.6 measurement is cheap to run.**
- **FORK B — only large K (heavy tail) clears Gate 1.** If §3.6 shows
  100m needs `K=64` and 3g still lags, then the aggregate burst is large,
  the §3.5.1 cap is required, and BLOCKING-3's small-class-first-allocator
  conflict is real → this approach is **architecturally blocked** by the
  same constraint that killed the per-5-tuple fairness mechanisms.
  Mechanism B's banking does not escape it (the banked credit still
  competes for the same global burst budget). In Fork B, the honest
  disposition is PLAN-KILL-of-bounded-carry and a pivot to either (i)
  shrinking `EPOCH_DURATION_NS` so the clamp loss is smaller per
  rotation (orthogonal, no carry), or (ii) a forced periodic rotation
  (a timer that rotates every epoch regardless of visits, eliminating
  the lag entirely — but that adds a cross-worker timer, its own design
  problem), or (iii) reframing Gate 1 (Path D, charter-unauthorized).

### Recommended next action

**Run the §3.6 SOLO A/B FIRST (throwaway local build, ~30 min on the free
loss cluster) to determine the fork before investing another plan round.**
The entire design complexity (regime-2 banking, global burst cap,
small-class-first allocator) exists ONLY for Fork B. If Fork A holds —
and the engineer's original probe (K=8 → 94.5% on 100m, close to gate)
plus P2's known sub-frame fix suggest it plausibly does — the fix is
simple and the r3 blockers (BLOCKING-1/3) evaporate. This is the
disciplined move: measure the pivot before designing for the harder
branch. Verdict stands at PLAN-NEEDS-MAJOR pending that measurement;
this is NOT yet PLAN-KILL because Fork A is live and untested.

---

## Appendix — verified source anchors (origin/master `dbfbf680c`)

- Clamp: `rotate_epoch_v8.rs:214-218` (`elapsed_ns = (now-start).min(EPOCH)`).
- Cap publish: `rotate_epoch_v8.rs:224`; `start` reset to `now`: `:237`;
  seq ODD→EVEN publish: `:239`.
- `EPOCH_DURATION_NS = 200_000`: `shared_cos_lease/mod.rs:241`.
- Rotation trigger (lazy, sole call site): `mod.rs:1042` in `acquire_v8`.
- Seqlock reader: `snapshot_epoch_v8` `mod.rs:1427-1455` (reads
  cap/share/grace/tag only — carry deliberately excluded).
- Lease constructor (epoch state at 0): `new_v8_with_rate_mode`
  `mod.rs:923`, `SharedCoSEpochState::new()` `mod.rs:309-321`.
- Lease map: `coordinator/cos_state.rs:8,24` (ArcSwap),
  `reconcile/bringup.rs:210` (re-store).
- **Lease REUSE on config match (Codex F4, decisive):**
  `coordinator/mod.rs:1106-1116` `matches_config_v8` →
  `out.insert(key, lease.clone())` (SAME Arc survives).
- **HA demote vacates V_min only, NOT epoch:** `ha.rs:48-55`
  (`DemoteOwnerRGS` + `VacateAllSharedExactSlots`); `ha.rs:119`
  (`RefreshOwnerRGS` on promote); `worker/cos/mod.rs:305`
  (`vacate_all_shared_exact_slots_for_binding` — V_min slots only).
- Worker re-attach (ptr_eq): `cos/token_bucket.rs:135`
  `ensure_v8_lease_attached`.
- Consumption: `cos/token_bucket.rs:93-110` `acquire_via_lease` →
  `acquire_v8`; top-up `:154 maybe_top_up_cos_queue_lease`.
- **Root lease raw-elapsed refill (no epoch clamp, §3.5.1):**
  `shared_cos_lease/mod.rs:853` `elapsed_ns = now_ns - last_refill_ns`.
- **Root burst floor 1% (§3.5.1):** `forwarding_build/cos.rs:66`.
