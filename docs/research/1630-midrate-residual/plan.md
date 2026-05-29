# #1630 cause-2 — the K-independent ~6% mid-rate (3g/6g) shape residual

- Issue: #1630 (surface). This plan owns **cause 2 only**.
- Branch: `research/1630-midrate-residual` (off `origin/master` @ `0e5bb3812`)
- Mode: `/research` — plan only; NO production code; STOP at PLAN-READY.
  Throwaway env-gated instrumented builds are allowed and MUST NOT be
  committed.
- Author: Claude SMR (CoS-shaper / token-bucket / rate-accuracy /
  AF_XDP-drain / timer-wheel domain).
- Rev: **v1 (DRAFT — pre-review).** Status: NOT YET REVIEWED. Drafted
  to be falsified by Codex + AGY + a hostile Claude SMR self-review.

> Companion: cause 1 (rotation clamp at `rotate_epoch_v8.rs:218`) is
> owned by `docs/research/1630-v8-credit-carry/plan.md` @ `852cf014c`.
> This plan composes with it (§9) — the eventual fix lands as ONE
> combined seqlock change.

---

## 1. The measured fact this plan starts from (do NOT re-derive)

A prior measurement-gated engineer ran the §3.6 SOLO A/B on
`loss:xpf-userspace-fw0/1` (push, v4, `guarantee-rate 0.7`, 12 streams,
`cos-iperf-config.set`, `reth0.80 shaping-rate 25g`). It isolated TWO
distinct root causes of the #1630/#1614 Gate-1 failure.

| Variant | 100m | 1g | 3g | 6g |
|---------|----:|---:|---:|---:|
| master  | 79 | 73 | 87 | 84 |
| K=8 +P2 | 93 | 94 | 91 | 90 |
| K=64+P2 | 95 | 95 | 90 | 90 |

Truly-solo (single port), master→K=64: 3g 89.1→93.8 (+4.7pp, still
<95), 6g 89.4→92.8 (+3.4pp, still <95). The 100m class is fixed by the
cause-1 carry (82→95, +13pp). The **3g/6g residual is the subject of
this plan**, and it has FOUR pre-registered properties (each is a
constraint the cause-2 mechanism must satisfy, and a falsifier for any
hypothesis that does not match):

- **P1 — K-independent.** Carry depth K=8 vs K=64 barely moves 3g/6g
  (91.0 vs 90.2 at +P2; solo 93.8 vs ~94). NOT the rotation clamp.
- **P2 — P2-independent.** Per-visit frame cap on/off barely moves 3g
  (91.2 K=8/P2-off vs 91.0 K=8/P2-on). NOT the selector sub-frame
  discard.
- **P3 — contention-independent.** Persists at ~93-94% even truly-solo
  (one class, whole cluster). NOT cross-worker fragmentation or
  inter-class competition.
- **P4 — flat across mid rates** (3g ≈ 6g ≈ ~90% four-way / ~93-94%
  solo). Smells like a *fixed fractional* loss or a rate-computation /
  granularity constant, NOT a per-class effect.

This plan does NOT re-run the §3.6 A/B (already done). It designs and
verifies the **instrumented bisection** that pins where the residual
~6% goes, then specifies the fix mechanism conditioned on the bisection
outcome — because this is a /research deliverable, the plan commits to a
*decision procedure + a primary hypothesis with a falsification gate*,
not a blind mechanism.

---

## 2. The shaper data-path, as it actually runs (verified, origin/master 0e5bb3812)

This is the spine every hypothesis below references. Confirmed by
reading the source, not the issue prose.

### 2.1 Per-class config (3g / 6g, the residual classes)

`cos-iperf-config.set`: `scheduler-3g transmit-rate 3.0g exact`,
`scheduler-6g transmit-rate 6.0g exact`. **Neither has `buffer-size`** —
so `buffer_bytes` defaults via `default_cos_burst_bytes(rate) =
max(rate/100, 64×1500)` (`forwarding_build/cos.rs:73`):

- 3g: `rate_bytes = 3e9/8 = 375_000_000 B/s`; `buffer_bytes = 3.75 MB`.
- 6g: `rate_bytes = 750_000_000 B/s`; `buffer_bytes = 7.5 MB`.

These buffers are huge relative to a 200µs epoch's worth of bytes
(75 000 B / 150 000 B), so the per-queue bucket ceiling is NOT the
binding limiter for 3g/6g. (Hypothesis 6 is therefore weak a priori;
§4 keeps it only as a falsified-by-arithmetic entry.)

### 2.2 The grant meter (per-class, lazy-rotated)

`maybe_rotate_epoch_v8` STEP 6 (`rotate_epoch_v8.rs:204-239`):
- `EPOCH_DURATION_NS = 200_000` (`mod.rs:241`).
- `elapsed_ns = (now - start).min(EPOCH)` — the cause-1 clamp (line 218).
- `new_cap_raw = rate_bytes × elapsed_ns / 1_000_000_000` (u128 math,
  integer-truncated to u64). For 3g full epoch: `375e6 × 200e3 / 1e9 =
  75_000 B` exactly (no truncation — `375e6 × 2e5 = 7.5e13`, `/1e9 =
  75_000`, exact). For 6g: `150_000 B` exact. **Integer-division
  truncation is ZERO at these rates** (hypothesis 1 falsified by
  arithmetic — see §4-H1).
- `epoch_grace_expires_ns = now + EPOCH/2 = now + 100µs` (line ~226).
- `epoch_start_ns := now` (line 237); seq ODD→EVEN publish (line 239).

### 2.3 The bucket top-up (per worker visit)

`maybe_top_up_cos_queue_lease` (`cos/token_bucket.rs:154`), exact branch:
- `lease_bytes = lease.lease_bytes().max(tx_frame_capacity()).min(buffer)`
  where `lease.lease_bytes() = config.lease_bytes =
  min(rate×200µs, burst/8, 512KB).max(1500)`
  (`compute_shared_cos_lease_config`, `mod.rs:694`). For 3g:
  `rate×200µs = 75_000`, `burst/8 = 469k` → `lease_bytes = 75_000`. For
  6g: `150_000`. `tx_frame_capacity() = 4096` (`UMEM_FRAME_SIZE`).
- **Early-return when `queue.hot.tokens >= lease_bytes`** (line 184) —
  no acquire, no rotation, when the bucket is already at/above the
  top-up watermark.
- Otherwise `acquire_v8(worker_id, now, lease_bytes - tokens)` →
  `maybe_rotate_epoch_v8(now)` then bounded by BOTH the class cap AND
  the per-worker `my_effective_share` (`acquire_v8`, `mod.rs:1066-1131`).

### 2.4 The drain + park + timer wheel (the per-visit gate)

`select_exact_cos_guarantee_queue_with_lease_telemetry`
(`queue_service/mod.rs:589-718`), per exact queue per drain pass:
1. top-up (2.3).
2. If `root.tokens < head_len`: park on root starvation.
3. If `queue.hot.tokens < head_len` (non-surplus-sharing exact): bump
   `drain_park_queue_tokens`, **park** with
   `estimate_cos_queue_wakeup_tick(..., require_queue_tokens=true)`
   (line 688).
4. Else service `secondary_budget = tokens.min(quantum).max(head_len)`.

`estimate_cos_queue_wakeup_tick` (`queue_service/mod.rs:1255`):
```rust
let queue_refill_ns = cos_refill_ns_until(queue_tokens, need_bytes, queue_rate)?; // div_ceil
let wake_ns = now_ns + root_refill_ns.max(queue_refill_ns);
Some(cos_tick_for_ns(wake_ns).max(cos_tick_for_ns(now_ns).saturating_add(1)))
```
`cos_tick_for_ns(ns) = ns / COS_TIMER_WHEEL_TICK_NS` and
**`COS_TIMER_WHEEL_TICK_NS = 50_000`** (`tx_completion.rs:104`). The
wheel advances in `advance_cos_timer_wheel` once per `prime_cos_root_for_service`
(`tx_completion.rs:214,314`), driven by `now_ns` sampled once per worker
poll-loop iteration (`loop_body/mod.rs:249 loop_now_ns = monotonic_nanos()`).
A parked queue is service-eligible only when
`next_wakeup_tick <= now_tick` (`cos_root_can_service_after_prime`,
`tx_completion.rs:288-293`).

**This is the spine of the leading hypothesis (§3).**

---

## 3. Leading hypothesis (the one the bisection must confirm or kill)

### 3.1 H-WHEEL — 50µs timer-wheel park quantization + `now_tick+1` floor

**Claim:** for a mid-rate exact class that is *bucket-bound* (its TCP
offered load exceeds its configured rate, so it runs `queue.hot.tokens`
to below `head_len` and parks), the park wake is quantized to the next
50µs timer-wheel tick boundary, **and is floored at `now_tick + 1`**.
Both rounding effects bleed TX-eligible time, and the bleed is a
*roughly fixed fraction* of the service period — matching P4 (flat
across rates) and P1/P2/P3 (independent of the clamp, the selector frame
cap, and contention).

**Why a mid-rate class parks but 24g/100m behave differently:**

- A bucket-bound exact queue with offered load > rate refills `tokens`
  at `rate` and drains it at line-rate whenever serviced. Steady state:
  drain a quantum, starve, park for `~refill_ns(quantum)`, repeat. The
  *park* is where time is lost to quantization.
- **6g**: `quantum = cos_guarantee_quantum_bytes = rate×VISIT_NS.clamp(1500, 512KB)`
  with `COS_GUARANTEE_VISIT_NS = 200_000` →
  `750e6 × 2e5 / 1e9 = 150_000 B`. To refill 150_000 B at 6g takes
  `150_000 / 750e6 = 200µs`. The wheel rounds that 200µs park to a
  50µs-granular tick. The rounding error is bounded by one tick (50µs)
  per park; a 200µs park rounded to the next 50µs boundary loses on
  average ~0..50µs depending on phase — **but the `now_tick + 1` floor
  (line 1288) forces a *minimum* one-tick (50µs) park even when the
  computed refill is shorter**, and `cos_tick_for_ns` *truncates*
  `wake_ns` (floor) while `cos_root_can_service_after_prime` requires
  `next_wakeup_tick <= now_tick` (so the queue cannot run until the
  wheel's integer tick counter reaches the target). The net is a
  per-park dead interval whose *expected* length is a fixed fraction of
  the tick (≈ half a tick mean), and the number of parks per second
  scales with rate — so the *fractional* loss `(dead_time / service_period)`
  is approximately rate-INDEPENDENT (a fixed fraction). **This is the
  P4 signature.**

**Worked fractional-loss estimate (the falsifiable number):**

Let a bucket-bound class drain `quantum` bytes per service then park for
the refill. Park interval before quantization `t_refill = quantum/rate`.
The wheel can only wake on tick boundaries every `T = 50µs`, and the
`now_tick+1` floor adds a guaranteed extra wait when `t_refill < T` or
when the phase offset within the current tick is small. Model the dead
time per park as the wait from `now` to the first tick boundary `≥ now +
t_refill`, plus the floor. With `t_refill` near a multiple of `T` the
expected extra wait is ~`T/2 = 25µs`. The effective period becomes
`t_refill + E[dead]`, and throughput = `rate × t_refill / (t_refill +
E[dead])`.

- 6g: `quantum = 150 000 B`, `t_refill = 200µs`, `E[dead] ≈ 25µs` ⇒
  efficiency `200/225 = 88.9%` — **matches measured 6g solo ~89-93%.**
- 3g: `quantum = rate×VISIT = 375e6×2e5/1e9 = 75 000 B`, `t_refill =
  75 000 / 375e6 = 200µs` (same VISIT_NS ⇒ same `t_refill`!), `E[dead]
  ≈ 25µs` ⇒ `200/225 = 88.9%` — **matches measured 3g ~89-93% AND
  explains P4 (flat): because `quantum` scales with rate, `t_refill =
  quantum/rate = VISIT_NS = 200µs` is CONSTANT across rates.** The flat
  residual falls directly out of `COS_GUARANTEE_VISIT_NS` being a fixed
  time quantum.

This is the single most important derivation in the plan: **the per-visit
service quantum is sized in *time* (`VISIT_NS = 200µs`), so every
bucket-bound class — regardless of rate — services for 200µs-worth of
bytes then parks for ~one tick of quantization overhead, giving a
rate-independent fractional loss.** That is exactly P1+P2+P3+P4.

**Why 100m and 24g don't show it (consistency check, not proof):**
- 100m: `quantum = clamp(100e6/8 × 2e5/1e9 = 2500, 1500, 512K) = 2500 B`
  but `t_refill = 2500 / 12.5e6 = 200µs` again — so 100m would ALSO show
  the wheel loss. It does (cause-1 measured 100m at 82% solo, lifted to
  95% by the K=64 clamp fix). **Caution (self-hostile):** if 100m's loss
  were ALSO the wheel, the clamp fix would NOT have lifted it to 95%.
  The fact that the clamp fix DID clear 100m but NOT 3g/6g is the
  central puzzle this hypothesis must survive — see §3.2.
- 24g: offered load ≈ shape; under 25g root cap the 24g class is
  root-bound, parks on ROOT tokens (different counter, different wake
  path with `require_queue_tokens=false`), so its quantization
  interacts with the root meter not the per-queue bucket.

### 3.2 The hostile tension H-WHEEL must survive (do not hand-wave)

If H-WHEEL (a fixed 200µs-quantum + 50µs-wheel loss) applied uniformly,
100m would not have been cleared by the cause-1 K=64 clamp fix. Two
candidate reconciliations, BOTH of which the §5 instrumentation must
disambiguate:

- **(a) 100m is dominated by the clamp, 3g/6g by the wheel.** At 100m
  the per-epoch cap is 2500 B < one 4096 frame, so the class is
  *grant-bound* (cause 1) far more than *bucket-park-bound*: it cannot
  even assemble a frame most epochs, so the clamp loss (rate×(lag−EPOCH))
  dwarfs the wheel loss. At 3g/6g the per-epoch cap (75k/150k) is many
  frames, the clamp loss is a smaller fraction (visited more often →
  smaller lag/EPOCH, exactly the cause-1 efficiency curve), and the
  *residual* after the clamp is removed is the wheel quantization. This
  predicts: cause-1 carry lifts 100m a lot (grant-bound → fixed) and
  3g/6g a little (already mostly grant-served, leaving the wheel floor).
  **Consistent with the measured +13pp / +3-5pp split.** This is the
  PRIMARY reconciliation.
- **(b) 3g/6g loss is something else entirely** (grant under-published,
  fair-share rounding, grace interaction). §5's bisection (cap-granted
  vs bytes-consumed) settles (a) vs (b) in ONE measurement.

**I am not asserting H-WHEEL is proven.** I am asserting it is the
leading hypothesis with a quantitative match to P4, and that §5's
instrumentation is the cheap experiment that confirms or kills it before
/engineer commits a mechanism.

---

## 4. Hypothesis table — falsify each (HOSTILE: every row needs a kill or a keep)

| # | Hypothesis | A-priori verdict | Falsifier / keeper |
|---|-----------|------------------|--------------------|
| H1 | Integer-division truncation in `rate×elapsed/1e9` | **KILLED by arithmetic.** 3g: `375e6×2e5/1e9 = 75 000` exact; 6g exact. Truncation = 0 bytes at these rates. Even at the worst sub-rate the truncation is ≤1 B/epoch ≪ 6%. | Killed in §2.2. Keep a counter anyway (§5 counter 5) to prove the published cap equals `rate×elapsed` to the byte. |
| H2 | Grace window (`grace = now + EPOCH/2`) caps throughput | **WEAK.** Grace only gates the *surplus/bypass* path (`acquire_v8:1189 bypass_was_reason = bypass && now < grace`); exact non-surplus classes never enter surplus (`select_cos_surplus_batch_filtered:837 skip exact && !surplus_sharing`). Grace cannot cap a non-surplus exact class. | §5 counter: confirm 3g/6g `bypass_grace_use_count == 0`. If nonzero, re-open. |
| H3 | Lease top-up cadence vs drain leaves a steady idle gap (bucket token-starved between top-ups) | **PLAUSIBLE — this IS H-WHEEL's mechanism** viewed from the bucket side. The bucket starves, the queue parks, the wheel quantizes the re-service. | This is H-WHEEL (§3). §5 counters 2+3 (park_queue rate + cap-vs-consumed) settle it. |
| H4 | `acquire_v8` lazy-rotation lag publishes stale cap even without the clamp | **OVERLAPS cause 1.** The clamp is the lag penalty; with the carry, lag is recovered. Engineer proved K-independent ⇒ not the dominant residual. | Killed by P1 (K-independence). §5 counter 5 (granted cap vs `rate×wall`) re-confirms. |
| H5 | Effective cap < shape due to a hidden reserve (priority min-share, root overhead, fair-share rounding) | **PLAUSIBLE secondary.** `worker_fair_share = new_cap × my_count / total_flows` (`rotate_epoch_v8.rs` STEP 6) is integer-divided per worker; if 12 streams split across N workers, per-worker share rounding could under-grant. But P3 (solo, persists) and the fact that solo single-port still shows it argue the split is not the cause unless RSS spreads even a single-port iperf across workers. | §5 counter 4 (`my_effective_share` sum vs cap) + worker-count check. If the 12 streams land on 1 worker, fair-share rounding is 0; if spread, measure the under-grant. |
| H6 | Buffer/burst depth limits sustained throughput | **KILLED by arithmetic.** 3g buffer = 3.75 MB, 6g = 7.5 MB ≫ per-epoch grant; `max_total_leased = burst/4` ≫ lease. Bucket never clips. | Killed in §2.1. §5 counter 6 (bucket high-water vs buffer) confirms headroom. |
| H7 | **NEW — `now_tick+1` minimum-park floor** | **PLAUSIBLE — the sharp edge of H-WHEEL.** Even when `t_refill < 50µs`, the floor forces a full-tick park. For a class whose refill is *just under* a tick this doubles the dead time. | §5 counter 7: histogram of `(wake_tick − now_tick)` deltas at park time; if the mode is 1 and refill < tick, the floor dominates. |
| H8 | **NEW — per-poll `now_ns` granularity vs wheel** | **PLAUSIBLE — coupling.** The wheel only advances when a poll iteration samples a `now_ns` in a new tick. Under saturation the poll loop spins sub-µs so the wheel is "fresh", BUT if the worker spends a whole tick servicing OTHER classes (11 classes RR), a parked 3g/6g queue's wake tick may already be past when revisited, adding RR-latency on top of the wheel. | §5 counter 8: time-between-service-visits histogram for 3g/6g vs `t_refill`. Distinguishes wheel-floor (H-WHEEL/H7) from RR-revisit-latency. Note: P3 (solo) weakens H8 because solo has few competing classes. |

**Net a-priori:** H1, H6 killed by arithmetic. H2, H4 killed by
code-path / P1. H5, H8 are secondary, measured. **H3≡H-WHEEL + H7 is the
leading cluster.** The bisection (§5) is designed to separate "the cap
is under-granted" (H1/H4/H5 family — cause is in rate-calc/rotation)
from "the cap is granted but not consumed because the queue is parked on
the wheel" (H-WHEEL/H7/H3 family — cause is in drain/park quantization).
**That single counter pair (cap-granted vs bytes-consumed) bisects the
entire space.**

---

## 5. The instrumented bisection (the verified second-root-cause proof)

All counters are **env-gated debug counters in a LOCAL throwaway build,
NOT committed.** They piggyback on the existing `owner_profile`
telemetry block (`types/cos.rs:914` already has `drain_park_*`) so the
build change is additive `AtomicU64` fields + `fetch_add` calls behind
`option_env!("XPF_COS_MIDRATE_DEBUG")`, exported via the existing
per-queue Prometheus/status path so they read out per-class.

### 5.1 The one bisecting measurement

Per 3g and 6g queue, per 1s window, accumulate:

1. **cap_granted_bytes** — sum of `new_cap` published by rotation
   (i.e. what the meter *allowed* this class to send).
2. **bytes_consumed** — sum of `total_granted` returned by `acquire_v8`
   (i.e. what the class actually drew). Already partly tracked as
   `v8_granted_bytes` in `CoSQueueLeaseAcquireTelemetry`.
3. **park_queue_count / park_root_count** — `drain_park_queue_tokens` /
   `drain_park_root_tokens` (already exist).
4. **sum_my_effective_share** vs **cap** (H5).
5. **cap_vs_rate_x_wall** — published cap compared to `rate ×
   wall_elapsed` over the window (H1/H4 — proves the meter granted the
   full rate-time product).
6. **bucket_high_water / buffer_bytes** (H6).
7. **wake_delta_histogram** — `(wake_tick − now_tick)` at each park (H7).
8. **service_gap_histogram** — ns between successive services of the
   same queue (H8), vs `t_refill = quantum/rate`.

### 5.2 The bisection truth table

Run 3g-solo and 6g-solo on the free loss cluster (single port, push, v4,
guarantee-rate 0.7) and read the counters:

| Observation | Conclusion |
|-------------|------------|
| `cap_granted ≈ rate × wall` (counter 5 ≈ 1.0) AND `bytes_consumed / cap_granted ≈ 0.94` | **GRANT IS FULL, CONSUMPTION IS SHORT** ⇒ cause is in DRAIN/PARK (H-WHEEL/H7). Counter 7's mode + counter 3's park_queue rate localize it to the wheel floor. **Expected primary outcome.** |
| `cap_granted < rate × wall` (counter 5 ≈ 0.94) | **GRANT IS SHORT** ⇒ cause is in rate-calc/rotation despite K-independence — re-open H4/H5; inspect fair-share split (counter 4) and worker count. |
| `park_queue_count` high AND counter-7 mode = 1 tick AND `t_refill < 50µs` | **H7 (now_tick+1 floor) dominates.** |
| `park_queue_count` high AND counter-7 mode > 1 AND counter-8 gap ≈ `t_refill` rounded up to tick | **H-WHEEL (tick rounding) dominates.** |
| `park_root_count > 0` for SOLO 3g/6g | root shaper IS throttling — re-confirm against prior "park_root=0" claim; if nonzero re-open root-meter hypothesis. |

This table is the deliverable. The ~6% MUST appear as either (a) under
counter 5 (under-granted cap → rotation/rate-calc) or (b) the gap
between counter 1 and counter 2 (granted-but-not-consumed → drain/park).
**One read bisects the hypothesis space.**

### 5.3 Confirm root is not the limiter (re-verify the prior claim)

Prior runs showed `park_root = 0`. Re-confirm for 3g/6g SOLO: counter 3
(`drain_park_root_tokens`) must be ~0 and counter 5b (root lease grant
vs `shaping_rate × wall`) ≈ 1.0. If the root meter throttles a SOLO
single-class run, the residual is a root-shaper artifact (different fix:
`EPOCH`/burst on the root lease), and H-WHEEL is demoted.

---

## 6. Fix mechanism (conditioned on §5 outcome — primary = H-WHEEL)

> The plan commits to the §5 bisection as the gate. The mechanism below
> is the PRIMARY (H-WHEEL-confirmed) design; §6.4 lists the alternate
> mechanisms for the non-primary §5 outcomes so /engineer is not blocked.

### 6.1 PRIMARY — eliminate the park-quantization dead time for bucket-bound exact classes

If §5 confirms "granted-but-not-consumed via wheel park" (the expected
outcome), the fix targets `estimate_cos_queue_wakeup_tick` /
`cos_root_can_service_after_prime`, NOT the rate meter. Three composable
sub-fixes, smallest first:

- **F-A (remove the `now_tick+1` floor when refill is sub-tick):**
  the floor (`queue_service/mod.rs:1288`) exists to guarantee forward
  progress (never wake in the past). But it forces a *full* 50µs park
  even when `t_refill ≪ 50µs`. Replace the floor with "wake at
  `now_tick + 1` only if the *computed* wake tick is `<= now_tick`;
  otherwise honor the computed tick." This is a no-op for correctness
  (still never wakes in the past) but stops rounding a 5µs refill up to
  a 50µs park. **Smallest, safest.** Kills H7.
- **F-B (sub-tick re-service via a "soon" fast-path):** a queue whose
  `t_refill < TICK` should not park on the wheel at all — it should stay
  *runnable* and be re-tried on the next poll iteration (which is
  sub-µs under saturation), letting the bucket refill naturally between
  poll passes. Mechanism: in the exact-queue park branch
  (`queue_service/mod.rs:688`), if
  `queue_refill_ns < COS_TIMER_WHEEL_TICK_NS`, do NOT park; `continue`
  and let the RR revisit it (the bucket top-up at line 611 refills it on
  the next visit with a fresher `now_ns`). Bounded by the existing
  drain-loop budget so it cannot spin. Kills H-WHEEL + H7 together.
- **F-C (shrink `COS_TIMER_WHEEL_TICK_NS`):** rejected as primary — a
  finer tick raises wheel-advance cost on every poll and changes the
  L0/L1 horizon math (`COS_TIMER_WHEEL_L0_SLOTS = 256`); orthogonal,
  global, and risky. Keep only as a fallback if F-A/F-B underperform.

**Recommended primary:** F-B (stay-runnable for sub-tick refills) with
F-A as the belt. Both are confined to the drain/park path and do **not
touch the seqlock or the rate meter** — so they compose cleanly with
cause 1 (§9).

### 6.2 Burst-safety of F-A/F-B (the hostile constraint)

Staying runnable for a sub-tick refill does NOT raise the class's
average rate above shape, because the **per-queue token bucket still
gates every send**: `queue.hot.tokens < head_len` still blocks the send
on the very next visit if the bucket hasn't actually refilled (the
`refill_cos_tokens`/lease top-up only adds `rate × (now − last_refill)`).
F-B only removes the *artificial 50µs floor* between a refill that has
already happened in wall-clock and the queue being allowed to notice it.
The bucket + the cause-1 grant cap remain the rate enforcers. **No new
burst surface.** Gate (§8) re-measures aggregate + retransmits to prove
this.

### 6.3 Why this is NOT cause 1 and does NOT need the carry

Cause 1 enlarges the *grant* (`epoch_total_grant_cap`) so the class is
*allowed* to send the lagged bytes. Cause 2 is downstream: even with a
full grant, the class can't *emit* it because the drain parks it on the
wheel. The two are orthogonal layers (meter vs drain). The carry without
F-A/F-B leaves 3g/6g at ~94% (measured); F-A/F-B without the carry
leaves 100m at ~82% (measured). **Both are required for Gate 1.**

### 6.4 Alternate mechanisms (non-primary §5 outcomes)

- If §5 shows **under-granted cap** (counter 5 < 1.0): the residual is
  in the meter. Sub-case fair-share rounding (H5): change per-worker
  share from floor-division to a remainder-distributing split, or grant
  the class-cap directly when `total_flows` is concentrated on one
  worker. Sub-case rotation-lag-without-clamp (H4): fold into the
  cause-1 carry (it already recovers lag). Either way it MERGES into the
  cause-1 seqlock change, not the drain path.
- If §5 shows **root throttling** (counter 3/5b): raise the root lease
  burst or epoch; orthogonal to both causes.

---

## 7. Seqlock / concurrency surface (composing with cause-1 + #1643)

The PRIMARY fix (F-A/F-B) touches `estimate_cos_queue_wakeup_tick` and
the exact-queue park branch — **single-worker, per-binding runtime
state** (`queue.hot.tokens`, `next_wakeup_tick`, the timer wheel). These
are NOT shared across workers and NOT in the v8 seqlock payload. So:

- **Zero new seqlock surface.** F-A/F-B add no atomic, no published
  field, no reader. The #1643 fence (cause-1 plan §4.0) is untouched and
  unaffected.
- **No interaction with the carry's `epoch_carry_bytes`** (cause-1
  rotation-private field). Cause 2 lives entirely below the meter.

This is the strongest argument for the F-A/F-B drain-path fix over any
meter-side mechanism: cause 2 can be made **orthogonal** to the
seqlock-sensitive cause-1 change, so the combined PR's seqlock review
surface is exactly cause-1's surface (carry + #1643 fence), with cause 2
as an independent, non-atomic drain-path delta.

---

## 8. Combined acceptance (cause-1 + cause-2 + #1643)

The eventual /engineer PR lands ONE combined change. Gate 1 is the
binding gate and now requires BOTH causes fixed.

- **Gate 1 — ALL FOUR classes SOLO ≥ 95%** (100m/1g/3g/6g, single port
  AND small-four-alone, 12 streams, push, v4, guarantee-rate 0.7). This
  is the gate cause-1 alone CANNOT pass (3g/6g plateau ~90-94) and
  cause-2 alone CANNOT pass (100m ~82). Combined MUST clear all four.
- **Cause-1 lowest-class preserved** — 100m must remain ≥95 (the carry's
  +13pp must not regress when F-A/F-B changes the park cadence).
- **Burst bound held** — Gate 5 (single-class stall→resume ≤ K×rate×EPOCH,
  per cause-1 plan §7) AND a NEW cause-2 burst check: F-B "stay-runnable"
  must not let any class exceed shape over any 10ms window (counter:
  per-class TX bytes / 10ms ≤ shape × 1.05). Proves §6.2.
- **`make test-failover`** — mandatory (TX-shaping change). Zero-drop;
  cause-1's reused-lease unit test passes; F-A/F-B park changes do not
  alter failover behavior (park state is per-binding, rebuilt on
  promote).
- **Full matrix** — v4+v6 × push+`-R` × CoS-off+CoS-on, per memory
  feedback. Gate 2 (priority-low ≥5%), Gate 3 (retransmits ≤100/30s),
  Gate 4 (aggregate ≥19.5G) must not regress.
- **Cause-2 regression test** — a Rust unit test on
  `estimate_cos_queue_wakeup_tick`: assert that a sub-tick refill
  (`queue_refill_ns < COS_TIMER_WHEEL_TICK_NS`) under F-A returns the
  computed tick (not `now_tick+1` floored) — pins F-A. And a drain-path
  test that a bucket-bound exact queue with a sub-tick refill stays
  runnable (F-B), bounded by the drain budget.

---

## 9. How cause-1 + cause-2 + #1643 combine (explicit, per the charter)

ONE combined seqlock change ships:

1. **Cause-1 bounded credit carry** (`rotate_epoch_v8.rs` STEP 6 +
   rotation-private `epoch_carry_bytes`, per
   `docs/research/1630-v8-credit-carry/plan.md` @ `852cf014c`) — fixes
   the lowest-rate (100m) grant-bound loss. **Meter layer.**
   *(Note: that plan itself converged at PLAN-NEEDS-MAJOR pending the
   §3.6 fork; the §3.6 measurement is now DONE and resolved to "neither
   fork — cause 2 is distinct", which is THIS plan. The cause-1 carry's
   own gate-clearing scope is reduced to the 100m/1g classes it actually
   fixes; cause-2 owns 3g/6g. /engineer must re-scope cause-1's Gate-1
   claim to "100m/1g cleared by carry; 3g/6g cleared by cause-2".)*
2. **#1643 acquire-fence** in `snapshot_epoch_v8` (`mod.rs:1427`) —
   `fence(Acquire)` between payload loads and `seq_after` re-read; payload
   stores downgraded to `Relaxed`. **Meter layer, seqlock-correctness.**
   `Closes #1643`.
3. **Cause-2 F-A/F-B drain-park fix** (`estimate_cos_queue_wakeup_tick`
   + exact-queue park branch) — fixes the mid-rate (3g/6g)
   park-quantization loss. **Drain layer — NO seqlock, NO atomic, NO
   shared state.**

**Composition is clean by layering:** (1)+(2) are the meter/seqlock
surface (carry + fence, the only concurrency-sensitive code); (3) is a
disjoint, single-threaded drain-path change. They share NO field. The
combined PR's hostile concurrency review is bounded to (1)+(2); (3) is
reviewed as ordinary single-worker logic. Gate 1 requires all three.

---

## 10. Risks & residuals

- **R1 — H-WHEEL not the cause (§5 shows under-granted cap).** Then the
  primary §6.1 mechanism is wrong and §6.4's meter-side fix applies
  (merges into cause-1). Mitigation: §5 runs FIRST at /engineer; the
  plan does not commit code before the bisection.
- **R2 — F-B "stay-runnable" busy-loops a starved queue.** If the bucket
  genuinely cannot refill (root-bound), staying runnable wastes poll
  cycles. Mitigation: F-B fires ONLY when `queue_refill_ns < TICK`
  (bucket WILL refill within a tick); a longer refill still parks. The
  drain-loop budget (`should_enter_shaped_drain` + REINGEST_BUDGET=4)
  bounds spins. Gate 4 (aggregate, CPU) catches a regression.
- **R3 — interaction with the 11-class full simul.** Solo clears the
  wheel hypothesis, but under 11 classes the RR-revisit latency (H8) may
  re-introduce a gap F-B cannot close (the worker is busy with other
  classes when the bucket refills). Mitigation: Gate 1b (full simul) is
  a gate; measure. If H8 dominates under load, F-B helps less and a
  finer-grained scheduler (out of scope, #1614) may be needed — call it
  out, do not silently pass.
- **R4 — `now_tick+1` floor exists for a reason.** Removing/relaxing it
  (F-A) could wake a queue in the same tick repeatedly. Mitigation: F-A
  preserves "never wake in the past" (still floors at `now_tick+1` when
  the computed tick ≤ now_tick); it only stops rounding a future sub-tick
  refill UP. The regression test (§8) pins this.
- **R5 — cause-1's reduced scope.** Cause-1's plan claimed Gate 1; with
  cause 2 split out, cause-1 only owns 100m/1g. /engineer MUST update the
  cause-1 plan's Gate-1 claim or the combined PR will appear to fail
  cause-1's own gate. Documented in §9 note.
- **R6 — VISIT_NS coupling.** If §5 confirms the residual is exactly
  `TICK/(VISIT_NS+TICK/2)`, an alternate one-line fix is to make
  `COS_GUARANTEE_VISIT_NS` an integer multiple of the wheel tick so the
  park always lands on a boundary with zero rounding. This is a
  candidate F-D to evaluate at /engineer (cheaper than F-B but couples
  two constants). Listed for completeness.

---

## 11. 5+ hostile open questions (for the reviewers to attack)

1. **Is `t_refill` really rate-independent?** §3.1 claims `t_refill =
   quantum/rate = VISIT_NS = 200µs` for ALL rates because `quantum =
   rate×VISIT_NS`. But `cos_guarantee_quantum_bytes` *clamps* quantum to
   `[1500, 512K]`. At 100m, `quantum = 2500` (unclamped); at 24g,
   `quantum = 24e9/8 × 2e5/1e9 = 600 000 > 512K` → CLAMPED to 512K, so
   `t_refill = 512K / 3e9 = 170µs ≠ 200µs`. **Does the clamp break P4's
   flatness at the high end?** 3g (75K) and 6g (150K) are both UNDER the
   512K clamp, so the flat residual holds for THEM — but a reviewer
   should verify the clamp does not also distort 6g (150K < 512K, safe)
   and that the "flat across 3g/6g" claim is not coincidental.
2. **Why does the wheel hurt a SOLO single-class run (P3)?** With one
   class the worker RR has nothing else to do — so why park at all
   instead of immediately re-servicing? Answer hinges on: does the
   bucket actually empty below `head_len` within a single poll pass
   (line-rate drain of 150K in <1µs) then have to wait `t_refill` for
   the NEXT frame? If the poll loop spins faster than `t_refill`, the
   wheel floor (`now_tick+1`) is what forces the 50µs park even with
   nothing else to do. **A reviewer must confirm the queue genuinely
   parks (counter 3 > 0) rather than staying runnable in the solo case;
   if it stays runnable, H-WHEEL is wrong and the loss is elsewhere.**
3. **Is the loss in the bucket refill cadence or the wheel?** H3 (bucket
   top-up early-return) and H-WHEEL (park quantization) are two views of
   the same starvation. Could the real cause be that the lease top-up
   target `lease_bytes = rate×200µs` is TOO SMALL — so the bucket can
   never hold more than 200µs of credit and ALWAYS starves between
   visits regardless of the wheel? **Counter 6 (bucket high-water)
   settles this: if high-water ≈ lease_bytes (75K/150K) and the queue
   still parks, the lease target is the limiter, not the wheel — and the
   fix is to raise `COS_ROOT_LEASE_TARGET_US`, not touch the wheel.**
   This is a genuinely different fix and the plan must not prejudge it.
4. **Does F-B violate work-conservation or fairness under contention?**
   Staying runnable for a sub-tick refill means a 3g queue could be
   re-serviced ahead of an 11-class RR cycle. Under full load this could
   steal service from other classes. **Is F-B's "stay runnable" actually
   a priority inversion that helps solo but hurts the simul (Gate 1b)?**
5. **Is the 6% an artifact of TCP, not the shaper?** The measurement is
   iperf3 TCP goodput. 200µs park × periodic = bursty delivery → could
   inflate RTT/jitter and depress the TCP window, costing throughput
   that is NOT the shaper's grant. **Counter 1 vs 2 (cap vs consumed) at
   the SHAPER layer settles this: if the shaper grants AND the class
   consumes ~100% of grant but iperf3 still reports 94%, the loss is in
   TCP/delivery-burstiness, and the fix is pacing/burst-smoothing, not
   the grant or the park.** This is the single most important falsifier:
   it could move cause 2 out of the shaper entirely.
6. **Does the cause-1 carry CHANGE the wheel behavior?** The carry
   enlarges `cap`, which enlarges the bucket top-up `lease_bytes`? No —
   `lease_bytes` is `config.lease_bytes` (static), not `cap`. So the
   carry does NOT refill the bucket more. **Confirm the carry and the
   park fix are truly independent (they touch different quantities), or
   the §9 "clean layering" claim is false.**

---

## Appendix — verified source anchors (origin/master `0e5bb3812`)

- Timer wheel tick: `cos/tx_completion.rs:104 COS_TIMER_WHEEL_TICK_NS = 50_000`;
  `cos_tick_for_ns = ns/TICK` (`:112`); advance (`:214`,`:314`);
  service-eligibility `next_wakeup_tick <= now_tick`
  (`cos_root_can_service_after_prime`, `:288-293`).
- Wake-tick floor: `queue_service/mod.rs:1288`
  `cos_tick_for_ns(wake_ns).max(cos_tick_for_ns(now).saturating_add(1))`.
- Refill ns: `cos/token_bucket.rs:284 cos_refill_ns_until` (`div_ceil`).
- Per-visit quantum: `cos_guarantee_quantum_bytes`
  (`queue_service/mod.rs:1246`); `COS_GUARANTEE_VISIT_NS = 200_000`,
  `QUANTUM_MIN = 1500`, `QUANTUM_MAX = 512K` (`tx/drain/mod.rs:561-563`).
- Exact-queue park branch (the H-WHEEL site): `queue_service/mod.rs:665-700`
  (`drain_park_queue_tokens` + park), `:688` wake-tick call.
- Bucket top-up + early-return: `cos/token_bucket.rs:154,184`.
- Lease target: `compute_shared_cos_lease_config` `mod.rs:694`
  (`COS_ROOT_LEASE_TARGET_US = 200`, `mod.rs:690`); `lease_bytes`
  `mod.rs:977`.
- Default buffer: `forwarding_build/cos.rs:73 default_cos_burst_bytes
  = max(rate/100, 64×1500)`.
- Grant meter (clamp + cap publish): `rotate_epoch_v8.rs:204-239`;
  `EPOCH_DURATION_NS = 200_000` (`mod.rs:241`).
- Grace gate (exact never enters surplus): `acquire_v8` surplus path
  `mod.rs:1186-1242`; exact-skip `queue_service/mod.rs:837`.
- Park telemetry fields: `types/cos.rs:914,920 drain_park_{root,queue}_tokens`.
- Poll-loop `now_ns` sample: `worker/loop_body/mod.rs:249`.
- Drain entry/budget: `tx/drain.rs:109,156` (`REINGEST_BUDGET=4`).
