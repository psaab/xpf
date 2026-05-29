# #1630 cause-2 — the K-independent ~6% mid-rate (3g/6g) shape residual

- Issue: #1630 (surface). This plan owns **cause 2 only**.
- Branch: `research/1630-midrate-residual` (off `origin/master` @ `0e5bb3812`)
- Mode: `/research` — plan only; NO production code; STOP at PLAN-READY.
  Throwaway env-gated instrumented builds are allowed and MUST NOT be
  committed.
- Author: Claude SMR (CoS-shaper / token-bucket / rate-accuracy /
  AF_XDP-drain / timer-wheel domain).
- Rev: **v2 (r1 reviews folded).** Status after r1: **PLAN-NEEDS-MAJOR,
  converged on a corrected-mechanism + measurement-gated bisection.**
  r1: Codex PLAN-NEEDS-MAJOR (BLOCKING-1 park basis is `head_len` not
  `quantum` → §3 derivation wrong; BLOCKING-3 `bytes_consumed` ≠ TX
  bytes; MAJOR-1/2/3; BLOCKING-2 HALLUCINATED — no waterfill drain path,
  rejected with grep evidence); Claude SMR PLAN-NEEDS-MAJOR (concur +3
  own); AGY succeeded but `agy_result` infra-timed-out 3× (investigation
  trace verified converging on the same park-basis defect, see
  `agy-plan-r1.md`). v2 rewrites §3 around `head_len`, drops the false
  "200/225 = 88.9% matches" precision, recasts §5 as a THREE-way
  TX-grounded split + goodput, demotes the defective F-A/F-B, and
  promotes the lease-target / sub-tick-wake mechanisms.

## v2 changelog (r1 response)

- **[Codex BLOCKING-1 / Claude MAJOR-1] §3 derivation FIXED.** The wake
  estimator is called with `head_len` (one frame), NOT the quantum. v2
  rewrites §3 (the park basis is `head_len/rate ≈ 2-4µs`, floored to a
  50µs tick) and DROPS the "t_refill = quantum/rate = 200µs → 88.9%"
  false precision. The corrected period model has explicit unknowns the
  §5 counters resolve.
- **[Codex BLOCKING-2] REJECTED as hallucinated.** No waterfill drain
  path exists on origin/master (§3.0). v2 does NOT add waterfill
  instrumentation.
- **[Codex BLOCKING-3 / Claude MAJOR-2] §5 recast as THREE-way.**
  `cap_granted` / `total_granted` / `drain_sent_bytes` + iperf3 goodput;
  the four ratios localize meter-under-grant vs grant-not-drawn vs
  drawn-not-sent vs TCP-artifact.
- **[Codex MAJOR-1 / Claude] lease-target promoted to first-class
  competing hypothesis** (§3.3, §6).
- **[Codex MAJOR-2/3 / Claude MAJOR-1] F-A/F-B DEMOTED** (F-A no-op
  same-tick; F-B busy-polls a cap-exhausted lease). Primary candidates
  are now the lease-target raise (F-C') and the sub-tick wake
  representation (F-E), §6.
- **[Claude MINOR-2] §9 layering re-argued** for the lease-target branch
  (shared meter config, not seqlock payload).

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
   `estimate_cos_queue_wakeup_tick(..., head_len, now_ns, true)`
   (line 688 — **note the bytes arg is `head_len`, one frame, NOT the
   quantum; this is the v2 correction**).
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

## 3. Leading hypothesis cluster (the bisection must confirm or kill — v2 CORRECTED)

> **v2 correction (Codex BLOCKING-1 / Claude MAJOR-1).** v1 derived the
> residual from `t_refill = quantum/rate = 200µs`. **That is wrong about
> the park basis.** The wake estimator is called with **`head_len`** (one
> frame), NOT the quantum. The quantum is only the *service batch size*.
> v2 rewrites the mechanism around the verified call and DROPS the false
> "200/225 = 88.9% matches" precision. The corrected model has explicit
> unknowns that §5 resolves — the plan no longer claims a quantitative
> match it cannot derive.

### 3.0 First: there is NO waterfill drain path (reject Codex BLOCKING-2)

Codex r1 BLOCKING-2 asserted `guarantee-rate 0.7` dispatches the drain
into `select_exact_cos_guarantee_queue_waterfill` with park sites at
`queue_service/mod.rs:603-613/:853-872/:973-982`. **Verified absent on
origin/master `0e5bb3812`:**

- `grep -rn "waterfill" userspace-dp/src/` → ONE hit, a COMMENT
  (`forwarding_build/cos.rs:424`): "the v5 two-phase waterfill allocator.
  **The Go control plane is responsible**…". Waterfill is a CONTROL-PLANE
  allocator, not a Rust drain path.
- `oversubscription_policy` is written to `CoSInterfaceConfig`
  (`forwarding_build/cos.rs:443`) but **never read** in the drain
  (`grep` of `userspace-dp/src/afxdp/` outside forwarding_build/README =
  0 consumer hits). The drain selector
  `select_exact_cos_guarantee_queue_with_lease_telemetry`
  (`queue_service/mod.rs:590`) has NO oversubscription branch.

So `guarantee-rate 0.7`'s dataplane effect arrives entirely as the
per-class v8 lease *rates* the Go allocator computes; 3g/6g traverse the
SINGLE exact-queue park branch (`:665-700`). **v2 does NOT add
waterfill instrumentation, and records this rejection so a later round
does not re-add it.** That the reviewers disagreed on which path runs is
itself the argument for §5: a counter on the ACTUAL drain path settles
it empirically.

### 3.1 The corrected per-visit cycle (verified call, `head_len` basis)

For a bucket-bound exact class (offered load > configured rate), one
worker visit to its queue does
(`select_exact_cos_guarantee_queue_with_lease_telemetry`,
`queue_service/mod.rs:611-716`):

1. top-up bucket to `lease_bytes = config.lease_bytes = rate×200µs`
   (75K for 3g, 150K for 6g), gated by `acquire_v8` (cap + share).
2. if `root.tokens < head_len` → park on ROOT (different counter).
3. if `queue.hot.tokens < head_len` (one frame, `cos_item_len(head)`):
   bump `drain_park_queue_tokens`, **park** with
   `estimate_cos_queue_wakeup_tick(..., head_len, now_ns, true)`
   (verified: the 4th positional arg is `head_len`, NOT the quantum).
4. else service `secondary_budget = tokens.min(quantum).max(head_len)`.

`estimate_cos_queue_wakeup_tick` computes
`queue_refill_ns = cos_refill_ns_until(tokens, head_len, rate)` =
`(head_len − tokens)/rate` ≈ **2µs for 6g** (`1500/750e6`), ~4µs for 3g.
Then `wake_ns = now + max(root_refill, queue_refill)` and
`wake_tick = cos_tick_for_ns(wake_ns).max(now_tick+1)` — quantized to a
**50µs** wheel tick, floored at `now_tick+1`. A parked queue is
service-eligible only when `next_wakeup_tick <= now_tick`.

**So the dominant rounding is the `now_tick+1` floor: a ~2µs real refill
is rounded up to a full 50µs park.** This is H-WHEEL restated correctly:
the loss is the floor + tick granularity, NOT a 200µs quantum.

### 3.2 The corrected period model — and why its magnitude is UNKNOWN without §5

Naïve corrected cycle for a queue that drains its bucket then parks:
- **Service phase**: drains up to `min(tokens, quantum)` =
  `quantum` = `rate×VISIT_NS` (75K/150K). At line-rate the bytes leave in
  `quantum/rate = VISIT_NS = 200µs` of *credit* — but the worker emits
  them across whatever poll passes happen in that window.
- **Park phase**: floored to ≥1 tick = 50µs even though the real refill
  is ~2µs.

If the queue drained a full quantum (200µs of bytes) then parked one
tick (50µs), efficiency would be `200/250 = 80%` — **WORSE than the
measured ~93-94% solo.** So the real behavior must be ONE of:

- (a) the queue does NOT drain a full quantum before parking (root-token
  interleave, cap exhaustion, or the bucket only ever holds `lease_bytes`
  = 200µs and refills incrementally), so the park fires more often but
  each park bleeds less; OR
- (b) the queue does NOT park every cycle — it stays runnable and the
  bucket refills across sub-µs poll passes faster than a tick, so the
  floor rarely bites; OR
- (c) the loss is NOT the wheel at all (lease-target starvation §3.3, or
  TCP burstiness §4-H-TCP).

**v2's honest position: the DIRECTION (sub-tick park floored to 50µs) is
the leading candidate, but no closed-form magnitude reproduces 6% from
first principles.** The number `6%` is an empirical fact; the mechanism
is a hypothesis; §5's counters (parks/sec, bytes-sent-per-park,
cap/granted/sent ratios) are what turn the hypothesis into a proof. The
plan deliberately stops short of claiming a derived match.

### 3.3 Competing first-class hypothesis: the lease target is the limiter

`config.lease_bytes = min(rate×COS_ROOT_LEASE_TARGET_US, burst/8, 512K)`
with `COS_ROOT_LEASE_TARGET_US = 200` (`mod.rs:690-711`). This is BOTH
the bucket top-up watermark (`token_bucket.rs:184` early-returns when
`tokens >= lease_bytes`) AND therefore the maximum credit the bucket can
hold. For 3g/6g that is 75K/150K = exactly 200µs of rate. **If the
bucket can never hold more than 200µs of credit, it ALWAYS starves
between visits regardless of the wheel** — and the fix is to raise
`COS_ROOT_LEASE_TARGET_US` (let the bucket bank 2-3 ticks), not touch
the wheel. This is Codex MAJOR-1 promoted to a co-equal hypothesis;
§5 counter 6 (bucket high-water vs `lease_bytes`) + the park rate
discriminate it from the wheel-floor hypothesis.

### 3.4 Reconciling with cause-1: why 100m was cleared but 3g/6g were not

The cause-1 K=64 clamp fix lifted 100m +13pp (→95, clears) but 3g/6g only
+3-5pp (→94, does not clear). Corrected explanation:
- 100m: per-epoch cap = 2500 B < one 4096 frame → the class is
  *grant-bound* (cause 1): it cannot assemble a frame most epochs, so the
  clamp loss dominates and the carry fixes it.
- 3g/6g: per-epoch cap = 75K/150K = many frames → the class is NOT
  grant-bound; the clamp loss is a small fraction (visited often), and
  the RESIDUAL after the clamp is removed is the §3.1/§3.3 drain-or-lease
  quantization. The carry cannot touch it (it enlarges the grant, not the
  bucket refill cadence or the park floor). **This is exactly the
  K-independent, flat residual the engineer measured.**

This reconciliation is consistent with the data but NOT proven; §5
settles it.

---
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
| H8 | **per-poll `now_ns` granularity vs wheel** | **PLAUSIBLE — coupling.** The wheel only advances when a poll iteration samples a `now_ns` in a new tick. Under saturation the poll loop spins sub-µs so the wheel is "fresh", BUT if the worker spends a whole tick servicing OTHER classes (11 classes RR), a parked 3g/6g queue's wake tick may already be past when revisited, adding RR-latency on top of the wheel. | §5 counter 8: time-between-service-visits histogram for 3g/6g vs the refill. Distinguishes wheel-floor (H7) from RR-revisit-latency. Note: P3 (solo) weakens H8 because solo has few competing classes. |
| H-LEASE | **lease target `rate×200µs` caps bucket credit (§3.3)** | **FIRST-CLASS (Codex MAJOR-1).** The bucket can never hold > 200µs of credit, so it starves between visits independent of the wheel. Different fix (raise `COS_ROOT_LEASE_TARGET_US`). | §5 counter 6: bucket high-water ≈ `lease_bytes` AND queue still parks ⇒ lease target is the limiter, not the wheel. |
| H-TCP | **NEW (Claude MAJOR-2) — the 6% is a TCP goodput artifact, not a shaper grant loss** | **MUST be ruled out.** 50µs-quantized bursty delivery inflates RTT/jitter → depresses the TCP window → iperf3 reports < shaper TX. If so, cause 2 is OUTSIDE the shaper. | §5 ratio `goodput/drain_sent`: if shaper grants AND sends ~100% but iperf3 reports 94%, the loss is TCP. **The single most important falsifier — it could move cause 2 out of the shaper entirely.** |

**Net a-priori:** H1, H6 killed by arithmetic. H2, H4 killed by
code-path / P1. H5, H8 are secondary, measured. **H7 (now_tick+1 floor),
H-LEASE (lease-target cap), and H-TCP (goodput artifact) are the three
live candidates** after the v2 correction. The bisection (§5) separates
FOUR layers — meter-under-grants / grant-not-drawn / drawn-not-sent /
sent-but-TCP-loses — with a THREE-way internal byte split + goodput. The
old v1 "single counter pair bisects" claim was too weak: it conflated
drawn vs sent and could not see the TCP artifact.

---

## 5. The instrumented bisection (the verified second-root-cause proof — v2 THREE-way)

All counters are **env-gated debug counters in a LOCAL throwaway build,
NOT committed** (additive `AtomicU64` behind `option_env!("XPF_COS_MIDRATE_DEBUG")`,
piggybacked on the existing `owner_profile` block in `types/cos.rs` so
they read out per-class via the existing per-queue status/Prometheus
path). They are removed before the /engineer PR.

### 5.1 The four quantities (THREE internal byte counters + goodput)

Per 3g and 6g queue, per 1s window:

1. **cap_granted_bytes** — Σ `new_cap` published by rotation (the meter
   ceiling; what the class was *allowed*). Source: `rotate_epoch_v8.rs`
   STEP 6 `new_cap`.
2. **total_granted_bytes** — Σ `acquire_v8` return (lease *authorization*
   drawn). Source: existing `CoSQueueLeaseAcquireTelemetry.v8_granted_bytes`
   (`token_bucket.rs`).
3. **drain_sent_bytes** — bytes ACTUALLY submitted to TX. Source:
   **existing** `owner_profile.drain_sent_bytes` / `drain_guarantee_sent_bytes`
   (`tx_completion.rs:483-489`, written post-submit). No new code needed —
   already plumbed.
4. **iperf3 goodput** — the externally measured ~94% (the gate metric).

Plus diagnostic counters:
5. **cap_vs_rate_x_wall** — cap_granted vs `rate × wall_elapsed` (proves
   H1/H4: meter granted the full rate-time product).
6. **bucket_high_water vs lease_bytes** (H-LEASE: if high-water ≈
   `lease_bytes` AND the queue parks, the lease target is the limiter).
7. **park_queue / park_root counts** — existing `drain_park_{queue,root}_tokens`.
8. **wake_delta histogram** `(wake_tick − now_tick)` at park (H7).
9. **service_gap histogram** ns between successive services of the queue (H8).

### 5.2 The FOUR-layer bisection truth table

Run 3g-solo and 6g-solo on the free loss cluster (single port, push, v4,
guarantee-rate 0.7). The three internal ratios + goodput localize the
cause to ONE layer:

| Ratio | If ≈ 1.0 | If ≈ 0.94 ⇒ cause is here |
|-------|----------|--------------------------|
| `cap_granted / (rate×wall)` (5) | meter grants full rate-time | **METER under-grants** ⇒ rate-calc/rotation/fair-share (H4/H5). Folds into cause-1. |
| `total_granted / cap_granted` | class draws all it's allowed | **GRANT NOT DRAWN** ⇒ drain can't pull the grant — bucket/park (H7/H-LEASE). |
| `drain_sent / total_granted` | drawn bytes are sent | **DRAWN NOT SENT** ⇒ TX-ring refusal / scratch-build fail / restore-retry. |
| `goodput / drain_sent` | TX bytes become goodput | **SHAPER IS FINE, TCP LOSES IT** (H-TCP) ⇒ cause 2 is OUTSIDE the shaper (pacing/burst-smoothing, not grant/park). |

**Expected primary outcome (the hypothesis to confirm):**
`cap_granted/(rate×wall) ≈ 1.0` AND `total_granted/cap_granted ≈ 0.94`
AND high `park_queue` ⇒ grant-not-drawn via park. Then counter 6
(H-LEASE) vs counter 8 (H7) decides whether the limiter is the lease
target or the wheel floor:
- high-water ≈ `lease_bytes` (bucket maxed at 200µs) ⇒ **H-LEASE** (fix:
  raise lease target).
- high-water ≪ `lease_bytes` but park fires with wake-delta mode = 1 tick
  and refill ≪ tick ⇒ **H7** (fix: sub-tick wake, §6).

**This four-layer table is the deliverable.** It cannot be short-cut: the
v1 two-way split conflated draw-vs-send and could not see TCP. One read
of these ratios on the free cluster names the layer.

### 5.3 Confirm root is not the limiter (re-verify the prior claim)

Prior runs showed `park_root = 0`. Re-confirm for 3g/6g SOLO: counter 7
(`drain_park_root_tokens`) ~0 and root-lease grant vs `shaping_rate ×
wall` ≈ 1.0. If the root meter throttles a SOLO single-class run, the
residual is a root-shaper artifact (fix: root `EPOCH`/burst), and all
per-queue hypotheses are demoted.

---

## 6. Fix mechanism (conditioned on the §5 layer — v2: defective F-A/F-B DEMOTED)

> v2 demotes v1's F-A and F-B (Codex MAJOR-2/3 + Claude MAJOR-1): F-A is
> a no-op for same-tick future wakes; F-B busy-polls a cap-exhausted
> lease. The mechanism is now chosen by the §5 layer, with the
> lease-target raise and the sub-tick wake as the two primary candidates.

### 6.1 If §5 layer = "grant-not-drawn, H-LEASE" — raise the lease target (PRIMARY candidate)

Raise `COS_ROOT_LEASE_TARGET_US` (or the per-queue `config.lease_bytes`
target) so the bucket can bank ≥2-3 wheel ticks of credit (e.g. 600µs
instead of 200µs). Then the queue parks far less often and the 50µs floor
amortizes over more sent bytes. **Burst-bound proof required:** a larger
bucket holds more burst. The per-queue `buffer_bytes` (3.75/7.5 MB) and
`max_total_leased = burst/4` already bound it; the cause-1 grant cap still
meters the *rate*. Gate (§8) must prove no class exceeds shape over any
10ms window. This touches `compute_shared_cos_lease_config` (meter-side
config) — see §9 for the revised layering argument.

### 6.2 If §5 layer = "grant-not-drawn, H7 (wheel floor)" — sub-tick wake (PRIMARY candidate)

The defect is that a ~2µs refill is rounded to a 50µs park. Two correct
fixes (NOT v1's F-A/F-B):

- **F-E (stay-runnable ONLY when grant is available AND refill < tick):**
  unlike v1's F-B, gate the stay-runnable on BOTH `queue_refill_ns < TICK`
  AND the class cap NOT being exhausted this epoch (so it cannot
  busy-poll a cap-exhausted lease — kills Codex MAJOR-3). Mechanism: in
  the exact park branch, if `queue_refill_ns < TICK && class_granted < cap`,
  `continue` (let RR revisit) instead of parking; bounded by the existing
  drain budget. When the cap IS exhausted, park to the epoch boundary
  (not the wheel), which is the correct wake.
- **F-F (sub-tick wake representation):** represent `next_wakeup_tick` at
  finer resolution for the bucket-refill case, OR shrink only the L0
  horizon. Heavier (touches the wheel L0/L1 math); fallback to F-E.

F-E is confined to the drain/park path — NO seqlock, NO atomic, NO shared
state (§7).

### 6.3 If §5 layer = "drawn-not-sent" — TX submit path

TX-ring refusal or scratch-build failure under bursty 200µs delivery.
Fix is in the submit path (`tx_completion.rs` apply paths), orthogonal to
both causes. Re-scope at /engineer.

### 6.4 If §5 layer = "sent-but-TCP-loses (H-TCP)" — the honest PLAN-KILL branch

If the shaper grants AND sends ~100% of shape but iperf3 still reports
94%, cause 2 is NOT a shaper bug. The residual is TCP's response to
50µs-quantized bursty delivery. Dispositions, in order of preference:
- (i) smooth delivery (smaller service quantum / sub-tick wake) to reduce
  burstiness — overlaps F-E/F-F, may recover goodput without a grant
  change;
- (ii) accept ~94% as the AF_XDP-per-CPU + TCP-pacing physics floor for
  mid-rate single-flow-bundle classes and **re-frame Gate 1** (requires
  charter authorization — this is the documented PLAN-KILL exit, matching
  the cause-1 §12 "neither fork" honesty).
This branch is why §5's goodput ratio is load-bearing: it is the
difference between "fixable shaper defect" and "rate-accuracy physics."

### 6.5 Why this is NOT cause 1 and (mostly) does NOT need the carry

Cause 1 enlarges the *grant*; cause 2 (except the H-LEASE branch) is
downstream of the grant. With a full grant the class still cannot emit it
if the drain parks it (H7) or the bucket can't bank it (H-LEASE). The
carry without a cause-2 fix leaves 3g/6g at ~94% (measured); a cause-2
fix without the carry leaves 100m at ~82% (measured). **Both are required
for Gate 1** — UNLESS §5 shows H-TCP, in which case neither shaper fix
helps and §6.4 applies.


## 7. Seqlock / concurrency surface (composing with cause-1 + #1643)

**Branch-dependent (v2).** The seqlock surface depends on which §5 layer
the bisection picks:

- **Drain-park branch (§6.2, H7/F-E):** touches
  `estimate_cos_queue_wakeup_tick` + the exact park branch —
  **single-worker, per-binding runtime state** (`queue.hot.tokens`,
  `next_wakeup_tick`, the timer wheel). NOT shared, NOT in the v8 seqlock
  payload. **Zero new seqlock surface**; the #1643 fence and the carry's
  `epoch_carry_bytes` are untouched. This is the cleanest composition.
- **Lease-target branch (§6.1, H-LEASE):** raises
  `COS_ROOT_LEASE_TARGET_US` / `config.lease_bytes` in
  `compute_shared_cos_lease_config`. `lease_bytes` IS read by the meter
  path (`token_bucket.rs:184` watermark, `max_total_leased`), so this is
  **meter-side config, NOT a drain-path constant.** It is still NOT in
  the v8 seqlock payload (the seqlock publishes `cap/share/grace/tag`,
  not `lease_bytes`), and it is set once at lease construction (immutable
  per lease), so it adds no new atomic and no torn-read surface. But it
  is NOT as cleanly disjoint from cause-1 as the drain fix — the lease
  config object is shared by all workers (Arc), so a change to its sizing
  interacts with the carry's grant sizing. Review must treat the combined
  meter change (carry + lease-target) as one surface.
- **TX-submit / TCP branches (§6.3/§6.4):** orthogonal to the seqlock
  entirely.

**The drain-park branch is preferred precisely because it is
seqlock-orthogonal.** If §5 forces the lease-target branch, §9's layering
claim weakens (see §9).

---

## 8. Combined acceptance (cause-1 + cause-2 + #1643)

The eventual /engineer PR lands ONE combined change. Gate 1 is the
binding gate and now requires BOTH causes fixed.

- **Gate 1 — ALL FOUR classes SOLO ≥ 95%** (100m/1g/3g/6g, single port
  AND small-four-alone, 12 streams, push, v4, guarantee-rate 0.7). This
  is the gate cause-1 alone CANNOT pass (3g/6g plateau ~90-94) and
  cause-2 alone CANNOT pass (100m ~82). Combined MUST clear all four.
- **Cause-1 lowest-class preserved** — 100m must remain ≥95 (the carry's
  +13pp must not regress when the cause-2 fix changes the park/lease
  cadence).
- **Burst bound held** — Gate 5 (single-class stall→resume ≤ K×rate×EPOCH,
  per cause-1 plan §7) AND a NEW cause-2 burst check: the cause-2 fix
  (F-E stay-runnable OR the larger lease target) must not let any class
  exceed shape over any 10ms window (counter: per-class TX bytes / 10ms ≤
  shape × 1.05). Proves §6.1/§6.2 burst-safety.
- **`make test-failover`** — mandatory (TX-shaping change). Zero-drop;
  cause-1's reused-lease unit test passes; the cause-2 park/lease change
  does not alter failover (park + lease state is per-binding, rebuilt on
  promote).
- **Full matrix** — v4+v6 × push+`-R` × CoS-off+CoS-on, per memory
  feedback. Gate 2 (priority-low ≥5%), Gate 3 (retransmits ≤100/30s),
  Gate 4 (aggregate ≥19.5G) must not regress.
- **Cause-2 regression test (branch-dependent):**
  - drain-park branch: a Rust unit test that a bucket-bound exact queue
    with `queue_refill_ns < TICK` AND `class_granted < cap` stays runnable
    (F-E, NOT parked), bounded by the drain budget; and that a
    cap-exhausted queue parks to the EPOCH boundary (not busy-poll) —
    pins the Codex-MAJOR-3 fix.
  - lease-target branch: a unit test that the bucket high-water can reach
    ≥2 ticks of credit and that `max_total_leased`/buffer still bound the
    burst.

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
3. **Cause-2 fix — branch-dependent on §5:**
   - if drain-park (H7): F-E in `estimate_cos_queue_wakeup_tick` + the
     exact park branch. **Drain layer — NO seqlock, NO atomic, NO shared
     state.** Cleanest composition.
   - if lease-target (H-LEASE): raise `COS_ROOT_LEASE_TARGET_US` /
     `config.lease_bytes`. **Meter-config layer** — immutable per lease,
     not in the seqlock payload, but shared (Arc) so it co-reviews with
     the carry's grant sizing.
   - if TX-submit / TCP: orthogonal (or §6.4 PLAN-KILL exit).

**Composition by layer (drain-park branch — the preferred outcome):**
(1)+(2) are the meter/seqlock surface (carry + fence, the only
concurrency-sensitive code); (3) is a disjoint single-threaded drain
change sharing NO field. The combined PR's hostile concurrency review is
bounded to (1)+(2).

**If §5 forces the lease-target branch:** the "clean layering" claim is
WEAKER — the lease config is shared meter state whose sizing interacts
with the carry. It is still seqlock-payload-disjoint (immutable per
lease, not seq-guarded), but the combined meter change (carry +
lease-target) must be reviewed as ONE sizing surface, and the burst-bound
proof (§8) must cover the carry's grant AND the larger bucket together.

Gate 1 requires cause-1 + the §5-selected cause-2 fix + #1643 — UNLESS §5
shows H-TCP, in which case §6.4 (smooth-or-reframe) applies and the
combined PR may not be able to clear Gate 1 as currently scoped (an
honest possible outcome, flagged in §10-R7).

---

## 10. Risks & residuals

- **R1 — the §5 layer is meter-under-grant, not drain.** Then the
  drain-park fix is wrong and the fix merges into cause-1
  (rate-calc/fair-share). Mitigation: §5 runs FIRST at /engineer; the
  plan commits NO mechanism before the bisection names the layer.
- **R2 — F-E "stay-runnable" busy-loops.** Mitigation (Codex MAJOR-3):
  F-E fires ONLY when `queue_refill_ns < TICK` AND `class_granted < cap`
  (grant available). A cap-exhausted queue parks to the EPOCH boundary,
  NOT the wheel — so it cannot busy-poll an exhausted lease. The drain
  budget (`should_enter_shaped_drain` + REINGEST_BUDGET=4) bounds spins.
  Gate 4 (CPU/aggregate) catches a regression.
- **R3 — 11-class full simul (H8).** Solo isolates the per-queue
  hypothesis, but under 11 classes the RR-revisit latency may re-open a
  gap F-E cannot close (worker busy elsewhere when the bucket refills).
  Mitigation: Gate 1b (full simul) is a gate; if H8 dominates under load
  a finer scheduler (#1614) may be needed — call it out, do not silently
  pass.
- **R4 — the lease-target raise increases burst.** A bigger bucket banks
  more credit. Mitigation: `buffer_bytes` (3.75/7.5 MB) +
  `max_total_leased = burst/4` already bound it, and the cause-1 grant
  cap still meters rate. Gate 5/8 burst checks are mandatory for this
  branch.
- **R5 — cause-1's reduced scope.** Cause-1's plan claimed Gate 1; with
  cause 2 split out, cause-1 only owns 100m/1g. /engineer MUST re-scope
  the cause-1 plan's Gate-1 claim or the combined PR appears to fail
  cause-1's own gate. Documented §9.
- **R6 — VISIT_NS / TICK alignment (F-D).** A cheap alternate: make
  `COS_GUARANTEE_VISIT_NS` an integer multiple of the wheel tick so the
  park lands on a boundary with less rounding. Couples two constants;
  evaluate only if §5 shows the wheel-floor is the layer and F-E is
  rejected. Listed for completeness.
- **R7 — H-TCP: the residual may be OUTSIDE the shaper.** If §5's
  `goodput/drain_sent < 1` while the shaper grants and sends full shape,
  cause 2 is TCP's response to bursty 50µs-quantized delivery, not a
  shaper defect. Then §6.4 applies: smooth delivery (may recover it) OR
  re-frame Gate 1 (charter-authorized PLAN-KILL exit). The combined PR
  may NOT clear Gate 1 at 95% if this is the physics floor — this is the
  honest worst case, matching the cause-1 §12 "neither fork" precedent.

---

## 11. 5+ hostile open questions (for the reviewers to attack)

1. **What sets the park CADENCE, given the basis is `head_len` not the
   quantum?** v2 corrected the park-refill basis to `head_len` (~2µs),
   so the per-park dead time is the 50µs floor — but how OFTEN does the
   queue park? That depends on how much credit the bucket holds when it
   starts draining (the service quantum 75K/150K, OR `lease_bytes`
   200µs-of-credit, whichever the bucket actually reaches). The flat-loss
   intuition only survives if `parks_per_second × 50µs` is a
   rate-independent fraction — which the v2 plan explicitly says it CANNOT
   derive and must MEASURE (counter 7 park rate). **A reviewer should
   attack whether the flatness across 3g/6g is mechanistic or
   coincidental, given the magnitude is now admittedly unknown.**
2. **Why does the wheel hurt a SOLO single-class run (P3)?** With one
   class the worker RR has nothing else to do — so why park at all
   instead of immediately re-servicing? Answer hinges on: does the
   bucket actually empty below `head_len` within a single poll pass
   (line-rate drain of 150K in <1µs) then have to wait `t_refill` for
   the NEXT frame? If the poll loop spins faster than `t_refill`, the
   wheel floor (`now_tick+1`) is what forces the 50µs park even with
   nothing else to do. **A reviewer must confirm the queue genuinely
   parks (`drain_park_queue_tokens` > 0) rather than staying runnable in
   the solo case; if it stays runnable, the wheel-floor hypothesis is
   wrong and the loss is elsewhere (H-LEASE or H-TCP).**
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
4. **Does F-E violate work-conservation or fairness under contention?**
   Staying runnable for a sub-tick refill means a 3g queue could be
   re-serviced ahead of an 11-class RR cycle. Under full load this could
   steal service from other classes. **Is F-E's "stay runnable" actually
   a priority inversion that helps solo but hurts the simul (Gate 1b)?**
   (Note the F-E `class_granted < cap` guard caps it at the class rate,
   so it cannot exceed shape — but RR-ORDER fairness vs other classes is
   a separate concern the reviewer should attack.)
5. **Is the 6% an artifact of TCP, not the shaper? (H-TCP — the killer
   question.)** The measurement is iperf3 TCP goodput. 50µs-quantized
   bursty delivery could inflate RTT/jitter and depress the TCP window,
   costing throughput that is NOT the shaper's grant. **The §5
   `goodput/drain_sent` ratio settles this: if the shaper grants AND
   SENDS ~100% of shape (drain_sent ≈ rate×wall) but iperf3 still reports
   94%, the loss is in TCP/delivery-burstiness, and the fix is
   pacing/burst-smoothing (or re-framing Gate 1), not the grant or the
   park.** This could move cause 2 out of the shaper entirely (§6.4 /
   §10-R7).
6. **Does the cause-1 carry CHANGE the cause-2 behavior?** The carry
   enlarges `cap` (the grant), NOT `lease_bytes` (the bucket top-up
   target = `config.lease_bytes`, static). So the carry does NOT refill
   the bucket more — confirming drain-park independence. BUT if §5 picks
   the H-LEASE branch (raise `lease_bytes`), the carry's larger grant AND
   the larger bucket BOTH increase burst — so on THAT branch the §9
   "clean layering" is false and the burst proof must cover both. **A
   reviewer should pick the branch and check the carry-interaction
   claim per branch, not in general.**

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
- Exact-queue park branch (the wheel-floor site): `queue_service/mod.rs:665-700`
  (`drain_park_queue_tokens` + park), `:688` wake-tick call. **Verified
  the 4th positional arg to `estimate_cos_queue_wakeup_tick` here is
  `head_len`, NOT the quantum** (Codex BLOCKING-1 — the v2 correction).
- Service batch (the ONLY quantum user): `secondary_budget =
  tokens.min(cos_guarantee_quantum_bytes).max(head_len)`,
  `queue_service/mod.rs:702-707`.
- **TX-sent counter for the §5 bisection:** `owner_profile.drain_sent_bytes`
  / `drain_guarantee_sent_bytes`, written post-submit at
  `cos/tx_completion.rs:483-489`; `lease.consume(sent_bytes)` `:540-549`.
- **No waterfill drain path (reject Codex BLOCKING-2):** `grep waterfill
  userspace-dp/src/` = 1 comment hit (`forwarding_build/cos.rs:424`);
  `oversubscription_policy` written `forwarding_build/cos.rs:443`, read in
  drain = 0 hits.
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
