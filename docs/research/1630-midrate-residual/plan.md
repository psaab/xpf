# #1630 cause-2 — the K-independent ~6% mid-rate (3g/6g) shape residual

- Issue: #1630 (surface). This plan owns **cause 2 only**.
- Branch: `research/1630-midrate-residual` (off `origin/master` @ `0e5bb3812`)
- Mode: `/research` — plan only; NO production code; STOP at PLAN-READY.
  Throwaway env-gated instrumented builds are allowed and MUST NOT be
  committed.
- Author: Claude SMR (CoS-shaper / token-bucket / rate-accuracy /
  AF_XDP-drain / timer-wheel domain).
- Rev: **v3 (r1+r2 folded).** Status after r2: **PLAN-NEEDS-MAJOR,
  re-grounded on the #1614 waterfill selector — the actual
  `guarantee-rate 0.7` drain path.** r2: Codex PLAN-NEEDS-MAJOR
  (BLOCKING-1 — the waterfill drain path EXISTS, both v1/v2's legacy-RR
  model AND the v2 "no-waterfill" rejection are wrong; BLOCKING-2 F-E
  busy-polls a worker-share-exhausted lease; BLOCKING-3 bisection unsound
  for the waterfill split); AGY PLAN-NEEDS-MAJOR (#3 bisection
  TX-contamination, #4 F-E busy-poll, **#6 H-LEASE is TOOTHLESS — the v8
  epoch ceiling caps grant at `rate×200µs` regardless of `lease_bytes`**;
  AGY's §2 "no-waterfill" claim is a WRONG-TREE error, retracted — see
  agy-plan-r2.md); Claude SMR PLAN-NEEDS-MAJOR (self-corrected the r1
  wrong-tree error, concur Codex, derived the waterfill Phase-1 boundary
  arithmetic).

> **CRITICAL CORRECTION (r2):** v1/v2 were built on the WRONG drain path.
> The cwd `/home/ps/git/bpfrx` is a stale detached checkout
> (`e01472f4a`) predating the #1614 A1 waterfill merge; origin/master and
> the research worktree are `0e5bb3812`, which dispatches
> `guarantee-rate 0.7` exact queues to **`select_exact_cos_guarantee_queue_waterfill`**
> (`queue_service/mod.rs:608`). Both my r1 grep and AGY r2 §2 "verified"
> against the stale tree and wrongly rejected it. Codex was right both
> rounds. v3 re-grounds the entire mechanism on the waterfill selector.

## v3 changelog (r2 response — major re-grounding)

- **[Codex r2 BLOCKING-1] §2/§3 RE-GROUNDED on the waterfill selector.**
  The leading hypothesis is now **H-WATERFILL** (§3): under
  `guarantee-rate 0.7` a solo/boundary mid-rate exact class is honored
  for only `fraction × quantum` per epoch in Phase 1; the residual rides
  the **non-parking, best-effort Phase 2** (`:973-977` "Don't park in
  Phase 2 … not a guarantee"). This is a fixed fractional shortfall set
  by `guarantee_fraction` — exactly the K/P2/contention-independent flat
  P1-P4 signature, and it appeared precisely when #1626/#1629 activated
  the knob (the issue title: "under guarantee-rate 0.7").
- **[AGY r2 #6] H-LEASE KILLED as a fix.** Raising `lease_bytes` is
  toothless: `acquire_v8` caps the grant at `my_effective_share ≤
  new_cap ≤ rate×EPOCH_DURATION_NS` (200µs). The bucket cannot bank more
  than 200µs without raising the global epoch. H-LEASE removed as a fix
  candidate (kept only as a measured falsifier).
- **[Codex r2 BLOCKING-2 / AGY #4] F-E guard fixed/retired.** The wheel
  fix is no longer primary; if revisited the guard must include
  `my_consumed < my_effective_share`.
- **[Codex r2 BLOCKING-3 / AGY #3] §5 bisection re-derived** around the
  waterfill Phase-1/Phase-2 byte split + TX-residual netting.
- **[AGY r2 #5] H-TCP** reframed: "needs a smoothing fix," not a pure
  PLAN-KILL dodge — only kill if bytes provably left the NIC at full rate.

## v2 changelog (r1 response — superseded by v3 where noted)

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

### 2.4 The drain + WATERFILL selector (the actual `guarantee-rate` path)

`select_exact_cos_guarantee_queue_with_lease_telemetry`
(`queue_service/mod.rs:590`) dispatches based on policy:

```rust
// :603-614
if matches!(root.oversubscription_policy, GuaranteeRate)
    && root.oversubscription_guarantee_fraction > 0.0 {
    return select_exact_cos_guarantee_queue_waterfill(root, …);  // <-- the smoke path
}
// else: legacy round-robin exact selector (Proportional)
```

The smoke runs `oversubscription-policy guarantee-rate 0.7`, so 3g/6g
traverse the **two-phase waterfill selector** (`:771`), NOT the legacy
RR path v1/v2 modeled. The waterfill mechanics (verified):

- **Phase-1 budget** (lazy-refilled per epoch when `pass1_remaining == 0`,
  `:787-799`): `pass1 = floor(quantum_sum × fraction)` where `quantum_sum`
  = Σ `cos_guarantee_quantum_bytes` over the runnable+nonempty exact set,
  and `fraction = 0.7`.
- **Phase 1** (`:808-912`): ascending-rate walk. For each eligible exact
  queue, top-up, then `candidate_budget = tokens.min(quantum).max(head_len)`.
  **If `candidate_budget > pass1_remaining` → `break` to Phase 2**
  (`:889`); else honor the queue (consume budget, return the selection).
  Token-starved queues here DO park (`:853-873`).
- **Phase 2** (`:922-1001`): descending walk over un-honored queues.
  **Crucially, Phase 2 does NOT park** — `:973-977`:
  `if root.tokens < head_len || queue.hot.tokens < head_len { … continue }`
  with the comment *"Don't park in Phase 2 — the queue may legitimately
  wait for next epoch … best-effort residual, not a guarantee."*
- **Epoch reset** (`:1002-1006`): when nothing is serviced,
  `pass1_remaining = 0` and the Phase-2 cursor resets; the next call
  refills the Phase-1 budget.

`cos_guarantee_quantum_bytes = clamp(rate×VISIT_NS, 1500, 512K)` with
`VISIT_NS = 200_000`. 3g quantum = 75 000, 6g = 150 000 (both < 512K).

The wake estimator (used by the Phase-1 park sites and the legacy path)
is `estimate_cos_queue_wakeup_tick(root_tokens, root_rate, queue_tokens,
queue_rate, need_bytes=head_len, now, require_queue_tokens)` — `head_len`
is the **5th** positional arg (`need_bytes`), per the signature at
`:1255-1263` (Codex/AGY r2 corrected v2's "4th arg" wording). Wheel tick
50µs, floored at `now_tick+1` (`:1288`). The wheel matters only for
Phase-1 parks; Phase-2 never parks.

---

## 3. Leading hypothesis: H-WATERFILL (v3 — re-grounded on the actual path)

### 3.1 The mechanism

Under `guarantee-rate 0.7`, the Phase-1 budget is `quantum_sum × 0.7`.
A class is **honored in Phase 1** (the guaranteed, park-capable pass)
only if its quantum fits the remaining Phase-1 budget when the ascending
walk reaches it (`:889`). The residual `(1 − 0.7) = 30%` of the eligible
quantum mass falls to **Phase 2, which does not park and is explicitly
"best-effort residual, not a guarantee."** A class served via Phase 2
gets serviced opportunistically — only when root tokens AND its bucket
both already hold a frame at the instant of the descending walk; whatever
it cannot place that epoch is simply skipped (`continue`), not parked for
a guaranteed retry. **That is a structural shortfall whose size is set by
`(1 − fraction)` and the Phase-2 placement efficiency — independent of
the carry depth K (cause 1), the per-visit frame cap P2, and cross-worker
contention.** This is the P1/P2/P3/P4 signature exactly.

### 3.2 Boundary arithmetic for the measurement configs (verified by computation)

`quantum(rg) = clamp(rg×1e9/8 × 200e-6, 1500, 512K)`:
100m=2500, 1g=25 000, 3g=75 000, 6g=150 000, … 24g=524 288.

| Config (fraction 0.7) | quantum_sum | Phase-1 budget | Phase-1 honored (ascending) | Boundary |
|-----------------------|------------:|---------------:|-----------------------------|----------|
| **solo 3g** | 75 000 | 52 500 | **none** (3g quantum 75 000 > 52 500) | 3g itself — served ONLY in Phase 2 |
| **solo 6g** | 150 000 | 105 000 | **none** (150 000 > 105 000) | 6g — Phase 2 only |
| **4-class small-four-alone** | 252 500 | 176 750 | 100m, 1g, 3g | **6g** (150 000 > 74 250 remaining) — Phase 2 only |
| solo 100m | 2 500 | 1 750 | none (2 500 > 1 750) | 100m — Phase 2 only (but ALSO grant-bound → cause 1 dominates) |
| **full 10-class** | 2 651 076 | 1 855 753 | through 18g | 21g/24g (so 3g/6g ARE Phase-1-honored in the full mix) |

**Two sharp, falsifiable predictions:**

1. **Solo 3g and solo 6g are NEVER honored in Phase 1** at fraction 0.7
   (their own quantum exceeds 0.7× their own quantum). They live entirely
   in the non-parking Phase-2 residual. Their guaranteed budget is
   effectively 0; they survive only on Phase-2 best-effort. **This is the
   prime candidate for the solo 3g/6g ~6% residual.**
2. In the **4-class** harness, 3g IS honored (Phase 1 reaches it) but 6g
   is NOT — predicting 6g should show a LARGER residual than 3g in that
   config. The measured 4-class numbers (3g 91.0, 6g 90.2 at K=8+P2) are
   close but 6g IS slightly lower — weakly consistent, MUST be confirmed.

These are concrete, checkable claims the §5 measurement either confirms
or kills. Note the tension (open question §11-Q1): in the FULL 10-class
mix 3g/6g ARE Phase-1-honored, yet the issue's 11-class simul ALSO shows
~20-23% — so H-WATERFILL explains the SOLO/4-class residual cleanly but
the full-simul failure has additional causes (cross-class budget
competition), which is #1614's broader scope, not cause-2's flat solo
residual. v3 is scoped to the SOLO/4-class flat residual.

### 3.3 Why H-LEASE is KILLED as a fix (AGY r2 #6, decisive)

Raising the bucket lease target cannot help: `acquire_v8` caps the grant
at `my_effective_share ≤ my_share = new_cap × my_count/total_flows`, and
`new_cap = rate × elapsed ≤ rate × EPOCH_DURATION_NS` (200µs)
(`rotate_epoch_v8.rs:220` + `:232`; `acquire_v8` break at
`mod.rs:1081`). The bucket can NEVER bank more than 200µs of credit
under the v8 epoch ceiling regardless of `lease_bytes`, and the
post-grace bypass is closed for strict exact CoS. **H-LEASE is removed
as a fix candidate** (kept only as a §5 falsifier — counter 6 confirms
the bucket never exceeds `rate×200µs`).

### 3.4 Reconciling with cause-1

Cause-1 K=64 lifted 100m +13pp but 3g/6g only +3-5pp. Under H-WATERFILL:
100m is BOTH Phase-2-relegated AND grant-bound (cap 2500 < one frame), so
the carry (which fixes the grant-bound part) moves it a lot; 3g/6g are
not grant-bound, so the carry barely helps and the Phase-2-residual
shortfall remains — the measured split. Consistent, not yet proven; §5
settles it.

---

## 4. Hypothesis table — falsify each (v3, re-grounded on the waterfill path)

| # | Hypothesis | Verdict | Falsifier / keeper |
|---|-----------|---------|--------------------|
| **H-WATERFILL** | **Solo/boundary mid-rate exact class served only via the non-parking Phase-2 residual (`fraction × quantum` Phase-1 budget excludes it)** | **LEADING.** Matches P1-P4; appeared with the `guarantee-rate 0.7` knob. Boundary arithmetic (§3.2) shows solo 3g/6g are NEVER Phase-1-honored at 0.7. | §5: per-phase byte counters — if 3g/6g solo bytes are ~all Phase-2 and Phase-2 places < 100% of quantum/epoch, confirmed. KILLED if 3g/6g are Phase-1-honored solo (they shouldn't be per §3.2). |
| H1 | Integer-division truncation `rate×elapsed/1e9` | KILLED by arithmetic (3g/6g exact). | §5 counter 5. |
| H2 | Grace window caps throughput | WEAK (grace gates only surplus/bypass; exact non-surplus never enters). | confirm `bypass_grace_use_count == 0`. |
| H4 | Lazy-rotation stale cap (no clamp) | Overlaps cause 1; K-independent ⇒ not dominant. | §5 counter 5. |
| H5 | Per-worker fair-share rounding under-grants | SECONDARY. `my_share = new_cap × my_count/total_flows` floor-div; if 12 streams spread across workers, contributes. AGY r2 #3 + Codex r2 B3: this contaminates the bisection — must be a SEPARATE branch. | §5: per-worker share-exhaustion counter; worker-count for the solo run. |
| H6 / H-LEASE | Bucket/lease-target depth limits throughput | **KILLED as a FIX (AGY r2 #6):** grant hard-capped at `my_effective_share ≤ rate×200µs` by the epoch ceiling regardless of `lease_bytes`. Kept only as a §5 falsifier. | §5 counter 6: bucket high-water never exceeds `rate×200µs`. |
| H7 | 50µs wheel park floor | NOW SECONDARY — only bites Phase-1 parks; Phase 2 (where solo 3g/6g live) does NOT park. If H-WATERFILL holds, the wheel is largely irrelevant to the solo residual. | §5: `drain_park_queue_tokens` for 3g/6g solo — if ~0 (because they're in non-parking Phase 2), H7 is not the cause. |
| H-TCP | The 6% is TCP goodput artifact, not shaper | MUST be ruled out (AGY r2 #5: only KILL if bytes provably leave the NIC at full rate; else it's a smoothing fix). | §5 `goodput/drain_sent` after L2 normalization. |

**Net (v3):** **H-WATERFILL is the prime suspect.** H7/H-LEASE demoted
(Phase 2 doesn't park; lease raise is epoch-capped). H5 (fair-share) and
H-TCP are the two that, with H-WATERFILL, the §5 bisection must
separate. The waterfill Phase-1/Phase-2 byte split is the new bisection
axis — NOT the wheel park histogram.

---

## 5. The instrumented bisection (v3 — waterfill-phase byte accounting)

Env-gated debug counters in a LOCAL throwaway build, NOT committed
(`option_env!("XPF_COS_MIDRATE_DEBUG")`, additive `AtomicU64` on the
existing `owner_profile` block + the waterfill selector). Removed before
the /engineer PR.

### 5.1 Counters (per 3g/6g queue, per 1s window)

1. **phase1_honored_bytes** — bytes for which this queue was SELECTED in
   Phase 1 (`select_exact_cos_guarantee_queue_waterfill` Phase-1 return,
   `:907`). Add `secondary_budget` at the return.
2. **phase2_served_bytes** — bytes selected in Phase 2 (`:996` return).
3. **phase1_skipped_count / phase2_skipped_count** — times the queue was
   walked but skipped (Phase-1 budget-exhausted break `:889`; Phase-2
   no-park `continue` `:978`).
4. **drain_sent_bytes** — actual TX (existing, `tx_completion.rs:482`),
   net of stranded `queue.hot.tokens` (AGY r2 #3: subtract residual hot
   tokens so a TX-ring refusal is not mis-attributed).
5. **cap_granted** vs `rate×wall` (H1/H4).
6. **bucket_high_water** vs `rate×200µs` (H-LEASE falsifier).
7. **per-worker share-exhaustion count** + worker count (H5).
8. **iperf3 goodput**, L2-normalized vs `drain_sent` (H-TCP).

### 5.2 The decision table

Run 3g-solo and 6g-solo (single port, push, v4, guarantee-rate 0.7):

| Observation | Conclusion |
|-------------|------------|
| `phase1_honored ≈ 0` AND `phase2_served ≈ all` AND `phase2_skipped` high | **H-WATERFILL CONFIRMED** — the class lives in the non-parking Phase-2 residual and Phase 2 cannot place a full epoch's worth. **Expected primary.** |
| `phase1_honored ≈ all` (queue IS Phase-1-honored solo) | H-WATERFILL WRONG (contradicts §3.2 arithmetic) — re-open. |
| `drain_sent/(cap_granted) ≈ 0.94` AND `phase2_served ≈ drain_sent` | the loss IS the Phase-2 placement shortfall (not TX, not TCP). |
| `goodput/drain_sent < 1` (normalized) while `drain_sent ≈ rate×wall` | **H-TCP** — bytes leave the NIC at rate, TCP loses goodput → smoothing fix (§6.4), not a Phase split fix. |
| per-worker share-exhaustion high with multiple workers | **H5** — fair-share rounding; folds into cause-1 meter, not the waterfill. |
| `bucket_high_water > rate×200µs` | H-LEASE alive (contradicts AGY r2 #6) — re-open. |
| `drain_park_queue_tokens` ≈ 0 for solo 3g/6g | confirms they're in non-parking Phase 2 (H7 not the cause). |

The Phase-1/Phase-2 byte split is the load-bearing measurement. It
directly tests H-WATERFILL and cleanly separates it from H5 (fair-share)
and H-TCP. One cluster run fills it.

### 5.3 Confirm root is not the limiter

Re-confirm `drain_park_root_tokens ≈ 0` and root-lease grant ≈
`shaping_rate × wall` for 3g/6g solo. If the root throttles a solo class,
that is a separate root-meter fix.

---

## 6. Fix mechanism (v3 — the waterfill allocator, conditioned on §5)

> v3 KILLS the v2 lease-target (F-C', epoch-capped) and demotes the wheel
> (F-A/F-B/F-E — Phase 2 doesn't park). If §5 confirms H-WATERFILL the
> fix is in the waterfill selector itself. This is a genuine #1614
> scheduler change, NOT a one-line tweak — and the plan says so honestly.

### 6.1 PRIMARY (H-WATERFILL confirmed): the Phase-1 budget must not exclude a class below its OWN rate

The defect: `guarantee_fraction` is meant to bound CROSS-class
oversubscription (when the sum of guaranteed rates exceeds the shaping
rate, honor `fraction` of the aggregate). But the current Phase-1 budget
`quantum_sum × fraction` is applied even when the eligible set is a
SINGLE class or fits comfortably under the shaping rate — so it shrinks a
solo class below its own configured rate, which is wrong: a class whose
rate fits the interface MUST get its full rate first (the
`docs/fairness-regimes.md` contract). Candidate fixes (for /engineer to
choose after §5):

- **F-W1 — gate the fraction on actual oversubscription.** Only apply the
  `× fraction` Phase-1 cap when `Σ guaranteed_rate > shaping_rate`
  (genuine oversubscription). When the eligible guaranteed mass fits the
  shaping rate (the solo and 4-class cases — 0.1+1+3+6 = 10.1g ≪ 25g),
  Phase 1 honors every class's FULL quantum and there is no Phase-2
  relegation. This directly fixes the solo/4-class residual and matches
  the documented "small classes reach 100% first" contract.
- **F-W2 — make Phase 2 a guaranteed (park-capable) pass for exact
  classes.** If the residual must ride Phase 2, Phase 2 should park and
  retry exact classes (not best-effort `continue`) so their guaranteed
  rate is still honored across epochs. Heavier; changes the Phase-2
  semantics and may interact with priority-low.
- **F-W3 — size the Phase-1 budget per-class** (each class gets
  `quantum_i` honored if `Σ quantum ≤ shaping×EPOCH`, else proportional
  shedding only of the over-subscribed surplus). Most faithful to WFQ
  but the largest change.

**Recommended primary: F-W1** — it is the smallest change that respects
both the oversubscription intent and the per-class rate floor, and it
makes the solo/4-class cases (which are NOT oversubscribed) behave
correctly by construction. /engineer confirms via §5 + a re-run.

### 6.2 Burst-safety

F-W1 only removes an INCORRECT throttle when there is headroom; it cannot
push a class above its own `transmit-rate exact` cap (the per-queue v8
grant `cap = rate×elapsed` still meters every class). Gate (§8) proves no
class exceeds shape over any 10ms window.

### 6.3 If §5 layer = H5 (fair-share) / H-TCP / root — alternates

- H5: distribute the per-worker share remainder (folds into cause-1).
- H-TCP: smooth delivery (sub-tick pacing) — overlaps a wheel/Phase
  change; only re-frame Gate 1 if bytes provably leave the NIC at rate
  (§6.4).
- root: raise root burst/epoch (orthogonal).

### 6.4 The honest PLAN-KILL exit

If §5 shows the shaper grants AND sends ~100% of shape (drain_sent ≈
rate×wall, normalized) but iperf3 still reports 94%, the residual is TCP
physics, not a shaper defect — and (per AGY r2 #5) the right move is a
delivery-smoothing fix, with Gate-1 re-framing only as a
charter-authorized last resort. This is the documented worst case.

### 6.5 Why this is NOT cause 1

Cause 1 (carry) enlarges the per-class grant. H-WATERFILL is a
SELECTOR-level relegation that happens AFTER the grant is computed — a
class with a full grant still only gets `fraction` of its quantum
honored in the guaranteed Phase 1. The carry cannot touch the Phase
split. Both are needed for Gate 1 (carry fixes 100m grant-bound; F-W1
fixes 3g/6g Phase-2 relegation) — unless §5 shows H-TCP.


## 7. Seqlock / concurrency surface (composing with cause-1 + #1643)

**The PRIMARY fix (F-W1, waterfill Phase-1 budget gating) is
seqlock-orthogonal.** The waterfill state —
`waterfill_pass1_remaining_bytes`, `waterfill_phase2_cursor`,
`exact_queues_by_rate_ascending`, `oversubscription_guarantee_fraction`,
`oversubscription_policy` — lives on `CoSInterfaceRuntime`
(`types/cos.rs`), which is **per-binding, single-worker runtime state**.
It is NOT an `Atomic`, NOT shared across workers, NOT in the v8 seqlock
payload (which publishes `cap/share/grace/tag` only). F-W1 only changes
WHEN the `× fraction` cap applies (gate it on `Σ guaranteed_rate >
shaping_rate`), reading config rates that are already immutable per
lease. **Zero new seqlock surface; the #1643 fence and the carry's
rotation-private `epoch_carry_bytes` are untouched.**

- The cause-2 fix (selector) and cause-1 fix (meter grant) touch
  DISJOINT layers: F-W1 decides which exact queue to SERVICE this visit;
  the carry decides how many bytes the v8 grant ALLOWS. They share no
  field. The combined PR's hostile concurrency review is bounded to the
  cause-1 carry + #1643 fence; F-W1 is reviewed as ordinary
  single-worker selector logic.
- Alternates: H5 (fair-share) folds into the cause-1 meter (then it IS in
  the rotation/seqlock surface — review together). H-LEASE is killed
  (§3.3) so its meter-config surface is moot. H-TCP/root are orthogonal.

**This is the strongest reason F-W1 is the preferred fix: cause 2 stays a
single-threaded selector change, leaving the seqlock review surface
exactly cause-1's (carry + fence).**

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
  per cause-1 plan §7) AND a NEW cause-2 burst check: F-W1 must not let
  any class exceed its `transmit-rate exact` shape over any 10ms window
  (counter: per-class TX bytes / 10ms ≤ shape × 1.05). F-W1 only removes
  an incorrect throttle when there is headroom; the per-queue v8 grant
  `cap = rate×elapsed` still meters each class.
- **`make test-failover`** — mandatory (TX-shaping change). Zero-drop;
  cause-1's reused-lease unit test passes; the waterfill state is
  per-binding and rebuilt on promote.
- **Full matrix** — v4+v6 × push+`-R` × CoS-off+CoS-on, per memory
  feedback. Gate 2 (priority-low ≥5%), Gate 3 (retransmits ≤100/30s),
  Gate 4 (aggregate ≥19.5G) must not regress. **Gate 1b (full 10/11-class
  simul):** F-W1's "no fraction cap when not oversubscribed" must still
  apply the cap WHEN genuinely oversubscribed (Σ guaranteed > shaping) —
  verify the full-mix oversubscription case still sheds correctly and
  priority-low still gets its min-share (the original #1614 intent).
- **Cause-2 regression test (F-W1):** a Rust unit test on the waterfill
  selector that (a) when `Σ guaranteed_rate ≤ shaping_rate` every
  eligible exact class is Phase-1-honored at its FULL quantum (no Phase-2
  relegation), and (b) when `Σ guaranteed_rate > shaping_rate` the
  `× fraction` Phase-1 cap still applies and sheds only the
  over-subscribed surplus. Plus a solo-class test: a single 3g class
  reaches its full quantum in Phase 1.

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
3. **Cause-2 fix (PRIMARY, H-WATERFILL confirmed): F-W1** — gate the
   waterfill Phase-1 `× fraction` cap on actual oversubscription
   (`Σ guaranteed_rate > shaping_rate`) in
   `select_exact_cos_guarantee_queue_waterfill` /
   `CoSInterfaceRuntime`. **Selector layer — per-binding, single-worker,
   NO seqlock, NO atomic, NO shared field.** (Alternates if §5 differs:
   H5 fair-share folds into the cause-1 meter; H-TCP → smoothing/§6.4;
   root → orthogonal. H-LEASE is killed, §3.3.)

**Composition by disjoint layer:** (1)+(2) are the meter/seqlock surface
(carry + fence — the ONLY concurrency-sensitive code); (3) F-W1 is a
single-threaded selector change on per-binding `CoSInterfaceRuntime`
state, sharing NO field with the seqlock payload. The combined PR's
hostile concurrency review is bounded to (1)+(2); F-W1 is reviewed as
ordinary selector logic. This is the clean three-layer composition the
charter asked for: **meter grant (carry) + meter publish (fence) +
selector service (F-W1)**, each independent.

The ONLY case where layering weakens: if §5 picks H5 (per-worker
fair-share rounding), the fix is in the rotation's `my_share`
computation — IN the seqlock writer — and must be reviewed together with
the carry. §5 distinguishes H-WATERFILL (selector, clean) from H5
(meter, coupled).

Gate 1 requires cause-1 + F-W1 + #1643 — UNLESS §5 shows H-TCP, in which
case §6.4 (smooth-or-reframe) applies and the combined PR may not clear
Gate 1 at 95% (an honest possible outcome, §10-R7).

---

## 10. Risks & residuals

- **R1 — H-WATERFILL not the cause (§5 shows the class IS Phase-1-honored
  solo, or the loss is H5/H-TCP).** Then F-W1 is wrong and the §6.3
  alternate applies. Mitigation: §5 runs FIRST at /engineer; the plan
  commits NO mechanism before the Phase-1/Phase-2 byte split names the
  layer. The §3.2 boundary arithmetic is itself a strong pre-check
  (solo 3g/6g CANNOT be Phase-1-honored at 0.7), but it MUST be confirmed
  by the runtime counter.
- **R2 — F-W1 mis-detects oversubscription.** The gate `Σ guaranteed >
  shaping` must use the SAME guaranteed-rate sum the allocator intends
  (and account for which classes are currently eligible/backlogged, not
  the static config sum, or a transiently-idle class inflates the test).
  Mitigation: reuse the existing `exact_demand_rate` / backlog mask
  machinery (`tx_completion.rs:400 exact_backlog_guarantee_rate_bytes_for_mask`)
  rather than a fresh sum. Unit-test both regimes (§8).
- **R3 — full 10/11-class simul still fails (#1614 broader scope).**
  H-WATERFILL explains the SOLO/4-class residual; in the full mix 3g/6g
  ARE Phase-1-honored (§3.2), yet the issue's 11-class run shows ~20%.
  That full-simul failure has additional causes (cross-class budget
  competition, priority-low starvation) that are #1614's scope, NOT
  cause-2's flat solo residual. **This plan is scoped to the solo/4-class
  flat residual; it does NOT claim to fix the full-simul equalization.**
  /engineer must not over-claim — Gate 1b (full simul) may still need
  #1614 work. Stated explicitly to avoid the cause-1 "neither fork"
  over-scope trap.
- **R4 — F-W1 changes priority-low / oversubscription behavior.** Gating
  the fraction could let exact classes consume more, squeezing
  priority-low's min-share in the genuinely-oversubscribed case.
  Mitigation: Gate 2 (priority-low ≥5%) is a hard gate; F-W1 keeps the
  `× fraction` cap WHEN oversubscribed, so the original shedding still
  applies in that regime.
- **R5 — cause-1's reduced scope.** Cause-1's plan claimed Gate 1; with
  cause 2 split out, cause-1 only owns 100m/1g. /engineer MUST re-scope
  the cause-1 plan's Gate-1 claim or the combined PR appears to fail
  cause-1's own gate. Documented §9.
- **R6 — H5 (fair-share) is the real cause, not H-WATERFILL.** If §5
  shows the solo run lands on multiple workers and per-worker share
  rounding under-grants, the fix is in the rotation `my_share`
  computation (coupled to the seqlock/carry, §9). §5's per-worker
  share-exhaustion counter + worker count distinguishes this from
  H-WATERFILL.
- **R7 — H-TCP: the residual may be OUTSIDE the shaper.** If §5's
  `goodput/drain_sent < 1` while the shaper grants and sends full shape,
  cause 2 is TCP's response to bursty 50µs-quantized delivery, not a
  shaper defect. Then §6.4 applies: smooth delivery (may recover it) OR
  re-frame Gate 1 (charter-authorized PLAN-KILL exit). The combined PR
  may NOT clear Gate 1 at 95% if this is the physics floor — this is the
  honest worst case, matching the cause-1 §12 "neither fork" precedent.

---

## 11. 5+ hostile open questions (for the reviewers to attack)

1. **Does the FULL-mix Phase-1-honoring of 3g/6g contradict H-WATERFILL?**
   §3.2 shows that in the full 10-class mix, the Phase-1 budget
   (1 855 753 B) honors through 18g — so 3g/6g ARE Phase-1-honored there,
   yet the issue's 11-class simul still shows ~20%. If H-WATERFILL were
   the whole story, 3g/6g should be FINE in the full mix. **Is
   H-WATERFILL only the SOLO/4-class story, with the full-simul failure a
   separate cause? If so, does fixing the solo residual (F-W1) even move
   the headline #1630 11-class numbers, or does it only clear the SOLO
   Gate-1 the engineer measured?** This is the scope question: the plan
   claims only the solo/4-class residual (§10-R3) — a reviewer should
   attack whether that is the right scope for #1630 or a narrowing dodge.
2. **Is the Phase-2 path actually lossy, or does it place the full
   residual?** §3.1 asserts Phase 2 is "best-effort" and loses a
   fraction, but Phase 2 IS reached every epoch and the drain loop
   re-enters until no work (`should_enter_shaped_drain` loop in
   `tx/drain.rs`). If Phase 2 successfully places the whole residual most
   epochs, the loss is small and H-WATERFILL over-predicts. **A reviewer
   must confirm Phase 2 genuinely sheds bytes (phase2_skipped > 0 with
   un-sent backlog), not just defers within the same drain pass.**
3. **Does the `secondary_budget`-based Phase-1 consumption double-count or
   mis-meter?** Phase 1 decrements `pass1_remaining` by `candidate_budget
   = tokens.min(quantum).max(head_len)` (`:896`), but the queue may not
   actually SEND that many bytes (root tokens, TX ring). So `pass1_remaining`
   is consumed by INTENDED not ACTUAL bytes — could a class be charged
   Phase-1 budget it never used, pushing OTHER classes to Phase 2
   prematurely? **Attack whether the budget accounting matches bytes sent.**
4. **Is F-W1's oversubscription test well-defined under churn?**
   `Σ guaranteed_rate > shaping_rate` must be computed over the right set.
   With backlog masks and transiently-idle classes, the sum flips
   regime-to-regime within an epoch. **Could F-W1 oscillate between
   "apply fraction" and "don't", causing jitter worse than the steady 6%?**
   (See §10-R2.)
5. **Is the 6% actually H-TCP, making F-W1 irrelevant?** If the shaper
   already SENDS ~100% of shape for solo 3g/6g (Phase 2 places it all)
   and iperf3 still reports 94%, then H-WATERFILL is wrong and the loss
   is TCP/burstiness — F-W1 would change nothing. **The §5
   `goodput/drain_sent` (L2-normalized) is the decisive falsifier; a
   reviewer should insist it is measured BEFORE any F-W1 code.**
6. **Does F-W1 break the documented oversubscription contract?** The
   `× fraction` cap was added in #1614 for a reason — to honor only
   `fraction` of the aggregate guaranteed rate under oversubscription.
   F-W1 says "skip the cap when not oversubscribed." **Is there a config
   where the eligible guaranteed sum fits the shaping rate at one instant
   but the operator INTENDED the fraction to throttle anyway (e.g.
   reserving headroom for best-effort)? Does F-W1 violate that intent?**
   A reviewer should check the #1614 contract doc
   (`docs/fairness-regimes.md`) before endorsing F-W1.

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
- **WATERFILL dispatch (the `guarantee-rate` path):**
  `queue_service/mod.rs:603-614` (`if GuaranteeRate && fraction > 0 {
  return select_exact_cos_guarantee_queue_waterfill(...) }`).
- **Waterfill selector:** `select_exact_cos_guarantee_queue_waterfill`
  `queue_service/mod.rs:771`; Phase-1 budget `floor(quantum_sum ×
  fraction)` `:787-799`; Phase-1 honor/return `:889` (budget-exhausted
  break), `:907` (honor return); **Phase 2 NON-PARKING** `:973-977`
  ("Don't park in Phase 2 … not a guarantee"); epoch reset `:1002-1006`.
- **Waterfill state (per-binding, single-worker, NON-atomic):**
  `CoSInterfaceRuntime.waterfill_pass1_remaining_bytes`,
  `waterfill_phase2_cursor`, `exact_queues_by_rate_ascending`,
  `oversubscription_policy`, `oversubscription_guarantee_fraction`
  (`types/cos.rs:369,378-406`) — confirmed NOT `Atomic`, NOT shared, NOT
  in the seqlock payload.
- **oversubscription detection machinery (for F-W1):**
  `exact_backlog_guarantee_rate_bytes_for_mask` `cos/tx_completion.rs:400`.
- Per-visit quantum: `cos_guarantee_quantum_bytes`
  (`queue_service/mod.rs:1246`); `COS_GUARANTEE_VISIT_NS = 200_000`,
  `QUANTUM_MIN = 1500`, `QUANTUM_MAX = 512K` (`tx/drain/mod.rs:561-563`).
- Wake estimator arg: `estimate_cos_queue_wakeup_tick(... queue_rate,
  head_len, now, require_queue_tokens)` — `head_len` is the **5th**
  positional arg (`need_bytes`), signature `:1255-1263` (r2 correction).
- **TX-sent counter for the §5 bisection:** `owner_profile.drain_sent_bytes`
  / `drain_guarantee_sent_bytes`, written post-submit at
  `cos/tx_completion.rs:482-489`; `lease.consume(sent_bytes)` `:540-549`;
  token decrement on send `tx_completion.rs:512` (AGY r2 #3 contamination).
- Timer wheel (Phase-1 parks only): `cos/tx_completion.rs:104
  COS_TIMER_WHEEL_TICK_NS = 50_000`; wake floor `queue_service/mod.rs:1288`.
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
