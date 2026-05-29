# #1630 cause-2 — the K-independent ~6% mid-rate (3g/6g) shape residual

- Issue: #1630 (surface). This plan owns **cause 2 only**.
- Branch: `research/1630-midrate-residual` (off `origin/master` @ `0e5bb3812`)
- Mode: `/research` — plan only; NO production code; STOP at PLAN-READY.
  Throwaway env-gated instrumented builds are allowed and MUST NOT be
  committed.
- Author: Claude SMR (CoS-shaper / token-bucket / rate-accuracy /
  AF_XDP-drain / timer-wheel domain).
- Rev: **v4 (r1+r2+r3 folded).** Status after r3: **PLAN-READY as a
  MEASUREMENT-FIRST plan with NO pre-committed fix.** Three mechanism
  hypotheses were code-falsified across r1-r3 (timer-wheel, lease-target,
  waterfill-relegation); the §5 instrumented bisection is the converged,
  honest next step. r3: Codex PLAN-NEEDS-MAJOR (BLOCKING-1 — H-WATERFILL
  falsified: `quantum_sum` is over the STATIC configured exact set, not
  the eligible set, so the full-config Phase-1 budget honors 3g/6g every
  epoch — F-W1 would be a no-op); Claude SMR PLAN-NEEDS-MAJOR (concur
  Codex; converge to measurement-first); AGY PLAN-READY but on a FALSE
  config assumption ("solo 3g ⇒ quantum_sum=75 000" — true only if the
  config is stripped to 3g; the harness loads ALL 10 classes), REJECTED
  on the §1 error (see agy-plan-r3.md). 2-of-3 decisive against the v3
  mechanism; v4 re-scopes to measurement-first.

> **THE r3 FINDING (decisive):** `exact_queues_by_rate_ascending` is built
> ONCE at config-apply over EVERY configured exact queue
> (`builders.rs:80-83`), and the waterfill `quantum_sum` loop
> (`queue_service/mod.rs:789`) sums it with NO eligibility guard. The
> solo/4-class harness loads the FULL `cos-iperf-config.set`
> (`apply-cos-config.sh load merge`) and sends traffic to one/four ports.
> So `quantum_sum = 2.65 MB`, Phase-1 budget = `0.7 × 2.65 = 1.85 MB`,
> which honors 3g (75 K) and 6g (150 K) EVERY epoch. **H-WATERFILL is
> falsified for the measured config.** Combined with the r1/r2 kills of
> the timer-wheel and lease-target hypotheses, NO code-derived mechanism
> survives static analysis — so the honest /research output is the §5
> measurement, not a fix.

> **CRITICAL CORRECTION (r2):** v1/v2 were built on the WRONG drain path.
> The cwd `/home/ps/git/bpfrx` is a stale detached checkout
> (`e01472f4a`) predating the #1614 A1 waterfill merge; origin/master and
> the research worktree are `0e5bb3812`, which dispatches
> `guarantee-rate 0.7` exact queues to **`select_exact_cos_guarantee_queue_waterfill`**
> (`queue_service/mod.rs:608`). Both my r1 grep and AGY r2 §2 "verified"
> against the stale tree and wrongly rejected it. Codex was right both
> rounds. v3 re-grounds the entire mechanism on the waterfill selector.

## v4 changelog (r3 response — converge to measurement-first)

- **[Codex r3 BLOCKING-1] H-WATERFILL FALSIFIED.** `quantum_sum` is over
  the static configured exact set (no eligibility guard), so the
  full-config Phase-1 budget (1.85 MB) honors 3g/6g every epoch in BOTH
  the solo and 4-class harness runs. §3.2's "solo 3g never Phase-1-honored"
  was based on the wrong assumption that `quantum_sum` is over the
  eligible set. Corrected; H-WATERFILL demoted to a measured falsifier.
- **[AGY r3 — REJECTED] PLAN-READY rested on a stripped-config assumption**
  the harness contradicts (loads all 10 classes). AGY's non-§1 findings
  kept as supporting context.
- **All three mechanisms now code-falsified** (wheel r1/r2, lease r2,
  waterfill r3). v4 re-scopes the deliverable to the **§5 measurement-first
  bisection with NO pre-committed fix** — the disciplined output when
  static analysis cannot attribute the residual. §6 lists candidate fixes
  per measured layer but commits to NONE.

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

## 3. Mechanism hypotheses — all THREE code-falsified (v4)

> v4 status: every concrete mechanism the team derived from the source
> has been falsified by code + arithmetic across r1-r3. This section
> records WHY each is dead, so the §5 measurement does not re-litigate
> them and a future round does not resurrect them. The honest conclusion:
> static analysis cannot attribute the ~6% — measure (§5).

### 3.1 H-WATERFILL (v3 leading hypothesis) — FALSIFIED (Codex r3 BLOCKING-1)

The idea: under `guarantee-rate 0.7`, the waterfill Phase-1 budget
`quantum_sum × 0.7` excludes a solo/boundary mid-rate class, relegating
its residual to the non-parking best-effort Phase 2 (`:973-977`).

**Why it is FALSE for the measured config:** `quantum_sum`
(`queue_service/mod.rs:789`) sums `cos_guarantee_quantum_bytes` over
`root.exact_queues_by_rate_ascending`, which is built ONCE at
config-apply over EVERY configured exact+guarantee queue
(`builders.rs:80-83`, "Built once at config-apply time; runtime is
read-only") with **NO nonempty/runnable guard in the sum**. The
solo/4-class harness loads the FULL `cos-iperf-config.set` (all 10 exact
classes) via `apply-cos-config.sh load merge` and sends traffic to
one/four ports. So:

| Config (full 10-class, fraction 0.7) | quantum_sum | Phase-1 budget | 3g (75K) honored? | 6g (150K) honored? |
|--------------------------------------|------------:|---------------:|-------------------|--------------------|
| solo 3g traffic (all 10 configured)  | 2 651 076 | 1 855 753 | **YES every epoch** | n/a |
| solo 6g traffic (all 10 configured)  | 2 651 076 | 1 855 753 | n/a | **YES every epoch** |
| 4-class traffic (all 10 configured)  | 2 651 076 | 1 855 753 | **YES** | **YES** |

The Phase-1 budget (1.85 MB) dwarfs the small-class quanta; empty queues
are skipped in the Phase-1 WALK (`:811-816`) but still count toward the
budget, so 3g/6g are honored in the guaranteed, park-capable Phase 1
every epoch. **H-WATERFILL cannot be the solo/4-class residual; F-W1
would be a no-op.** (It would matter ONLY if the config were stripped to
a single class — which the harness never does. §5 counter
`phase1_honored_bytes` for 3g/6g confirms ≈ all at runtime; if it is ~0,
the static reading is wrong and H-WATERFILL reopens — but the code says
≈ all.)

### 3.2 H-LEASE (lease-target) — KILLED as a fix (AGY r2 #6)

Raising `lease_bytes` is toothless: `acquire_v8` caps the grant at
`my_effective_share ≤ my_share = new_cap × my_count/total_flows`, and
`new_cap = rate × elapsed ≤ rate × EPOCH_DURATION_NS` (200µs)
(`rotate_epoch_v8.rs:218-232`; `acquire_v8` break `mod.rs:1081`). The
bucket can NEVER bank more than 200µs of credit under the v8 epoch
ceiling regardless of `lease_bytes`; the post-grace bypass is closed for
strict exact CoS. Kept only as a §5 falsifier (counter 6: bucket
high-water never exceeds `rate×200µs`).

### 3.3 H-WHEEL / H7 (timer-wheel park floor) — DEMOTED (r1/r2)

v1/v2 derived the residual from the 50µs wheel park. r1 corrected the
park basis to `head_len` (~2µs refill floored to a 50µs tick). For
strict exact classes the queue parks in Phase 1 only when its bucket
drops below one frame; whether that produces 6% is unproven and the
magnitude could not be derived (the v1 "200/225 = 88.9%" claim was
retracted). Kept as a §5 falsifier (counter:
`drain_park_queue_tokens` for 3g/6g — if ~0, the wheel is not the cause).

### 3.4 Other hypotheses — killed by arithmetic / single-worker

- **Integer truncation** in `rate×elapsed/1e9`: 0 bytes at 3g/6g (exact).
- **Grace window**: gates only the surplus/bypass path; exact non-surplus
  never enters surplus (`queue_service/mod.rs:837`).
- **Fair-share rounding (H5)**: for a TRULY-SOLO single-port run on one
  worker, `total_flows = 1` ⇒ `my_share = new_cap` ⇒ zero rounding. So
  H5 cannot explain the truly-solo residual; it is a candidate only for
  the multi-stream/multi-worker case (§5 worker-count counter).

### 3.5 The honest conclusion

**No code-derived mechanism survives static analysis.** The ~6% mid-rate
residual is real (measured) but un-attributed. This is precisely the
situation that mandates a measurement-first plan: ship the §5 instrumented
bisection, run it on the free cluster, and let the four ratios
(phase1/phase2/drain_sent/goodput) NAME the layer. The plan commits to
the MEASUREMENT and the decision procedure — NOT to a fix it cannot
derive. (Same discipline as the cause-1 §12 fork: when the code can't
tell you, measure.)

---

## 4. Hypothesis table — all mechanisms falsified; §5 is the live path (v4)

| # | Hypothesis | Verdict (v4) | §5 confirmer/falsifier |
|---|-----------|--------------|------------------------|
| H-WATERFILL | Phase-1 budget relegates solo 3g/6g to non-parking Phase 2 | **FALSIFIED (Codex r3 B1):** full-config Phase-1 budget (1.85 MB) honors 3g/6g every epoch (§3.1). | `phase1_honored_bytes` for 3g/6g ≈ all (re-confirms at runtime). |
| H-LEASE | Lease target caps bucket credit | **KILLED as a fix (AGY r2 #6):** epoch ceiling caps grant at `rate×200µs`. | counter 6: high-water ≤ `rate×200µs`. |
| H-WHEEL/H7 | 50µs wheel park floor | DEMOTED (r1/r2): basis is `head_len` (~2µs); magnitude undrivable. | `drain_park_queue_tokens` for 3g/6g — if ~0, dead. |
| H1 | Integer truncation | KILLED by arithmetic (exact at 3g/6g). | counter 5. |
| H2 | Grace window | WEAK (gates only surplus; exact never enters). | `bypass_grace_use_count == 0`. |
| H4 | Lazy-rotation stale cap | Overlaps cause 1; K-independent. | counter 5. |
| H5 | Per-worker fair-share rounding | **Cannot explain TRULY-SOLO** (1 worker → total_flows=1 → no rounding). Candidate only for multi-stream/multi-worker. | per-worker share-exhaustion + worker count. |
| H-TCP | 6% is TCP goodput artifact, not shaper | LIVE — must be ruled out. Only KILL if bytes provably leave the NIC at full rate (AGY r2 #5). | `goodput/drain_sent` (L2-normalized). |

**Net (v4): NO mechanism survives static analysis.** H-WATERFILL,
H-LEASE, H-WHEEL all falsified by code+arithmetic; H1/H2/H4 killed; H5
cannot explain truly-solo. The only LIVE candidates are H-TCP (the loss
is outside the shaper) and "something not yet modeled in the drain/TX
path." **This is exactly why §5 is the deliverable** — the measurement
NAMES the layer; the plan does not pre-commit a mechanism it cannot
derive.

---

## 5. The instrumented bisection (v4 — THE DELIVERABLE; both reviewers confirmed the counters)

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

## 6. Fix mechanism — DEFERRED pending §5 (v4: no pre-committed fix)

> v4 position: all three derived mechanisms are falsified (§3). The plan
> does NOT commit a fix. The §5 measurement names the layer; the fix is
> designed in a short follow-up once the four ratios land. This is the
> honest /research output when static analysis cannot attribute the
> residual — it is NOT a dodge: it is the disciplined refusal to ship a
> fix on a falsified hypothesis (the cause-1 §12 fork precedent).

Candidate fixes BY MEASURED LAYER (each is a hypothesis to be confirmed,
not a commitment):

- **§5 layer = H-TCP (`goodput/drain_sent < 1`, drain_sent ≈ rate×wall):**
  the shaper sends full shape; TCP loses goodput to 50µs-quantized bursty
  delivery. Fix = delivery smoothing (finer service granularity / pacing)
  — NOT a grant/selector change. If smoothing cannot recover it, the
  residual is AF_XDP-per-CPU + TCP-pacing physics and Gate-1 re-framing
  is the charter-authorized last resort (§6.4). **This is now the LEADING
  expected outcome** given every shaper-internal mechanism is falsified.
- **§5 layer = drawn-not-sent (`drain_sent/total_granted < 1`):** TX-ring
  refusal / scratch-build failure under bursty delivery. Fix = submit
  path (`tx_completion.rs` apply paths). Orthogonal to causes 1/2.
- **§5 layer = grant-not-drawn with park (`drain_park_queue_tokens` high
  for 3g/6g):** the Phase-1 wheel park IS biting despite §3.3's demotion.
  Fix = sub-tick wake for the bucket-refill case (the gated F-E from v3,
  with the `my_consumed < my_effective_share` guard, Codex r2 B2).
- **§5 layer = meter under-grant (`cap_granted < rate×wall`, multi-worker
  H5):** per-worker fair-share rounding. Fix = distribute the share
  remainder in the rotation; folds into the cause-1 meter (coupled to the
  seqlock/carry, §9).
- **§5 layer = root throttle (`drain_park_root_tokens > 0` solo):** raise
  root burst/epoch. Orthogonal.

### 6.1 What /engineer does FIRST

Run §5 on the free `loss` cluster (3g-solo and 6g-solo, single port,
push, v4, guarantee-rate 0.7, FULL `cos-iperf-config.set`). Read the four
ratios + `phase1_honored_bytes`. The decision table (§5.2) names the
layer. ONLY THEN design the fix for that layer. Do NOT write fix code
before the bisection.

### 6.2 Burst-safety (whatever the fix)

Any fix must preserve `transmit-rate exact`: the per-queue v8 grant
`cap = rate×elapsed` meters every class. Gate (§8) proves no class
exceeds shape over any 10ms window.

---

## 7. Seqlock / concurrency surface (composing with cause-1 + #1643)

**The layering contract for WHATEVER fix §5 selects.** Most candidate
fixes (§6) are seqlock-orthogonal — they live in the drain/selector/TX
path, which is per-binding single-worker `CoSInterfaceRuntime` state
(verified non-atomic, not in the v8 seqlock payload: the waterfill state
`waterfill_pass1_remaining_bytes`/`waterfill_phase2_cursor`/
`exact_queues_by_rate_ascending`, `types/cos.rs:406-419`; the timer
wheel; `queue.hot.tokens`). The v8 seqlock publishes `cap/share/grace/tag`
only.

- **Drain/selector/TX/smoothing fix (H-TCP, drawn-not-sent, wheel-park):**
  **zero new seqlock surface.** The #1643 fence and the carry's
  rotation-private `epoch_carry_bytes` are untouched; cause 2 is reviewed
  as ordinary single-worker logic. Cleanest composition.
- **Meter-side fix (H5 per-worker fair-share rounding):** the fix is in
  the rotation `my_share` computation — IN the seqlock writer — and MUST
  be reviewed together with the carry. This is the only case that couples
  to cause 1.
- H-LEASE killed (§3.2); root throttle orthogonal.

**The seqlock review surface of the combined PR is bounded to cause-1's
(carry + #1643 fence) UNLESS §5 selects the H5 meter-side cause.** §5
distinguishes the clean (selector/drain) from the coupled (meter) layer.

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
  per cause-1 plan §7) AND a NEW cause-2 burst check: the §5-selected
  cause-2 fix must not let any class exceed its `transmit-rate exact`
  shape over any 10ms window (counter: per-class TX bytes / 10ms ≤ shape
  × 1.05). The per-queue v8 grant `cap = rate×elapsed` still meters each
  class regardless of the fix.
- **`make test-failover`** — mandatory (TX-shaping change). Zero-drop;
  cause-1's reused-lease unit test passes; the drain/selector state is
  per-binding and rebuilt on promote.
- **Full matrix** — v4+v6 × push+`-R` × CoS-off+CoS-on, per memory
  feedback. Gate 2 (priority-low ≥5%), Gate 3 (retransmits ≤100/30s),
  Gate 4 (aggregate ≥19.5G) must not regress.
- **Cause-2 regression test** — branch-specific to the §5-selected fix
  (designed at /engineer after the bisection names the layer). The plan
  does not pre-specify it because the fix is not pre-committed.

**NOTE (v4):** because cause-2's fix is deferred to the §5 outcome, this
combined-acceptance section is the gate the EVENTUAL fix must clear, not a
claim that any specific code in this plan clears it. The binding /research
deliverable is §5 (the measurement) + this gate (the bar). cause-1 +
#1643 can ship and be gated independently NOW.

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
3. **Cause-2 fix — DEFERRED, selected by §5 (§6).** All three derived
   mechanisms are falsified (§3); the fix is the one the §5 bisection
   names. Most candidate layers (drain/selector/TX/smoothing) are
   seqlock-orthogonal (§7); only the H5 meter-side cause couples to the
   carry. **The plan commits to the §5 measurement + the layering
   contract, not to a specific cause-2 code change.**

**Composition (expected, most-likely layers):** (1)+(2) are the
meter/seqlock surface (carry + fence — the ONLY concurrency-sensitive
code); a drain/selector/TX/smoothing cause-2 fix is a single-threaded
change sharing NO field with the seqlock payload, reviewed independently.
The clean three-layer ideal — **meter grant (carry) + meter publish
(fence) + drain-layer cause-2 fix** — holds for every candidate EXCEPT
H5, which is meter-side and reviews with the carry.

**Sequencing:** cause 1 + #1643 can ship together NOW (both are
meter/seqlock and independently justified). Cause 2's fix waits on §5 and
may land in the SAME combined PR (if §5 fires quickly at /engineer) or a
fast follow-up. Gate 1 (all four ≥95% solo) is met only when cause 1 AND
the §5-selected cause-2 fix are both in — UNLESS §5 shows H-TCP, in which
case the residual is delivery/transport physics and Gate-1 re-framing
(§6.4) is the charter-authorized last resort.

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

1. **If no shaper mechanism explains it, is the residual even a SHAPER
   bug?** Three derived mechanisms are falsified (§3). The strongest
   remaining candidate is H-TCP (the bytes leave the NIC at rate; TCP
   loses goodput to bursty delivery). **Should this issue be re-scoped
   from "fix the shaper" to "characterize the AF_XDP delivery-burstiness
   / TCP-pacing floor"? Is §5's `goodput/drain_sent` (L2-normalized)
   actually measurable accurately enough to settle this on iperf3?**
2. **Could the residual be a measurement artifact of the §3.6 harness
   itself?** The solo numbers (3g 89→94, 6g 89→93) came from a throwaway
   K/P2 probe build. **Is there ANY chance the ~6% is TCP slow-start /
   `-O` omission / the 30s window / RSS landing the single port's 12
   streams across workers — i.e. not a steady-state shaper property at
   all?** §5 must run long-window steady-state and report the worker
   landing of the solo streams BEFORE concluding a shaper cause.
3. **Does the §5 instrumentation perturb the very thing it measures?**
   Env-gated `fetch_add` counters on the hot drain path add atomics. **At
   25G line rate, could the instrumentation cost itself depress 3g/6g by
   a few %, masking or faking the residual?** The build must be A/B'd
   (instrumented vs not) to confirm the counters are free, or use
   thread-local non-atomic accumulators flushed at 1s.
4. **Is the four-ratio bisection truly exhaustive?** It covers
   meter-under-grant / grant-not-drawn / drawn-not-sent / TCP. **Is there
   a FIFTH layer — e.g. the ingress/RX side limiting how fast the class's
   packets even ARRIVE to be shaped, so the shaper is never offered a
   full rate's worth?** For a push test the firewall forwards; if RX or
   the conntrack/forward path caps a single flow-bundle, the shaper sees
   less than `rate` of offered load and the residual is upstream. §5 must
   confirm offered load ≥ shape at the queue ingress.
4b. **(restated for emphasis)** The plan asserts the classes are
   "bucket-bound" (offered > rate). **Has anyone VERIFIED the offered
   load actually exceeds the shape for solo 3g/6g, or is the class
   RX/CPU-bound below its rate?** If offered < rate, there is no shaper
   residual to fix.
5. **Is shipping cause-1 + #1643 WITHOUT cause-2 the right move?** §9 says
   cause-1+#1643 can ship now. **But cause-1's plan claimed Gate 1; if it
   ships fixing only 100m/1g while 3g/6g stay <95%, does the combined PR
   FALSELY appear to fix #1630? Should cause-1 be held until §5 resolves
   cause-2, or shipped with an explicit "100m/1g only" scope note?** The
   sequencing has a contract-honesty risk.
6. **Has the team over-fit to "flat fractional" (P4)?** The measured
   spread (3g 93.8, 6g 92.8 solo) is NOT identical — 6g is ~1pp lower.
   **Is the "flat" framing hiding a weak rate-dependence that would point
   at a DIFFERENT cause (e.g. a per-frame fixed overhead that matters
   more at higher pps)?** §5 should report the residual at 3g AND 6g AND
   9g to see if it is truly flat or slowly rate-varying.

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
