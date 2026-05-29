# Claude SMR hostile plan-review — #1630 cause-2 mid-rate residual — r1

Reviewer: Claude SMR, framed as CoS-shaper / token-bucket / rate-accuracy
/ AF_XDP-drain / timer-wheel domain expert.
Target: `docs/research/1630-midrate-residual/plan.md` @ v1 (`b0847fe93`).
Posture: HOSTILE. No first-pass PLAN-READY-WITH-NITS (this domain has
burned that 4×+ this session).

**VERDICT: PLAN-NEEDS-MAJOR.** The plan's instrumentation-first
discipline and layering analysis are sound, but the LEADING HYPOTHESIS
(§3 H-WHEEL) is derived against the WRONG source path and must be
rewritten. Codex r1 independently found the same linchpin defect. I
concur and add three findings of my own.

---

## Concurrence with Codex r1 (verified independently against origin/master `0e5bb3812`)

- **Codex BLOCKING-1 — CONCUR, decisive.** `estimate_cos_queue_wakeup_tick`
  is called with **`head_len`** (one frame, `cos_item_len(head)`), NOT
  the quantum. Verified: `queue_service/mod.rs` exact-park branch passes
  `head_len` (line confirmed via `sed`: the 4th positional arg to both
  the root-starvation and queue-starvation `estimate_cos_queue_wakeup_tick`
  calls is `head_len`). The plan's §3.1 derivation `t_refill =
  quantum/rate = 200µs` is therefore **factually wrong about the park
  basis**: the park refill is `head_len/rate ≈ 1500/750e6 = 2µs` for 6g,
  not 200µs. The quantum (`cos_guarantee_quantum_bytes`) is used ONLY for
  `secondary_budget` (the service batch size, line ~706). §3 must be
  rewritten.

- **Codex BLOCKING-3 — CONCUR, decisive.** `bytes_consumed = total_granted
  from acquire_v8` is lease *authorization*, not bytes *transmitted*. The
  bisection (§5 counter 2) is mis-specified. The correct TX-side counter
  is `drain_sent_bytes` (in `owner_profile`, written in `tx_completion.rs`
  after the frame is actually submitted). §5 MUST compare `cap_granted`
  vs `drain_sent_bytes` (and ALSO `total_granted`, so the three-way
  split distinguishes meter-under-grant vs grant-not-drawn vs
  drawn-not-sent). This three-way is strictly stronger and directly
  answers my own §11-Q5 (TCP artifact) — see my MAJOR-2.

- **Codex MAJOR-1 — CONCUR.** The lease-target hypothesis (Q3) is
  first-class, not secondary. `config.lease_bytes = rate×200µs` IS the
  bucket top-up watermark, so the bucket can never hold more than 200µs
  of credit — independent of the wheel. §6 prematurely commits to a
  wheel fix.

- **Codex MAJOR-2 — CONCUR.** F-A is a no-op for same-tick future wakes:
  if `wake_ns` and `now_ns` fall in the same 50µs tick,
  `cos_tick_for_ns(wake_ns) == cos_tick_for_ns(now_ns)` and the floor
  still returns `now_tick+1`. F-A as written cannot fix a sub-tick refill
  without a non-wheel fast path. Demote F-A.

- **Codex MAJOR-3 — CONCUR.** F-B's "bucket WILL refill within a tick"
  is false for the v8 meter: rotation refuses before 200µs
  (`rotate_epoch_v8.rs`: `if now < start + EPOCH_DURATION_NS return`),
  and `acquire_v8` stops at `class_granted >= cap`. A sub-tick frame
  deficit does NOT imply new grant is available sub-tick. Staying
  runnable can busy-poll a cap-exhausted lease until the epoch boundary.

## Rejection of Codex BLOCKING-2 (HALLUCINATED — do NOT fold in)

Codex BLOCKING-2 claims `guarantee-rate 0.7` dispatches the drain into a
`select_exact_cos_guarantee_queue_waterfill` with park sites at
`queue_service/mod.rs:603-613, :853-872, :973-982`. **This function and
this dispatch DO NOT EXIST on origin/master `0e5bb3812`.** Verified:

- `grep -rn "waterfill" userspace-dp/src/` returns exactly ONE hit, a
  COMMENT in `forwarding_build/cos.rs:424`: "the v5 two-phase waterfill
  allocator. **The Go control plane is responsible**..." — i.e. waterfill
  is a CONTROL-PLANE (Go) allocator, not a dataplane drain path.
- `grep -rn "oversubscription_policy" userspace-dp/src/afxdp/` shows it
  is written into `CoSInterfaceConfig` (`forwarding_build/cos.rs:443`)
  but **never READ in the drain/queue_service path** (zero consumer hits
  outside forwarding_build/README).
- The drain selector `select_exact_cos_guarantee_queue_with_lease_telemetry`
  (`queue_service/mod.rs:590`) has NO oversubscription branch.

So `guarantee-rate 0.7`'s dataplane effect is entirely via the per-class
v8 lease *rates* the Go allocator computes — NOT a separate Rust park
branch. The single exact-queue park branch the plan cites IS the path
3g/6g traverse. **Codex BLOCKING-2 is a fabricated counter-example; the
v2 plan must NOT add waterfill-path instrumentation Codex demanded, and
must document this rejection so a future round does not re-add it.** (Per
`feedback_no_test_dismissal` / quote-grounded discipline: I verified the
absence with grep, not assertion.)

This is exactly why the plan needs the §5 instrumentation: the reviewers
themselves disagree on which code path runs, and only a counter on the
ACTUAL drain path settles it.

---

## My own findings (beyond Codex)

### MAJOR-1 (Claude) — the corrected mechanism still predicts a flat loss, but via a DIFFERENT magnitude that the plan must re-derive honestly

With BLOCKING-1 fixed, the corrected per-visit cycle for a bucket-bound
exact class is: service up to `min(tokens, quantum)` bytes (quantum =
`rate×VISIT_NS` = 75K/150K for 3g/6g, both < 512K clamp), THEN when
`tokens < head_len` park for `head_len/rate` (~2-4µs) — but the wheel
floors the park to `now_tick+1` (up to 50µs). So:

- **Service phase** drains ~`quantum` = 200µs-of-bytes (because
  `quantum/rate = VISIT_NS = 200µs`).
- **Park phase** is floored to ≥1 tick = 50µs even though the real refill
  is ~2µs.
- Naïve period ≈ 200µs service + 50µs park → efficiency 200/250 = 80% —
  which is WORSE than the measured ~93-94% solo. So either (a) the queue
  does NOT drain the full quantum before parking (root-token or
  cap-exhaustion interleaves), or (b) the queue does NOT park every
  cycle (it stays runnable and the bucket refills across poll passes
  faster than a tick). **The plan's own corrected arithmetic does not
  cleanly reproduce 6% — which means the magnitude is genuinely unknown
  without the counters.** v2 must (i) drop the false-precision "200/225 =
  88.9% matches" claim, (ii) state the corrected period model with its
  unknowns, (iii) make the §5 counters resolve service-bytes-per-park
  and parks-per-second directly.

This is the honest core: the DIRECTION (wheel/lease quantization) is
plausible; the MAGNITUDE derivation in v1 is wrong twice over (quantum
vs head_len, and even the corrected version doesn't hit 6%). The plan
must stop claiming a quantitative match and let the bisection produce it.

### MAJOR-2 (Claude) — the bisection needs a THREE-way split, and a TX-vs-goodput counter, or it cannot rule out the TCP artifact

§5 as written is two-way (cap_granted vs bytes_consumed). To bisect ALL
of {meter under-grants, grant-not-drawn, drawn-not-sent, sent-but-TCP-
loses-goodput} the counters must be:

1. `cap_granted` (rotation `new_cap` sum) — meter ceiling.
2. `total_granted` (acquire_v8 sum) — lease draw.
3. `drain_sent_bytes` (owner_profile, post-submit) — actual TX.
4. iperf3 goodput (the measured 94%).

The three internal ratios localize the cause:
- `total_granted/cap_granted < 1` → grant not drawn (drain/park, bucket).
- `drain_sent/total_granted < 1` → drawn but not sent (TX-ring refusal,
  scratch fail).
- `goodput/drain_sent < 1` → **the shaper is fine; the loss is TCP**
  (burstiness/RTT/window) — cause 2 leaves the shaper entirely.

v1's two-way split conflates 2 and 3 and cannot see 4. This is the
single most important fix to §5 — without it the plan could "fix" the
wheel and still measure 94% if the loss is TCP.

### MINOR-1 (Claude) — F-D (align VISIT_NS / lease target to the tick) is under-developed and may be the cheapest real fix

If the bisection shows "grant-not-drawn via park floor", the minimal fix
is NOT F-A/F-B (both shown defective) but either: (i) raise the per-queue
lease target so the bucket holds ≥2-3 ticks of credit (then the queue
parks far less often — but this raises burst, gate it), or (ii) represent
the wake at sub-tick resolution for the bucket-refill case only. v2
should promote these over the defective F-A/F-B and design the
burst-bound proof for (i).

### MINOR-2 (Claude) — §9 layering claim survives but needs the lease-target caveat

If the fix turns out to be "raise the lease target" (MAJOR-1/Codex-MAJOR-1),
that touches `compute_shared_cos_lease_config` / `COS_ROOT_LEASE_TARGET_US`
— which IS read by the meter path (`lease_bytes`) and feeds
`max_total_leased`. That is NOT as cleanly disjoint from cause-1 as the
wheel fix. The §9 "clean layering" claim holds ONLY for the drain-park
fix; if the bisection picks the lease-target fix, v2 must re-argue
layering (the lease config is shared meter state, though still not in the
seqlock payload).

---

## What v2 must do

1. **Rewrite §3** around `head_len` (not quantum) as the park basis;
   drop the "200/225 = 88.9% matches" false precision; state the
   corrected period model with explicit unknowns (service-bytes-per-park,
   parks-per-sec) that §5 resolves.
2. **Reject Codex BLOCKING-2 explicitly** with the grep evidence (no
   waterfill drain path); do NOT add waterfill instrumentation.
3. **Rewrite §5** as the three-way split (cap_granted / total_granted /
   drain_sent_bytes) + iperf3 goodput; the four ratios localize the cause
   and rule out the TCP artifact.
4. **Demote F-A/F-B** (Codex MAJOR-2/3 + my MAJOR-1): F-A no-op
   same-tick, F-B busy-polls cap-exhausted lease. Promote the
   lease-target and sub-tick-wake mechanisms as primary candidates,
   conditioned on §5.
5. **Re-argue §9 layering** for the lease-target branch (shared meter
   config, not seqlock payload).
6. Keep the strong parts: instrumentation-first, the P1-P4 constraints,
   the cause-1 composition framing, the hostile open questions (they were
   the right questions — Q3 and Q5 are now load-bearing).
