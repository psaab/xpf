# #1754 — Reduce AF_XDP TX-wake `sendto()` kick CPU (Path B of #1752)

**Status: v2 — CONVERGED. Codex r1 PLAN-NEEDS-MAJOR, AGY r1 PLAN-NEEDS-MAJOR
(both with a narrow defensible V-B path), Claude SMR r1 PLAN-KILL-LEANING. All
three agree: the research (Step 1 + 1b) is sound and the lever is correctly
re-aimed; the only ship candidate is V-B (`needs_wakeup()`-only gate); the
default outcome is PLAN-KILL unless a clean V-B A/B (idle-binding latency +
per-CoS-class CoV + contention-rebound) clears a high bar. v2 addressed every
finding: §4/§5 contradiction, V-A/V-B split, idle-binding proof, contention
rebound (AGY), tid-filtered re-attribution (AGY).**

Research-only. Stops at PLAN-READY or PLAN-KILL. No production code ships from
this doc; the implementation (if approved) is a separate `/engineer 1754`.

## 1. Issue framing

#1752 found `-P48 -p5210` forwarding CPU-bound on a 6-vCPU / 6-queue / 6-worker
box (mlx5_core SR-IOV VF, native XDP, zero-copy). The "crypto DEK churn" (~5.5 %
in `mlx5_crypto_modify_dek_key`) was proven a **perf symbolization artifact**
(kprobe = 0 calls; `mlx5_core.ko.xz` compressed) — see
`docs/research/1752-remaining-paths/evidence/pathb-crypto-dek-artifact.md`. The
real cost is the AF_XDP TX/RX wake `sendto()` kick path. #1754 owns the gated
research into recovering that CPU.

## 2. Step 1 (MANDATORY, DONE) — TX-vs-RX per-site attribution

Live on `loss:xpf-userspace-fw0` (kernel 7.0.0-rc7+, 6 workers, interrupt mode,
CoS ON, `-P48 -p5210` v4). Full data + .bt scripts:
`evidence/step1-tx-vs-rx-attribution.md`. Headline (10 s steady-state window,
aggregate over 6 worker tids):

| site | count/10 s | core-seconds | % of 6-core box |
|---|---|---|---|
| **TX-kick** (`maybe_wake_tx`) | **762,132** | **5.32 s** | **~8.9 %** |
| RX-wake (`maybe_wake_rx`) | 163,928 | 0.61 s | ~1.0 % |

Validation gates passed (the crypto-DEK lesson): `sys_enter_sendto` ≈
`xsk_sendmsg` (~95K/s, 1:1); `kretprobe:xsk_sendmsg` retval = 0 for 100 % of
calls (no EAGAIN churn); per-kick `xsk_sendmsg` latency mode [2K,4K) ns, mean
~6.5 µs.

**Three findings that re-aim the lever away from the umbrella's proposal:**

1. **TX-kick dominates RX-wake ~8.7:1 by time.** The dominant site is the TX
   kick, not RX-wake. Tune TX.

2. **`TX_WAKE_MIN_INTERVAL_NS = 50_000` (mod.rs:302) is almost entirely
   bypassed.** `maybe_wake_tx(binding, force, now_ns)` (rings.rs:237) only
   consults the 50 µs interval / `needs_wakeup()` gate when `force == false`.
   Every TX-submit and CoS-drain caller passes `force = true`
   (`tx/transmit/mod.rs:92,186,231,260`, `tx/transmit/finalise.rs:27,54`,
   `cos/queue_service/service.rs:107,159,193,281,326,367,511,543,675,716`).
   Only `tx/drain/phase_trivial.rs:31` (the no-pending-work re-kick) is gated.
   **Therefore widening `TX_WAKE_MIN_INTERVAL_NS` 50 µs → 100–200 µs — the
   umbrella's proposed A/B — touches one minor site and recovers ~nothing.**

3. **~83 % of kicks never reach the driver.** `mlx5e_xsk_wakeup` = 154,646/10 s
   vs 926,060 `sendto`/10 s. Only ~17 % of `sendto` calls reach
   `ndo_xsk_wakeup` (a real TX doorbell); the other ~83 % enter `xsk_sendmsg`,
   find NEED_WAKEUP clear / nothing to do, and return. That ~83 % is the
   population the userspace `needs_wakeup()` gate *would have* suppressed but
   `force = true` bypasses.

**Conclusion:** the real lever is to **route the post-successful-submit TX
kicks through the existing `needs_wakeup()` gate** (i.e. stop passing
`force = true` on the steady-state submit path), NOT to widen the interval.

### 2.1 OPEN BLOCKER — which forced site actually fires under CoS-ON?

The measured workload targets reth0.80, which **has** a CoS scheduler-map
(`bandwidth-limit`, confirmed live). Under CoS-ON, `drop_cos_bound_prepared_
leftovers` / `drop_cos_bound_local_leftovers` (drain/mod.rs:137,~227) **eject
CoS-interface-bound traffic from the `transmit_batch` / `transmit_prepared_batch`
backup path** and route it through the shaper via `ingest_cos_pending_tx` → TX
happens in `cos/queue_service/service.rs` (all those kicks stay `force = true`).
`tx_request_targets_cos_interface` returns true when `forwarding.cos.interfaces`
contains the egress ifindex — which it does for reth0.80.

**Implication:** under the very CoS-ON workload measured in §2, the dominant
762K TX kicks are most likely the **`service.rs` CoS-drain kicks**, not the two
generic `transmit/mod.rs:260` / `finalise.rs:54` sites the §4 primary lever
proposes to gate. If so, gating those two sites is a **no-op under the measured
load** and the lever must either (a) re-aim at the CoS-drain kicks (which are
correctness-coupled to the exact-guarantee quantum — the #1207/#1545 trap), or
(b) PLAN-KILL. **This must be resolved by a Step-1b per-call-site count BEFORE
any code** (kprobe with `func+offset` / a temporary per-site debug counter on a
throwaway build), and is the single most likely KILL vector. See Q5.

## 3. Honest scope & value (PLAN-KILL is an acceptable outcome)

- **Upper bound on recoverable CPU:** TX-kick is 5.32 core-s / 60 core-s =
  ~8.9 % of the box. The recoverable share is bounded by the ~83 % non-wakeup
  kicks — but those skew to the cheap [1K,4K) ns bucket, so the *time*
  recoverable is **materially less than 8.9 %**. Realistic target: recover a
  meaningful fraction of the [1K,4K) mass (193K+332K of 842K kicks) ≈ a few %
  of total CPU. **Exact figure is TBD until the A/B.**
- **The tradeoff that can KILL this:** the post-submit `force = true` exists for
  a documented reason (`transmit/mod.rs:258`): *"Latency-sensitive reply traffic
  can stall indefinitely on otherwise idle zerocopy bindings unless we
  explicitly kick TX after committing descriptors."* Gating the post-submit kick
  re-introduces exactly the idle-binding TX-stall risk `needs_wakeup()` was
  added to avoid (rings.rs:155-163 documents the fill-ring-starvation history).
  If the A/B shows added TX latency / retransmits / idle-binding stalls that
  outweigh the CPU saved, **PLAN-KILL is the correct outcome** and 50 µs +
  `force` is near-optimal.
- This is a CPU-vs-latency tradeoff on a worker-bound box. A *modest* CPU win
  with a latency regression is a net loss for a firewall dataplane. The bar is:
  net CPU recovered with **no** measurable TX-latency / retransmit / throughput
  regression across the full smoke matrix.

## 4. Proposed change — RE-AIMED after Step 1b (the dominant site is CoS-drain)

Step 1b (§2.1, evidence) proved the v1 target sites are cold under CoS-ON.
The forced kicks that cost the 5.32 core-s come from `cos/queue_service/
service.rs` (`drain_shaped_tx` 1.89M/10 s, `service_exact_*` 657K/10 s).
`maybe_wake_tx` fires 1.10M/10 s (not every drain submits). So any real lever
MUST touch the CoS-drain post-submit kicks — exactly the
fairness/exact-guarantee-coupled path with the #1207/#1545 PLAN-KILL history.

**Re-aimed primary lever (HIGH RISK):** on the CoS-drain *post-successful-submit*
kicks only (`service.rs:193,367,543,716` — the unconditional end-of-function
kicks after a `commit()`). **Keep `force = true` on the ring-full / no-free-frame
error kicks** (`service.rs:107,159,281,326,511,675`) — those must drain.

Two candidate variants, NOT equivalent (Codex F4):
- **V-A (`force = false`):** routes through `needs_wakeup() || interval`. This
  STILL kicks every `TX_WAKE_MIN_INTERVAL_NS` (50 µs) even when `needs_wakeup()`
  is clear — so it can defer a doorbell up to 50 µs (the cadence risk) AND, at
  50 µs/binding = ~20K kicks/s/binding vs observed ~12.7K TX-kicks/s/worker
  (76K/s ÷ 6, step1b), the interval may already be *looser* than the current
  rate — meaning V-A could suppress far LESS than the headline 83 %. V-A is the
  worst of both: real cadence risk, uncertain win.
- **V-B (`needs_wakeup()`-only, NO interval delay):** a NEW `maybe_wake_tx` mode
  that kicks iff `needs_wakeup()` is set, else skips entirely (no 50 µs timer).
  This preserves every kernel-requested doorbell and suppresses exactly the
  wasted non-wakeup kicks — the cleanest map onto the "recoverable population".
  **V-B is the only variant worth A/B-ing**, but it requires (i) a new gate arm
  in `maybe_wake_tx` and (ii) a proof that the idle-binding stall (§5,
  transmit/mod.rs:258) cannot recur when no interval timer backstops a binding
  that committed with `needs_wakeup()` momentarily clear.

Expected upper bound on the win: the ~83 % non-wakeup fraction of the CoS
post-submit kicks (step1:49-55), skewed to the cheap [1K,4K) ns bucket — so the
recoverable *time* is materially below 83 % of 5.32 core-s.

**Important gate nuance (`force=false` is NOT a blind delay).** The
`maybe_wake_tx` condition (rings.rs:239-243) fires the kick when
`!zerocopy || needs_wakeup() || force || (now-last >= INTERVAL)`. With
`force=false` on a zerocopy binding, a kick STILL fires immediately whenever
`needs_wakeup()` is set — i.e. whenever the kernel is actually asking for a
doorbell. The interval only gates the case where `needs_wakeup()` is clear
(the ~83 % wasted kicks). So `force=false` already approximates the
"`needs_wakeup()`-only" variant; it suppresses wasted kicks but preserves every
doorbell the kernel requests. This materially weakens the fairness-regression
argument below.

**Why this is still likely a PLAN-KILL:**
- Even preserving kernel-requested doorbells, the CoS exact-guarantee scheduler
  may rely on the *unconditional* post-submit kick to advance a shaped queue's
  drain cadence before `needs_wakeup()` is set (a queue that just committed but
  whose ring has not yet signaled NEED_WAKEUP). Suppressing that kick can defer
  the doorbell up to 50 µs, perturbing per-class cadence — the #1207/#1545 trap.
  The fairness CoV gate (`docs/fairness-regimes.md`) must be re-validated per
  CoS class, not just throughput.
- The win is bounded by the cheap-bucket time (Q2) and may convert to spin, not
  throughput (Q3), on a worker-bound box.

A `transmit_batch`/`finalise` gating change (v1) remains valid **only for a
CoS-OFF deployment** — but the production/smoke target runs CoS-ON, so it does
not address the measured cost.

**Idle-binding safety net (required, not optional).** `force = false` alone
re-opens the idle-binding stall: a binding that commits one descriptor and then
goes idle may never re-enter `maybe_wake_tx`, so the gate's interval check never
fires again. Mitigations to evaluate in the A/B (pick the cheapest that holds):
- (a) The `phase_trivial.rs:31` gated re-kick already runs every poll cycle when
  `outstanding_tx > 0 && pending empty` — verify it covers the idle-binding case
  (it kicks with `force = false`, so the interval still bounds wake latency).
- (b) If (a) is insufficient, add a single forced kick when `needs_wakeup()` is
  set at commit time only (cheap; the kernel is explicitly asking).

**Secondary lever (only if primary nets out positive):** raise
`TX_WAKE_MIN_INTERVAL_NS` 50 µs → 100 µs **after** the gate actually applies to
the dominant site (it currently does not, per §2.2). Sequencing matters: the
interval is a no-op until the `force=false` change lands.

**Explicitly NOT doing:** batching/coalescing kicks across multiple submit
calls (adds state + complexity; the gate already coalesces via the interval),
and touching RX-wake (1.0 % — not worth the fill-ring-starvation risk
documented at rings.rs:155-163).

## 5. Invariants that MUST hold

- **No idle-binding TX stall.** A binding that commits descriptors and goes idle
  must still get its TX doorbell within bounded latency. `force = true`
  guarantees this trivially today (transmit/mod.rs:258-260 documents the stall it
  prevents). Any candidate variant (§4) MUST separately prove a bounded idle
  safety path (the `phase_trivial.rs:31` gated re-kick fires only when
  `outstanding_tx > 0 && pending empty`, so it may NOT cover the commit-then-idle
  window — this must be measured, not assumed).
- **Ring-full paths stay forced.** `inserted == 0` / no-free-frame must keep
  `force = true` so the kernel drains and frees completions
  (`service.rs:107,159,281,326,511,675`).
- **CoS exact-guarantee cadence preserved.** `publish_committed_queue_vtime`
  (service.rs:359) + `apply_direct_exact_send_result` (service.rs:366) run
  immediately BEFORE the post-submit kick (service.rs:367); V_min relies on
  post-settle commit boundaries (v_min.rs:32-46). The candidate variant MUST NOT
  decouple vtime accounting from the physical TX doorbell by more than the
  per-class CoV gate tolerates — validated per CoS class in the A/B, not assumed.
- **Telemetry parity.** `tx_kick_latency_*` / `dbg_sendto_*` counters keep
  counting actual `sendto` calls; a drop in count is the *expected* signal, not
  a regression.

## 6. Risk table

| Risk | Severity | Mitigation |
|---|---|---|
| Idle-binding TX stall (latency-sensitive replies) | HIGH | V-B has NO interval backstop — must prove bounded idle path (transmit/mod.rs:258); A/B TCP_RR; KILL if regresses |
| CoS exact-guarantee cadence skew (vtime decoupled from doorbell) | HIGH | V-B preserves kernel doorbells; per-CoS-class CoV A/B; KILL on any CoV regression (#1207/#1545 trap) |
| V-A interval may already be looser than the rate → tiny win + cadence risk | MED | prefer V-B; V-A only as a measured comparison arm |
| **Contention rebound (AGY r1):** suppressing ~83 % of syscalls runs worker loops faster → MORE polls of shared `shared_exact_backlogs` (service.rs:236) / `shared_queue_leases` (queue_service/mod.rs:406) → cacheline bouncing + atomic contention across 6 workers, which can ITSELF perturb the #1207/#1545 cadence | HIGH | A/B must track atomic-contention / loop-frequency + per-class CoV; a CPU "win" that just moves into contention is a net loss |
| Win too small to justify (cheap-bucket skew) | MED | A/B with explicit % threshold; PLAN-KILL exit |
| Run-to-run throughput noise masks the delta | MED | ≥3 paired runs each arm; report CoV |
| Interrupt-mode vs busy-poll changes the picture | LOW | deployed mode is interrupt; measure as-deployed |

## 7. Test / A/B plan

Baseline arm = master (all `force = true`). Test arm = §4 primary lever.
For BOTH arms, on `loss:xpf-userspace-fw0`, CoS ON, ≥3 paired 30 s runs:
1. **CPU:** `xsk_sendmsg` total core-seconds (the §2 .bt) + `pidstat` worker
   CPU%. Primary metric: TX-kick core-seconds delta.
2. **Driver-wakeup ratio:** `mlx5e_xsk_wakeup` count — expect it ~unchanged
   (real doorbells preserved) while `sendto` count drops (the win).
3. **TX latency + idle-binding stall:** `iperf3` is throughput-biased; add a
   latency probe — netperf TCP_RR / `sockperf` — to catch the idle-binding stall
   V-B's missing interval backstop risks (transmit/mod.rs:258). Run a
   low-rate single-flow + idle-then-burst pattern specifically, not just
   saturating load. **This is a kill-deciding metric.**
3b. **Per-CoS-class fairness:** run the per-class iperf3 matrix (one flow per
   configured CoS class, ports 5201-5211) and compute per-class CoV against the
   `docs/fairness-regimes.md` gate. Any CoV regression vs the master baseline is
   a hard KILL (the #1207/#1545 trap). **Also kill-deciding.**
4. **Throughput + retransmits:** `iperf3 -P48` SUM Gbit/s + retransmit count,
   v4 AND v6, push AND `-R`.
4b. **Contention rebound (AGY r1):** track cross-worker atomic-contention /
   loop-frequency (e.g. `perf c2c` or a worker-loop-iters counter) to confirm
   the faster loop does NOT trade syscall CPU for cacheline-bounce CPU on
   `shared_exact_backlogs` / `shared_queue_leases`. A win that moves into
   contention is a net loss.
5. **Full smoke matrix** before any merge (v4/v6 × push/`-R` × CoS-off/CoS-on),
   per the per-class iperf3 requirement.
6. **Clean re-attribution (AGY r1):** before committing to V-B, re-run Step 1
   with a tid/fd-filtered .bt that excludes the worker idle-loop `libc::poll`
   (loop_body:1429) from the RX-wake tag, removing the F1 contamination, to pin
   the true TX-kick fraction.

**Pass:** net CPU recovered (TX-kick core-seconds ↓ by a stated threshold, e.g.
≥2 % of box) with **zero** measurable TX-latency / retransmit / throughput
regression. **KILL:** any latency/retrans/throughput regression, or CPU
recovery below threshold (50 µs+force near-optimal).

## 8. Out of scope

- RX-wake tuning (1.0 %; fill-ring-starvation risk).
- Kick batching/coalescing across submit calls.
- Raising `TX_WAKE_MIN_INTERVAL_NS` *before* the `force=false` change (no-op).
- Naming the exact unexported mlx5_core function behind the perf artifact
  (already established as NOT crypto; #1752 evidence).
- Busy-poll-mode behavior (deployed mode is interrupt).

## 9. Open questions (inviting PLAN-KILL)

1. **Does gating the post-submit kick re-introduce the idle-binding TX stall
   the `force=true` comment warns about (transmit/mod.rs:258)?** Is the
   `phase_trivial.rs:31` gated re-kick a sufficient safety net, or does it only
   fire when `outstanding_tx > 0 && pending empty` — missing the
   commit-then-idle window? If the safety net is insufficient and (b) is needed,
   does (b) claw back most of the saving?
2. **Is the recoverable *time* actually material?** 83 % of kicks are
   recoverable by count but skew to [1K,4K) ns. If gating saves only the cheap
   bucket, the win could be <2 % of box — below a worthwhile threshold → KILL.
3. **Will the CPU saved on `sendto` just move into more poll cycles / busier
   spin?** On a worker-bound interrupt-mode box, does freed syscall time convert
   to throughput, or does the worker just spin more (no net win)?
4. **Is the ~6.5 µs mean `xsk_sendmsg` cost inflated by kprobe overhead?** The
   median [2K,4K) is plausible for a syscall; is the 8–32 µs tail real TX work
   (irreducible) or probe artifact? If the tail is the real cost and it's the
   wakeup kicks (irreducible), recoverable shrinks further.
5. **Does CoS interact?** All `service.rs` kicks stay forced in v1; is the
   non-CoS `transmit/mod.rs` path even hot when CoS is ON (does CoS-on traffic
   route through `service.rs` instead, leaving the gated sites cold)? If CoS-on
   traffic bypasses the two sites we gate, the change does nothing under the
   measured CoS-ON workload → re-scope or KILL.
6. **Is 50 µs already the right interval once the gate applies?** If the gate
   starts working (force=false) and 50 µs already coalesces well, the secondary
   100 µs lever may be unnecessary or harmful (latency).

## 10. Recommendation (pre-review) — KILL-LEANING

The mandatory attribution (Step 1 + 1b) is solid and **redirected the lever
twice**: (1) away from the umbrella's `TX_WAKE_MIN_INTERVAL_NS` widen (a no-op
because the gate is bypassed by `force=true`), and (2) away from the generic
`transmit_batch`/`finalise` sites (cold under CoS-ON) onto the CoS-drain
`service.rs` post-submit kicks (the only hot forced site).

That final target is the **CoS exact-guarantee path with documented #1207/#1545
PLAN-KILL history** — gating its post-submit doorbell risks exactly the
per-class fairness-cadence regression those issues died on, for a win that is
(a) bounded by the cheap [1K,4K) ns bucket and (b) may convert to worker spin
rather than throughput on a worker-bound box.

**Recommended disposition: PLAN-KILL-LEANING.** The only candidate worth an A/B
is V-B (`needs_wakeup()`-only gate, NO interval delay) on the four CoS
post-submit kicks — it maps exactly onto the recoverable ~83 % non-wakeup kicks
while preserving every kernel-requested doorbell. Plain `force=false` (V-A) is
rejected: it keeps the 50 µs interval (real cadence risk) AND at ~20K
kicks/s/binding the interval may already be looser than the ~12.7K/s/worker
rate, so its win is uncertain (Codex F4).

Even V-B is guarded by TWO high-consequence invariants: (1) the idle-binding TX
stall (transmit/mod.rs:258) — V-B removes the interval backstop, so a binding
that commits with `needs_wakeup()` momentarily clear could stall until the next
poll cycle; this must be proven bounded, not assumed; and (2) the CoS
exact-guarantee cadence — vtime is published/accounted at service.rs:359-366
immediately before the doorbell, the #1207/#1545 trap. The win is a few percent
of CPU that may convert to worker spin, not throughput, on a worker-bound box
(Codex F6 / Q3).

**Ship gate (high bar):** proceed to `/engineer` ONLY with V-B, a proof of the
bounded idle path, and a per-CoS-class A/B (§7) measuring CoV + TCP_RR latency +
retransmit + throughput with a hard KILL exit on ANY regression. Absent a clean
V-B A/B, **PLAN-KILL** is the well-evidenced default outcome.
