# #1756 Path C — control-plane CPU isolation (dedicate core 0 to Go)

**Status: PLAN-KILL (v2). Recommendation: PLAN-KILL.**
PLAN-KILL is the explicitly acceptable and likely outcome per the issue
and the #1752 umbrella. The A/B bar (the GC-preemption jitter Go steals
from the workers must cost MORE than the ~16.7% raw capacity cut of
going 6→5 workers) is **not cleared by the live measurement**, the exact
variant was **already PLAN-KILLED at #1243** ("5-worker dedicated CPU
mode … −17% saturation throughput, zero quantitative gain"), and the
levers that *would* matter — (a) pinning Go to core 0 while KEEPING all
6 workers (the #1244-era recipe measured +30%, see §3a), and (b)
kernel-cmdline `isolcpus`/`nohz_full` (#739) — do **not** require giving
up a worker at all. Path C is the one framing of control-plane isolation
that pays a worker; that is precisely why it loses.

> v2 incorporates Codex + AGY + SMR round-1: cites the #1243 precedent
> and the #1244 keep-6-workers +30% recipe, softens "softirq invariant"
> to "inferred (unchanged unless IRQ/RSS reshaped)", corrects the
> `poll-mode interrupt` (NAPI, not pure busy-poll) wording, fixes the
> `manager.go` line refs and the `Nth-allowed-CPU` off-by-one note.

## 1. Issue framing

#1752 found `-P48 -p5210` forwarding CPU-bound (~16 Gb/s best-effort)
on a 6-vCPU / 6-RX-queue / 6-worker box, no headroom by design. The
#1752 body asserted (un-committed, no evidence file) that a "futex
profile showed the Go control plane's GC threads run across all 6 cores
and preempt the busy-polling Rust workers." Path C: pin Go (xpfd) to
core 0 (cpuset / `GOMAXPROCS=1` + affinity) and the 6 workers to cores
1-5 — i.e. **dedicate one core to the control plane, dropping from 6 to
5 workers**.

The issue itself states this is "likely a net LOSS": 6→5 workers ≈
16.7% raw packet-processing capacity cut; the GC-preemption jitter must
be proven to cost more than that before it nets positive.

## 2. What is actually on master (code walk)

- **Workers are already core-pinned.** `pin_current_thread(worker_id)`
  (`userspace-dp/src/afxdp/neighbor.rs:713`) reads the inherited mask
  via `sched_getaffinity` and pins worker `i` to the i-th allowed CPU
  (`nth_allowed_cpu`). Called once at `worker_loop` entry
  (`afxdp/worker/loop_body/mod.rs:59`). The #740 fix (master
  `b5e7fc2f`) made this honour an inherited `CPUAffinity=` mask
  correctly. **There is no per-worker core MAP** — pinning is purely
  positional within the inherited mask; the lever for "which cores
  workers may use" is the systemd unit mask + the worker COUNT.
- **Worker count** = `--workers N`
  (`userspace-dp/src/server/lifecycle.rs:269`), fed from Go `cfg.Workers`
  (`pkg/dataplane/userspace/process.go:79`), derived from
  `system.userspace-dataplane workers` in `deriveUserspaceConfig`
  (`pkg/dataplane/userspace/manager.go:1196-1198`; the `Workers: 1` at
  `:1191` is only the default before the config override). Cluster
  config sets `workers 6;` (`docs/ha-cluster-userspace.conf:286`).
- **Queue→worker map**: `binding.worker_id = (queue_id %
  workers.max(1))` in `replan_bindings_from_candidates`
  (`userspace-dp/src/server/helpers.rs:636`). With 6 RX queues and
  `workers=5`, queue 5 % 5 = 0 → worker 0 owns queues 0 AND 5 while
  workers 1-4 own one each. This is not a clean 5-way split; it
  concentrates load on worker 0 (see §6 risk).
- **Go daemon process model**: `cmd/xpfd` is a normal Go binary,
  `GOMAXPROCS` unset (= NumCPU = 6), 39 OS threads observed live, no
  `CPUAffinity=` in `test/incus/xpfd.service`. The Rust `userspace-dp`
  is a **separate process** spawned by the Go manager
  (`process.go`), with its own thread set (6 workers + ~8 aux).

So "pin Go to core 0" means: (a) put a `CPUAffinity=0` (or cgroup
cpuset) on `xpfd.service`, AND (b) the Rust helper inherits a DIFFERENT
mask `1-5` so its workers pin to cores 1-5 — but the helper is a child
of xpfd and inherits xpfd's affinity unless explicitly re-masked, so
this needs a per-process affinity split (spawn the helper with
`sched_setaffinity(1-5)` or its own cpuset), PLUS `--workers 5`.

A note on "busy-polling": the cluster config runs `poll-mode interrupt;`
(`docs/ha-cluster-userspace.conf:288`), so workers are interrupt-driven
NAPI threads, not pure 100%-spin busy-poll. The preemption argument is
unchanged — a descheduled NAPI worker still misses its RX service
window and lets the ring drain — but the 92-94% per-core busy is NAPI
processing under load, not idle spinning.

## 3a. Prior art — the keep-6-workers pin already WON (+30%), Path C's worker-drop is the part that loses

`docs/per-5-tuple/even-flows-recipe.md:214-238` ("Daemon CPU pinning —
additional finding, 2026-05-07 round 3"): pinning ALL xpfd daemon +
helper aux threads to CPU 0 **while keeping all 6 workers** (worker 0
still co-resident with the daemon on CPU 0) took aggregate from
`17 Gbps → 22.7 Gbps (+30%)` on the saturated push iperf-c workload.
This proves daemon contention CAN cost real throughput — but it was
recovered **without surrendering a worker**. Path C's distinguishing
move (drop to 5 workers, give core 0 to Go *exclusively*) is exactly the
part that is NOT supported by this result. The honest read: there is a
real, free, no-worker-sacrifice daemon-pinning win available (pin Go to
core 0, keep `workers 6`), and Path C throws it away by also cutting a
worker.

## 3b. Prior art — the exact 5-worker variant was already PLAN-KILLED at #1243

`docs/per-5-tuple/state.md:144`: #1243 "5-worker dedicated CPU mode"
was **PLAN-KILLED 2026-05-08**: "multinomial(12,5)+uniform vs
(12,6)+skew CoV cancels (~55.5% vs ~55.8%). **Zero quantitative gain to
justify −17% saturation throughput.** Plus single-CPU control-plane
**VRRP-starvation risk** + i40e ethtool-order disagreement between
reviewers." This is the same lever #1756 proposes (5 workers + dedicated
control-plane CPU). It was killed on: (i) no fairness gain, (ii) −17%
throughput, (iii) starving VRRP/HA on a single control CPU. #1756 adds
nothing new to overturn that; the live measurement here re-confirms it
at the mechanism level. **#1756 is a re-litigation of #1243 and should
be killed by reference plus the fresh measurement.**

The single-CPU control-plane VRRP/HA-starvation risk (#1243's point
iii) is independently disqualifying: confining all 39 xpfd threads —
including the 30 ms RETH VRRP advertiser, the 200 ms heartbeat, session
sync, and FRR reload — to one core that also runs a worker invites
missed VRRP adverts under load → spurious failover. The whole point of
the HA timing budget (~60 ms failover) assumes the control plane is not
CPU-starved.

## 3. Prior art on master — this lever was already measured (and reverted)

This is the decisive context the issue framing omits. **#712 / #741
already ran the workers-off-the-busy-cores A/B on this exact lab** and
reverted it:

- `docs/cos-validation-notes.md` §"CPU pinning layout" + §"CPU pinning
  retry post-#740": `CPUAffinity=2 3 4 5` (workers confined to cores
  2-5, reserving 0-1), #740 fix verified live (`psr` 1:1 with
  `cpus_allowed`). Phase-4 A/B, 3×30 s×16-flow:
  - rate ratio +2% (worse), retrans +11% (worse), per-flow CoV mean
    −0.6 pp (better), CoV max +1.7 pp (worse) — **all within noise;
    no metric crossed the keep threshold. Decision: revert.**
- Root cause documented: pinning workers off cores 0-1 does not help
  because **softirq / virtio RX IRQ is spread 1-per-CPU across all 6
  cores** — moving the workers just co-locates them with the same
  softirq they were already sharing. To actually quiet a worker core
  you need `isolcpus=`/`nohz_full=`/`rcu_nocbs=` (kernel cmdline,
  reboot) — filed as **#739** (OPEN) — or an RSS reshape to park RX
  queues on a subset of cores.

Path C is a *variant* of #712 Option A (it dedicates core 0 to Go
rather than reserving 0-1 for IRQ), but it shares #712's fatal property
on this hardware: it does not remove the dominant per-core softirq, and
it now ALSO pays a worker.

## 4. Live measurement (this research) — evidence/gc-preemption-measurement.md

Captured 2026-06-03, master `380bbb8ed`, no BTF (used `/proc` counters,
not `sched_switch`). Under sustained P48 on port 5210:

- All 6 cores **92-94% busy**; **softirq ≈ 25% on every core** (mlx5
  NAPI + virtio), invariant to Go isolation.
- Per-worker CPU 83-92%; the cpu0 worker (sharing with the most Go
  threads) is the lowest at 83%.
- **Total xpfd Go CPU = ~22% of ONE core** across all 39 threads. This
  is the *entire* envelope Path C could reclaim — ≈ 3.7%/core if spread
  over the surviving 5 cores. softirq is not in this envelope.
- Worker involuntary preemptions: **15-134/s** (clean single load),
  worst on the cpu0 + cpu5 workers. Using #712's 10-500 µs stall: worst
  case 134/s×500 µs = 6.7% of one worker; typical (10-50 µs) ≈ 0.4%;
  median worker <0.1%. And only a SUBSET of these preemptions are Go
  (softirq/RCU/ksoftirqd/timer-tick are the rest).
- Anchor baseline: **12.3 Gb/s receiver, 0 retransmits**, P48 5210, 6
  workers. 0 retrans ⇒ no descheduling-induced TX-ring starvation
  visible at this offered load.

## 5. The bar, worked out

- **Cost of Path C**: drop 1 of 6 workers = remove ~one core of
  packet-processing. Workers run 83-92% useful CPU, so this is a
  **~16.7% raw worker-capacity cut**, partly mitigated only if the box
  is not actually worker-bound (it is — 92-94% busy).
- **Benefit ceiling of Path C**: reclaim the ~22%-of-one-core Go
  envelope from the 5 surviving worker cores (≈ +3.7%/core) **plus**
  the jitter reduction (sub-1% typical, ≤6.7% worst on two workers,
  and only the Go-attributable subset of that).
- **Net**: −16.7% raw to recover ≤ ~3.7%/core compute + sub-1% typical
  jitter. **The benefit is ~5× smaller than the cost.** The bar is not
  cleared. This matches #712/#741's empirical revert and is now
  quantified at the mechanism level.

## 6. Why even the "benefit" is overstated

1. **softirq dominates and doesn't move.** ~25%/core of NIC/virtio
   softirq is the largest non-worker load. Go isolation does nothing to
   it; #739 (`nohz_full`/`rcu_nocbs`) + RSS reshape are the only levers
   that touch the per-core kernel/IRQ jitter, and neither costs a
   worker.
2. **`queue_id % 5` is not a clean split.** With 6 RX queues and 5
   workers, worker 0 owns queues 0 and 5 → it carries 2× the queue load
   while one core sits dedicated to a ~22%-busy Go process. This
   re-introduces exactly the cross-binding funnel that #1183 showed
   causes a 10× reverse-throughput regression when one worker is
   overloaded. The 5-worker layout is *worse than uniform* 16.7% loss.
   Additionally, `pin_current_thread` picks the Nth ALLOWED CPU
   (`neighbor.rs` `nth_allowed_cpu`), so with helper mask `1-5` worker 0
   lands on CPU 1, worker 1 on CPU 2, etc. — the queue→core mapping
   shifts by one relative to the RX-queue IRQ affinity unless IRQ/RSS is
   also reshaped, so the double-loaded worker 0 no longer sits on the
   core handling its own queues' softirq. Another reason B underperforms
   a clean −16.7%.
3. **0 retransmits at baseline** means the jitter is not currently
   manifesting as ring starvation / loss at this offered load — there
   is no observed throughput pathology for Path C to fix.

## 7. A/B design (for completeness — expected to confirm the kill)

If run anyway, the A/B is:
- **A (control)**: current 6 workers, no affinity directive,
  `workers 6`. Baseline anchored at 12.3 Gb/s / 0 retrans.
- **B (treatment)**: `xpfd.service` `CPUAffinity=0` (or cgroup cpuset
  cpu 0 for the xpfd slice) + spawn `userspace-dp` with mask `1-5` +
  `system.userspace-dataplane workers 5`. Verify live with
  `taskset`/`/proc/<tid>/stat psr`: 5 workers on cores 1-5, all xpfd
  threads on core 0.
- **Metrics** (3×30 s×P48, both v4 `172.16.80.200` and v6
  `2001:559:8585:80::200`, push + `-R`, CoS-on): aggregate Gb/s,
  per-flow CoV, retransmits, AND RX-ring drops
  (`ethtool -S ge-0-0-2 | grep -i drop` / `rx_xdp_drop` / xsk fq
  starvation counters) + worker involuntary-preemption/s.
- **Keep gate**: aggregate throughput must IMPROVE (not just hold) by
  more than the 16.7% it gives up — i.e. B's 5-worker aggregate must
  beat A's 6-worker aggregate outright, OR retrans/RX-drops must fall
  enough to prove the jitter was costing >16.7%. Per the measurement,
  neither is plausible.

## 8. Recommendation: PLAN-KILL

- The mechanism is measured: Go's total CPU footprint is ~22% of one
  core; the jitter it induces is sub-1% typical and ≤6.7% worst-case on
  the two most-contended workers; the dominant per-core load is softirq
  which Go isolation does not touch.
- The cost is a hard 16.7% raw worker cut, made worse by the
  `queue%5` funnel onto worker 0.
- Prior art (#712/#741) already ran the closely-related off-IRQ-core
  pin A/B and reverted it as a no-op on this hardware, for the same
  softirq-spread reason.
- The real jitter lever is **#739** (`isolcpus`/`nohz_full`/
  `rcu_nocbs`, kernel cmdline + reboot) — it quiets worker cores
  WITHOUT surrendering a worker, and it is already filed and OPEN.

- The exact 5-worker dedicated-CPU variant was **already PLAN-KILLED at
  #1243** (−17% saturation throughput, zero gain, VRRP-starvation risk);
  #1756 is a re-litigation with no new overturning evidence.
- There is a **real, free, no-worker-sacrifice win** instead: pin Go to
  core 0 while keeping `workers 6` (the #1244-era recipe measured
  17→22.7 Gbps, §3a). That is the version worth pursuing — and it is NOT
  Path C. If anything ships from the control-plane-isolation idea, it is
  this keep-6-workers daemon pin, tracked separately, not #1756.

**Disposition:** PLAN-KILL #1756 with `plan-kill` label. Redirect: (a)
control-plane-jitter on worker cores → #739 (kernel-cmdline
`isolcpus`/`nohz_full`, no worker sacrifice); (b) the daemon-contention
throughput win → a keep-6-workers "pin Go to core 0" experiment (§3a),
which does not drop a worker and therefore does not trip #1243's −17%
penalty or the VRRP-starvation risk. Do not implement Path C's 6→5
worker core-0 dedication.

## 9. If reviewers want to resurrect it

A resurrection would need ONE of:
- A measured load where Go isolation alone (not #739) recovers >16.7%
  aggregate throughput — contradicted by the present data and #741.
- A control plane that genuinely needs a dedicated core (e.g. a future
  ISSU/bulk-sync workload that saturates a core for seconds) — not the
  steady-state forwarding case #1752 is about.
- A box where workers are NOT the throughput unit (more cores than RX
  queues), where a spare core exists to give Go — not the 6/6 lab.

## 10. Test/validation plan

No production code ships from this research (kill). Validation = the
committed `evidence/gc-preemption-measurement.md` (live `/proc` +
throughput capture) + the #712/#741 prior-art cross-check in
`docs/cos-validation-notes.md`. If the A/B in §7 is run to satisfy a
reviewer, attach its table here before closing.

## 11. Open questions for adversarial review

1. **Measurement validity without BTF.** `/proc/<tid>/status`
   nonvoluntary_ctxt_switches counts ALL involuntary preemptions, not
   just Go-caused ones — so the 15-134/s is an UPPER bound on the
   Go-attributable jitter (good for the kill: even the upper bound is
   sub-7%). Is `/proc`-counter methodology sufficient to kill, or does
   a reviewer demand a BTF-enabled kernel to attribute preemptions to
   `next_comm == xpfd` specifically? (The kill holds either way: the
   total Go envelope is 22% of one core, an independent ceiling.)
2. **Is 22%-of-one-core Go CPU representative?** It was measured at
   steady forwarding load. Could a control-plane burst (HA bulk sync,
   config commit, FRR reload) transiently spike Go to >1 core and
   stall workers for seconds? If so, the fix is to bound/throttle that
   burst (or #739), not to permanently dedicate a core. Does any
   reviewer have a worked trace of such a burst costing >16.7%
   sustained?
3. **`queue_id % 5` funnel.** Is the worker-0-owns-2-queues skew under
   5 workers actually as bad as #1183's 10× reverse regression, or
   does RSS spread mitigate it? Either way it makes B worse than a
   clean −16.7%; does anyone dispute that it strengthens the kill?
4. **Does Path C even differ from #712?** #712 reserved cores 0-1 for
   IRQ (kept 4 workers historically); Path C reserves core 0 for Go
   (5 workers). Both leave softirq on the worker cores. Is there any
   regime where dedicating to GO specifically (vs IRQ) wins where #712
   lost? If not, this is #712 re-litigated and should be killed by
   reference.
