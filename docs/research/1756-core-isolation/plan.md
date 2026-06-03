# #1756 Path C — control-plane CPU isolation (dedicate core 0 to Go)

**Status: PLAN-KILL candidate (v1, DRAFT). Recommendation: PLAN-KILL.**
PLAN-KILL is the explicitly acceptable and likely outcome per the issue
and the #1752 umbrella. The A/B bar (the GC-preemption jitter Go steals
from the workers must cost MORE than the ~16.7% raw capacity cut of
going 6→5 workers) is **not cleared by the live measurement**, and the
levers that *would* matter (kernel-cmdline `isolcpus`/`nohz_full`,
already filed as #739) do not require giving up a worker at all.

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
- **Worker count** = `--workers N` (`server/lifecycle.rs:269`),
  fed from Go `cfg.Workers` (`process.go:79`), derived from
  `system.userspace-dataplane workers` (`manager.go:1191`). Cluster
  config sets `workers 6;` (`docs/ha-cluster-userspace.conf:286`).
- **Queue→worker map**: `worker_id = queue_id % workers`
  (`server/helpers.rs` `replan_bindings_from_candidates`). With 6 RX
  queues and `workers=5`, queue 5 wraps onto worker 0 → worker 0 owns
  TWO queues while workers 1-4 own one each. This is not a clean
  5-way split; it concentrates load on worker 0 (see §6 risk).
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

**Disposition:** PLAN-KILL #1756 with `plan-kill` label. Redirect the
control-plane-jitter concern to #739 (kernel-cmdline isolation, no
worker sacrifice). Do not implement core-0 Go isolation.

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
