# #1756 evidence — GC-preemption cost vs the 16.7% worker-loss bar

All on `loss:xpf-userspace-fw0` (6-vCPU VM, primary node), client
`loss:cluster-userspace-host` → `172.16.80.200 -p 5210 -P48`. mlx5 VF
WAN, 6 RX queues → 6 workers. Captured 2026-06-03 on master `380bbb8ed`.
No kernel BTF in the VM (`/sys/kernel/btf/vmlinux` absent) and
`finish_task_switch` is inlined/notrace, so `sched:sched_switch`
bpftrace is unavailable — measurement uses `/proc/<tid>/status`
(voluntary/nonvoluntary ctxt switches), `/proc/<tid>/stat` (utime+stime,
psr), and `/proc/stat` per-core counters instead.

## Topology / process model (live)

- `nproc` = 6. Workers `xpf-userspace-w` tids 1001..1006 pinned 1-per-core
  on PSR 0..5 (confirmed; matches `pin_current_thread`,
  `neighbor.rs:713`). Worker count = 6 from `workers 6;` in
  `docs/ha-cluster-userspace.conf:286` → `--workers 6`
  (`process.go:79`, derived `manager.go:1191` from
  `system.userspace-dataplane workers`).
- Go daemon `xpfd`: **39 OS threads**, `GOMAXPROCS` unset (= 6), no
  `CPUAffinity=` in `test/incus/xpfd.service`. Go threads observed on
  every core 0..5 — this is the cross-core preemption Path C targets.

## Per-core utilization under sustained P48 (8 s window)

| core | busy% | sys% | softirq% |
|---|---|---|---|
| cpu0 | 93 | 9 | 25 |
| cpu1 | 92 | 7 | 26 |
| cpu2 | 93 | 6 | 26 |
| cpu3 | 94 | 8 | 25 |
| cpu4 | 92 | 7 | 26 |
| cpu5 | 93 | 8 | 24 |

All six cores ~92-94% busy under load (near-saturated, consistent with
#1752's "6/6 no-headroom"). **softirq ≈ 25% on EVERY core** — mlx5 NAPI +
virtio RX/TX processing, distributed across all cores. This load does
**not** move when Go is isolated; it is bound to the RX-queue→core IRQ
affinity, not to the Go scheduler.

## Per-worker CPU (8 s window)

| tid | psr | worker CPU% |
|---|---|---|
| 1001 | 0 | 83 |
| 1002 | 1 | 88 |
| 1003 | 2 | 92 |
| 1004 | 3 | 91 |
| 1005 | 4 | 88 |
| 1006 | 5 | 86 |

Worker on cpu0 is lowest (83%) — it shares its core with the largest
Go-thread residency + softirq. Gap between worker% and core-busy% is
softirq + Go + kernel.

## Total Go (xpfd) CPU cost — THE benefit ceiling for Path C

Summed utime+stime across all 39 xpfd threads over 8 s:

**xpfd total = ~22% of ONE core** (≈ 3.7% per core averaged over 6).

This is the entire CPU envelope Path C can reclaim from the worker
cores by relocating Go to core 0. softirq (~25%/core) is NOT reclaimed.

## Worker involuntary preemptions (the jitter signal)

10 s window, clean single P48 load, involuntary (nonvoluntary) ctxt
switches per second per worker:

| tid | psr | involuntary/s |
|---|---|---|
| 1001 | 0 | 93 |
| 1002 | 1 | 15 |
| 1003 | 2 | 30 |
| 1004 | 3 | 17 |
| 1005 | 4 | 17 |
| 1006 | 5 | 134 |

(Earlier 10 s sample under heavier overlap: cpu0 worker 674/s, others
140-450/s — preemption scales with contention but stays bounded.)

Cost bound using #712's documented 10-500 µs per scheduler stall:
- Worst worker 134/s × 500 µs = 67 ms/s = **6.7%** of that worker's
  time, absolute worst case (every preemption maximal).
- Typical (10-50 µs) = 134 × 30 µs = 4 ms/s = **0.4%**.
- Median worker (~20/s) = negligible (<0.1%).

Not all of this preemption is Go — softirq/ksoftirqd, virtio IRQ, RCU,
and kernel timer ticks also preempt. Go is a subset of the ~22%-of-one-
core envelope; the softirq + kernel-timer share stays on the worker
cores regardless of Go isolation.

## Anchored throughput baseline (6 workers, current)

Clean single P48, port 5210, 15 s: **12.3 Gb/s receiver, 0 retransmits**
(`[SUM] 0.00-15.01 sec 21.4 GBytes 12.3 Gbits/sec receiver`). 0 retrans
= workers are keeping the TX ring fed; no visible descheduling-induced
ring starvation at this offered load. (Lower than #1752's 16 Gb/s
because 5210 is a CoS-shaped class, not best-effort; it is a stable
A/B anchor, not the raw ceiling.)

## Bottom line

- **Benefit ceiling** (all Go CPU reclaimed from worker cores, zero
  jitter): ~22% of one core total, spread over the 5 surviving worker
  cores ≈ +3.7%/core of compute, AND the jitter saved is at most ~0.4-
  6.7% on the two worst-contended workers and <0.1% on the rest. The
  dominant non-worker load (softirq ~25%/core) does not move.
- **Cost** (6→5 workers): one core of packet-processing capacity is
  removed outright. Each worker carries 83-92% useful CPU, so the cut
  is ~16.7% of raw worker capacity (one of six workers gone).
- **Net**: removing one of six workers (−16.7% raw) to reclaim ~3.7%/
  core of Go time on the other five (and a sub-1% typical jitter
  reduction) is a large structural loss to chase a small, mostly-
  softirq-dominated gain. The 16.7% bar is not cleared.
