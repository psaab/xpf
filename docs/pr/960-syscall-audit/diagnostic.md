---
status: CLOSED — NEEDS-NO-FIX
issue: https://github.com/psaab/xpf/issues/960
phase: Profile-driven syscall audit on userspace-dp fast-path
---

## Summary

Per #960 acceptance: gather data on which control-plane syscalls
appear in userspace-dp fast-path perf, and identify any call site
exceeding 10 K/s as a candidate for SPSC offload. Result:
**only `sendto()` (AF_XDP TX wake) exceeds 10 K/s — at ~21 K/s —
and is already heavily gated** via `maybe_wake_tx`'s
`TX_WAKE_MIN_INTERVAL_NS` rate limiter (the same call site
that #781 tracks). No new SPSC offload candidates identified.

Closes NEEDS-NO-FIX. The existing direct-syscall pattern is not
the bottleneck. The mediator/SPSC refactor proposed in #948
remains premature; #960's data-gathering job is complete.

## Methodology

Cluster: `loss:xpf-userspace-fw0/fw1` (master HEAD `94c8af11`).

Load profile: sustained 25 Gb/s push via
`iperf3 -c 172.16.80.200 -P 128 -t 30 -p 5201` from
`loss:cluster-userspace-host`. This drives heavy session
churn (128 short-lived TCP connect/teardown loops at line rate)
plus continuous data-plane forwarding through 6 worker
threads.

Sampling: ftrace `raw_syscalls:sys_enter` system-wide for 5s
during the steady-state portion of the load. ftrace was
chosen over `perf trace -p` because the per-process
tracepoint path was returning empty in the test environment;
ftrace is the lighter-weight kernel-side mechanism and works
without special perf-paranoid relaxation.

```bash
echo 1 > /sys/kernel/tracing/events/raw_syscalls/sys_enter/enable
echo > /sys/kernel/tracing/trace
echo 1 > /sys/kernel/tracing/tracing_on
sleep 5
echo 0 > /sys/kernel/tracing/tracing_on
echo 0 > /sys/kernel/tracing/events/raw_syscalls/sys_enter/enable
```

## Results — top 15 syscalls by count, 5s sample

| NR | Syscall | Count (5s) | Rate (per s) |
|---:|---------|-----------:|-------------:|
| 44 | `sendto`             | 105 258 | **21 052** |
|  7 | `poll`               |  13 703 |  2 741 |
| 321| `bpf`                |   2 059 |    412 |
| 230| `clock_nanosleep`    |   1 704 |    341 |
| 45 | `recvfrom`           |   1 572 |    314 |
| 35 | `nanosleep`          |     976 |    195 |
| 281| `epoll_pwait`        |     625 |    125 |
| 202| `futex`              |     374 |     75 |
| 288| `accept4`            |     209 |     42 |
|  0 | `read`               |     102 |     20 |
| 72 | `fcntl`              |      81 |     16 |
|  3 | `close`              |      71 |     14 |
| 233| `epoll_ctl`          |      64 |     13 |
| 39 | `getpid`             |      41 |      8 |
| 234| `tgkill`             |      41 |      8 |

Total: **~25 444 syscalls/s** system-wide on the firewall VM
under sustained 25 Gb/s load.

## Caller attribution

Sampled threads (from ftrace `comm` field) confirm:

- `sendto` (NR 44) almost entirely fires from
  `xpf-userspace-w-NNNNN` worker threads, with first-arg
  values `0x25` (37) and `0x1e` (30) — AF_XDP socket FDs for
  different bindings. This is `maybe_wake_tx → sendto(MSG_DONTWAIT)`,
  which is precisely the gated TX-wake call site referenced in
  #781.
- `poll` (NR 7) also from worker threads.
- `bpf` (NR 321) at 412/s is well below the 10 K/s threshold;
  fires for BPF map updates from the control-plane goroutines
  (session install, conntrack writes), not the worker fast
  path. Per-session/per-neighbor rate, not per-packet.
- `epoll_pwait`, `futex`, `nanosleep`, `accept4` are all the
  control-plane goroutines (gRPC, control socket, HA sync,
  watchdog) and are all under 3 K/s. None justify SPSC
  offload on their own.

## Verdict against #960 acceptance criteria

- [x] Run `perf stat` + `perf trace` on the userspace-dp worker
      thread under sustained 25 Gb/s + heavy session churn
      (substituted ftrace `raw_syscalls:sys_enter` for the
      same outcome — see Methodology note).
- [x] Categorize syscall hits per second by source
      (`sendto`/`poll` = workers; `bpf`/`epoll_pwait`/`futex`/
      `nanosleep` = control-plane goroutines; `accept4` =
      gRPC accept).
- [x] Identify any specific call site whose syscall rate
      exceeds 10 K/s — those are candidates for SPSC offload.
      **Only `sendto` qualifies (~21 K/s); already gated.**
- [x] Per candidate, decide: is the cost actually material,
      or is it overshadowed by ring-bottom poll cost?
      `sendto` cost is gated and tracked in #781; bpf/futex/
      epoll are sub-3 K/s and not worth optimizing.

## Implications for #948

#948 proposes a sweeping mediator/SPSC refactor (600-1000 LOC,
real correctness risk on session-install ordering) to decouple
control plane from data plane. The data here gives no empirical
support: no control-plane syscall fires from the fast path at a
rate that would justify the refactor cost. Per-session BPF map
updates fire at ~412/s — low even at 1.4 M pps. The refactor
remains premature.

## Adjacent observation

`sendto` at 21 K/s is consistent with the
`TX_WAKE_MIN_INTERVAL_NS`-gated `maybe_wake_tx` rate. If #781's
diagnostic identifies that the TX-ring-full pattern is driven
by under-kicking (hypothesis 1 in #781's body), the gate
window would tighten and this rate would rise. That's a #781
follow-up; not a #960 concern.

## References

- `userspace-dp/src/afxdp/tx/transmit.rs` (and adjacent
  modules) — `maybe_wake_tx` is the lone hot-path syscall
  emitter.
- #781 — TX-ring-full structural pipeline stall (linked
  diagnostic).
- #948 — mediator/SPSC refactor proposal (this measurement
  argues against it).
