# #1754 Step 1 — TX-vs-RX wake-kick attribution (live, mandatory first step)

Environment: `loss:xpf-userspace-fw0`, kernel 7.0.0-rc7+, 6 vCPU / 6 workers,
`--poll-mode interrupt --ring-entries 16384`, CoS ON (reth0.80 scheduler-map
`bandwidth-limit` confirmed), iperf3 `-c 172.16.80.200 -p5210 -P48` (v4 push).
All numbers are aggregate across the 6 worker threads (tid 1001-1006).
Run date 2026-06-03.

## Metric validation FIRST (the crypto-DEK lesson)
- `sys_enter_sendto` ≈ `xsk_sendmsg`: 950,347 vs 945,716 in 10 s (~95K/s) —
  ~1:1, so every worker `sendto` reaches the AF_XDP `xsk_sendmsg` path. The
  umbrella's "~108K/s sendto" reproduces (run-to-run 92–95K/s).
- `kretprobe:xsk_sendmsg` retval: **@ret[0] = 876,855 / 876,855 (100%
  success, 0 EAGAIN)** in 10 s. The forced kicks are NOT failing/EAGAIN — they
  are *successful* syscalls; the cost is syscall + in-kernel ring walk, not
  retry churn.

## The decisive split — RX-wake vs TX-kick `sendto` (10 s steady-state window)
`maybe_wake_rx` does `poll()`+`sendto()`; `maybe_wake_tx` does `sendto()` only.
Tagged each `xsk_sendmsg` by whether an `xsk_poll` fired <5 µs earlier on the
same tid (RX-wake) or not (TX-kick):

| site | count / 10 s | in-kernel ns / 10 s | = core-seconds | share of one core |
|---|---|---|---|---|
| **TX-kick** (`maybe_wake_tx`) | **762,132** | **5,322,919,935** | **5.32 s** | **53.2 %** |
| RX-wake (`maybe_wake_rx`)     | 163,928 | 613,034,802 | 0.61 s | 6.1 % |
| (poll, RX wake)               | ~30K/s | ~1.19 s | | 11.9 % |
| `mlx5e_xsk_wakeup` (driver)   | 154,646 | — | — | — |

**TX-kick dominates RX-wake ~4.6:1 by count and ~8.7:1 by time.** On a 6-core
box, the TX-kick `sendto` alone is **~8.9 % of total CPU** (5.32 core-s / 60
core-s wall). RX-wake is ~1.0 % of total CPU.

## Per-kick cost distribution (`xsk_sendmsg` latency hist, ~842K samples / 8 s)
```
[512,1K)     5,284
[1K,2K)    193,460  @@@@@@@@@@@@@@@@@@@@@@@@@@@@
[2K,4K)    331,716  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  <- mode
[4K,8K)    141,923  @@@@@@@@@@@@@@@@@@@@@@
[8K,16K)   129,540  @@@@@@@@@@@@@@@@@@@@
[16K,32K)   19,006
[32K,64K)   14,442
... tail to [512K,1M) x4
```
mean = 5.50 s / 842,091 = **~6.5 µs/kick**; median bucket [2K,4K) ≈ 3 µs.
The 8–32 µs tail is where the kick actually drives NAPI/TX; the [1K,4K) mass is
the cheap "ring didn't need it" walk.

## Driver-wakeup ratio — the over-kick signal
`mlx5e_xsk_wakeup` = 154,646 / 10 s vs 926,060 `sendto` (762K TX + 164K RX).
**Only ~17 % of `sendto` kicks actually reach the driver `ndo_xsk_wakeup`;**
~83 % return after the in-kernel `xsk_sendmsg` ring check finds NEED_WAKEUP
clear / nothing to do. That ~83 % is the recoverable population — kicks the
userspace `needs_wakeup()` gate *would* have suppressed, but `force=true`
bypasses it.

## Root-cause code finding (NOT what the umbrella assumed)
`TX_WAKE_MIN_INTERVAL_NS = 50_000` (mod.rs:302) is **almost entirely bypassed**.
`maybe_wake_tx(binding, force, now_ns)` (rings.rs:237) only consults the
interval/`needs_wakeup` gate when `force == false`. Grep of call sites:
- `force = true` (gate BYPASSED): `tx/transmit/mod.rs:92,186,231,260`,
  `tx/transmit/finalise.rs:27,54`, `cos/queue_service/service.rs:107,159,193,
  281,326,367,511,543,675,716` — i.e. **every TX-submit / CoS-drain site**.
- `force = false` (gate ACTIVE): only `tx/drain/phase_trivial.rs:31`
  (the no-pending-work re-kick).

So widening `TX_WAKE_MIN_INTERVAL_NS` 50 µs → 100–200 µs (the umbrella's
proposed A/B) would touch **only the one gated re-kick site** and do
**essentially nothing** to the 762K/10 s forced kicks that constitute the cost.
The genuine lever is to **route the forced TX-submit kicks through the
`needs_wakeup()` + interval gate** (drop `force=true` on the steady-state
submit path), not to widen the interval.

## Inherent-vs-recoverable framing
- Genuinely inherent: the ~17 % of kicks that hit `mlx5e_xsk_wakeup` (real TX
  doorbell) — ~154K/10 s — are doing necessary work.
- Recoverable candidate: the ~83 % that return without a driver wakeup, i.e.
  the forced kicks issued when `needs_wakeup()` would have been clear.
- Recoverable fraction is therefore **bounded above by the share of TX-kick
  time spent in non-wakeup `xsk_sendmsg` calls** — large by count (83 %) but
  the cheap [1K,4K) bucket, so the *time* recoverable is less than 83 % of
  5.32 s. A/B must measure the actual delta, not assume.

## Step 1b — which forced TX-kick site fires under CoS-ON (uprobe call counts)
The measured workload targets reth0.80 (CoS scheduler-map `bandwidth-limit`).
uprobe on the mangled caller symbols, 10 s under `-P48 -p5210` load:

| caller (uprobe) | calls / 10 s | path |
|---|---|---|
| `transmit::transmit_batch` | **0 (never fired)** | non-CoS backup |
| `cos::queue_service::drain_shaped_tx` | **1,890,060** | CoS shaped |
| `cos::queue_service::service_exact_guarantee_queue_direct_with_info` | 657,206 | CoS exact |
| `rings::maybe_wake_tx` (all callers) | 1,096,738 | — |

**Decisive:** under CoS-ON, `transmit_batch` / `finalise_prepared` are stone
cold. The forced TX kicks come entirely from the CoS-drain path
(`service.rs:*`). Gating `transmit/mod.rs:260` + `finalise.rs:54` (the §4 v1
primary lever) is a **no-op under the measured workload**. The recoverable
forced kicks live in `drain_shaped_tx` / `service_exact_*`, which are
correctness-coupled to the CoS exact-guarantee quantum (the #1207/#1545 trap).
