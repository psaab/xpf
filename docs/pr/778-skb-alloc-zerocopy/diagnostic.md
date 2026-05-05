---
status: CLOSED — NEEDS-NO-FIX (rolled into #781)
issue: https://github.com/psaab/xpf/issues/778
phase: Diagnostic — verify zero-copy binding + measure SKB-fallback cost on current master
---

## Summary

`mlx5e_xsk_skb_from_cqe_linear` cost on current master
(commit `b029e91c`) under sustained P=12 -R iperf3 load is
**0.95 %** of CPU (was 1.40 % when #778 was filed). Zero-copy
IS bound (mlx5 driver mode XDP, not generic), so the kernel
SKB-alloc path only fires on `rx_xsk_buff_alloc_err` —
i.e., when the fill ring runs empty and the driver falls back
to the SKB path for that descriptor. Over a steady-state
sample, `rx_xsk_buff_alloc_err = 899` against
`rx_xsk_packets = 4.6 M` (0.02 %), which matches the residual
~0.95 % CPU observed.

Closes NEEDS-NO-FIX. The remaining cost is the same fill-ring
replenishment mechanism #781 tracks at the bigger structural
scale (9.67 M cumulative rx_xsk_buff_alloc_err in #781's
report; 506 M tx_xsk_full). Any fix to fill-ring replenishment
in #781 would naturally close out #778's residual cost.

## Methodology

Cluster: `loss:xpf-userspace-fw0/fw1` (master HEAD `b029e91c`,
post-#915 surplus-sharing merge).

Step 1 — `ethtool -S ge-0-0-2` xsk counters:
- `rx_xsk_packets`            = 4 646 534
- `rx_xsk_xdp_redirect`       = 1 399 585 812
- `rx_xsk_oversize_pkts_sw_drop` = 0
- `rx_xsk_buff_alloc_err`     = 899 (~0.02 % of rx_xsk_packets)
- `tx_xsk_full`               = 0 (CURRENT state; #781 reports
                                  cumulative 506 M from before the
                                  #785/#917/#940-#943 chain landed)

Step 2 — driver mode confirmed:
- `ip link show ge-0-0-2`: `mtu 1500 xdp qdisc mq state UP mode DEFAULT`
- `bpftool net show`: `ge-0-0-2(6) driver id 5693`
  (`driver` = native XDP, NOT `generic`/`xdpgeneric` — zero-copy
  is attached)

Step 3 — perf record under load (P=12 -R, 10 s):

| % | Symbol | Source |
|---|---|---|
| 13.43 | `__memmove_evex_unaligned_erms` | libc — #776 cross-worker memcpy |
| 9.45 | `poll_binding_process_descriptor` | xpf-userspace-dp — #777 RX hot path |
| 5.94 | bpf_prog (XDP) | kernel — XDP redirect program |
| 4.50 | `worker_loop` | xpf-userspace-dp |
| 4.20 | `enqueue_pending_forwards` | xpf-userspace-dp — #779 TX dispatch |
| 2.07 | `mlx5_crypto_modify_dek_key` | mlx5_core |
| 1.79 | `ingest_cos_pending_tx_with_provenance` | xpf-userspace-dp |
| 1.52 | **`htab_map_hash`** | kernel — BPF hash map lookup (the cost #761 proposes to eliminate via dense slots) |
| **0.95** | **`mlx5e_xsk_skb_from_cqe_linear`** | **mlx5_core — #778 (this issue)** |

The original #778 observation reported 1.40 %. Current 0.95 %
on the same path. The difference is small but the trend is
right: post-#915 the residual SKB-fallback cost has slightly
declined.

## Verdict against #778 acceptance

- [x] Step 1: ethtool xsk counters captured. Only `rx_xsk_buff_alloc_err`
      shows non-zero in the relevant set, and it's 0.02 % rate.
- [x] Step 2: driver mode confirmed via `ip link` + `bpftool net show`.
      Zero-copy IS attached. NOT in generic/SKB mode.
- [x] Step 3: zero-copy bind path verified — the daemon binds
      via the xsk_user_helpers.{c,rs} path with
      `XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY` (per
      `userspace-dp/src/afxdp/umem.rs` and `csrc/xpf-xsk-helpers.c`).
- [x] Fix hypothesis 1 (descriptors falling back) — CONFIRMED.
      Cause is `rx_xsk_buff_alloc_err` (fill-ring drained
      transiently), not a wholesale binding mode mismatch.

## Implication for #781

#781's "9.67 M rx_xsk_buff_alloc_err + 506 M tx_xsk_full"
report describes the same mechanism at a larger structural
scale. The current cluster shows 899 / 0 of those counters,
which means whatever was driving the original #781 burst has
been substantially mitigated by the post-#785/#917/#940-#943/
#1183 mergeline. The remaining 0.95 % is the natural floor
for the rare-fallback-still-allocates-SKB cost.

If #781's investigation lands a fill-ring replenishment fix
(under-kicking is hypothesis 1 in #781), this 0.95 % would
move toward 0. Until then, NEEDS-NO-FIX.
