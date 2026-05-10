# bpf/tc/

5 TC egress programs, tail-call chained.

```
tc_main → tc_screen_egress → tc_conntrack → tc_nat → tc_forward
```

## Stage responsibilities

- `tc_main` — egress entry; per-RG and per-zone classification.
- `tc_screen_egress` — egress-direction checks (rate limits on outbound
  to remote zones, etc.).
- `tc_conntrack` — egress session table lookup (separate from XDP
  ingress conntrack — egress sees post-routing tuple).
- `tc_nat` — egress NAT (SNAT pool allocation, address-persistent
  mapping).
- `tc_forward` — final L2/L3 emission; TC redirect to the egress
  netdev.

## Why TC, not XDP, on egress

XDP has no egress equivalent that's universally supported across drivers
the lab uses. TC clsact is supported everywhere and integrates with the
kernel's `netfilter` chains (which we don't use, but interoperate
with). NetEm test setups also hook here.

## Notes

- The conntrack table is shared with the XDP ingress side; both
  directions update the same flow entry.
- TCP MSS clamping ingress is in XDP (`xdp_screen`); the egress side is
  here in `tc_main` for GRE-specific gre-in / gre-out cases.
