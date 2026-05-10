# bpf/xdp/

9 XDP ingress programs, tail-call chained.

```
xdp_main → xdp_screen → xdp_zone → xdp_conntrack → xdp_policy
                                                       ↓
                                              xdp_nat → xdp_nat64 → xdp_forward
```

`xdp_main` is the lightweight CPU-distribution stage; `xdp_cpumap` runs
on the target CPU after the cpumap redirect.

## Stage responsibilities

- `xdp_main` — cpumap redirect for parallelism.
- `xdp_cpumap` — entry point on the destination CPU.
- `xdp_screen` — DDoS / sanity checks (land, syn-flood, ping-of-death,
  teardrop, rate limits, SYN-cookie generation).
- `xdp_zone` — zone classification, per-RG / fabric redirect for HA
  fallback (`try_fabric_redirect`), NAT64 translate, conntrack
  fast-path entry.
- `xdp_conntrack` — session lookup, sets `meta->next_prog`. When no NAT
  flag is set, jumps directly to `xdp_forward`.
- `xdp_policy` — first-match-wins zone-pair policy lookup. Builds REJECT
  responses (TCP RST, ICMP unreachable) with `__noinline` helpers using
  the session_v4_scratch map as a byte buffer (stack budget would
  otherwise exceed 512B).
- `xdp_nat` — SNAT / DNAT / static. Owns the TTL check for non-NAT
  flows that bypass `xdp_forward` via the conntrack fast path.
- `xdp_nat64` — RFC 6052 IPv6↔IPv4 translation. Generic-XDP
  CHECKSUM_PARTIAL trap: write only the pseudo-header seed when
  `meta->csum_partial` is set.
- `xdp_forward` — FIB lookup, MAC rewrite, TX. TTL check duplicated here
  for sessions that skipped `xdp_nat`. `redirect_capable` flag falls
  back to `XDP_PASS` for non-native interfaces (iavf VFs).

## Notes

- All TTL handling lives in `xdp_nat` AND `xdp_forward`; either path
  alone misses the other's session class. Don't consolidate.
- The 4 REJECT helpers (RST v4/v6, ICMP unreach v4/v6) are
  `__noinline` — inlining blew the 512B combined-stack limit.
