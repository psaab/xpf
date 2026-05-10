# userspace-dp/src/afxdp/frame/

Packet parsing + L3/L4 byte-level mutation + checksum recomputation.
The bottom layer that the rest of the pipeline reaches into to
inspect or rewrite a packet sitting in a UMEM frame.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub + cross-module helpers (`apply_dscp_rewrite_to_frame`, `decode_frame_summary`, `frame_has_tcp_rst`, etc.). |
| `byte_writes.rs` | In-place IP and L4 port rewrites (`write_ipv4_dst`, `write_ipv4_src`, `write_ipv6_dst`, `write_ipv6_src`, `write_l4_dst_port`, `write_l4_src_port`). |
| `checksum.rs` | IPv4 header + L4 checksum incremental adjust + recompute. Owns the `checksum16_*` family. |
| `inspect.rs` | Read-only parsers / matchers used by screen, policy, conntrack hot paths. |
| `tcp.rs` | TCP-specific inspection + mutation kernels (#989) — flags, MSS clamp, header munging. |
| `tcp_segmentation.rs` | TCP segmentation kernels for forwarded over-MSS frames; re-exported from `mod.rs`. The `#[cold]` annotation is on the TX-side wrapper in `tx/tcp_segmentation.rs` that calls into these kernels, not on the kernels themselves. |
| `tests.rs` | Co-located unit tests; relocated out of `mod.rs` in #1046 Phase 1. |

## Where it sits

- Read by every stage that inspects a packet (screen, policy,
  conntrack, NAT, forwarding).
- Mutated by NAT / NAT64 / NPTv6 to rewrite addresses + ports +
  checksums.
- Mutated by CoS for ECN CE-marking and DSCP rewrite.

## Notable invariants

- Visibility is tight: `adjust_l4_checksum_ipv6_addr_bytes` is
  file-private to `checksum.rs` (only the local SNAT/DNAT rewrites
  use it) and is pulled into `mod.rs` via a non-pub `use` so it
  doesn't leak via a glob re-export.
- All byte-level helpers assume the caller has already validated the
  packet bounds. The validation lives in `inspect.rs` and the worker
  hot path; do not call a `byte_writes` fn on an unvalidated frame.
- IPv4 checksum is incrementally adjusted (`adjust_*`) on each
  per-field rewrite. The `recompute_*` helpers exist for the rare
  case where the previous checksum is unknown (e.g. NAT64 from
  scratch in generic XDP — the BPF-side handling of this case is
  documented in `bpf/headers/` and the `xdp_nat64.c` source).
