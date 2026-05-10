# bpf/headers/

Shared C headers for every BPF program in the pipeline.

## Files

- `xpf_common.h` — packet metadata layout (`struct pkt_meta`), AF_XDP
  frame header, the per-CPU scratch map shape that crosses tail-call
  stages.
- `xpf_maps.h` — BPF map definitions: conntrack, NAT pools, session
  indices, screen counters, application table, redirect-capable flags,
  HA watchdog.
- `xpf_helpers.h` — packet parsing, checksum incremental update, GRE
  encap helpers.
- `xpf_conntrack.h` — flow-key hashing (5-tuple, NAT-aware).
- `xpf_nat.h` — NAT helpers (SNAT/DNAT/static, NAT64, NPTv6).
- `xpf_trace.h` — debug logging (`bpf_printk` wrappers, gated on
  compile-time flag).

## Conventions

- Go code in `pkg/dataplane` mirrors these structs. When you change a
  layout here, run `make generate` and update the matching Go struct's
  trailing `Pad [N]byte` so `unsafe.Sizeof` matches the C `sizeof`.
- IP addresses are `__be32` on the wire but read with
  `binary.NativeEndian` in Go because cilium/ebpf serializes map values
  in native endian.
