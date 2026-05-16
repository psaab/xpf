# bpf/

> Deprecation notice (#1373): this legacy eBPF dataplane is being retired in
> favor of `userspace-dp`. Phase 0 is documentation/audit only, so this source
> tree remains intact until later removal phases.

eBPF programs that drive the in-kernel packet pipeline. 14 programs
total: 9 XDP ingress, 5 TC egress. They compose via tail-calls; metadata
crosses stages through a per-CPU array scratch map.

```
XDP ingress: main → screen → zone → conntrack → policy → nat → nat64 → forward
TC egress:   main → screen_egress → conntrack → nat → forward
```

## Layout

- `headers/` — shared C headers used by every program.
- `xdp/` — XDP ingress programs.
- `tc/` — TC egress programs.

## Compilation

`make generate` invokes `bpf2go` (cilium/ebpf) which compiles the C and
emits Go bindings. Don't write Go that pokes at BPF map keys/values
without going through those bindings — they encode the C struct layout.

## Verifier traps (CLAUDE.md authoritative)

- Branch merges lose packet range; re-read `ctx->data` /
  `ctx->data_end` after every branch.
- 512-byte combined stack across call frames. Push large locals to a
  scratch map and mark big helpers `__noinline`.
- Variable-offset packet pointers lose range when `var_off` is wide
  (0xffff). Use a constant offset from a validated pointer.
- Mask `meta->l3_offset` (u16) with `& 0x3F` before pointer arithmetic
  (commit `66833c5`) so the verifier can track the range.
- `__u16` causes sign-extension (`smin=-32768`) — fails for packet-pointer
  math. Use `__u32` then narrow.
- Pointer bitwise OR is rejected. `if (sv4 || sv6)` where both are
  pointers triggers a compiler `|=` on pointer registers — split into
  separate null checks.

## Kernel-version notes

- xdp_zone fails the verifier on kernel 6.12 (NAT64 complexity). Passes
  on 6.18+. Production is 6.18.9.
- Generic XDP on virtio-net preserves `skb->ip_summed=CHECKSUM_PARTIAL`
  through `bpf_redirect_map`. From-scratch checksums get corrupted —
  use the `meta->csum_partial` path that writes only the pseudo-header
  seed.

## Subdirs

See `headers/README.md`, `xdp/README.md`, `tc/README.md`.
