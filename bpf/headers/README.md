# bpf/headers/

Retained C ABI mirror for the live Go/Rust mirrors — not compiled
code. No BPF program or `.c` file includes these headers since the
#1476 eBPF retirement; the legacy `bpf/xdp/*.c` and `bpf/tc/*.c`
sources were deleted then, and this directory survives only where a
build script or test outside `bpf/` still reads it.

## Files

- `xpf_common.h` — shared constants and layouts read by the shim
  build (`MAX_INTERFACES`), Go parity tests (`MAX_INTERFACES`,
  `MAX_NAT_POOLS`, `GLOBAL_CTR_MAX`, `struct event`) and the C-side
  sizing below.
- `xpf_conntrack.h` — session key/value layouts parsed by
  `bpf_conntrack_abi_6984_test.go`.
- `xpf_maps.h` — legacy map declarations whose names, key/value
  structs and sizing constants are mirrored by Go/Rust map code.

Deleted in #17146 (no compiler, no live reader; history in
`git log`): `xpf_helpers.h`, `xpf_nat.h`, `xpf_trace.h`.

## Conventions

- Every `#define`/`struct` left here must appear in some `.go`,
  `.rs` or `.sh` outside `bpf/` (enforced by
  `TestEveryHeaderIdentifierHasLiveReader17146`). Do not add
  retired-pipeline content here without a live reader.
- Go code in `pkg/dataplane` mirrors these structs. When you change a
  layout here, run `make generate` and update the matching Go struct's
  trailing `Pad [N]byte` so `unsafe.Sizeof` matches the C `sizeof`.
- IP addresses are `__be32` on the wire but read with
  `binary.NativeEndian` in Go because cilium/ebpf serializes map values
  in native endian.
