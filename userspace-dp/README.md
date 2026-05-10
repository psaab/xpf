# userspace-dp/

Standalone Rust AF_XDP dataplane that mirrors the BPF pipeline
(screen → zone → conntrack → policy → NAT → forward) but in userspace.
Runs as a separate `xpf-userspace-dp` binary the Go daemon spawns over a
Unix-socket control protocol.

The eBPF backend (`pkg/dataplane`) is the default; this crate is the
opt-in AF_XDP zero-copy backend used on hardware that benefits from it.

## Crate entry

`src/main.rs` — argv parsing, then `server::lifecycle::run()`.

## Top-level layout

| Path | Purpose |
|------|---------|
| `src/afxdp/` | Core dataplane: workers, UMEM, RX/TX rings, frame parsing, session glue. |
| `src/server/` | Control-socket lifecycle and request dispatch. |
| `src/session/` | Session table (slab + Fx-hash indices) + timer wheel. |
| `src/filter/` | Junos-style firewall filter compiler + engine + policer. |
| `src/event_stream/` | Push-based binary session-delta stream to the daemon. |
| `src/bin/` | Helper binaries (`fairness-eval`). |
| `src/nat.rs`, `nat64.rs`, `nptv6.rs`, `policy.rs`, `screen.rs`, `slowpath.rs`, `fairness.rs`, `flowexport.rs` | Single-file feature modules consumed by the worker hot path. |

## Architecture

One worker thread per RSS queue. Each worker owns its AF_XDP socket,
UMEM (12K+ RX/TX frames, 256-byte headroom), RX/TX/fill/completion rings,
a per-worker reverse-NAT cache, and a per-worker session table view.

The hot path is the `worker_loop` (in `src/afxdp/worker/`), which polls
all bindings in batch (`RX_BATCH_SIZE=64`, up to `MAX_RX_BATCHES_PER_POLL=4`
per tick). Per descriptor: parse → screen → session lookup → NAT/policy
decision → forwarding build → enqueue TX or recycle.

## External interfaces

- **Unix socket** (`/tmp/xpf-userspace-dp.sock`): newline-delimited text
  protocol — `BIND`, `CONFIG`, `SESSION_INJECT`, `STATUS`, `STOP`, etc.
- **AF_XDP rings** (kernel ↔ userspace): RX/TX/fill/completion.
- **BPF maps** (shared with the XDP shim): session table mirror,
  conntrack, NAT pools, heartbeat.
- **Sysctl tuning**: raises `SO_RCVBUF`, enables NAPI busy-poll in
  `BusyPoll` mode.

## Critical invariants

These invariants are enforced in code (`const_assert`s and runtime
checks) and discussed in `docs/per-5-tuple/state.md`. They aren't
mirrored into CLAUDE.md — that file's authoritative content covers
Go, BPF, and Rust-helper logging rules, but not these specific
hot-path constants.

- AF_XDP UMEM ownership is per-queue. A flow that hashes to queue N is
  *physically tied* to worker N — there is no cross-worker descriptor
  sharing. This is why every "rebalance flows across workers" design
  has been plan-killed; see `docs/per-5-tuple/state.md` for the formal
  ceiling.
- `RX_BATCH_SIZE = 64` is paired with the L1d footprint (≤14 KB
  working set per batch). A `const_assert` enforces it; don't bump it
  without re-validating.
- `TX_BATCH_SIZE = 64` is paired with the CoS guarantee quantum in
  `tx/`. Changing requires re-running the `guarantee_phase_*` tests.
- Generic-XDP fallback consumes UMEM frames permanently on mlx5; the
  XDP shim redirects `XDP_PASS` to a cpumap stage that frees the frame
  immediately.
- `HEARTBEAT_GRACE_PERIOD_NS = 6 s` — during the bootstrap window the
  XDP shim falls back to `XDP_PASS` so the kernel bootstraps NAPI.
  After 6 s the userspace heartbeat keeps the redirect alive.

## Subdir READMEs

See `src/afxdp/README.md`, `src/server/README.md`, `src/session/README.md`,
`src/filter/README.md`, `src/event_stream/README.md`, `src/bin/README.md`.
