# userspace-dp/src/afxdp/umem/

UMEM (User-space Memory) management — the per-binding shared-memory
region where AF_XDP zero-copy frames live. Owns the `mmap` region,
wraps the crate-local `Umem` type from `xsk_ffi` (a libxdp-backed
drop-in for xdpilone), and tracks frame budgets per binding.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `WorkerUmem` / `WorkerUmemInner` — Rc-shared UMEM handle held by the owner worker. |
| `mmap.rs` | `MmapArea` — the raw `mmap` region. |
| `mmap_tests.rs` | Co-located mmap unit tests. |
| `profile.rs` | `OwnerProfileOwnerWrites` / `OwnerProfilePeerWrites` — per-frame profiling counters split by who's writing. |
| `tests.rs` | Co-located UMEM unit tests. |

## Where it sits

- Constructed once per binding by the worker before AF_XDP socket
  bind.
- Consumed by `tx/` (frame submit), `frame/` (byte mutation), and
  the AF_XDP rings in `xsk_ffi`.

## Notable invariants

- **UMEM ownership is per-queue.** A flow that hashes to queue N is
  *physically tied* to worker N — there is no cross-worker
  descriptor sharing. This is the reason every "rebalance flows
  across workers" design has been plan-killed; see
  `docs/per-5-tuple/state.md` for the formal ceiling.
- `Rc<WorkerUmemInner>` (not `Arc`) is intentional — UMEM ownership
  doesn't cross thread boundaries within the worker. The cross-binding
  redirect path in `cos/cross_binding.rs` *copies* frames into the
  destination binding's UMEM rather than sharing.
- In **zero-copy mode on mlx5**, an `XDP_PASS` action permanently
  consumes a fill-ring frame: the kernel holds the UMEM buffer in
  an SKB and never returns it. Sustained traffic drains all 12K+ RX
  frames within seconds. The mitigation (#209): the XDP shim
  replaces every `XDP_PASS` path with a cpumap redirect
  (`USERSPACE_CPUMAP`), which frees the XSK frame immediately while
  still delivering the packet to the kernel stack. Bind flags try
  zero-copy first and fall back to copy mode if the driver doesn't
  support it; copy mode is unaffected because `XDP_PASS` there
  operates on kernel DMA buffers, not UMEM frames.
