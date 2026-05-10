# userspace-dp/src/afxdp/umem/

UMEM (User-space Memory) management — the per-binding shared-memory
region where AF_XDP zero-copy frames live. Owns the `mmap` region,
wraps `xdpilone::Umem`, and tracks frame budgets per binding.

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
- Generic-XDP fallback consumes UMEM frames permanently on mlx5.
  The XDP shim redirects `XDP_PASS` to a cpumap stage that frees the
  frame immediately to avoid draining the ring.
