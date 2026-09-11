# userspace-dp/src/afxdp/umem/

UMEM (User-space Memory) management — the per-binding shared-memory
region where AF_XDP zero-copy frames live. Owns the `mmap` region,
wraps the crate-local `Umem` type from `xsk_ffi` (a libxdp-backed
drop-in for xdpilone), and tracks frame budgets per binding.

> #6436: the per-binding runtime-state cluster that historically
> lived here (`BindingLiveState`, the redirect TX inbox, the latency
> histogram primitives, the HA session-delta fallback buffer, and the
> snapshot/debug-state/profile renderers) moved to
> `../binding_state/`. This module is now only the memory region.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `WorkerUmem` / `WorkerUmemInner` / `WorkerUmemPool` — Rc-shared UMEM handle held by the owner worker, plus the free-frame pool. |
| `mmap.rs` | `MmapArea` — the raw `mmap` region. |
| `mmap_tests.rs` | Co-located mmap unit tests. |
| `tests/` | Co-located UMEM unit tests: `mod.rs` + `drop_order.rs` + `mmap_area.rs`. The binding-state concern tests moved to `../binding_state/tests/` in #6436 (the #4667 per-concern split maps 1:1 onto the new location). |

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
- **`WorkerUmemInner` field order is load-bearing (#5192).** `umem`
  is declared BEFORE `area` because Rust destroys struct fields in
  declaration order, and `xsk_ffi::Umem::new` is `unsafe` on the
  precondition that the mmap'd area outlives the `Umem`. Declared the
  other way round, `munmap` runs while the libxdp UMEM object is still
  registered against those pages — a latent use-after-free whose only
  defence is that `xsk_umem__delete` in the linked libxdp happens not
  to read the user area, which is an unpinned external library's
  implementation detail rather than an invariant this repo controls.
  Rust has no compile-time drop-order assertion, so the order is
  pinned by observation: both destructors record into
  `crate::drop_order_probe` under `cfg(test)` and
  `tests/drop_order.rs` asserts `[Umem, MmapArea]`. Swapping the two
  declarations back reds it.
- `Rc<WorkerUmemInner>` (not `Arc`) is intentional — UMEM ownership
  doesn't cross thread boundaries within the worker. The cross-binding
  redirect path in `cos/cross_binding.rs` *copies* frames into the
  destination binding's UMEM rather than sharing.
- `WorkerUmem::new_for_test` is hermetic test scaffolding paired with
  the in-memory ring fixtures in `xsk_ffi.rs`. It exists so CoS and TX
  unit tests can exercise worker-owned drain paths without creating
  kernel AF_XDP sockets; production UMEM construction remains
  `WorkerUmem::new`.
- **UNVERIFIED PREMISE (#9043), stated as fact until now.** In
  **zero-copy mode on mlx5**, an `XDP_PASS` action was claimed to
  permanently consume a fill-ring frame — the kernel holding the UMEM
  buffer in an SKB and never returning it — draining all 12K+ RX frames
  within seconds under sustained traffic.

  **Nothing in this tree corroborates that, and two independent readings
  contradict it.** `mlx5e_xsk_skb_from_cqe_linear` copies into a fresh
  SKB and reuses the UMEM frame on `XDP_PASS`; a verifier checking a
  neighbouring claim reached the same conclusion by a different route
  ("the driver builds an skb by copying out of the UMEM and then
  recycles the frame; there is no descriptor leak").

  It is left in place, marked, rather than deleted, because it cannot be
  settled from inside the repo — the decisive check is one flood test on
  a zero-copy mlx5 bind, or one read of the running kernel's
  `mlx5e_xsk_*` path. **Do not build a new argument on this sentence
  until that is done.** A claim that is steering a design decision and
  has never been measured is the reason #9043 exists; the harm is not the
  mitigation below, which is cheap and shipped, but the next decision
  someone makes on the strength of an unverified premise.

  The mitigation (#209) covers IP frames only, and only while the
  cpumap flag is set: those local-delivery paths take a cpumap redirect
  (`USERSPACE_CPUMAP`) instead of `XDP_PASS`, which frees the XSK frame
  immediately while still delivering the packet to the kernel stack.
  Two shim paths still return `XDP_PASS` (#9695):
  - every non-IP frame, through `pass_non_ip_l2_direct`, deliberately,
    because a cpumap redirect breaks ARP neighbor resolution;
  - `cpumap_or_pass`, whenever the cpumap flag is unset or the redirect
    fails.

  So if the #9043 premise holds, the mitigation does not cover those
  paths, and the non-IP arm is exactly the unrate-limited ARP/LLDP path
  #9043 was worried about. Bind flags try
  zero-copy first and fall back to copy mode if the driver doesn't
  support it; copy mode is unaffected because `XDP_PASS` there
  operates on kernel DMA buffers, not UMEM frames.
