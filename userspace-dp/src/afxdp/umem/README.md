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
  - every non-IP frame except nested-VLAN (a still-VLAN post-unwrap
    ethertype — QinQ-double or legacy 0x9100 — is an explicit `XDP_DROP`
    with the `qinq_drop` counter since #9888), through
    `pass_non_ip_l2_direct`, deliberately, because a cpumap redirect
    breaks ARP neighbor resolution;
  - `cpumap_or_pass`, whenever the cpumap flag is unset or the redirect
    fails.

  So if the #9043 premise holds, the mitigation does not cover those
  paths, and the non-IP arm is exactly the unrate-limited ARP/LLDP path
  #9043 was worried about. Bind flags try
  zero-copy first and fall back to copy mode if the driver doesn't
  support it; copy mode is unaffected because `XDP_PASS` there
  operates on kernel DMA buffers, not UMEM frames.

## Fill-alignment contract (F-069, #9904)

The RX-recycle path pushes the RX descriptor's `addr` VERBATIM into the
FILL ring: every `scratch_recycle.push(desc.addr)` site (~30, in
`poll_descriptor/` and `neighbor_dispatch.rs`), plus shared-UMEM
`(slot, offset)` recycles, flow through `pending_fill_frames` into
`tx/rings.rs::drain_pending_fill` → `xsk_ffi::WriteFill::insert` with no
masking anywhere on the path. That `addr` is headroom-shifted: with
`UMEM_HEADROOM == 256` the kernel delivers
`desc.addr == frame_base + 256`, while the FILL ring was primed with
`frame_base` (`prime_fill_ring_offsets` feeds `Umem::frame().offset`,
already base-aligned).

This is correct ONLY because of an AF_XDP CORE contract, not a driver
quirk: in aligned-chunk mode the kernel masks FILL-ring addresses to the
chunk base on consume (`xp_check_aligned`; docs.kernel.org AF_XDP,
"aligned chunk mode"). The preconditions are pinned by construction:
`WorkerUmem::new` / `new_for_test` hardcode `flags: 0` (aligned mode,
never `XDP_UMEM_UNALIGNED_CHUNK_FLAG`) and
`frame_size == UMEM_FRAME_SIZE == 4096`. In unaligned mode the kernel
does NOT mask, so flipping `flags` without adding an explicit mask at
the fill-submit boundary would silently corrupt the fill ring — do not
do that on the strength of this section alone.

Deliberately doc-only (#9904 adjudication): production keeps relying on
the kernel mask rather than adding a per-frame AND at drain, because the
mask would be pure redundancy in aligned mode on a warmed path. The
reference harness (`test/xsk-repro/libbpf_xsk_{,shared_}test.c`,
`test/xsk-repro/main.rs`) masks explicitly
(`addr & ~(FRAME_SIZE - 1)`) before refill — defense-in-depth, and the
reason F-069 has twice been misread as a latent bug. Both shapes are
correct in aligned mode; they are now recorded as such instead of
diverging silently.
