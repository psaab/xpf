# #1545 — Eliminate cross-worker mirror clone heap allocation

## Status

DRAFT v1 — pending adversarial plan review.

## Issue framing

`userspace-dp/src/afxdp/mirror.rs` currently materialises a heap `Vec<u8>`
on every cross-worker mirror clone. The producer worker calls
`frame.to_vec()`, wraps it in `TxRequest { bytes, … }`, and pushes
the request through the MPSC redirect inbox to the target binding's
owner worker. The owner drains the inbox, copies `req.bytes` into a
UMEM TX frame, and drops the `Vec<u8>` — which means the `dealloc`
of the producer-side `Vec` happens on the consumer's core, the
classic cross-core free pattern.

Same-worker mirroring already runs allocation-free: it reserves a
TX frame from the target binding's `free_tx_frames` and copies into
the UMEM slab in place. The issue asks cross-worker to converge on
the same zero-allocation discipline.

Exact allocation sites (file:line, head SHA on this branch):

- `userspace-dp/src/afxdp/mirror.rs:164`
  inside `enqueue_sampled_mirror_clone` →
  `frame.to_vec()` argument to `enqueue_admitted_mirror_clone_to_live`.
- `userspace-dp/src/afxdp/mirror.rs:272`
  inside `enqueue_mirror_clone_to_live` →
  `frame.to_vec()` argument to `enqueue_admitted_mirror_clone_to_live`.
- `userspace-dp/src/afxdp/mirror.rs:356`
  inside `enqueue_sampled_mirror_clone_to_live` →
  `frame.to_vec()` argument to `enqueue_admitted_mirror_clone_to_live`.

All three feed `enqueue_admitted_mirror_clone_to_live` (mirror.rs:295)
which builds a `TxRequest { bytes: Vec<u8>, … }` and pushes via
`PendingTxAdmission::enqueue_owned` (umem/mod.rs:554) onto the
`MpscInbox<TxRequest>` field `pending_tx` of `BindingLiveState`.

The owner consumes via `take_pending_tx_into`
(umem/mod.rs:1306) which drains the inbox into
`pending_tx_local: VecDeque<TxRequest>`, then `transmit_prepared_batch`
(tx/transmit.rs:146) does the final `frame.copy_from_slice(&req.bytes)`
into a UMEM TX slot and drops the `Vec`.

## Honest scope / value framing

Mirroring is opt-in operational telemetry; in production the rate is
typically sampled (e.g. 1-in-100, 1-in-1000), so the cross-worker
mirror path is NOT the global hot path. The heap allocation churn is
real but bounded by `MIRROR_PENDING_LIMIT = TX_BATCH_SIZE = 64`
in-flight requests per binding.

Per-mirror-clone overhead being eliminated (rough estimates on x86-64,
glibc malloc, frame size ≈ 1500 bytes):

- One `malloc(1500)` on the producer worker (~50-100 ns sampled,
  worst-case allocator slow path several µs).
- One `memcpy(1500)` into the freshly-allocated buffer (this stays —
  we still need to copy off the RX descriptor, since the RX frame is
  recycled back to the FILL ring after the producer returns).
- One `free(1500)` on the consumer worker (cross-core free path),
  same magnitude as the malloc and tends to hit allocator cache
  invalidation on the producer side that originally allocated.
- Allocator metadata write traffic on whatever heap region the malloc
  lands in, which is shared across all producer workers running on
  different cores — this is the variance-injecting bit that mirror
  shares with the pre-#706 mutex inbox era.

Total expected gain at 1 Mpps mirror rate (a very high sampled mirror
load): ~150 ns × 1e6 = ~150 ms of CPU saved per second per producer
worker, plus reduced allocator contention across workers.

At sampling rates closer to production (1-in-1000 of a 10 Gbps stream
≈ 10 Kpps), the absolute saving is ~1.5 ms/s of CPU. The variance and
latency-jitter properties of removing cross-core free traffic are
probably the more important wins than the raw cycles.

**If reviewers conclude the perf gain is too small to justify the
churn (lifetime complexity, pool sizing risk, schema disturbance),
PLAN-KILL is an acceptable verdict.** The single mitigating factor
is that mirror is the last documented heap-alloc producer on a
per-packet TX path in `userspace-dp`; once it's gone, the inbox is
fully zero-alloc and we can audit-prove that.

## What's already shipped / partially batched

- The MPSC redirect inbox is lock-free (#706) and the admission gate
  (`try_acquire_pending_tx_admission`) provides linearisable soft-cap
  semantics (`umem/mod.rs:1256`).
- `MIRROR_PENDING_LIMIT = TX_BATCH_SIZE` (mirror.rs:4) caps mirror
  in-flight per binding at 64 — separate from the `max_pending_tx`
  general inbox soft cap.
- Same-worker mirroring already uses zero-alloc UMEM-slab copy
  (`enqueue_mirror_clone_to_binding`, mirror.rs:172). The bytes are
  copied straight into the target binding's reserved TX frame and a
  `PreparedTxRequest { offset, len, … }` is pushed onto
  `tx_pipeline.pending_tx_prepared` — no `Vec` involved.
- Mirror drop counter taxonomy is already split into
  `NoBinding / NoFrame / TxFrameReserve / QueueFullSameWorker /
  QueueFullCrossWorker` (mirror.rs:6-14) and surfaced through
  `record_mirror_clone_result` (mirror.rs:376).

## Concrete design

**Chosen approach: a bounded reusable byte-buffer pool owned by
`BindingLiveState`** (Option 2 from the issue body), with a new
`PooledMirrorBuf` smart-pointer that returns itself to the pool on
drop.

Rationale for choosing Option 2 over the other two:

- Option 1 ("reserve a TX frame from the target worker before copying")
  requires the producer to manipulate the target worker's `free_tx_frames:
  VecDeque<u64>`, which is a single-writer (owner) structure on
  `BindingWorker`, not on `BindingLiveState`. Making it MPSC would
  re-introduce cross-core contention in the very place the lock-free
  inbox was supposed to eliminate, plus the producer would have to
  call `slice_mut_unchecked` on the target's UMEM area — which is
  Arc-shared but writes to a TX-frame slot must not race with the
  owner's `transmit_prepared_batch` writing to a different slot in
  the same UMEM area. Actually safe (no aliasing) but the owner's
  recycle path (`free_tx_frames.push_back`) becomes MPSC which means
  another lock-free queue. Two queues per binding is more complexity
  than the alloc churn warrants.
- Option 3 ("extend pending TX admission so it can carry an owned
  UMEM frame") fundamentally has the same constraint as Option 1 —
  the UMEM frame ownership lives on the owner side, so the producer
  has to claim it across cores.
- Option 2 keeps the owner's UMEM allocator single-writer (no change
  to `free_tx_frames` semantics), only changes the byte buffer holding
  the in-transit copy, and is a strict superset of the same-worker
  zero-alloc property: both paths now do a single copy into a
  pre-allocated buffer (UMEM frame for same-worker, pool buffer for
  cross-worker), with no allocator involvement.

### Types

In `userspace-dp/src/afxdp/umem/mod.rs` (or a new
`userspace-dp/src/afxdp/mirror_buf_pool.rs` if the module hits the
2000-LOC ceiling — TBD during implementation):

```rust
/// Bounded ring of pre-allocated mirror buffers per `BindingLiveState`.
/// Each slot stores a `Vec<u8>` pre-allocated to `tx_frame_capacity()`
/// (4096 bytes). The slot's `Vec` length is reset to the in-flight
/// frame's size on acquire and reset to 0 on release. The `Vec`
/// itself is never re-allocated — only `set_len` / `extend_from_slice`
/// touch the buffer.
///
/// Capacity is `MIRROR_PENDING_LIMIT`, matching the existing
/// admission-gate soft cap; the pool can never block under correct
/// callers because admission gates ahead of pool acquire.
pub(in crate::afxdp) struct MirrorBufPool {
    /// Lock-free free-slot index queue. Producers pop indices, the
    /// `PooledMirrorBuf::Drop` path pushes them back.
    free_indices: MpscFreeRing,
    /// Per-slot storage. `UnsafeCell` because the indexed buffer is
    /// owned by exactly one thread at a time: the producer that
    /// popped the index, then transferred to the consumer that pops
    /// the request from the redirect inbox.
    slots: Box<[UnsafeCell<Vec<u8>>]>,
}

/// Owned handle to one pool slot. Drop returns the slot to the
/// pool's free ring; both producer (admission-fail unwind) and
/// consumer (post-copy normal path) drop this.
pub(in crate::afxdp) struct PooledMirrorBuf {
    pool: Arc<MirrorBufPool>,
    slot_index: u32,
}
```

The free-ring is a u32-payload MPSC ring (single-consumer release
side from producer's admission-fail unwind is acceptable as MP because
the free pool itself is MPMC-shaped — multiple producers may push back
slot indices, multiple producers may pop). We can reuse the
`MpscInbox` algorithm but with `T = u32` and rename it to a MP-friendly
ring; or use a fixed-size lock-free Treiber stack of indices.
**Decision deferred to implementation: prefer the simplest correct
primitive, likely a `crossbeam::queue::ArrayQueue<u32>` from the
`crossbeam-queue` crate** — it's an established lock-free MPMC ring
that the codebase already pulls in transitively via `crossbeam-utils`.

(Open question 1, see below: is the dep already in `Cargo.toml`? If
not, prefer extending `MpscInbox` to MPMC over adding a new crate.)

### Schema change to `TxRequest`

The cleanest fit is to make `TxRequest.bytes` carry a `MirrorBytes`
enum so non-mirror callers keep their existing `Vec<u8>` shape and
mirror callers carry a pooled handle:

```rust
pub(in crate::afxdp) enum TxBytes {
    /// Heap-owned byte vector; existing schema for non-mirror callers.
    Owned(Vec<u8>),
    /// Pooled cross-worker mirror buffer. The owner worker copies out
    /// of `as_slice()` and drops the handle to recycle the slot.
    PooledMirror(PooledMirrorBuf),
}

impl TxBytes {
    #[inline]
    pub(in crate::afxdp) fn as_slice(&self) -> &[u8] { … }
    #[inline]
    pub(in crate::afxdp) fn as_mut_slice(&mut self) -> &mut [u8] { … }
    #[inline]
    pub(in crate::afxdp) fn len(&self) -> usize { … }
}
```

Then `TxRequest.bytes: TxBytes` (was `Vec<u8>`). All call sites that
do `&req.bytes` (a `&Vec<u8>` deref'd to `&[u8]`) work unchanged
because `TxBytes::as_slice` returns `&[u8]` — but they need to be
updated from `&req.bytes` to `req.bytes.as_slice()`. That's a
mechanical change across ~10 call sites.

The owner's transmit path becomes (in tx/transmit.rs around line 146):

```rust
frame.copy_from_slice(req.bytes.as_slice());
```

The drop of `req` then drops `TxBytes::PooledMirror`, which returns
the slot to the pool. Zero alloc per mirror packet.

### Producer flow change

`enqueue_admitted_mirror_clone_to_live` becomes:

```rust
pub(in crate::afxdp) fn enqueue_admitted_mirror_clone_to_live(
    admission: PendingTxAdmission,
    config: MirrorRuntimeConfig,
    frame: &[u8],                       // was: Vec<u8>
    meta: ForwardPacketMeta,
    flow_key: Option<&SessionKey>,
    cos_queue_id: Option<u8>,
) -> MirrorCloneResult {
    if frame.len() > tx_frame_capacity() {
        return MirrorCloneResult::NoFrame;
    }
    // Acquire a pool slot from the target binding's mirror buf pool.
    let pool = admission.mirror_buf_pool();
    let Some(mut buf) = pool.try_acquire(frame.len()) else {
        // Pool full at the same logical instant the admission gate
        // accepted us — extremely rare since pool capacity matches
        // the admission cap, but possible if frees haven't propagated
        // through the lock-free queue yet. Map to QueueFullCrossWorker
        // so operators see consistent attribution.
        return MirrorCloneResult::QueueFullCrossWorker;
    };
    buf.as_mut_slice().copy_from_slice(frame);
    let req = TxRequest {
        bytes: TxBytes::PooledMirror(buf),
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: flow_key.cloned(),
        egress_ifindex: config.output_ifindex,
        cos_queue_id,
        dscp_rewrite: None,
        mirror_clone: true,
    };
    admission
        .enqueue_owned(req)
        .map(|_| MirrorCloneResult::Enqueued)
        .unwrap_or(MirrorCloneResult::QueueFullCrossWorker)
}
```

The three producers (`enqueue_sampled_mirror_clone`,
`enqueue_mirror_clone_to_live`, `enqueue_sampled_mirror_clone_to_live`)
all stop passing `frame.to_vec()` — they pass `&[u8]` straight through.

### Pool lifecycle

- Allocated lazily in `BindingLiveState::new()` (umem/mod.rs:575)
  with capacity `MIRROR_PENDING_LIMIT`. Pre-allocates 64 ×
  `Vec::with_capacity(tx_frame_capacity())` = 64 × 4 KiB = 256 KiB per
  binding. At 256 bindings worst case that's 64 MiB across the whole
  dataplane — comparable to UMEM sizing.
- The pool's `Arc` is held by `BindingLiveState` (one) and by each
  in-flight `PooledMirrorBuf` (at most `MIRROR_PENDING_LIMIT`).
- On `BindingLiveState::drop`, the pool's `Arc` is released; any
  in-flight handles will outlive the live state as long as the
  consumer worker still has the `TxRequest` in `pending_tx_local`.
  The handle's `Drop` will call `pool.free_indices.push(idx)` and
  the pool will be reaped when the last handle drops. This requires
  `MirrorBufPool` itself to be `Arc<MirrorBufPool>`, which is the
  shape declared above.

### Memory layout

`PooledMirrorBuf` is 16 bytes (`Arc<MirrorBufPool>` = 8, `slot_index: u32` = 4,
+ 4 padding). That's smaller than `Vec<u8>` (24 bytes: ptr + len + cap).
So `TxBytes::PooledMirror` is at most as large as `TxBytes::Owned`. The
discriminant adds 8 bytes total — `TxBytes` is 32 bytes (vs the 24
`Vec<u8>` was). `TxRequest` grows by 8 bytes.

This is acceptable: `TxRequest` is queue payload, not per-packet
state on a fast-path stack, and the size delta is one cache line —
nothing.

## Public API preservation

Methods that must keep their signatures (external callers depend on
them — there are no module-external callers since these are all
`pub(in crate::afxdp)`, but the call sites internal to `afxdp` are
broad):

- `enqueue_mirror_clone` — outer entry point, signature unchanged
  (frame stays `&[u8]`).
- `enqueue_sampled_mirror_clone` — outer sampled variant, signature
  unchanged.
- `enqueue_mirror_clone_to_live` — signature unchanged (frame stays
  `&[u8]`).
- `enqueue_sampled_mirror_clone_to_live` — signature unchanged.
- `admit_mirror_clone_to_live` — signature unchanged.
- `record_mirror_clone_result` — signature unchanged.
- `MirrorCloneResult` enum — variants unchanged; values still map
  1:1 to existing drop counters.
- `MIRROR_TX_FRAME_RESERVE` const — unchanged.
- `PendingTxAdmission::enqueue_owned` — signature changes from
  `(TxRequest)` to `(TxRequest)` (no change at type level; what
  changes is the internal `TxRequest.bytes` field type).
- `BindingLiveState::take_pending_tx_into` — signature unchanged
  (`&mut VecDeque<TxRequest>`).
- `BindingLiveState::enqueue_tx`, `enqueue_tx_owned`,
  `try_enqueue_tx_owned` — signatures unchanged; callers continue to
  build `TxRequest { bytes: TxBytes::Owned(vec), … }`.

Non-mirror call sites that construct `TxRequest { bytes: vec_u8, … }`
(coordinator/inject.rs, tunnel.rs, cos/cross_binding.rs,
tx/dispatch.rs, tx/test_support.rs, multiple test files) need
mechanical updates: `bytes: vec` → `bytes: TxBytes::Owned(vec)`. The
`PreparedTxRequest::to_local_request` helper (types/tx.rs:98) also
needs updating to wrap its `bytes: Vec<u8>` parameter.

The `apply_dscp_rewrite_to_frame(&mut req.bytes, …)` call in
tx/transmit.rs:111 needs `&mut req.bytes.as_mut_slice()` —
`PooledMirrorBuf::as_mut_slice` returns `&mut [u8]` so DSCP rewrite
still works on mirror clones. (Critical: DSCP rewrite on mirror
clones is a real path — mirror_clone packets can carry
`dscp_rewrite: Some(...)` when the CoS config requests it. The
plan assumes the rewrite happens on the pool buffer, not the source
RX frame. Need to verify this is correct semantics.)

## Hidden invariants the change must preserve

1. **Side-effect ordering**: `record_mirror_clone_result` is called
   AFTER the enqueue attempt resolves. The pool-acquire failure path
   maps to `QueueFullCrossWorker`, which already exists in the
   counter taxonomy. No new ordering risk.
2. **Allocation rules on the per-packet path**: the goal is to remove
   the existing alloc, not just shift it. The pool buffers must be
   pre-allocated at pool construction, never grown after.
   Specifically: `buf.as_mut_slice()` must operate on the pre-existing
   backing storage of the pooled `Vec<u8>` without ever calling
   `Vec::reserve` or `Vec::push`. We'll enforce this with a
   wrapper that exposes `as_mut_slice(len)` which calls
   `self.vec.set_len(len)` (with debug-asserted `len <= capacity`).
3. **HA sync portability**: mirror packets don't participate in HA
   session sync; mirror state is local to the dataplane. No
   sync-protocol change.
4. **Stale-handle hazards**: dropping a `PooledMirrorBuf` after the
   `MirrorBufPool` is itself dropped must not panic or leak. The
   `Arc<MirrorBufPool>` shape inside the handle keeps the pool
   alive as long as any handle exists, so this is naturally safe.
5. **Lifetime / borrow shape**: the producer passes a `&[u8]` from
   the RX descriptor; the source frame is recycled on producer
   return. Our copy into `PooledMirrorBuf` happens BEFORE the
   producer returns, so source-frame recycle is safe. The pooled
   buffer is owned by the `TxRequest` for the duration of its
   journey through the inbox; the consumer drops the request
   (and thus the buffer) AFTER copying into UMEM. No use-after-free.
6. **Cross-binding ordering preservation**: mirror requests are
   already not ordering-coupled with the original packet's TX
   path — they go to a separate egress interface. So the change
   does not perturb the per-flow ordering of either the original
   or the mirrored stream.
7. **CoS queue selection / mirror_clone identity**: `cos_queue_id`
   and `mirror_clone: true` are unchanged on the `TxRequest`. The
   owner's TX path still routes mirror clones through the same
   `MIRROR_TX_FRAME_RESERVE` reserve check in
   `transmit_prepared_batch` (tx/transmit.rs:102).
8. **Counter taxonomy**: `mirror_drops_*` counters keep their
   exact meanings; the new pool-exhaustion path maps to the
   existing `mirror_drops_queue_full_cross_worker` counter.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Counters preserved 1:1, frame contents byte-identical, no schema change visible outside `afxdp`. |
| Lifetime / borrow-checker | MED | `TxBytes::PooledMirror` introduces a new `Drop` impl that touches an `Arc<MirrorBufPool>`. Most risk is in the unsafe interior — UnsafeCell access from producer + consumer must be ordered correctly. Plan: keep the inbox as the ordering primitive (Release on push, Acquire on pop already exist), so buffer hand-off naturally piggybacks on the existing release/acquire pair. |
| Performance regression | LOW-MED | The pool free-ring is lock-free MPMC, slightly more contended than the per-binding `pending_tx` MPSC inbox (multiple workers can push and pop). At 64-slot capacity and mirror sample rates ≤ 1 Mpps, contention is bounded. **Worst case to verify**: 12 producer workers all mirroring to the same target binding at peak — pool free-ring CAS contention. Plan: add a focused microbench (criterion or simple Instant-based) that mirrors 1M frames cross-worker and measures cycles per mirror op vs `master`. |
| Architectural mismatch | LOW | This is exactly what same-worker mirroring already does, just with a buffer that lives in `BindingLiveState` instead of in `BindingWorker.umem`. Pattern is established and Codex has signed off on equivalent designs in #964 (slab) and #946 (poll_stages). The risk is if reviewers conclude the pool is overkill vs just letting the existing path keep its `Vec` — that's a valid PLAN-KILL path. |

## Test plan

Gates that must pass before merge:

1. **cargo build clean**, including `cargo check --tests`.
2. **cargo test --release**: full userspace-dp suite (952+ tests).
3. **5/5 flake check** on the most-affected named tests:
   - `afxdp::mirror::tests::cross_worker_live_enqueue_preserves_full_frame`
   - `afxdp::mirror::tests::live_mirror_queue_full_drops_before_enqueue`
   - `afxdp::mirror::tests::sampled_cross_worker_enqueue_records_counter`
     (named test from the existing suite — verify exact name during
     implementation; fall back to nearest sampled-mirror test).
4. **Go suite**: `go test ./...` (30 packages) — should be unaffected
   but confirm.
5. **New regression tests** added in this PR (per acceptance
   criterion 3):
   - `pool_acquire_succeeds_when_admission_gate_admits` — the pool
     never starves on the happy path.
   - `pool_recycles_after_consumer_drops_request` — drop a
     `TxRequest::PooledMirror`, confirm the slot index returns to
     the free ring.
   - `cross_worker_clone_zero_alloc_when_pool_warm` — instrument
     with a counting allocator (or `cap` allocator) and verify zero
     `alloc` calls on the producer side for the second-and-onward
     mirror packets to the same target.
   - `queue_full_cross_worker_drops_counter_increments_under_pool_exhaustion`
     — force pool exhaustion (e.g. via test-only API holding handles)
     and verify the right counter increments.
   - `no_frame_drop_when_frame_exceeds_tx_capacity` — preserved
     from existing coverage.
   - `tx_frame_reserve_drop_preserved` — same-worker path keeps
     its drop counter.
6. **Smoke matrix** on `loss:xpf-userspace-fw0/fw1` per the standing
   30-cell smoke matrix (Pass A CoS-disabled + Pass B per-class
   CoS, v4+v6, push+reverse). Skipped per skill args
   (AWAITING-BATCH-MERGE).
7. **Optional perf evidence**: focused Rust microbench that times
   `enqueue_mirror_clone_to_live` over 1M iterations with the same
   target binding, comparing `master` vs the PR head. Goal: confirm
   the cycles-per-op delta is non-negative (faster or equal) and
   that the `alloc` count drops to zero after pool warmup. If a
   bench harness isn't already present, build one in
   `userspace-dp/benches/mirror_clone.rs` (criterion). If criterion
   isn't already a dev-dep, use a plain `std::time::Instant` loop
   with `--release`. Acceptable to ship without if reviewers find
   the design self-evidently zero-alloc.

## Out of scope (explicitly)

- **Non-mirror TX paths' `Vec<u8>` allocations**:
  `coordinator/inject.rs:233`, `tunnel.rs:101`, `cos/cross_binding.rs`
  redirect, `tx/dispatch.rs` redirect-on-overflow paths all build
  `TxRequest { bytes: Vec<u8>, … }`. These are slow paths
  (exceptions, tunnels, CoS-redirect-on-overflow) and not part of
  #1545's scope. The `TxBytes::Owned` variant exists exactly to
  let them stay heap-backed without forcing a pool sizing decision
  on every TX caller.
- **Pool sizing tuning**: 64 slots × 4096 bytes is the proposed
  initial sizing. Operator tuning knob is deferred — if it ever
  matters, a follow-up issue can expose it.
- **Multi-target mirror fanout**: one mirror clone per packet,
  unchanged. The pool is per-target-binding, so 12 targets ×
  256 KiB = 3 MiB worst case; acceptable.
- **Eliminating the producer-side memcpy**: the copy off the RX
  descriptor stays — the RX frame returns to FILL when the producer
  exits. We can't share a reference across the inbox boundary.

## Open questions for adversarial review

1. **Pool sizing**: 64 slots × 4096 bytes per binding × N bindings.
   Is the per-binding 256 KiB overhead acceptable, or should the
   pool be sized smaller (e.g., 16 slots, dropping cross-worker
   peak burst to 16) and let admission-gate drop the rest?
2. **TxBytes enum vs separate field**: would reviewers prefer a
   separate `TxRequest.pooled_buf: Option<PooledMirrorBuf>` field
   over the enum, so non-mirror callers literally don't touch a new
   type? The enum is more idiomatic but touches every call site.
3. **Free-ring primitive choice**: should we add `crossbeam-queue`
   as a dep (well-trodden, dual-licensed) or extend the existing
   `MpscInbox` algorithm to MPMC pop? Extending MpscInbox is more
   code; using crossbeam is more crates.
4. **DSCP rewrite on mirror clones**: `apply_dscp_rewrite_to_frame`
   currently writes into the `Vec<u8>` carried by the request. With
   pool buffers, this still works (write into the pool buffer's
   slice), but does mirror semantics actually want DSCP rewrite on
   the cloned stream? It happens today via `cos_queue_id` resolution
   in `mirror_cos_queue_id`. Preserving the existing behaviour is the
   safe call.
5. **Worth the churn?**: if the absolute saving at production mirror
   rates (1-in-1000 sample) is ~1.5 ms/s, is the design churn
   (~20 call-site updates, one new pool type, schema enum change)
   justified? PLAN-KILL is acceptable if the reviewers conclude
   it isn't.
6. **`PooledMirrorBuf` Drop on consumer side — Sync concern**: the
   producer pops the slot index and writes into the slot via
   UnsafeCell; the inbox push is a Release; the consumer's inbox
   pop is an Acquire and reads the slot via the request's deref.
   Is the slot-index push-back on Drop (which happens on the
   consumer worker) safely visible to a future producer attempt on
   that same slot? The free-ring's own Release on push + Acquire on
   pop should cover this, but let's confirm explicitly.
7. **Pool draining on shutdown**: when `BindingLiveState` is dropped
   (binding torn down), any in-flight `PooledMirrorBuf` keeps the
   pool alive. The consumer worker may still be holding those
   `TxRequest`s in `pending_tx_local` if shutdown raced with drain.
   The current design uses `Arc` so this is safe, but is the small
   leak window (until the consumer drains and drops) acceptable?
   Yes — this is the same shape as the existing `Arc<BindingLiveState>`
   itself.
