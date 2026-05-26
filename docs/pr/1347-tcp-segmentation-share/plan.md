# Plan — #1347: share one TCP segmentation algorithm between two emission strategies

**Status:** DRAFT v1 — pending adversarial plan review.

## 1. Issue framing

Two near-twin functions implement userspace TCP fragmentation when the
forwarded payload exceeds the egress MTU:

- `userspace-dp/src/afxdp/frame/tcp_segmentation.rs::segment_forwarded_tcp_frames_from_frame`
  — 307-LOC body, 6 params, emits `Vec<Vec<u8>>`. Handles native GRE
  encapsulation. Used as the **fallback path** in
  `tx/dispatch.rs` when the fast path is unavailable, and exclusively
  by `tests.rs` (≥ 6 named tests via the `segment_forwarded_tcp_frames`
  `XdpDesc` adapter).
- `userspace-dp/src/afxdp/tx/tcp_segmentation.rs::segment_forwarded_tcp_frames_into_prepared`
  — 281-LOC body, 16 params, emits segments straight into a binding's
  `pending_tx_prepared` queue from UMEM-owned frames. **Bails on
  tunnel endpoints** and is the **fast path** call site in
  `tx/dispatch.rs:285`.

Both functions share the same control flow: validate → parse TCP
header → compute MSS-derived plan → loop emitting per-segment headers
+ checksum updates. They have already drifted in three concrete ways
that bite at review time:

1. **Tunnel handling.** `frame/` invokes
   `native_gre_inner_mtu(forwarding, decision)` and wraps each emitted
   slice in `encapsulate_native_gre_frame(...)`. `tx/` returns `None`
   immediately when `tunnel_endpoint_id != 0`.
2. **L4 checksum strategy.** `frame/` has a sophisticated **incremental
   adjust** path (`checksum16_adjust` over per-segment IP/port deltas)
   when `expected_ports.is_none()`, with `recompute_l4_checksum_ipv4`
   only when port enforcement modified the header. `tx/` always does
   the full recompute.
3. **MTU lookup.** `frame/` falls back to `native_gre_inner_mtu` for
   tunnel paths; `tx/` only looks at the egress map.

#1166 already extracted these two functions from larger files
(`tx/dispatch.rs` and `frame/mod.rs`); the relocation is good but the
bodies are still god-functions and they will continue to drift.

## 2. Honest scope/value framing

This is a **drift-prevention refactor**, not a perf refactor. The
absolute-scale cost of the existing duplication is roughly:

- ~280 LOC duplicated algorithm. Maintenance cost: every fix to one
  side needs a mirror review of the other (we've already missed this
  once — the checksum-strategy divergence is undocumented).
- 16-param signature is well past the project's 8-param refactor cue,
  and the param cluster (`worker_id`,
  `worker_commands_by_id`, `post_recycles`, `now_ns`, `target_binding`)
  is structurally a context, not free arguments.

Perf claim: **zero hot-path effect**. The shared algorithmic core
must compile to identical machine code on both call sites (verified
via `#[inline(always)]` plus byte-identical-output golden vectors).

If reviewers conclude the maintenance win is too small to justify the
churn (in particular the byte-equality risk), **PLAN-KILL is an
acceptable verdict**.

## 3. What's already shipped / partially batched

- **#1046** — original TCP segmentation extraction into the two
  separate files (still living at `frame/tcp_segmentation.rs` &
  earlier in `tx/dispatch.rs`).
- **#1166** — relocation of the `tx/`-side body from
  `tx/dispatch.rs` into the dedicated `tx/tcp_segmentation.rs`,
  plus `#[cold]` annotation. **No body consolidation happened in
  #1166.**
- **`frame/checksum.rs`** — already exports `checksum16`,
  `checksum16_adjust`, `recompute_l4_checksum_ipv4`,
  `recompute_l4_checksum_ipv6`, `ipv4_words`,
  `apply_nat_ipv4/ipv6`. All shared helpers exist; the consolidation
  is purely structural.
- **`frame/tcp_tests.rs`** (575 LOC) — exists at `frame/` but is
  scoped to non-segmentation TCP helpers (clamp_tcp_mss). Segmentation
  tests live at `frame/tests.rs:3308+` via the `XdpDesc` adapter.

## 4. Concrete design

### 4.1 Module placement

The canonical state machine lives in **`frame/`** (not a new
`afxdp/tcp_segmentation/` module).  Reasons:

1. The `frame/` variant is the more complete one — it handles tunnels;
   `tx/` is a non-tunnel-only specialisation. Asymmetric specialisations
   should be wrappers over the general kernel, not co-equal siblings.
2. All the shared helpers (`checksum16_adjust`, `recompute_l4_*`,
   `apply_nat_*`, `frame_l3_offset`, `frame_l4_offset`,
   `live_frame_ports_from_meta_bytes`, `write_eth_header_slice`,
   `enforce_expected_ports`) are already at `frame::` visibility. The
   `tx/` variant already reaches into them via `use super::*`. Moving
   the core to `tx/` would require widening 8+ helper visibilities.
3. Test gravity: existing segmentation tests in `frame/tests.rs` are
   already wired to `frame/` symbol paths.

Reject (with rationale): a new `afxdp/tcp_segmentation/` sibling
module. That would split the algorithm from its closest helpers and
force visibility-widening for 8+ existing private items.

### 4.2 Layout

```
userspace-dp/src/afxdp/frame/tcp_segmentation.rs   # canonical core
  pub(super) struct SegmentationPlan { ... }
  pub(in crate::afxdp) fn build_segmentation_plan(...) -> Option<SegmentationPlan>;
  #[inline(always)]
  pub(in crate::afxdp) fn segment_one<E: SegmentEmitter>(
      plan: &SegmentationPlan,
      frame: &[u8],
      decision: &SessionDecision,
      meta: ForwardPacketMeta,
      apply_nat: bool,
      vlan_id: u16,
      enforced_ports: Option<(u16,u16)>,
      data_offset: usize,
      emitter: &mut E,
  ) -> Result<(), SegmentationError>;
  // Existing public wrappers, byte-for-byte identical output:
  pub(in crate::afxdp) fn segment_forwarded_tcp_frames_from_frame(...) -> Option<Vec<Vec<u8>>>;
  pub(in crate::afxdp) fn segment_forwarded_tcp_frames(...) -> Option<Vec<Vec<u8>>>;  // XdpDesc adapter

userspace-dp/src/afxdp/tx/tcp_segmentation.rs
  pub(super) fn segment_forwarded_tcp_frames_into_prepared(ctx: SegIntoPreparedCtx) -> Option<(u32, u64, u32)>;
  // Body: build plan via frame::build_segmentation_plan, reserve UMEM frames,
  // for each segment call frame::segment_one with a PreparedEmitter.
```

### 4.3 Shared `SegmentationPlan` (pure data, no allocations)

```rust
pub(super) struct SegmentationPlan {
    // Parser outputs — frozen once.
    pub eth_len: usize,
    pub ip_header_len: usize,
    pub tcp_offset: usize,     // TCP offset relative to L3 (== ip_header_len)
    pub tcp_header_len: usize,
    pub segment_payload_max: usize,
    pub data_off_in_payload: usize, // tcp_offset + tcp_header_len
    pub data_len: usize,
    pub original_seq: u32,
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub vlan_id: u16,
    pub ether_type: u16,
    pub apply_nat: bool,
    pub addr_family: i32,
    pub protocol: u8,
    pub meta_flags: u8,
    pub mtu: usize,            // resolved (with native_gre_inner_mtu for tunnel)
    pub tunnel_endpoint_id: u32,
    pub segment_count: usize,  // data_len.div_ceil(segment_payload_max)
}
```

Plan construction returns `Option<SegmentationPlan>`; all the early
returns currently scattered across both functions move into
`build_segmentation_plan`. Plan is `Copy`-free but is consumed by
emit-loop callers via `&SegmentationPlan` (no ownership transfer).

### 4.4 The emitter trait

To preserve **byte-identical** output, the emitter abstracts the
**only** per-segment difference: where the output buffer comes from
(`Vec<u8>` vs UMEM slice) and what happens after the buffer is
written (push to `out` vs push to `pending_tx_prepared`). The
write-into-buffer logic itself stays in `segment_one` so both call
sites execute the same instruction sequence.

```rust
pub(super) trait SegmentEmitter {
    fn reserve(&mut self, frame_len: usize) -> Option<&mut [u8]>;
    fn commit(&mut self, frame_len: usize, is_last: bool);
    fn rollback(&mut self);  // free any partially-reserved frame
}
```

Two concrete impls:

- **`VecEmitter`** (`frame/tcp_segmentation.rs`) — owns
  `Vec<Vec<u8>>`, allocates a fresh `Vec<u8>` per reserve. Used by
  `segment_forwarded_tcp_frames_from_frame`. Post-commit, applies
  `encapsulate_native_gre_frame` if `tunnel_endpoint_id != 0` (the
  one tunnel-handling spot that today lives at the end of the
  emit loop).
- **`PreparedEmitter`** (`tx/tcp_segmentation.rs`) — borrows
  `target_binding`, reserves a UMEM frame via
  `free_tx_frames.pop_front()`, returns the slice via
  `slice_mut_unchecked`. Maintains a per-call `Vec<PreparedTxRequest>`
  staged-but-uncommitted; `rollback()` returns offsets to
  `free_tx_frames.push_front` in reverse order (preserves current
  rollback ordering exactly).

### 4.5 Param reduction via context structs

`SegIntoPreparedCtx` collapses the 16-param surface of the prepared
variant:

```rust
pub(super) struct SegIntoPreparedCtx<'a> {
    pub target_binding: &'a mut BindingWorker,
    pub frame: &'a [u8],
    pub meta: ForwardPacketMeta,
    pub decision: &'a SessionDecision,
    pub forwarding: &'a ForwardingState,
    pub apply_nat_on_fabric: bool,
    pub expected_ports: Option<(u16, u16)>,
    pub flow_key: Option<SessionKey>,
    pub cos_queue_id: Option<u8>,
    pub dscp_rewrite: Option<u8>,
    pub now_ns: u64,
    pub post_recycles: &'a mut Vec<(u32, u64)>,
    pub worker_id: u32,
    pub worker_commands_by_id: &'a BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
}
```

The Vec-emitting variant keeps its 6-param signature (already
acceptable).

### 4.6 Tunnel handling reconciliation

Current `tx/` behaviour (early bail on `tunnel_endpoint_id != 0`)
**is preserved** by `PreparedEmitter::pre_check`. The shared
`build_segmentation_plan` accepts an optional
`tunnels_supported: bool` and returns `None` early when the call site
declares no tunnel support. This keeps the wire behaviour identical:
when called from `tx/` with `tunnels_supported=false` and the
decision has a tunnel, the fast path returns None and `tx/dispatch.rs`
falls through to the Vec variant (which DOES support tunnels) at
line 320 — exactly today's behaviour.

### 4.7 Checksum strategy reconciliation

The two checksum strategies are **observably non-identical** on
IPv4: `frame/` produces incrementally-adjusted L4 checksums while
`tx/` produces full-recompute checksums. Both result in valid
on-wire packets (same correct checksum value), so this is technically
allowed divergence — **but** the byte-equality contract demands we
pick one.

**Decision: pick the `frame/` strategy (incremental adjust with
recompute fallback when ports were enforced) as canonical.**
Rationale: it's the more capable one (handles both branches); the
"always full recompute" strategy is a degenerate case
(`enforced_ports.is_some()` always). The `tx/` fast path will gain
the incremental shortcut for free — a small (~3.6% per the
file-internal comment) CPU win on the common no-port-enforcement
fabric path.

**Risk: this is a behaviour change for the `tx/` fast path.** The
output is still bit-identical to a freshly-computed checksum (because
incremental adjust is mathematically equivalent), so on-wire packets
are identical. But the instruction sequence differs from today's
`tx/` path. Byte-equality between today-`tx/` output and
post-refactor-`tx/` output must be proven by golden vectors
(see §9). If the equality fails, plan needs revision (e.g. keep both
strategies as separate emit subroutines, gated by a plan field).

### 4.8 Inlining strategy

- `build_segmentation_plan` — NOT `#[inline(always)]`. Called once
  per packet (cold-ish entry; per-large-packet rate, not per-packet
  rate). Let the optimizer choose.
- `segment_one<E>` — **`#[inline(always)]`**. Generic over `E`, called
  in a tight inner loop. We want monomorphisation at each call site
  so the per-segment write/checksum work compiles into the caller
  body (matching today's flat layout).
- `SegmentEmitter::{reserve, commit, rollback}` — **`#[inline]`**
  on trait impls. Trait method calls through monomorphised generics
  + `#[inline]` give the compiler enough freedom to fold into
  `segment_one`.
- Public wrappers `segment_forwarded_tcp_frames_from_frame`,
  `segment_forwarded_tcp_frames`,
  `segment_forwarded_tcp_frames_into_prepared` — `#[cold]` retained
  on the prepared variant (matches today). No `#[inline(always)]`
  on the wrappers; they're the call-site entries.

### 4.9 Public API preservation

The three public-from-`afxdp` symbols stay at their existing visibility
and signature:

- `pub(in crate::afxdp) fn segment_forwarded_tcp_frames_from_frame(...)
  -> Option<Vec<Vec<u8>>>` — signature **unchanged**, exported from
  `frame/tcp_segmentation.rs`.
- `pub(in crate::afxdp) fn segment_forwarded_tcp_frames(...)
  -> Option<Vec<Vec<u8>>>` — signature unchanged, XdpDesc adapter.
- `pub(super) fn segment_forwarded_tcp_frames_into_prepared(...)
  -> Option<(u32, u64, u32)>` — **signature changes**: replaces the
  16 free params with a single `ctx: SegIntoPreparedCtx<'_>`.
  Only one caller (`tx/dispatch.rs:285`); update the call site.

## 5. Hidden invariants the change must preserve

- **Side-effect ordering on rollback.** `tx/` returns staged
  offsets to `free_tx_frames.push_front(...)` in **reverse**
  iteration order via `prepared.drain(..).rev()` (3 distinct
  rollback sites — capacity check, slice_mut_unchecked failure,
  built.is_none()). `PreparedEmitter::rollback()` must preserve
  this exact ordering or the free-list's spatial-locality invariants
  (most-recently-popped is at front) drift. Verified by manual
  walk over the three rollback sites today.
- **Post-recycle drain race.** `tx/` runs `drain_pending_tx_local_owner`
  when free_tx_frames < segment_count AND there are outstanding
  tx_pipeline items. This drain must still run BEFORE the capacity
  recheck. Plan: put the drain call in
  `PreparedEmitter::pre_check_capacity(segment_count)`, invoked
  immediately after `build_segmentation_plan` so the ordering is
  preserved.
- **`bound_pending_tx_prepared` post-call.** `tx/` calls
  `bound_pending_tx_prepared(target_binding, Some(post_recycles))`
  AFTER pushing all PreparedTxRequest. Must remain post-loop.
- **No per-packet allocations beyond today's footprint.** Today
  `tx/` allocates exactly one `Vec<PreparedTxRequest>` with
  `Vec::with_capacity(segment_count)`; `frame/` allocates exactly
  one `Vec<Vec<u8>>` with `Vec::with_capacity((data.len() /
  segment_payload_max) + 1)` plus one `vec![0u8; ...]` per segment.
  The refactor must allocate **the same set**, no extra Vecs/Boxes
  introduced by the trait machinery.
- **GRE encapsulation ordering.** `frame/` calls
  `encapsulate_native_gre_frame(&frame_out, ...)` **per segment**,
  after the segment is fully built. `VecEmitter::commit()` must
  invoke encap before pushing into `out`, with the exact same
  pre-condition (tunnel_endpoint_id != 0).
- **IPv6 hop-limit guard.** `tx/` checks
  `if (meta.meta_flags & 0x80) == 0 && packet[7] <= 1` (combined);
  `frame/` checks `if (meta.meta_flags & 0x80) == 0 && packet[7] <= 1`
  too. Both bail on hop-limit-1 with no LOG-AND-DROP outside
  the function. Plan: preserve verbatim.
- **HA sync portability.** Segmentation is downstream of session
  decision; doesn't touch HA. No risk vector here.
- **Borrow-checker shape.** `segment_one<E>` borrows
  `&SegmentationPlan` immutably and `&mut E` mutably; the emitter
  borrows `target_binding: &mut BindingWorker` (PreparedEmitter)
  but the plan does NOT borrow from binding — plan is constructed
  before the emitter binds to the binding. No borrow conflict.
- **`tcp_offset` variable shadowing.** Today's `tx/` reuses
  `tcp_offset` for both the parsed TCP header offset (line 43) and
  reads through the same name inside the inner builder closure
  (`let tcp = packet.get_mut(tcp_offset..)?` line 182). With the
  plan-and-emit split, `tcp_offset` becomes a `SegmentationPlan`
  field; no name reuse.

## 6. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | **HIGH** | Byte-equality contract must hold for both call sites. Checksum-strategy reconciliation in §4.7 is the most material change to wire output (semantically same, instruction sequence different). Golden vectors are non-negotiable. |
| Lifetime / borrow-checker | MED | `PreparedEmitter` holds `&mut BindingWorker` for the duration of segment_one's inner loop. Inner loop must NOT re-borrow binding directly. `SegmentationPlan` must NOT borrow from frame slice (it copies out parsed integers + arrays for dst_mac/src_mac/etc.) — verified by avoiding `&[u8]` fields in the plan struct. |
| Performance regression | LOW (with verification) | `#[inline(always)]` on segment_one plus monomorphisation should compile to identical code as today's flat fn. Verified by `cargo asm` spot-check (segment_one inlined into both wrappers). Hot-path allocations unchanged. Smoke matrix on cluster confirms no perceptible regression. |
| Architectural mismatch | LOW | Algorithm + two emit strategies is the textbook strategy pattern. Both call sites already exist and are called today; we are not inventing a new pipeline shape. Not analogous to #946 Phase 2 (which tried to introduce a batch-iteration loop that didn't fit the order-coupled state). |

The HIGH on behaviour-regression is the gate. If byte-equality
golden vectors don't pass, the plan is wrong, not the
implementation.

## 7. Test plan

Mandatory gates before PR:

1. **Cargo build clean** —
   `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build`.
2. **Cargo full release tests** —
   `cargo test --release` — must pass all 952+ tests including the
   6 named segmentation tests in `frame/tests.rs`.
3. **5/5 named-test flake check** on the most-affected named test
   (`segment_forwarded_tcp_frames_keeps_ipv4_snat_inside_native_gre`
   — exercises the tunnel branch).
4. **Byte-equality golden vectors** (NEW). Two new tests in
   `frame/tests.rs`:
   - `segment_forwarded_tcp_frames_byte_equality_v4` — build a
     forwardable IPv4 TCP frame, call the OLD impl (preserved as a
     `#[cfg(test)]` snapshot reference) and the NEW impl. Assert
     `Vec<Vec<u8>>` equality byte-for-byte.
   - `segment_forwarded_tcp_frames_byte_equality_v6` — IPv6 variant.
   - **AND** a `PreparedEmitter`-side equivalence test in
     `tx/tcp_segmentation.rs` tests: call `into_prepared` over a
     mock binding, snapshot the `pending_tx_prepared` buffer bytes,
     compare to the corresponding Vec-emitter output, and assert
     equality modulo the checksum-strategy change (i.e. both
     checksums are valid on-wire — implemented by running the
     standard verify-against-pseudo-header oracle on each emitted
     packet).
5. **Go suite** — `go test ./...` clean.
6. **Cluster smoke** on `loss:xpf-userspace-fw0/fw1`:
   - **No per-PR smoke** for Wave-5 (per skill rule + user
     directive). Batch-merge marker is posted instead.
7. **Optional perf** — record `perf stat -e cycles,instructions`
   over a 30s iperf3 v4 push to validate no instruction-count
   regression in the `tx/` fast path. Not gating; informational.

### 7.1 Snapshot reference impl

For golden-vector tests, copy the **current** body of
`segment_forwarded_tcp_frames_from_frame` (frame/ variant) into a
`#[cfg(test)] mod legacy_reference` block at the bottom of the new
`tcp_segmentation.rs` BEFORE refactoring. Wire the golden tests to
diff `legacy_reference::segment_forwarded_tcp_frames_from_frame_v1`
against the new public symbol. Once the tests are green, the
reference block stays in-tree for the life of this PR's branch as
oracle; it can be deleted in a follow-up PR (NOT in this one — we
want the oracle present at merge so the reviewer can re-run it).

## 8. Out of scope (explicitly deferred)

- Removing `legacy_reference` block — follow-up.
- Reconciling the `tx/` checksum strategy with `frame/`'s incremental
  path **if** golden vectors fail — plan revision required, NOT
  silent fallback to keep both.
- Adding NIC-offloaded GSO/TSO — separate perf issue.
- Tunnel inner-MTU computation refactor — out.
- Touching `frame/tcp_tests.rs` MSS-clamping tests — unrelated.

## 9. Open questions for adversarial review

1. **Byte-equality contract — is the checksum-strategy reconciliation
   acceptable?** §4.7 picks `frame/`'s incremental strategy
   canonical, making `tx/`'s on-wire output bit-identical (same
   correct checksum value, different instruction sequence) but
   **different from today's `tx/` output's instruction trace**. Is
   that the right call? Alternative: keep two `emit_checksum_*`
   subroutines, dispatched by the plan field. Tradeoff: one extra
   branch per segment vs zero opportunity for divergence.

2. **`#[inline(always)]` on `segment_one<E>` — does the compiler
   actually inline?** The body is ~200 LOC after consolidation,
   well past LLVM's default inlining heuristics. Will
   `#[inline(always)]` punch through, and if it does, is the
   resulting tx/ binary actually faster or slower than today's flat
   fn? **Hostile concern: I'm claiming "compile to identical
   instructions" without a `cargo asm` proof — demand one.**

3. **Rollback ordering — is the trait machinery preserving the
   "reverse order push_front" invariant correctly?** Today there
   are 3 distinct rollback sites with carefully chosen
   `prepared.drain(..).rev()` ordering. The trait abstraction adds
   one indirection. If a future implementer of `SegmentEmitter`
   gets rollback() ordering wrong, the free-list spatial-locality
   degrades silently. **Hostile concern: should rollback be a
   guard pattern (RAII drop) instead of an explicit method, so
   wrong-impl is impossible?**

4. **Plan struct field count is large (18+).** Is that the right
   shape, or should the plan be split into "parser output" + "emit
   inputs"? The current draft is one struct; splitting could clarify
   ownership but doubles the borrow surface.

5. **Should the canonical home really be `frame/`?** It's the
   tunnel-capable variant, so naturally more general — but the
   `tx/` variant is the **hot path** (called first in
   `tx/dispatch.rs`, only falls back to `frame/` on capacity-deny).
   Hot-path code is usually expected to live in the more-visible
   spot. Counter-argument: callability matters more than visibility
   here; both wrappers are equally callable, just one is faster.

6. **Is this refactor worth the diff?** Net diff: probably +400
   LOC (new shared core + trait + tests) and -200 LOC (eliminated
   duplication). The win is a single algorithm to maintain. If
   the algorithm rarely changes in practice, the up-front cost
   doesn't amortise. **PLAN-KILL is allowed if you conclude the
   drift hasn't actually hurt us yet.**

7. **`apply_nat_on_fabric` semantics.** Today both functions check
   `disposition == FabricRedirect` and pass `apply_nat_on_fabric`
   through. The shared parser must compute the right `apply_nat`
   bool with no semantic change. **Hostile concern: walk both
   today-functions' apply_nat resolution path step-by-step and
   confirm bit-equivalence of the result.**

8. **#1166 cross-reference.** PR #1199 (#1166 implementation)
   landed `#[cold]` on `segment_forwarded_tcp_frames_into_prepared`
   — Copilot's addition. The refactor must keep `#[cold]` on the
   public wrapper. Confirm the inlined-into-call-site code retains
   the cold hint in practice.
