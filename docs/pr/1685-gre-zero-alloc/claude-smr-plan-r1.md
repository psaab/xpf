# Claude-SMR hostile PLAN review — #1685 round 1

Reviewer seat: domain SMR + CPU-arch/design + SW-design-patterns (HOSTILE).
Plan: docs/pr/1685-gre-zero-alloc/plan.md @ dadcf0c4.

## Verdict: PLAN-KILL

The issue's premise — "mirror the #1433 WG zero-copy scratch, a small
mechanical fix" — is wrong against the actual data flow, and the perf
justification is unmeasured and sub-threshold. This is the #1545
pattern with worse economics. Three independently sufficient grounds:

### 1. The WG single-buffer scratch pattern does not transfer (FATAL)

Verified by reading the code end-to-end:

- Decap output `NativeGrePacket.frame` (`gre.rs:293`) becomes
  `owned_packet_frame` (`poll_descriptor/mod.rs:490`) and is moved into
  `PendingForwardFrame::Owned(Vec<u8>)` via `.take()` at
  `mod.rs:837`, `mod.rs:2245`, and `flow_cache_hit.rs:362`. The
  enclosing `PendingForwardRequest` is pushed onto
  `binding.scratch.scratch_forwards: Vec<PendingForwardRequest>` and
  consumed only at end-of-batch in `tx/dispatch/mod.rs:176-189`
  (`PendingForwardFrame::Owned(frame) => frame.as_slice()`).
- `RX_BATCH_SIZE = 64` (`afxdp/mod.rs:219`). A burst of GRE packets in
  one batch yields up to 64 owned decap frames **alive at the same
  time**. A single per-worker `decap_out` buffer (the WG `try_decap(..,
  out: &mut [u8])` shape, `wg/engine.rs:633`) would be overwritten by
  packet N+1 while packet N's forward request still references it →
  data corruption on the wire. WG is safe because it consumes its
  decap plaintext inline before advancing; GRE explicitly defers
  (the `owned_packet_frame.take()` contract, `poll_stages.rs:118-153`).
- Encap is the same: output moves into `TxRequest.bytes: Vec<u8>`
  (`tx/dispatch/mod.rs:545-546`) and is enqueued until the UMEM TX copy
  completes; TSO fans out N owned encap Vecs (`tcp_segmentation.rs:309`
  pushing onto `Vec<Vec<u8>>`).

The only sound zero-alloc shapes are (a) a per-worker **arena** of
≥64 max-frame buffers reused across batches, or (b) a **direct-TX
rewrite** that builds into UMEM with in-place offset adjustment. (a)
relocates the allocation and adds ~256 KiB/worker resident for decap
alone; (b) is a HIGH-risk control-flow change to the deferred-stage
pipeline, far beyond the issue's "mirror #1433" framing. Neither is the
fix the issue describes.

### 2. The #1433 precedent is a primitive, not a shipped integration

`WgWorkerScratch` (`wg/scratch.rs`) is constructed **only** in
`wg/tests.rs` — `grep WgWorkerScratch userspace-dp/src` shows no live
worker-poll construction. Citing #1433 as proof that "the zero-copy
pattern applies cleanly" is unsound: #1433 shipped the buffer type and
the `out: &mut [u8]` signatures, not an end-to-end hot-path
integration, and it works only because WG output is inline-consumed —
the exact property GRE lacks.

### 3. Perf is unmeasured and structurally sub-threshold (#1545)

- The decap alloc fires only for `meta.protocol == PROTO_GRE`
  (`gre.rs:186-188`); encap only for `tunnel_endpoint_id != 0`
  (`frame/mod.rs:236`, `tcp_segmentation.rs:308`). This is **not** the
  per-packet forward path.
- The loss userspace smoke target (172.16.80.200 / `::200`, reth0.80
  plain-IP forward) does not traverse GRE at all, so the project's own
  validation harness never exercises this path under load.
- No in-repo flamegraph or allocator-contention measurement shows GRE
  alloc as a hot frame; the audit asked for one and did not provide it.
- One warm small-class alloc/free per GRE packet is ~tens of ns. At
  realistic overlay rates (tens of kpps) it is below measurement
  noise; even at 1 Mpps pure-GRE it is single-digit-% of one core and
  amortizes against NAT/checksum/FIB/neighbor work the forward path
  already does. This is materially the #1545 cost/benefit, which was
  PLAN-KILLED for ~0.15%-of-a-core.

## What would change the verdict

A reviewer or the author producing a flamegraph under *pure* multi-Gbps
GRE load showing `gre.rs` alloc as a measurable hot frame, AND a sound
arena/direct-TX design whose memory and complexity cost is justified by
that measurement. Absent that, ship-it is churn-for-churn on an
unmeasured, smoke-uncovered path with HIGH wire-byte/deferred-stage
regression risk.

## Recommended disposition

Label `plan-kill` + `perf` (already present), close #1685 with the
verdict, preserve this plan + reviewer findings on the branch for the
archive. If GRE perf ever surfaces as a real bottleneck, reopen with a
measurement and an arena/direct-TX design — not a WG single-buffer
mirror.
