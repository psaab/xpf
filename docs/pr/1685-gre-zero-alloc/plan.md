# #1685 — Native GRE decap/encap per-packet `Vec` elimination

**Status:** DRAFT v1 — pending adversarial plan review

## 1. Issue framing

The AGY refactor audit (agy-review-002) flagged that the native GRE
tunnel engine heap-allocates a fresh `Vec<u8>` per packet on the
datapath, violating the zero-alloc hot-path mandate in `CLAUDE.md` /
`docs/engineering-style.md` ("Never allocate per packet"):

- **Decap** — `try_native_gre_decap_from_frame` (`gre.rs:231`):
  `let mut synthetic = vec![0u8; 14 + inner_packet.len()];` per inbound
  GRE packet.
- **Encap** — `encapsulate_native_gre_frame` (`gre.rs:329`):
  `let mut out = vec![0u8; frame_len];` per outbound packet on a tunnel
  egress.

The issue proposes mirroring the #1433 WireGuard zero-copy pattern:
reuse a per-worker preallocated scratch buffer instead of a fresh `Vec`
per packet.

## 2. The actual data-flow constraint (verified — this is the crux)

Reading `gre.rs` end-to-end and walking both call sites changes the
picture materially. The GRE allocations are **not** transient scratch
that dies at the end of the helper (which is what the WG `try_encap` /
`try_decap` `out: &mut [u8]` scratch pattern requires). Both outputs
are **moved into owned, batch-lived structures**:

### Decap output is batched, not transient

`stage_native_gre_decap` (`poll_stages.rs:142`) returns the synthetic
frame as `Option<Vec<u8>>` (`NativeGrePacket::frame`). At the call site
(`poll_descriptor/mod.rs:490`) it becomes `owned_packet_frame`, which is
later **moved into `PendingForwardFrame::Owned(Vec<u8>)`**
(`mod.rs:837`, `:2245`, `flow_cache_hit.rs:362`) via
`owned_packet_frame.take()`. That request is pushed onto
`binding.scratch.scratch_forwards: Vec<PendingForwardRequest>` and is
consumed **at end-of-batch** in `tx/dispatch/mod.rs:176-189`
(`PendingForwardFrame::Owned(frame) => frame.as_slice()`).

`RX_BATCH_SIZE = 64` (`afxdp/mod.rs:219`). Up to 64 decapped GRE frames
can coexist in `scratch_forwards` simultaneously within a single batch.
**A single per-worker `decap_out` scratch buffer (the WG pattern) cannot
hold 64 live decap outputs at once** — the second decap would overwrite
the first while the first is still queued for TX. The WG `try_decap`
returns its plaintext inline and the caller consumes it before the next
packet; GRE does not.

### Encap output is also batched, not transient

`encapsulate_native_gre_frame` returns `Option<Vec<u8>>`. Both callers
move it into a batch-lived owner:

- `frame/mod.rs:237` (`build_forwarded_frame_from_frame`) — the encap
  `Vec` becomes the return value, which at `tx/dispatch/mod.rs:505-546`
  is moved into `TxRequest { bytes: frame, .. }`. `TxRequest.bytes:
  Vec<u8>` is enqueued onto the target binding's pending-TX queue and
  lives until the frame is copied into the UMEM TX ring and the TX
  completes. Many `TxRequest`s queue simultaneously.
- `frame/tcp_segmentation.rs:309` — pushes each encapsulated segment
  onto `out: Vec<Vec<u8>>`; a single TSO packet produces N owned
  encap Vecs that all coexist.

So the GRE `Vec` is not a hot-path scratch that a per-worker reused
buffer trivially replaces. It is one instance of the dataplane's
**broader owned-`Vec`-per-forwarded-frame TX architecture**. The
non-direct-TX copy path in `tx/dispatch/mod.rs` already carries an
intermediate `Vec` for every copy-mode forward (the code at
`tx/dispatch/mod.rs:583` explicitly documents a separate "Direct TX
build" path that writes into UMEM to *eliminate the intermediate Vec*,
which the GRE path does not currently use). Eliminating the GRE `Vec`
in isolation, without addressing the owned-`Vec` TxRequest model it
feeds, is a partial cut at best.

## 3. Honest scope/value framing (measure-first — the #1545 lesson)

**#1545 (mirror clone alloc elim) was PLAN-KILLED because ~0.15%-of-a-
core of alloc didn't justify the churn. The same discipline applies
here, and the numbers are arguably worse for the "ship it" case.**

### Is the GRE path on the dataplane hot path?

- The decap alloc fires **only** for packets whose `meta.protocol ==
  PROTO_GRE` (early return at `gre.rs:186-188`). It is **not** on the
  per-packet path for ordinary forwarded traffic.
- The encap alloc fires **only** when
  `decision.resolution.tunnel_endpoint_id != 0`
  (`frame/mod.rs:236`, `tcp_segmentation.rs:308`) — i.e. only for
  traffic egressing a configured native GRE tunnel.
- **The smoke target path (reth0.80 plain-IP forwarding, the iperf3
  172.16.80.200 / `::200` fast path) does not traverse GRE at all.**
  GRE is exercised only when a `tunnel` forwarding decision is made,
  which requires a configured GRE tunnel endpoint carrying production
  traffic.

GRE tunnels in this product are a routing/overlay feature. Whether GRE
is ever a *saturating* path (multi-Gbps, allocator-contended) in a real
deployment is the open question. If GRE is light/occasional overlay
traffic, the per-packet alloc amortizes against everything else the
forward path does (NAT rewrite, checksum, FIB, neighbor) and the win is
sub-threshold — **PLAN-KILL territory, exactly like #1545.**

### Per-packet alloc cost, stated honestly

Each GRE packet currently does **one** `Vec` allocation (decap: one
`synthetic`; encap: one `out`; the encap path also does a `.to_vec()`
at `gre.rs:317` for `inner_packet`, so encap is actually *two* allocs).
A glibc/jemalloc small-to-medium allocation + free is on the order of
tens of nanoseconds when the size class is warm. At, say, 1 Mpps of
*pure GRE* traffic that is ~1-3% of one core; at realistic overlay
rates (tens of kpps) it is far below measurement noise. There is **no
captured flamegraph or allocator-contention measurement** in the repo
showing GRE alloc as a hot frame (the audit explicitly asked for one
and did not provide it).

**If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable — and likely correct — verdict.**
The burden this plan must clear is: show GRE is a saturating, allocator-
contended path in a believable config, OR show the fix is cheap and
risk-free enough to be worth doing on principle. Section 5 argues the
fix is *not* cheap because of the batching constraint in Section 2.

## 4. What's already shipped / partially batched

- **#1433 WireGuard** introduced `WgWorkerScratch` (`wg/scratch.rs`)
  with `encap_out` / `decap_out` `RefCell<Vec<u8>>` buffers and
  `try_encap(.., out: &mut [u8])` / `try_decap(.., out: &mut [u8])`
  signatures (`wg/engine.rs:500,633`). **Caveat:** that scratch is
  **not yet wired into a live worker poll path** — grep shows
  `WgWorkerScratch` is constructed only in `wg/tests.rs`, never in the
  worker dispatch. The WG precedent is a *primitive*, not a
  demonstrated end-to-end integration. It works for WG because WG
  encap/decap output is consumed inline before the next packet; that
  is the property GRE lacks (Section 2).
- **Direct-TX path** (`tx/dispatch/mod.rs:583+`) already writes some
  forwarded frames directly into the target UMEM TX frame, bypassing
  the intermediate `Vec`. GRE-encapped frames do not currently take
  this path.
- `WorkerScratch` (`worker/scratch.rs:33`) holds the per-worker reused
  `Vec` batch buffers (`scratch_forwards`, etc.) but none for raw frame
  bytes.

## 5. Candidate designs and why each is hard

### Option A — single per-worker `gre_decap_out` / `gre_encap_out` scratch (the issue's literal proposal)

**Does not work for decap.** Per Section 2, up to 64 decap outputs
coexist in `scratch_forwards` within one batch. A single reused buffer
would be aliased/overwritten. Would require either (a) one scratch slot
per batch index — i.e. a `Vec` arena of 64 max-frame buffers reused
across batches, which is just relocating the allocation, not removing
it, and adds 64 × 4096 = 256 KiB per worker of resident memory; or
(b) restructuring decap to be consumed inline before the forward
request is built, which is a control-flow rewrite of the deferred
flow-cache / session-hit / missing-neighbor stages that the
`owned_packet_frame.take()` contract (documented at `poll_stages.rs:118-153`)
explicitly depends on.

**Marginal for encap.** Encap output is moved into `TxRequest.bytes`.
A scratch buffer only helps if the encap result is copied into UMEM
*before* the next encap — but the copy-mode TX path enqueues the
`TxRequest` and defers the UMEM copy. Reusing one buffer here is the
same aliasing hazard as decap.

### Option B — extend decap/encap into UMEM TX frames (direct-TX) for GRE

Mirror the existing direct-TX path: build the encapped frame straight
into the target binding's UMEM TX slot, and for decap, point the
forward at the original UMEM frame with adjusted offsets instead of
synthesizing a new L2+inner frame. This is the *correct* zero-alloc
shape, but it is a **substantial control-flow change**, not the
"mirror #1433" one-liner the issue describes. Decap currently
*synthesizes* a 14-byte Ethernet header + inner payload because the
downstream pipeline expects an L2 frame at `l3_offset = 14`; doing this
in place requires either rewriting the inner-frame offset handling
across the whole post-decap pipeline or carving the synthetic header
into a reused arena. Risk: HIGH (touches the documented deferred-stage
contract).

### Option C — arena/pool of reusable frame buffers keyed by batch slot

A per-worker `Vec<Vec<u8>>` pool, hand out a buffer per decap/encap,
return on batch completion. This removes the *allocator call* but keeps
the memory resident and adds pool-management complexity. Net win is
"allocator contention avoided" only — which is exactly the unmeasured
claim in Section 3. If allocator contention is not demonstrated, this
is churn.

## 6. Public API preservation

If a fix proceeds, these signatures are observed by callers and must be
preserved or updated atomically with their call sites:

- `try_native_gre_decap_from_frame(&[u8], UserspaceDpMeta, &ForwardingState) -> Option<NativeGrePacket>`
- `encapsulate_native_gre_frame(&[u8], impl Into<ForwardPacketMeta>, &SessionDecision, &ForwardingState) -> Option<Vec<u8>>`
- `stage_native_gre_decap(..) -> (UserspaceDpMeta, Option<Vec<u8>>)`
- `NativeGrePacket { frame, meta }`
- callers: `poll_stages.rs:147`, `tunnel.rs:189`, `frame/mod.rs:237`,
  `frame/tcp_segmentation.rs:309`, `frame/tests.rs:557`.

## 7. Hidden invariants any change must preserve

- **`owned_packet_frame.take()` deferred-stage contract**
  (`poll_stages.rs:118-153`): the decap frame is moved out by the
  flow-cache, session-hit reverse-NAT, and missing-neighbor side-queue
  paths. Any scratch reuse must not alias a frame still owned by a
  queued forward request.
- **Neighbor learning uses the un-decapped raw frame**
  (`poll_descriptor/mod.rs:496-506`, `learn_from_live_frame =
  owned_packet_frame.is_none()`): a zero-copy decap must keep the raw
  outer frame readable for source-MAC learning.
- **Encap DF=1 + IPv4 checksum wire bytes** (`gre.rs:374-388`, #1440):
  any in-place builder must reproduce the exact outer-header bytes.
- **`packet_trimmed_len` trimming** (`gre.rs:216`, `:318`): inner
  payload is trimmed to IP total-length before copy; a scratch path
  must preserve the trim.
- **TSO fan-out** (`tcp_segmentation.rs:309`): N encapped segments must
  remain independently owned through TX.

## 8. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | MED–HIGH | Touches deferred-stage `take()` contract and outer-header wire bytes; GRE has no smoke coverage (Section 9). |
| Lifetime / borrow-checker | HIGH | Batched owned frames (up to 64 decap + N TxRequest) cannot share one reused buffer without an arena; the WG single-buffer pattern does not transfer. |
| Performance regression | LOW | A reused-buffer/arena won't slow things; but the *upside* is the risk — it may be unmeasurable (Section 3). |
| Architectural mismatch (#961 / #946-P2 / #1545) | **HIGH** | The issue frames this as "mirror #1433 one-liner". The real data flow makes it an owned-`Vec` TX-architecture change. This is the #1545 pattern: small/unmeasured win, real churn. |

## 9. Test plan (if a fix proceeds)

- `cargo build` clean; full `cargo test --release` (952+ tests).
- 5× flake on GRE-specific tests
  (`frame/tests.rs` GRE decap/encap roundtrip; `gre.rs` unit tests).
- Go suite (30 packages).
- **Smoke caveat:** the loss userspace smoke matrix (172.16.80.200 /
  `::200`, push+reverse, CoS off/on, ports 5201-5206) **does not
  exercise GRE** — that path is plain-IP forwarding. A GRE-specific
  connectivity check is required (configure a GRE tunnel endpoint
  between the cluster and a peer, push iperf3 through it) or the smoke
  must explicitly note GRE is unverified on the wire. This absence is
  itself an argument that GRE is not a saturating production path.
- Optional: capture a flamegraph under *pure GRE* load to confirm/deny
  the alloc is a hot frame before/after.

## 10. Out of scope (explicitly)

- The 416-LOC `gre.rs` → `gre/{decap,encap}` split the audit mentioned
  (incidental; below the split threshold).
- Direct-TX integration for the general copy-mode path (broader than
  GRE).
- WG scratch end-to-end wiring (#1433 follow-up).

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is GRE ever a saturating, allocator-contended path in any real
   xpf config?** If GRE is light overlay traffic (tens of kpps), the
   per-packet alloc is sub-threshold and this is #1545 redux →
   PLAN-KILL. Is there *any* evidence (flamegraph, deployment profile)
   that GRE alloc is hot?
2. **The batching constraint (Section 2) defeats the issue's "mirror
   #1433" premise.** Decap output lives in `PendingForwardFrame::Owned`
   across the batch (up to 64 concurrent); encap output lives in
   `TxRequest.bytes` until TX completion. A single per-worker scratch
   buffer cannot replace these. Is any reviewer aware of a single-buffer
   scheme that is sound here, or does this force an arena (which only
   removes the allocator call, not the memory) / a direct-TX rewrite
   (HIGH risk, far beyond the issue's framing)?
3. **WG precedent is a primitive, not a shipped integration**
   (`WgWorkerScratch` constructed only in tests). Does citing #1433
   actually establish a path, given WG consumes its scratch inline and
   GRE does not?
4. **Memory cost of an arena.** Option A(a)/C resident memory is
   64 × 4096 = 256 KiB per worker just for decap, plus encap. With N
   workers this is non-trivial. Does removing one warm small-alloc per
   GRE packet justify a quarter-MB-per-worker resident arena?
5. **Wire-byte / deferred-stage regression risk vs zero smoke
   coverage.** GRE has no smoke-matrix coverage (Section 9). Is it
   responsible to land a control-flow change to the GRE path that can
   only be validated by a bespoke GRE tunnel setup, for an unmeasured
   win?
