# userspace-dp/src/afxdp/tx/

The TX side of a binding: classify into a CoS queue, dispatch
through the queue service, drain shaped queues, segment large TCP
frames, submit to the kernel's TX ring, reap the completion ring,
and recycle UMEM frames.

Every file here is **single-writer (owner worker)**. Atomic
operations use `Ordering::Relaxed` because there is no second
writer to synchronize against.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub. |
| `cos_classify.rs` | Maps a packet's policy / filter / classifier signals to a CoS queue id and an optional DSCP rewrite, then enqueues onto the chosen queue. |
| `dispatch.rs` | Batch dispatch from descriptor loop into the CoS queue runtime; handles fast-path interface lookup and falls back to the CoS engine. |
| `drain.rs` | Per-tick drain dispatch + queue-bound / pending-queue helpers. Owns the `COS_GUARANTEE_QUANTUM_*` and `COS_GUARANTEE_VISIT_NS` constants. |
| `rings.rs` | XSK kernel-ring discipline: completion drain, fill submit, RX/TX kernel wake. |
| `stats.rs` | Per-frame counters and submit-latency histogram bucketing. The sidecar `&mut [u64]` is non-atomic since it's owner-only. |
| `tcp_segmentation.rs` | TCP segmentation for forwarded frames (extracted in PR #1199). `#[cold]` — segmentation is the slow path; line-rate flows don't enter it. **#5141:** the local-owner fast-path twin of `frame/tcp_segmentation.rs` — it clamps the segmentable payload to the IP-declared datagram end (`declared_l3_end`, IPv4 `total_len` / IPv6 `40 + payload_len`) instead of the raw `&frame[l3..]` backing, so trailing Ethernet slack / appended bytes are never chunked into fresh checksummed segments. Kept byte-identical to the copy-path twin; the admission gate `forwarded_tcp_may_need_segmentation` in `dispatch/mod.rs` clamps the same way. **#5148:** neither the admission gate NOR the builder segments ANY IP fragment — first or non-first. A fragment (IPv4 MF=1 or offset≠0, or an IPv6 Fragment extension header) still carries the fragment-bearing IP header (Identification / MF / offset), so segmenting it would clone that header into every output while rewriting seq/checksum — overlapping offset-0 pseudo-fragments that break reassembly. The gate uses `is_any_fragment` (was the non-first-only `is_non_first_fragment` before #5148) and the builder repeats the guard (defense in depth); any fragment is routed to the normal forwarding path unchanged, matching the sibling #1852 non-first handling. Segmentation is only for WHOLE (unfragmented) over-MTU TCP datagrams. **#5159:** the egress-MTU lookup now uses the ACTUAL interface MTU — the prior `.unwrap_or_default().max(1280)` floored every plain-interface MTU to 1280, the IPv6 *minimum link* MTU, which is NOT an IPv4 floor (IPv4 min is 68). A valid egress MTU of 68–1279 was raised to 1280, so a non-DF TCP datagram whose L3 length fell in `(real_mtu, 1280]` was never flagged/chunked and was submitted OVERSIZE to AF_XDP TX. All three plain-forward sites drop the floor and treat `0` (no egress entry / unknown MTU) as "don't segment" via the now-live `mtu == 0` guard: the admission gate (`forwarded_tcp_may_need_segmentation`, `dispatch/mod.rs`), this TX builder, and the `frame/tcp_segmentation.rs` copy-path twin — kept byte-identical. Any IPv6-minimum floor belongs at interface config, not the per-packet segmenter. **#6125 (DF contract):** the admission gate deliberately does NOT check the IPv4 Don't-Fragment bit — an oversize *whole* transit TCP datagram is re-segmented into within-MTU segments REGARDLESS of DF, a delivery-over-strict-PMTUD choice. Each output is an independent whole IP datagram ≤ MTU (no IP fragmentation → DF-compliant on the wire), and it delivers even where ICMP Frag-Needed is filtered (a common PMTUD black-hole); the cost is that re-segmentation does NOT drive the sender's PMTUD the way a Frag-Needed reply would. Only the non-segmentable oversize classes (UDP/ICMP/ESP/GRE, any IP fragment, unknown egress MTU) route to the `compute_forwarded_egress_ptb` Frag-Needed/PTB path. Adjudicated non-blocking in #6125 (the PR #6123/#5159 hostile review): delivery posture retained; strict PMTUD (DF → PTB) would be an explicit config knob, not the default. |
| `transmit/` | XSK TX-ring submit + per-frame recycle. Owns `transmit_batch`, `transmit_prepared_queue`, shared-UMEM-aware prepared recycle helpers, and the `TxError` enum. **#4971:** `TxError::Retry`/`Drop` carry `Copy` reason codes (`TxRetryReason` / `TxDropReason`), NOT heap `String`s — the expected-backpressure retry path recurs every drain pass under ring pressure, so it must be allocation-free. The un-inserted retry tail is restored to `pending` by reverse-popping the staged scratch (`pop()` → new `len()` == popped index), preserving FIFO order with no side `Vec`. |

| `test_support.rs` | Test helpers for the per-file unit tests. |

## TX status precedence: Drop error vs expected-retry hint (#4971 / #6145)

The two TX outcomes reach operator status through **different** channels,
and the status snapshot has a deliberate precedence between them:

- `TxError::Retry(reason)` — the expected-backpressure path — records its
  reason lock-free via `BindingLiveState::set_tx_retry_status` (a single
  `Relaxed` `AtomicU8`). It never takes the `last_error` mutex; the send
  hot path must stay lock-free / alloc-free.
- `TxError::Drop(reason)` — the rare exceptional capacity / slice-bounds
  fault — renders a message into the `last_error` **mutex** via
  `set_error`.

`BindingLiveState::snapshot()` (`umem/snapshot.rs`, ~1s read side)
surfaces the retry hint **only as the `last_error` fallback** — i.e. when
the `last_error` string is empty. A non-empty `last_error` therefore
**outranks** the live retry hint.

**#6145 — intentional stale-masking.** A latched `TxError::Drop` leaves
`last_error` non-empty and the ongoing retry path (atomic-only) never
clears it. So while a Drop is latched, sustained retries afterward keep
surfacing the **Drop** string, not the current retry reason, until the
binding rebinds and `clear_error()` wipes both (mutex string + retry
atomic). This precedence is deliberate: a `TxError::Drop` is rarer and
more severe than expected backpressure — it flags a real capacity /
slice fault an operator must see — so it must not be masked by a flood of
routine retry hints. `clear_error()` (rebind / successful reconcile) is
the single reset point; a fresh retry recorded after the clear renders
normally. Pinned by
`tx_status_drop_error_outranks_retry_hint_until_rebind_6145`
(`umem/tests/snapshot_propagation.rs`).

## Where it sits

- Driven from `worker/lifecycle.rs::poll_binding`.
- Reads decisions from `forwarding/` and CoS state from `cos/`.
- Writes to UMEM via `umem/` and to the kernel via `xsk_ffi`.

## Notable invariants

- Single-writer per binding: every TX path here runs on the binding's
  owner worker. Cross-binding redirect (the only legitimate
  cross-worker writer) lives in `cos/cross_binding.rs` and uses an
  MPSC inbox plus slot-routed prepared recycle records to release
  source UMEM frames after copy.
- Prepared-frame discard paths are not local by default in shared-UMEM
  mode. Any path that drops, demotes, bounds, cancels, or rejects a
  `PreparedTxRequest` must call the `_with_shared` recycle helper while
  carrying the worker's shared recycle accumulator, then route the
  `(slot, offset)` records back through the shared slot-resolution helper.
  The split-slice path used while holding the ingress binding and the
  all-bindings cleanup path must share this resolver so stale lookup entries
  are handled identically. Unknown recycle slots must fail closed and
  increment both aggregate `tx_errors` and the subset
  `tx_shared_recycle_unknown_slot_drops` on the worker status surface with
  bounded one-line logging per drain; never push a foreign offset into an
  arbitrary binding's fill ring.
- The cross-binding direct-TX build's `debug-log` tuple-mismatch diagnostic
  (`dispatch/mod.rs`) drops the built frame by setting `build_failed`; the
  frame's `tx_offset` is recycled to `free_tx_frames` through the SINGLE
  `if build_failed` handler. The diagnostic branch records the mismatch
  exception but must NOT push the offset itself. Recycling the same offset in
  both the diagnostic branch and the `build_failed` handler double-frees it —
  the offset is then handed out for two later TX descriptors that alias one
  in-flight frame (on-wire corruption / double-free on the debug-log build).
  Regression: `direct_tx_tuple_mismatch_recycles_frame_exactly_once` (#4041).
- `Ordering::Relaxed` is intentional and correct given the
  single-writer invariant. Don't promote without proving a second
  writer exists.
- TCP segmentation is `#[cold]`. The fast path is direct submit;
  segmentation only fires for over-MSS forwarded frames.

## Ongoing refactor: `enqueue_pending_forwards` outlining (#4408)

`dispatch/mod.rs::enqueue_pending_forwards` is a large TX-drain
orchestrator (build + segmentation + WG/GRE + output-filter + CoS). It
is being decomposed into named private helpers in bounded, behaviour-
identical (pure code-motion) increments tracked by #4408. Each helper
preserves the hot-path invariants the function guards: no-alloc /
zero-copy for non-NAT64 forwards, the single-recycle invariant, and the
CoS guarantee-guard.

- **Increment 1** — `compute_forwarded_egress_ptb`: the #2301/#2330/#2845
  Path-MTU-Discovery block. Given the source (inner) frame, meta, and
  decision it derives the inner-source MTU, runs
  `forwarded_egress_mtu_decision`, builds the ICMP Frag-Needed (v4) /
  Packet-Too-Big (v6) reply (subject to RFC / #2472 rate-limit
  suppression), and records the `egress_mtu_exceeded` exception. Returns
  `(ptb_reply, mtu_signalled)`; the caller drops the oversized original
  when `mtu_signalled` and enqueues `ptb_reply` at the finalizer.

  **The DF-CLEAR IPv4 oversize case is FORWARDED and now RECORDED (#9328).**
  There is no IPv4 transit fragmenter in this dataplane. Verified by a
  positive-controlled grep for MF/offset WRITERS: it finds the three in
  `nat64.rs` (which copy MF and offset verbatim from an existing IPv6
  Fragment Header — none splits a datagram) and nothing else, and nothing
  in `tx/transmit/`, `tx/rings.rs` or `tx/drain/` compares a frame against
  an MTU. The only length guard on the forward path is
  `copy_frame_is_oversized`, which tests the UMEM chunk (4096), not the
  egress MTU. So an oversized DF-clear datagram is submitted at full
  length; what happens to it next is stated on `ForwardOversizeNoDf`.

  Before #9328 that outcome was the SAME `EgressMtuDecision::Forward`
  value as a frame that fits, so it was booked as `enqueue_ok`,
  `enqueue_copy`, `pending_copy_tx_packets` and `tx_bytes_total` with no
  exception at all — an operator debugging a loss saw a healthy counter,
  a wrong diagnostic rather than a missing one. The asymmetry was with the
  TCP arm of an oversized forward, which has recorded
  `tcp_segmentation_miss` since #1282.

  `EgressMtuDecision::ForwardOversizeNoDf` now distinguishes it and the
  dispatcher records `egress_mtu_exceeded_forwarded_no_df`. **Behaviour is
  unchanged** — the frame still forwards, and no PTB is sent, because ICMP
  Fragmentation-Needed is meaningful only to a sender that set DF.

  **The POLICY is decided: keep forwarding, and record the exception (#9395).**
  The decision,
  the plain-forward measurement it rests on, and what it does not cover are
  stated once, on `EgressMtuDecision::ForwardOversizeNoDf` in `icmp_ptb.rs`.
