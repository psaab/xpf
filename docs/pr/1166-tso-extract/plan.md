---
status: v4 FINAL — Codex round-4 PLAN-READY; v3 → v4 scrubbed remaining v1 residue in sections 3 and 9 (no further revisions needed; merged version)
issue: #1166
phase: Pure code-motion refactor
---

## 1. Issue framing

Issue #1166: `segment_forwarded_tcp_frames_into_prepared`
(`userspace-dp/src/afxdp/tx/dispatch.rs:1204-1484` — 281 lines)
inlined into the dispatch hot path. The original prescription:
extract to `frame/tcp_segmentation.rs` as a dedicated stage so
the heavy memory-copy instructions don't pollute dispatch.rs's
L1-i.

Codex's Tier D review confirmed the function is **not extracted**
in current master (the existing `frame/tcp_segmentation.rs`
contains a sibling `segment_forwarded_tcp_frames_from_frame`
which is the *frame*-level builder; the *dispatch*-level
adapter still lives inline in `tx/dispatch.rs`).

## 2. Honest scope/value framing

This is **pure code-motion** — moving a 281-line function from
one file to another with no behavior change. Win:

- `tx/dispatch.rs` shrinks from 1,517 to ~1,236 LOC (under the
  modularity threshold even further)
- L1-i benefit unproven — but the issue's premise (segmentation
  code pollutes dispatch hot-path icache for non-segmented flows)
  is reasonable; pure code motion can't make L1-i worse and may
  help when the linker keeps the moved function out of the
  dispatch's icache lines
- No risk to forwarding correctness if the move preserves call
  sites and signatures

**If reviewers find any non-trivial state coupling that prevents
pure code motion, PLAN-KILL is acceptable** — though the
function's signature suggests it's reasonably self-contained.

## 3. Code paths affected

### Source: `userspace-dp/src/afxdp/tx/dispatch.rs:1204-1484`

`fn segment_forwarded_tcp_frames_into_prepared(...)` — the
target. Currently a free function (not a method on a type).

### Existing frame-layer sibling (informational only)
`userspace-dp/src/afxdp/frame/tcp_segmentation.rs` (338 lines):

```
12   fn segment_forwarded_tcp_frames_from_frame(...)  // pure builder
321  fn segment_forwarded_tcp_frames(...)             // XdpDesc adapter
```

The frame-layer file already owns frame-level segmentation. It
is **not** the destination for the dispatch wrapper — the
dispatch wrapper mutates `BindingWorker.tx_pipeline`, consumes
`free_tx_frames`, writes UMEM, and calls drain helpers, all of
which are tx-layer concerns. See section 4 for the v2/v3 layer
correction.

### Destination: new file `userspace-dp/src/afxdp/tx/tcp_segmentation.rs`

A new sibling of `tx/dispatch.rs` and `tx/drain.rs` inside the
`tx/` module. Pure frame-builder logic stays in
`frame/tcp_segmentation.rs`; the tx-layer wrapper lands here.

### Caller(s)

`tx/dispatch.rs:259` — invoked from inside `enqueue_pending_forwards`:

```rust
let segmented = segment_forwarded_tcp_frames_into_prepared(...)?;
```

Call site stays in `tx/dispatch.rs`; the move adds an import
`use super::tcp_segmentation::segment_forwarded_tcp_frames_into_prepared;`.

## 4. Concrete design — v2 (Codex round-1 layer-violation fix)

**Target changed.** Codex caught that the function isn't a pure
frame builder — it mutates `BindingWorker.tx_pipeline`, consumes
`free_tx_frames`, writes UMEM directly, pushes `PreparedTxRequest`,
and calls `bound_pending_tx_prepared` + `drain_pending_tx_local_owner`
(the latter two already live in `tx/drain.rs` as
`pub(in crate::afxdp)`). Moving it into `frame/tcp_segmentation.rs`
would make `frame` depend on TX-pipeline / worker / CoS-owner /
drain state. Layer violation.

**Correct target: `userspace-dp/src/afxdp/tx/tcp_segmentation.rs`**
(new file, sibling of `tx/dispatch.rs`, same `tx/` module).
Pure frame-builder logic stays in `frame/tcp_segmentation.rs`.
Layer boundary preserved: `frame/` builds packets;
`tx/` owns UMEM/prepared queue/drain side effects.

Steps:

1. Create new file `userspace-dp/src/afxdp/tx/tcp_segmentation.rs`.
2. Cut lines `tx/dispatch.rs:1204-1484` (the function).
3. Paste into the new file.
4. Add `mod tcp_segmentation;` to `tx/mod.rs`.
5. Visibility: `pub(super) fn segment_forwarded_tcp_frames_into_prepared(...)`
   so the caller in `tx/dispatch.rs:259` reaches it via the parent
   `tx/` module — minimum visibility required.
6. Update `tx/dispatch.rs` `use` block:
   `use super::tcp_segmentation::segment_forwarded_tcp_frames_into_prepared;`
7. Verify no other callers (Codex confirmed only one).
8. The `pub(in crate::afxdp)` helpers
   `bound_pending_tx_prepared` (`tx/drain.rs:33`) and
   `drain_pending_tx_local_owner` (`tx/drain.rs:464`) are already
   reachable from the new sibling file in `tx/` — no further
   visibility changes needed.
9. **Implementation note:** the new `tx/tcp_segmentation.rs`
   needs `use super::*;` at the top, matching the import shape
   used by `tx/dispatch.rs`, `tx/drain.rs`, and the rest of the
   `tx/` siblings. This brings in `BindingWorker`,
   `PreparedTxRequest`, `XdpDesc`, fabric/CoS types, and the
   `bound_pending_tx_prepared` / `drain_pending_tx_local_owner`
   helpers that the moved function calls.

No behavior change. No new tests needed (function body intact).

## 5. Public API preservation

Function name unchanged. Visibility widens from `fn` (file-local
in `tx/dispatch.rs`) to `pub(super)` (callable from sibling
files inside `tx/`). The single caller in `tx/dispatch.rs:259`
imports it via `use super::tcp_segmentation::segment_forwarded_tcp_frames_into_prepared;`.
No external callers exist outside `tx/`.

## 6. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | **VERY LOW** | Pure code motion; function body unchanged |
| Visibility / namespace | LOW | One-callsite import update; `pub(super)` is the minimum needed |
| L1-i benefit | UNPROVEN | Not measured; benefit is theoretical until smoke confirms |
| Cargo build | LOW | Internal helpers (`bound_pending_tx_prepared`, `drain_pending_tx_local_owner`) are already `pub(in crate::afxdp)` — reachable from the new sibling file with no further visibility changes |

The only real risk is **#4**: if the moved function calls
file-local (non-`pub`) helpers that live in `tx/dispatch.rs`,
those would need to be exposed. Verify in the implementation
phase before claiming this is risk-free.

## 7. Test plan

**Compile:** `cargo build` clean. The visibility / import
change is the only thing that can fail.

**Cargo tests:** existing 952+ cargo tests must still pass.
Specifically the `segment_forwarded_tcp_frames_into_prepared`
tests (which today live in `tx/dispatch_tests.rs` if any) need
to follow the function — relocate them in the same PR if
present.

**Go tests:** unaffected (Rust-only change).

**Smoke matrix on loss userspace cluster:**
- Pass A (CoS off, baseline + multi-stream)
- Pass B (CoS on, per-class)
- 30 cells, 0 retrans expected (this is pure code motion)

**Specific TSO smoke:** force a path where TCP MSS exceeds the
segment-encap MTU (e.g., GRE/IPsec encapsulated TCP). The
segmenter fires; verify same throughput + 0 retrans pre/post.

## 8. Out of scope

- L1-i benefit measurement via `perf stat -e
  L1-icache-load-misses` — interesting but #1166's prescription
  is the move itself, not the measurement
- SIMD vectorization of the copy loop (issue body mentions
  `_mm256_storeu_si256`) — speculative; the copy is already
  driven by `copy_nonoverlapping` which the compiler vectorizes
  if profitable; explicit SIMD is a separate issue
- Hardware TSO via AF_XDP metadata (issue body mentions) — also
  separate; no AF_XDP TSO API exists today

## 9. Open questions for adversarial review

1. Are there any file-local (non-`pub`) helpers in
   `tx/dispatch.rs` that the moved function calls internally? If
   so, those need to be widened to `pub(super)` so the new
   sibling file in `tx/` can reach them.
2. Does the existing frame-layer `tcp_segmentation.rs` already
   have a test harness whose shape we should mirror in the new
   `tx/tcp_segmentation.rs`?
3. Is there a name clash with other functions in the `tx/`
   module? (Unlikely — function names are distinct.)
4. Is `pub(super)` the minimum visibility, or should it stay
   `fn` (file-local) with a `mod tcp_segmentation;` declaration
   inside `tx/dispatch.rs` instead of `tx/mod.rs`? The latter
   would keep the function reachable only from the file that
   declares the submodule, but adds awkward placement.

## 10. Verdict request

PLAN-READY → execute the move.
PLAN-NEEDS-MINOR → tweak (e.g., test relocation), then execute.
PLAN-NEEDS-MAJOR → revise.
PLAN-KILL → premise wrong.
