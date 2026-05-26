# #1165 Plan: Inline thread_local! / Logging Branch L1-i Bloat

**Status:** DRAFT v1 — pending adversarial plan review.

> If reviewers conclude the perf gain is too small to justify the
> churn, **PLAN-KILL is an acceptable verdict**. The drafter's prior
> position (below) is that an empirical measurement on the actual
> release binary largely contradicts the issue's stated CPU-reality
> framing, and that a minimal SEG_MISS_LOG out-of-line move is the
> only intervention with a measurable case.

## Issue framing (what #1165 asks)

> Deep inside the hot-path loops in
> `userspace-dp/src/afxdp/tx/dispatch.rs` and `poll_descriptor.rs`,
> there are inline `thread_local!` macro declarations (e.g.,
> `SEG_MISS_LOG`, `HB_LOG_COUNT`) surrounded by `if` statements and
> complex string formatting (`eprintln!`).
>
> A `thread_local!` access in Rust is not free. It compiles down to
> a TLS (Thread Local Storage) lookup, which can involve function
> calls (`__tls_get_addr`) depending on the linkage model. By
> putting this *inside* your 14.8M pps forwarding loop, you are
> adding hidden function calls and branch instructions to the most
> performance-critical code in the system. Even if gated by cold
> branches, the instruction footprint pollutes the L1-i cache.

Prescribed fix in the issue:

1. Remove inline `thread_local!`; pre-allocate in `WorkerStats`.
2. Outline logging via `#[cold]` + `#[inline(never)]`.
3. Branchless arithmetic for rate-limiting (bitwise AND on
   packet counters instead of `if count < 20`).

## Empirical baseline — what's actually in the release binary

Built `userspace-dp` at commit `3b1f56a8` (origin/master) with
`cargo build --release` (default features, no `debug-log`).

### All `thread_local!` sites in `userspace-dp/src/`

```
filter/mod.rs:327                          PENDING_FILTER_COUNTER_RECORD     (40 B BSS, structural)
afxdp/bpf_map.rs:153                       HB_LOG_COUNT                       (gated by cfg!(feature="debug-log"))
afxdp/frame/mod.rs:385                     BUILD_FWD_DBG_COUNT                (gated by cfg!(feature="debug-log"))
afxdp/frame/mod.rs:421                     BUILD_RST_CORRUPT_COUNT            (gated by cfg!(feature="debug-log"))
afxdp/frame/mod.rs:809                     INPLACE_FWD_DBG_COUNT              (gated by #[cfg(feature="debug-log")] block)
afxdp/frame/mod.rs:1637                    IP_LEN_MISMATCH_LOG                (verifier helper, debug-only flow)
afxdp/frame/mod.rs:1732                    CSUM_VERIFY_COUNT                  (verifier helper, debug-only flow)
afxdp/tx/dispatch.rs:403                   SEG_MISS_LOG                       (NOT gated — survives in release)
afxdp/tx/transmit.rs:151                   TX_RST_LOG_COUNT                   (gated by cfg!(feature="debug-log"))
afxdp/tx/transmit.rs:403                   PREP_TX_RST_LOG_COUNT              (gated by cfg!(feature="debug-log"))
afxdp/poll_descriptor/rx_telemetry.rs:110  OVERSIZED_RX_LOG                   (gated by cfg!(feature="debug-log"))
afxdp/poll_descriptor/rx_telemetry.rs:157  RX_RST_LOG_COUNT                   (gated by cfg!(feature="debug-log"))
```

### Surviving thread_local statics in the release binary

`nm --print-size --radix=d xpf-userspace-dp | grep RUST_STD_INTERNAL_VAL`
filtered to crate-local symbols yields **only two**:

| Symbol                              | Size  | Source                              |
|-------------------------------------|-------|-------------------------------------|
| `SEG_MISS_LOG`                      | 4 B   | `afxdp/tx/dispatch.rs:403`          |
| `PENDING_FILTER_COUNTER_RECORD`     | 40 B  | `filter/mod.rs:327`                 |

Every other `thread_local!` from the issue's "guilty list" is
already **dead code** in the release build — the surrounding
`cfg!(feature = "debug-log")` is `false`, LLVM constant-folds the
whole arm, and the static plus its initializer plus the formatting
machinery are dropped from the binary entirely.

### TLS lookup mechanism in this binary

`objdump -d xpf-userspace-dp | grep -c __tls_get_addr` → **0**.

The binary uses the **initial-exec** TLS model (statically linked
into the main binary, glibc): TLS slots are addressed via
`%fs:offset` directly. There is no `__tls_get_addr` function call
on any TLS access. The issue's "compiles down to a function call
that may involve `__tls_get_addr`" framing is the *general-dynamic*
PIC model for `dlopen`-ed shared objects — it does not describe
this binary's hot path.

### Hot-path function sizes (baseline)

```
worker_loop                              47,735 B
poll_binding_process_descriptor          71,056 B
drain_pending_tx                          6,930 B
enqueue_pending_forwards                 15,161 B    (callee containing SEG_MISS_LOG)
```

L1-i on modern x86 is 32 KiB. `worker_loop` and
`poll_binding_process_descriptor` already do not fit in L1-i at
function granularity — the meaningful footprint metric is which
*paths* are taken in steady state, not the total `.text` of the
parent function. That is what `#[cold]` annotations already
arrange via the `cold` attribute hint to LLVM's basic block
placement: cold blocks get sunk to function tail past the warm
exit. We can verify this with `objdump --disassemble=<sym>` after
any change.

## Honest scope/value framing

The issue cites a 14.8M-pps hot path. The actual production-build
intervention surface, given the empirical evidence above, reduces
to:

- **One `thread_local!`** (`SEG_MISS_LOG`, 4 B) on a path
  (`enqueue_pending_forwards`) that fires only when
  `tcp_segmentation_needed && !copied_source_frame` — i.e. the
  rare TCP-segmentation miss diagnostic counter increments. The
  preceding `if count_forwarded_tcp_segmentation_miss_if_needed`
  is also a branch that, when taken, leads into the diagnostic
  block; LLVM has no static hint that this is cold.
- **Zero remaining unconditional `thread_local!` declarations
  inside the descriptor loop or TX drain.** All
  `cfg!(feature="debug-log")`-gated ones are eliminated.

The drafter's pre-review position is that this is at best a
**low-single-digit-byte L1-i tightening on a single slow-path
branch**. It is highly likely that any *measurable* throughput
effect at 14.8M pps requires far larger interventions than this
issue scopes. The empirical reality of "what survives in the
release binary" is the load-bearing finding; reviewers should
challenge it directly.

If reviewers think this scope yields a measurable cycle/throughput
benefit larger than the noise floor of the loss userspace cluster,
the plan proceeds. Otherwise, **PLAN-KILL is the right call**.

## What's already shipped / partially handled

- `debug_log!` macro (`afxdp/mod.rs:50`) — already compiles out
  to nothing without the `debug-log` feature. Most "guilty"
  thread_locals are inside `cfg!(feature="debug-log")` runtime
  guards that LLVM folds to `false` and DCEs.
- `#[cfg(feature = "debug-log")] { … }` static blocks
  (`frame/mod.rs:803`, `frame/mod.rs:1644`) — fully gated at
  compile time, no runtime cost.
- `cfg!(...)`-gated arms — fold to `false` and DCE'd, but the
  source still LOOKS like it's in the hot path on a reader's
  first pass, which is part of what the issue reacts to.
- `PENDING_FILTER_COUNTER_RECORD` in `filter/mod.rs` — this is
  structural batching (firewall filter counter rollup), not
  telemetry. Out of scope for this refactor.

## Concrete design

Given the empirical finding, the proposed plan is **the minimum
intervention that has a measurable case**:

### Change 1 — outline `SEG_MISS_LOG` rate-limited diagnostic

Move the `eprintln!` plus its formatting closure out of
`enqueue_pending_forwards` into a `#[cold]` free function:

```rust
// Slow path, called only when segmentation was needed but neither
// builder produced an output frame.
#[cold]
#[inline(never)]
fn log_seg_miss_cold(
    source_frame_len: usize,
    request_meta: &ForwardPacketMeta,
    egress_ifindex: u32,
    tx_ifindex: u32,
    target_ifindex: u32,
    egress_mtu: Option<u16>,
) {
    thread_local! {
        static SEG_MISS_LOG: std::cell::Cell<u32> =
            const { std::cell::Cell::new(0) };
    }
    SEG_MISS_LOG.with(|c| {
        let n = c.get();
        if n < 20 {
            c.set(n + 1);
            eprintln!(
                "DBG SEG_MISS[{}]: frame_len={} proto={} egress_if={} \
                 tx_if={} egress_mtu={:?} target_if={} src_frame_bytes={}",
                n, source_frame_len, request_meta.protocol,
                egress_ifindex, tx_ifindex, egress_mtu, target_ifindex,
                source_frame_len,
            );
        }
    });
}
```

The call site shrinks to:

```rust
if count_forwarded_tcp_segmentation_miss_if_needed(
    dbg, copied_source_frame, tcp_segmentation_needed,
) {
    let egress_mtu = forwarding.egress
        .get(&request.decision.resolution.egress_ifindex)
        .or_else(|| forwarding.egress.get(&request.decision.resolution.tx_ifindex))
        .map(|e| e.mtu);
    log_seg_miss_cold(
        source_frame.len(),
        &request.meta,
        request.decision.resolution.egress_ifindex,
        request.decision.resolution.tx_ifindex,
        request.target_ifindex,
        egress_mtu,
    );
}
```

The `thread_local!` static moves with the closure into the
`#[cold]` function. The call site is now a single conditional
`call` to an out-of-line cold function.

### Change 2 — apply the same `#[cold]` outline to the
`cfg!(feature="debug-log")`-gated thread_local sites

Even though these are already DCE'd in release, the source code
form invites the misreading the issue makes. Outlining them into
named `log_*_cold` helpers makes the slow-path nature explicit at
the source level. **Cost = zero in release** (the cold helper
itself is also gated by `cfg!(feature="debug-log")` from the
caller-side guard, so it gets DCE'd too). **Value = readability +
defense against future refactors that might accidentally remove
the cfg guard.**

This second change is **optional** and only included if reviewers
think the source-level clarity is worth ~12 small cold helper
fns. If it's just churn for zero behavior change, drop it.

### Change 3 — branchless rate-limiting?

The issue proposes `bitwise AND on packet counters` for
rate-limiting. This is the wrong knob:

- The current rate-limit is "log first N occurrences then stop",
  not "log every Nth occurrence". `n & MASK == 0` cannot encode
  "stop after N".
- The diagnostic in question (SEG_MISS_LOG) is already a slow
  path that fires only on TCP segmentation misses — there is no
  case where the rate-limit branch fires at 14.8M pps.

**Reject the branchless rewrite.** Out of scope; mis-specified
in the issue text.

## Public API preservation

- `enqueue_pending_forwards` signature unchanged.
- `count_forwarded_tcp_segmentation_miss_if_needed` unchanged.
- All callers see no observable change.
- New private `log_seg_miss_cold` fn is local to
  `afxdp/tx/dispatch.rs`.

## Hidden invariants the change must preserve

- **Diagnostic semantics:** SEG_MISS_LOG still emits the first 20
  events per worker thread, then stops. Cross-worker counts must
  remain independent (worker-local), which `thread_local!` in the
  `#[cold]` fn preserves.
- **Side-effect ordering:** the `dbg.seg_needed_but_none` counter
  increment inside `count_forwarded_tcp_segmentation_miss_if_needed`
  still fires before any cold-fn call.
- **Borrow shape:** the cold fn takes a `&ForwardPacketMeta` and
  primitive types — no Rc/Arc clones, no allocation, no map
  lookup inside the cold fn.
- **Allocation:** the cold fn does NOT allocate. `eprintln!` does
  format-arg construction on the stack (no heap), same as before.
- **HA sync portability:** unchanged. No sync state involved.

## Risk assessment

| Class                                      | Level | Notes                                                                                                                                   |
|--------------------------------------------|-------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Behavioral regression                      | LOW   | Pure move of one diagnostic site to a `#[cold]` helper. No semantic change. Slow path only.                                              |
| Lifetime / borrow-checker                  | LOW   | Cold fn takes `&` borrows; no `&mut` aliasing. `ForwardPacketMeta` already `Copy`-able fields.                                            |
| Performance regression                     | MED   | Could MOVE bloat to a different cache line rather than eliminate it. Mitigation: measure `enqueue_pending_forwards` size + worker_loop size before/after; if size delta is < ~200 B, the change is rounding noise. |
| Architectural mismatch (#961/#946 pattern) | LOW   | This is not architectural; it's a code-motion of one slow-path block.                                                                    |

## Verification plan (post-implementation)

Before/after the change, capture:

```bash
# Function-level size delta on the hottest symbols
nm --print-size --radix=d xpf-userspace-dp | grep -E "worker_loop|poll_binding_process_descriptor|enqueue_pending_forwards|drain_pending_tx" | sort -k2 -n
# Surviving thread_local statics from crate code
nm --print-size --radix=d xpf-userspace-dp | grep RUST_STD_INTERNAL_VAL | grep xpf_userspace_dp
# Confirm the cold fn lives separately and is not inlined
objdump -d xpf-userspace-dp | grep -F 'log_seg_miss_cold' | head -5
# Confirm no __tls_get_addr emitted (initial-exec invariant preserved)
objdump -d xpf-userspace-dp | grep -c __tls_get_addr
```

**Required pass criteria (drafter's proposal — reviewers can
tighten):**

- `enqueue_pending_forwards` size shrinks by at least the size of
  the formatting + eprintln! block (a few hundred bytes
  expected). If shrinkage is < 64 B, the move accomplished
  nothing measurable and PLAN-KILL is appropriate.
- `worker_loop` total size unchanged or smaller (since
  `enqueue_pending_forwards` is its callee chain). Movement to
  another sibling caller would be a red flag.
- `__tls_get_addr` count still 0.
- Throughput delta on the loss userspace cluster: not gated; any
  measurable delta at all is below the cluster's noise floor for
  a 4-byte BSS move. Treat smoke as a no-regression check only.

## Test plan

```bash
# Build
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo-1165 \
  cargo build --release 2>&1 | tail -5

# Cargo full suite
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo-1165 \
  cargo test --release 2>&1 | tail -3

# 5x flake on the touched module
for i in 1 2 3 4 5; do
  TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo-1165 \
    cargo test --release -p xpf-userspace-dp dispatch 2>&1 | grep "test result" | tail -1
done

# Go suite
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./... 2>&1 \
  | grep -v "^ok\|^?" | tail
```

Per the task framing: **no per-PR smoke**. Marker
`<!-- AWAITING-BATCH-MERGE -->` on the PR. Perf delta measured at
the batch smoke.

## Out of scope (explicitly)

- Touching `PENDING_FILTER_COUNTER_RECORD` — structural batching,
  not telemetry.
- Touching `debug_log!`-gated sites that are already DCE'd.
  (Optional Change 2 may include these for clarity; default is
  to skip them.)
- Adding `WorkerStats` plumbing for `SEG_MISS_LOG` counters —
  per-worker thread_local Cell<u32> already gives worker-local
  semantics; `WorkerStats` would only buy aggregation across
  workers, which the diagnostic doesn't need.
- "Branchless rate-limiting" — issue's proposal is mis-specified
  against current "first N" semantics; reject.
- Touching the `cfg!(feature="debug-log")`-gated thread_local
  sites without changing behavior. Optional in Change 2.

## Open questions for adversarial review

1. **Is the empirical baseline ("only `SEG_MISS_LOG` survives in
   release") correct?** Re-run `nm --print-size | grep
   RUST_STD_INTERNAL_VAL` on a fresh `cargo build --release` at
   `3b1f56a8` (origin/master) and confirm. If a reviewer finds
   *any* additional surviving thread_local static from
   `xpf_userspace_dp`, the scope of this plan is wrong.
2. **Is the `cfg!(feature="debug-log")` DCE actually happening?**
   Check by disassembling
   `xpf_userspace_dp::afxdp::frame::build_forwarded_frame` (or
   wherever `BUILD_FWD_DBG_COUNT` is referenced) and confirming
   no TLS access, no `eprintln!` formatting code, and no string
   constants from the `DBG BUILT_ETH` literal in the release
   `.text`/`.rodata`.
3. **Is the SEG_MISS_LOG path actually cold in production
   traffic?** If `tcp_segmentation_needed` fires on more than a
   tiny fraction of packets in the cluster, the `#[cold]`
   annotation may mis-predict branch direction. Confirm by
   reading the `dbg.seg_needed_but_none` counter after a
   smoke run.
4. **Does moving the `eprintln!` formatting into a `#[cold]` fn
   actually shrink `enqueue_pending_forwards`?** If LLVM was
   already block-placing the diagnostic code at the function
   tail past the warm exit (which `#[cold]` blocks ARE supposed
   to enable), the change is no-op. Verify with `objdump
   --disassemble=<sym>` before AND after.
5. **Is "PLAN-KILL with a documented empirical-finding writeup"
   the right outcome?** The issue's CPU-reality framing is
   factually wrong about this binary (initial-exec TLS, not
   general-dynamic; `__tls_get_addr` count is 0; most sites
   already DCE'd). If reviewers agree, the right shipping
   artifact is a `closed: needs-no-fix` issue comment with the
   empirical evidence and zero code change. Be hostile here —
   don't ship churn for the sake of "doing something about
   #1165".
6. **Architectural mismatch check.** This is NOT the #946/#961
   class of architectural mismatch, but it IS the #944 / #966
   class of "issue describes a perf concern that doesn't
   reproduce in the current codebase". Of the prior such issues,
   the project usually closed with a "doesn't reproduce" comment
   rather than a no-op refactor. Is that the right precedent here?

## Drafter's recommendation

Lean toward **PLAN-KILL** with a comprehensive empirical writeup
on the issue, citing:

- 12 thread_local! sites in scope; 10 already DCE'd in release.
- 0 `__tls_get_addr` calls in the binary.
- 1 remaining hot-path-adjacent site (`SEG_MISS_LOG`) on a slow
  branch that fires only on TCP segmentation misses.

If reviewers want to proceed anyway, **Change 1 only** (move
SEG_MISS_LOG to a `#[cold]` helper). Skip Changes 2 and 3.

This plan deliberately includes the empirical evidence inline so
adversarial review can attack the measurement itself — that's the
load-bearing claim.
