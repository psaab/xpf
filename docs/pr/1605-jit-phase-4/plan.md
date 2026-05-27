# Phase 4 Cranelift JIT — Plan (DRAFT v1)

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY +
Claude SMR).

**Tracking issue:** #1605
**Design doc:** `docs/userspace-jit-design.md` (co-canonical per the
doc-coherency contract).

**Headline framing (read this first):** This plan starts from the
*leading hypothesis that Phase 4 is a PLAN-KILL*. Phase 1 already
shipped a straight-line `apply_rewrite_descriptor()` whose IPv4 arm is
~30 instructions of byte writes + 2 csum folds, marked
`#[inline(always)]` with a single call site. The descriptor path got
the dataplane from 13 Gbps (eBPF) to 23 Gbps; the design doc's own
post-implementation accounting credits the cache-hit short-circuit
(skipping session/policy/NAT/FIB) for ~35% of that win and the
zero-copy XSK path for the remaining ~65%. The doc's CPU breakdown at
23 Gbps shows `memcpy` 8% (cross-UMEM, unavoidable), NIC NAPI 12%,
syscalls 3%, `poll_binding` 22%. **`apply_rewrite_descriptor` is a
subset of `poll_binding`, and the descriptor path's residual cost is
already at the noise floor.** The +30-50% Phase 4 estimate in the doc
is a 2026-03-18 number written before Option C was implemented and
measured; that number is no longer credible.

This plan exists to either be killed or to find a sliver of Phase 4
that survives hostile review.

## Issue framing

Issue #1605 tracks Phase 4 of the userspace dataplane JIT pipeline:
replacing the per-flow `RewriteDescriptor` with Cranelift-emitted
native code that hard-codes the flow's constants as immediate
operands. The issue raises seven architectural questions that this
plan must answer before any code lands:

1. Code-generator choice (Cranelift vs dynasm-rs vs widen-descriptor).
2. Compile granularity and compile-vs-interpret threshold under churn.
3. Memory ownership for PROT_EXEC pages + HA failover semantics.
4. Config-invalidation barrier when JIT functions are captured by
   in-flight TX frames.
5. Cross-binding rewrite — does Phase 4 inherit AF_XDP UMEM ownership
   or transcend it?
6. Verifier-like safety: bounds encoding policy in IR + adversarial
   inputs.
7. Phase 3 (address-book trie compilation) ordering relative to
   Phase 4.

## Honest scope/value framing

### Phase 4 estimate at absolute scale

The doc claims "+30-50% over descriptors". Convert that to wall clock
on this hardware:

- 23 Gbps sustained on the loss userspace cluster, 12 streams, 1500 B
  MTU ⇒ ~1.92 Mpps aggregate across all workers.
- 8 vCPU VM; 6 worker threads + NAPI on shared CPUs.
- At 3 GHz, ~9.4 G-cycles/sec/CPU total; ~56 G-cycles/sec across 6
  workers.
- 56 G-cycles ÷ 1.92 Mpps ≈ 29 k-cycles/packet across the whole VM
  budget.

`apply_rewrite_descriptor_ipv4()` body (verified by reading
`userspace-dp/src/afxdp/frame/rewrite/ipv4.rs:14-123`) compiles to
roughly: 1 length check, 1 IHL check, 1 TTL check, 4 conditional byte
writes (NAT IPs + ports), 1 TTL decrement, 1 IP-csum 32→16 fold, 1
L4-csum 32→16 fold + UDP-zero patch. With LLVM `#[inline(always)]`
this folds into the per-packet loop body. Roughly 25-35 micro-ops on
x86-64 + 6-8 dependent loads from `&RewriteDescriptor`.

A Cranelift JIT replacing this with embedded immediates would
eliminate ~6-8 loads × ~0.3 ns each ≈ 2-3 ns per packet. At 1.92 Mpps,
that's 4-6 ms/sec of CPU saved — about **0.4-0.6% of one core**. The
"30-50%" number in the design doc is an arithmetic ceiling computed
against a stylized descriptor implementation; the actual descriptor
implementation has already absorbed most of that ceiling via
`#[inline(always)]` + precomputed csum deltas.

The hardware ceiling is elsewhere:

- **Cross-UMEM memcpy at 8% CPU** is structural to AF_XDP's
  per-binding UMEM ownership model. Phase 1 explicitly documents that
  cross-binding in-place rewrite is "architecturally impossible"
  (`flow_cache.rs` historical note; design doc Phase 1 "Not
  possible").
- **NAPI 12% + syscalls 3%** are kernel side; Phase 4 doesn't touch
  them.
- **`poll_binding` 22%** includes cache lookup, validation, mirror
  sampling, COS classification, TX pipeline push, and the
  PreparedTxRequest construction in `flow_cache_hit.rs:310-326` —
  none of which a per-flow Cranelift function would eliminate.

> If reviewers conclude the perf gain is too small to justify the
> churn, **PLAN-KILL is an acceptable verdict** and the
> recommendation is to flip `docs/userspace-jit-design.md` Phase 4
> status from "Not started" to "KILLED — descriptor path already
> saturates AF_XDP UMEM physics on this hardware".

### Compile-cost amortization math

Cranelift compile time is ~100 µs per function (design doc claim,
consistent with Wasmtime numbers). At 100 µs, the per-flow JIT must
serve **at least 100 µs / per-packet-saving** packets in its lifetime
to break even.

- Optimistic saving: 3 ns/packet ⇒ 100 µs / 3 ns = **33,333 packets
  per flow** to amortize the JIT.
- Pessimistic saving (2 ns): **50,000 packets per flow**.

A short HTTP flow (10 KB transfer, 1500 B MSS) is ~7 packets. A
30-second TLS bulk transfer at 100 Mbps is ~250 k packets. A DNS
query is 2 packets.

This puts Phase 4 at "useful only for iperf-class long-lived flows".
Real production firewall traffic is dominated by short flows. Under
DDoS / port-scan / SYN-flood, Phase 4 makes things *worse* — every
new flow burns 100 µs of compile time that the interpreter would
service in <100 ns total.

### What's actually shipped

- `apply_rewrite_descriptor()` orchestrator with `#[inline]` and
  one call site — `userspace-dp/src/afxdp/frame/rewrite/mod.rs:44`.
- `apply_rewrite_descriptor_ipv4()` and `_ipv6()` family arms with
  `#[inline(always)]` — `userspace-dp/src/afxdp/frame/rewrite/`.
- `RewriteDescriptor` struct with precomputed `ip_csum_delta` and
  `l4_csum_delta` — `flow_cache.rs:50-74`.
- 4096-entry, 4-way set-associative flow cache —
  `flow_cache.rs:6-25`.
- `FlowCacheStamp` validation (config_generation, fib_generation,
  owner_rg_id, owner_rg_epoch, owner_rg_lease_until) —
  `flow_cache.rs:76-112`.
- HA-aware invalidation via `cached_flow_decision_valid` and
  `flow_cache_hit.rs`.
- `PrefixTrieV4` / `PrefixTrieV6` already in `prefix_set.rs:180-225`
  (Phase 3 partial — trie types exist; integration with policy
  match is the open work).

The current descriptor path is the realistic upper bound of what
"compile the flow at session creation, replay it per packet" can do
without changing AF_XDP UMEM physics.

## Concrete design (proposed but expected to be killed)

If Phase 4 *did* land, here is the most honest sketch:

### Code-generator choice (Question 1)

Recommendation: **dynasm-rs OR widen the descriptor**, NOT Cranelift.

- Cranelift adds ~5 MB binary size, ~100 µs/function compile, and a
  large dependency surface (cranelift-codegen pulls in regalloc2,
  cranelift-frontend, target-lexicon, etc.). Build-time and CI
  binary-size budget hits.
- dynasm-rs is x86_64-only, ~10 µs/function, ~50 KB binary
  footprint. The aarch64 gap is real but the deployed target is
  x86_64 only today.
- Widening the descriptor (Option D, new in this plan): keep the
  RewriteDescriptor interpreted, but unroll the `apply_nat` branches
  by splitting into 4 specialised `apply_rewrite_descriptor_*`
  variants (apply_nat × {src_only, dst_only, both, none}) selected
  at cache insertion time via a function-pointer field. This gets
  most of the immediate-operand win without any JIT.

Option D is the path most likely to ship a non-trivial benefit if
the plan survives.

### Compile granularity (Question 2)

- Per-flow compilation gated by `bytes_observed > 64 KB` AND
  `lifetime_packets > 1000`. Below the gate, use the descriptor
  path. The flow cache already tracks `observed_bytes`
  (`flow_cache.rs:144-147`).
- Under churn (>10 k flows/sec), gate aggressively: only compile
  if hit-count crosses a static threshold.
- Static fallback: zone-pair / address-pair compile (one function
  per (src_zone, dst_zone) tuple), not per-flow. Amortizes over
  all flows in that zone pair. Sketch: O(zones²) compile budget
  at config apply, not per-flow.

### Memory ownership + PROT_EXEC (Question 3)

- One mmap'd PROT_READ|PROT_WRITE pool per worker (~256 KB), then
  `mprotect` to PROT_READ|PROT_EXEC after code emission. Workers
  do NOT share JIT pages — avoids cross-CPU iTLB shootdown and
  matches the per-CPU flow cache model.
- Lifecycle: tied to flow cache entry. Eviction triggers
  `mprotect` back to RW, zero-fill, return to free list.
- HA failover semantics: peer takes over with **no JIT pages
  replayed**. On failover, the new primary re-builds the
  descriptor path for synced sessions; any per-flow JIT is rebuilt
  lazily on the data path. This is consistent with Phase 1: the
  flow cache is per-worker and not session-sync state.

### Config invalidation (Question 4)

- Generation counter (already exists) bumps on config apply.
- JIT function pages tagged with the generation they captured.
- Hot path checks `entry.stamp.config_generation == current` — if
  stale, falls through to slow path (which will recompile).
- **Critical hazard**: a TX frame in flight may still reference a
  JIT function pointer that has been mprotect'd away. Mitigation:
  RCU-style epoch barrier — track in-flight TX completions; do
  not zero/unmap a function page until the next "all workers
  completed all in-flight TX" epoch boundary. The TX completion
  ring poll already happens every batch; instrument it to
  publish an epoch counter that the eviction path reads.

### Cross-binding rewrite (Question 5)

**No change vs Phase 1.** Cross-binding requires a memcpy into the
target binding's UMEM (kernel AF_XDP constraint, not a userspace
choice). A Cranelift function emitting a fused copy+rewrite would
still have to perform the memcpy; the win would be ~0%. Phase 1's
"not possible" verdict stands.

### Verifier-like safety (Question 6)

- All IR construction goes through a single `RewriteCompiler` trait
  with bounds-checked field offsets baked into the IR.
- Differential test: `apply_rewrite_descriptor()` and the JIT
  function MUST produce byte-identical output for the same input
  frame. Property test in CI covers ~10 k random
  (frame, descriptor) tuples.
- Adversarial inputs: short frames (< 60 B), VLAN-overlap, embedded
  ICMP, malformed IHL, IPv6 with extension headers. JIT function
  must fall back to descriptor path for any input it can't handle;
  flow cache `descriptor` field stays populated for the fallback.

### Phase 3 ordering (Question 7)

**Phase 3 already partial.** `PrefixTrieV4` and `PrefixTrieV6` are
in `userspace-dp/src/prefix_set.rs:180-225`. The remaining work is
wiring them into `policy.rs:match_address()` callers. That work
is independent of Cranelift and should ship as a separate small PR
under issue #1605 or a child issue. **Recommended**: ship Phase 3
integration first as a ~200-LOC PR; revisit Phase 4 after.

## Public API preservation

- `RewriteDescriptor`, `FlowCache`, `FlowCacheEntry` keep their
  current public-in-`afxdp` shape.
- `apply_rewrite_descriptor()` signature unchanged.
- Phase 4 (if it ships) adds an OPTIONAL `Option<JitFn>` field to
  `FlowCacheEntry`. When `None`, hot path uses descriptor (current
  behaviour). When `Some`, hot path uses the JIT function.
- No protocol/IPC change required.

## Hidden invariants the change must preserve

1. **Hot-path allocation rule**: no per-packet allocation. The JIT
   function pages are mmap'd once per worker at startup. Eviction
   does NOT munmap; it zero-fills and returns to free list.
2. **Side-effect ordering**: the descriptor path's order is (NAT
   IPs) → (NAT ports) → (TTL decrement) → (IP csum fold) → (L4 csum
   fold). The JIT must emit the same order so that any concurrent
   reader of the frame observes the same intermediate states. This
   matters for the in-place rewrite path where the same UMEM frame
   is the source and the destination.
3. **HA sync portability**: flow cache entries are NOT
   HA-synced (per Phase 1 design). JIT pages are local to the
   active node. On failover, the new primary rebuilds the cache
   from synced session state. The plan does not change this.
4. **Stale-handle hazard**: a TX frame's `PreparedTxRequest`
   captures `desc.addr` (UMEM offset) but not the JIT function
   pointer. Even if the JIT page is reclaimed mid-flight, the
   already-emitted bytes in UMEM are stable. The TX completion
   path does NOT re-call the JIT function. This makes the
   PROT_EXEC lifetime barrier (Question 4) tractable.
5. **Lifetime / borrow-checker shape**: the JIT-page region is a
   single `*const u8` per worker; the function pointers stored in
   `FlowCacheEntry` borrow from it implicitly. Lifetime must be
   tied to the worker, not the cache entry, to keep entries
   `Send + Clone` without unsafe.
6. **Verifier safety**: every emitted function MUST be
   differentially fuzz-tested against the descriptor path before
   merge. No exception.

## Risk assessment

| Class | Risk | Notes |
|-------|------|-------|
| Behavioral regression | **HIGH** | Per-flow code generation introduces N independent code paths; one buggy IR pattern affects only the flows that hit it, making bugs invisible to the existing test suite. Differential fuzzing is mandatory. |
| Lifetime / borrow-checker | **MED-HIGH** | `*const u8` function pointers with PROT_EXEC backing memory cannot easily be expressed in safe Rust. Wrapping in `JitArena` with manual unsafe and lifetime ties to the worker is workable but adds an `unsafe` surface that the project has otherwise minimised. |
| Performance regression | **MED** | At 100 µs compile cost, a session-creation burst (DDoS, port scan) can starve the slow path. Need an opt-in gate AND a kill switch. Even with a gate, the additional branch in the cache-lookup path (`if entry.jit_fn.is_some()`) costs a few cycles on every cache hit — possibly net-negative for the median case. |
| Architectural mismatch | **HIGH (likely PLAN-KILL)** | The dataplane is currently memcpy + NAPI + syscall bound on this hardware. Phase 4 optimises a code path (apply_rewrite_descriptor) that is no longer on the critical path. This matches the #946 Phase 2 and #961 PacketContext patterns: "Refactor: <Pattern>" issue proposing a large rearchitecture that the codebase reality has overtaken. |

## Test plan

- **PLAN review is the gating step**. If reviewers concur that the
  expected gain is < 5% on the loss userspace cluster smoke matrix
  (v4 + v6 × push + reverse × CoS-off + CoS-on), the plan is KILLED
  and no code lands.
- **If the plan survives**: cargo build clean; cargo test --release
  full suite; 5/5 named-test flake check on
  `flow_cache::tests::*` and any new `jit::tests::*`; Go suite (30
  packages); deploy on loss userspace cluster; full smoke matrix
  (v4 + v6 × push + reverse × CoS-off + CoS-on, plus per-class
  5201-5206 = 30 measurements); HA failover regression
  (`make test-failover`).
- **Differential fuzz**: 10 k random `(frame, RewriteDescriptor)`
  tuples; JIT output MUST equal descriptor output byte-for-byte.
- **Compile-cost stress**: synthetic 10 k flows/sec session-creation
  rate; latency p99 of new-flow forwarding MUST NOT regress more
  than 5 µs vs descriptor-only baseline.

## Out of scope

- Phase 3 address-book trie integration (separate PR even if Phase 4
  ships — they are independent).
- Filter / firewall-filter JIT (issue out-of-scope per #1605 body).
- NAT pool selection JIT (out-of-scope per #1605 body).
- ARM64 support (deployed target is x86_64; if dynasm-rs is the
  pick, ARM64 is a future ask).
- Cross-NIC shared UMEM (separate research; doesn't change the
  Phase 4 calculus).

## Open questions for adversarial review

1. **Is the +30-50% Phase 4 estimate still real?** The doc's number
   predates Option C shipping. The descriptor path is already
   `#[inline(always)]` straight-line code with precomputed deltas.
   Quote-line evidence requested: which fraction of `poll_binding`'s
   22% CPU is plausibly compressible by per-flow JIT, given
   `flow_cache_hit.rs:263-279` already inlines `apply_rewrite_descriptor`?
2. **At 100 µs compile cost per flow, what session-creation rate
   makes Phase 4 net-negative?** Compute the break-even flow lifetime
   given a 2-3 ns per-packet saving. Is that lifetime above or
   below the 90th-percentile production flow size? Reviewer should
   propose a concrete production traffic mix (mean flow size,
   median, p99) and compute amortisation.
3. **Does the PROT_EXEC eviction barrier (Question 4 above) actually
   work?** The plan proposes an RCU-style epoch barrier tied to TX
   completion polling. Is there a scenario where a worker's TX
   completion path lags long enough that an in-flight `PreparedTxRequest`
   still references a now-reclaimed JIT page? The plan claims the
   TX path doesn't re-call the JIT function — verify this against
   the actual `tx_pipeline.pending_tx_prepared` consumer.
4. **Is Cranelift's IR-level bounds-check claim sound?** The design
   doc says "Cranelift JIT generates verified code through its IR
   builder, which prevents out-of-bounds access by construction".
   This is only true if the bounds are encoded in the IR. The plan
   proposes a `RewriteCompiler` trait. Is that trait actually
   sufficient, or does it have the same "guard at the entry point
   only" hole that a hand-written rewrite function has?
5. **Is Option D (widen the descriptor with 4 variants) a better
   path than Cranelift?** Option D ships ~50 LOC of new helper
   selectors and a `fn(&mut [u8], ...)` field on `FlowCacheEntry`.
   Same immediate-operand win, no PROT_EXEC, no Cranelift
   dependency, no compile-cost amortisation problem. If the
   estimated win is 2-3 ns/packet, Option D probably captures
   90% of that for 5% of the engineering cost. Reviewer should
   propose Option D's ceiling and either ratify it as the
   pragmatic Phase 4 OR confirm Cranelift is justified.
6. **Phase 3 ordering**: should the existing `PrefixTrieV4/V6`
   types in `prefix_set.rs` be wired into `policy.rs` first as a
   small standalone PR? If yes, this plan's recommendation is to
   close #1605 with a "Phase 4 plan-killed; Phase 3 spun out to
   child issue" outcome. Reviewer to confirm.
7. **Is there a non-rewrite-path JIT win the plan is missing?** The
   plan focuses on Phase 4 as defined in #1605 (rewrite functions).
   Are there other compile-time-knowable, hot-path branches in
   `poll_binding` that a JIT could fuse — e.g., specialising the
   mirror-sampling branch (`flow_cache_hit.rs:240-309`), the COS
   queue selection (`mirror_cos_queue_id` lookup), or the
   `PreparedTxRequest` construction itself? If yes, the plan
   should be re-scoped from "compile rewrite functions" to
   "compile the full hit-path stage". This is a substantial
   re-scoping and would block the current plan pending a new
   one.
