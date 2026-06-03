# #1755 — CoS exact-guarantee hot-path CPU reduction (Path A of #1752)

**Status: v2 (PLAN-READY — converged after round-1 review: Codex PLAN-READY for
Change A / NEEDS-MAJOR if Change B unspecified; AGY PLAN-NEEDS-MAJOR for a second
probe site; Claude SMR PLAN-READY). v2 folds in (1) the second live probe site
`ensure_cos_interface_runtime` AGY found, (2) a properly-specified `MaybeUninit`
heap constructor for Change B per Codex, (3) a ≥1 pp ship gate per all three.**

**Recommendation: PLAN-READY for a narrow, fairness-neutral codegen lever —
eliminate TWO live `__rust_probestack` frames on the per-packet path:
`cos_queue_push_back` (352 KB) and `ensure_cos_interface_runtime` (36 KB).
PLAN-KILL the issue's three schema/hash headline candidate sub-levers (flow-hash
caching, structural-compare bypass, descriptor-indexed queuing) as
not-the-dominant-cost and/or fairness-perturbing — they are the #1207/#1545 trap.
The min-bucket O(1)/heap lever is PLAN-DEFER pending its own measured case.**

## 1. Issue framing and the kill-risk it carries

#1755 (Path A of the #1752 umbrella) targets the ~19% of `-P48 -p5210` CoS-on
self-time attributed to the CoS exact-guarantee queue machinery. The issue text
proposes four candidate sub-levers from the AGY umbrella review (flow-hash
caching, structural-compare bypass, descriptor-indexed queuing, O(1) min-bucket)
and explicitly flags that the CoS path has **two prior PLAN-KILLs** (#1207
queue_service skeleton, #1545 mirror clone) and demands "a no-code-PLAN-KILL
exit if the dominant sub-cost is irreducible per-packet enqueue work."

This plan takes that exit seriously. It does **not** optimize from the umbrella
doc's candidate list. It annotates the dominant sub-cost to a concrete reducible
operation on the live cluster first, then picks the single most-tractable lever
that the annotation actually supports — which turns out to be **none of the four
headline candidates**.

## 2. Live annotation — the dominant sub-cost is a codegen artifact, not per-packet algorithm work

Method: loss userspace cluster, `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env`.
iperf3 `-c 172.16.80.200 -t180 -p 5210 -P 48` from `loss:cluster-userspace-host`
(port 5210 → `iperf-24g` queue, `scheduler-24g transmit-rate 24.0g exact` — the
exact-guarantee path the profile targets, confirmed via
`show configuration class-of-service` + `cos-iperf-config.set` term 10).
`perf record -F 1999` (flat) on the live `xpf-userspace-dp` (build-id
`f8949d18…`, `/usr/local/sbin/xpf-userspace-dp`) for 10 s under load.

Top CoS self-time (`perf report --no-children`, matches the issue's numbers):

| symbol | self% |
|---|---|
| `cos_queue_push_back` | 5.94 |
| `cos_queue_pop_front_inner_with_cap` | 3.64 |
| `service_exact_guarantee_queue_direct_with_info` | 3.13 |
| `ingest_cos_pending_tx_with_provenance` | 1.94 |
| `publish_cos_exact_backlog` | 1.87 |
| `drain_shaped_tx` | 1.63 |
| `enqueue_cos_item` | 1.61 |
| `account_cos_queue_flow_enqueue` | 0.79 |

Evidence files: `evidence/flat-report.txt`, `evidence/pushback-annotate.txt`,
`evidence/pop-annotate.txt`.

### 2.1 `cos_queue_push_back` — ~61% of its self-time is a stack-probe loop, NOT queue work

`perf annotate -s cos_queue_push_back` (verbatim in `evidence/pushback-annotate.txt`):

```
    0.14 :  3703aa: mov    %rsp,%r11
    0.00 :  3703ad: sub    $0x56000,%r11          ; reserve 352 KB frame
   10.98 :  3703b4: sub    $0x1000,%rsp           ; __rust_probestack touch loop
    7.23 :  3703bb: movq   $0x0,(%rsp)            ;   zero a page
   43.23 :  3703c3: cmp    %r11,%rsp              ;   loop until whole frame touched
    0.03 :  3703c6: jne    3703b4 ...
```

**10.98 + 7.23 + 43.23 = 61.4% of `cos_queue_push_back`'s self-time** is the
Rust large-stack-frame probe loop touching every page of a **352 KB
(`0x56000`)** stack frame — on **every** call, including the >99.99% of calls
that take the already-promoted fast path.

Control: `cos_queue_push_front` (`evidence` objdump) has a **0x58 (88-byte)**
frame and **no probe loop**. The two functions are structurally identical
except push_back contains the lazy-promotion path
(`maybe_promote_best_effort` → `promote_to_flow_fair` →
`Box::new(FlowFairState::new(...))`, push.rs:42-86). `FlowFairState` is ~352 KB
(`flow_bucket_bytes/head/tail/tx_bytes/observed_bps/last_tx_ns: [u64;4096]` =
32 KB each, `flow_bucket_items: [VecDeque;4096]` = 128 KB inline headers,
`flow_bucket_pending_bytes: [u32;4096]` = 16 KB — types/cos.rs:735-928).

`FlowFairState::new()` returns the struct **by value**. Even though `new` is a
separate symbol (`nm`: it is NOT inlined), its 352 KB return value must be
materialized in `cos_queue_push_back`'s frame before the move into the `Box`
allocation at push.rs:79. RVO does not elide it here because the value crosses
the `promote_to_flow_fair` (`#[inline]`) → `cos_queue_push_back` boundary. So
push_back reserves and probe-touches 352 KB on every packet.

### 2.2 The exact path NEVER promotes at runtime — the probe is pure waste

Exact-guarantee queues (the -P48 -p5210 path) are promoted to flow-fair
**eagerly at build** (`admission.rs:526` `Some(Box::new(FlowFairState::new(...)))`),
not via the lazy front-key probe (that is the #1735 best-effort path).
`maybe_promote_best_effort` returns at push.rs:44 on the first
`flow_fair_state.is_some()` check; `promote_to_flow_fair` is never reached at
runtime on an exact queue. The 352 KB frame is reserved and probed anyway,
purely because of the inlined-but-never-taken promotion path. This is the same
class of defect the codebase already fixes elsewhere with
`#[cold] #[inline(never)]` (`poll_descriptor/cookie_reply.rs:46`,
`poll_descriptor/nat_exception.rs`, `tx/dispatch/mod.rs:17`).

### 2.2a Second live probe site — `ensure_cos_interface_runtime` (36 KB, ingress per-packet) [AGY round-1]

AGY round-1 found, and §`evidence/ensure-cos-iface-annotate.txt` confirms live, a
**second instance of the identical defect** on the ingress/classify hot path:

```
000000000036f410 <…cos::builders::ensure_cos_interface_runtime>:
    0.00 : 36f41d: sub    $0x9000,%r11          ; reserve 36 KB frame
    5.42 : 36f424: sub    $0x1000,%rsp          ; probe loop
    1.41 : 36f42b: movq   $0x0,(%rsp)
   18.43 : 36f433: cmp    %r11,%rsp
    0.00 : 36f436: jne    36f424 ...
```

5.42 + 1.41 + 18.43 = **25.3% of `ensure_cos_interface_runtime`'s self-time**
(1.12% of total, `evidence/flat-report.txt`) is a 36 KB probe loop. Root cause is
identical: `ensure_cos_interface_runtime` is `#[inline]` (builders.rs:21), is
called per-packet from `tx/cos_classify.rs:443` and `:579` (before
`enqueue_cos_item`), and inlines the cold builder branch
(`build_cos_interface_runtime` → `CoSInterfaceRuntime` ~36 KB by value,
builders.rs:51,66). The probe runs on every packet **before** the
`cos_interfaces.contains_key` early-exit at builders.rs:37 — pure waste on the
>99.99% hot path where the interface runtime already exists.

This is the same fix pattern (out-line the cold builder) and is folded into the
scope below.

### 2.3 `cos_queue_pop_front` — self-time is the O(N) min-finish scan over active buckets

`perf annotate` (verbatim in `evidence/pop-annotate.txt`): pop has a normal 0xf8
frame (no probe). Its self-time concentrates in the
`cos_queue_min_finish_bucket` linear scan (`36fae0`-`36fb43`): per active bucket
it does `and $0xfff` (1.90%) + strided loads of `flow_bucket_head_finish_bytes`
(`0x28028(%rbp,%rax,8)`, 1.12%) and `flow_bucket_observed_bps`
(`0x40028(%rbp,%rax,8)`, 1.51%) — two cold-cache-line loads per bucket from the
big arrays. With -P48 ≈ up to 48 active buckets this is the documented O(N)
scan (`mod.rs:77-120`, whose own comment says "If we ever profile this as
hot… replacement is a min-heap"). It is real per-packet algorithm work, ~1.5-2%
of total, and touches the **selection key** — i.e. fairness-sensitive.

## 3. Disposition of the issue's four headline candidate sub-levers

The annotation refutes the umbrella doc's framing that "the dominant sub-cost is
per-packet enqueue/dequeue (~9.2%)" as *algorithmic* enqueue/dequeue work. The
dominant single line item is a **codegen stack-probe**, not the hash or the
VecDeque ops.

- **Flow-hash caching (headline candidate #1) — PLAN-KILL.** The 5-tuple hash
  (`exact_cos_flow_bucket`) lives in `account_cos_queue_flow_enqueue` (0.79%
  self-time, total across enqueue+dequeue ≤ ~1.5%) and a cold branch of
  push_back (line 132, 0.00% in the annotate). Caching a `u32` bucket index in
  `TxRequest`/`PreparedTxRequest` would: (a) save < ~1.5% best case; (b) be
  **unsound across queue boundaries** — the bucket index is
  `f(queue.flow_hash_seed, key)` and the seed is per-queue and re-drawn on every
  promotion/demotion (`cos_flow_hash_seed_from_os`), so a cached index is only
  valid for one (queue, seed) epoch; the #1735 demote/re-promote cycle and the
  `promote_to_flow_fair` re-enqueue (push.rs:80-85) silently invalidate it.
  Carrying a seed-tag to detect staleness reintroduces a compare and grows the
  already-100+-byte `CoSPendingTxItem`. Low gain, real soundness risk → KILL.
  *Note (Codex round-1):* a **safe local** reuse does exist — `cos_queue_push_back`
  currently hashes the key twice within one call (once in
  `account_cos_queue_flow_enqueue` at accounting.rs:29, once at push.rs:132) under
  the same `ff.flow_hash_seed`; these could be computed once and threaded. That is
  sound (single seed epoch, intra-call) but it is < 0.4 pp and not worth doing
  before/with the probe fix; recorded for the #4-follow-up, not this PR.

- **Structural-compare bypass in `maybe_promote_best_effort` (candidate #2) —
  PLAN-KILL.** The annotate shows the `SessionKey` compare at push.rs:50 is a
  short-circuiting SSE compare (`pcmpeqb`/`pmovmskb`, `3704…`) at **0.00%
  self-time**. It is already cheap and is on the best-effort path, not the exact
  path. The #785 hash-free contract (push.rs:19-41) is load-bearing: caching a
  hash to bypass the structural compare reintroduces exactly the hash the #1183
  fast-path was written to avoid. Negative value → KILL.

- **Descriptor-indexed queuing (candidate #3) — PLAN-KILL (scope/risk).**
  Queuing `u32` frame indices instead of `CoSPendingTxItem` is the #1545 trap
  one level up: `CoSPendingTxItem::Local(TxRequest)` owns a `Vec<u8>` (locally
  built frames, not yet in UMEM) and a `flow_key`; it is not reducible to a bare
  descriptor without re-architecting the Local-vs-Prepared admission split
  (the exact #1207 Local/Prepared asymmetry). The VecDeque ops are not the
  dominant cost (the probe is). Large blast radius, no measured win → KILL.

- **O(1) / min-heap min-bucket (candidate #4) — PLAN-DEFER.** This one is real
  (§2.3) but it is ~1.5-2% and it touches the MQFQ selection key, so it is
  fairness-sensitive and needs property-differential testing + a CoV-neutrality
  gate. It is a separate, smaller, higher-risk PR. Defer to its own follow-up
  after the §4 codegen win lands and is re-measured. Do **not** bundle it.

## 4. The chosen lever — remove the two per-packet `__rust_probestack` frames

Narrow, **fairness-neutral by construction** (it changes only where large
temporaries are materialized; it does not touch any vtime, finish-time, bucket,
active-count, V_min, or lease arithmetic, nor any classify decision).

### 4.1 Design

**Change A1 — out-line `promote_to_flow_fair`** (push.rs:77, the 352 KB
push_back probe). Add `#[cold] #[inline(never)]`. `maybe_promote_best_effort`
stays `#[inline]` (its hot path is the `is_some()` short-circuit + SSE key
compare); only the genuinely-cold `promote_to_flow_fair` body out-lines.

**Change A2 — out-line the cold builder branch of `ensure_cos_interface_runtime`**
(builders.rs, the 36 KB ingress probe; AGY round-1). Keep the `#[inline]` outer
fn doing only the `egress_ifindex <= 0` and `cos_interfaces.contains_key`
early-exits, and move the `build_cos_interface_runtime` + insert/sort tail into a
`#[cold] #[inline(never)] fn ensure_cos_interface_runtime_cold(...)`. The 36 KB
`CoSInterfaceRuntime` by-value return then lives only in the cold callee's frame,
which fires at most once per (binding, egress-ifindex) — not per packet.

Both A1 and A2 are the same #1207-reviewer-endorsed salvage direction (out-line a
cold large-stack body) and match the existing `#[cold] #[inline(never)]` sites
(`cookie_reply.rs:46`, `nat_exception.rs`, `tx/dispatch/mod.rs:17`).

**Change B — `MaybeUninit` heap constructor for `FlowFairState`** (Codex
round-1; AGY wants it mandatory). Rust has **no guaranteed placement-new into
`Box`**, so A1 alone may only *relocate* the 352 KB by-value return slot into
`promote_to_flow_fair`'s frame rather than eliminate it. On the profiled exact
path that is already sufficient (promote is build-time only), but to guarantee
the giant frame never lands on any thread's stack (and to fix the build-time
`admission.rs:526` site), add:

```rust
impl FlowFairState {
    pub(in crate::afxdp) fn new_boxed(flow_hash_seed: u64) -> Box<Self> {
        // SAFETY contract: build into an uninit heap allocation, writing
        // every field exactly once via raw ptr writes, THEN assume_init.
        // Per-field writes are mandatory — a zeroed Vec/VecDeque is NOT a
        // valid initialized representation (Codex round-1 finding 3), so
        // Box::new_zeroed + transmute is unsound. Use addr_of_mut! writes
        // for the Vec/VecDeque fields and ptr::write_bytes(0) only for the
        // [u64;N]/[u32;N] POD arrays. Drop-safety: no field is initialized
        // twice; if a future panic is introduced between writes, guard with
        // a drop-on-unwind scaffold or keep the body panic-free (it is —
        // all writes are infallible).
        ...
    }
}
```

Call `FlowFairState::new_boxed(seed)` at push.rs:79, admission.rs:526, and the
`fairness.rs`/`test_support.rs` sites. **Change B is REQUIRED, not optional**
(decision per §4.3 procedure): the by-value `new()` return slot is the actual
352 KB temporary; A1 only moves which function reserves it. Keep `new()` as a
thin `*Self::new_boxed(seed)` for any caller that genuinely needs an owned value
(tests), or delete it if unused.

**Implementation guard (Codex finding 3):** do NOT improvise Change B from a
`Box::new_zeroed + field init` sketch. Use `Box<MaybeUninit<FlowFairState>>` +
`addr_of_mut!` per-field writes + `assume_init`, miri-verified.

### 4.2 Why this is not the #1207 trap

#1207 was killed because its `#[inline(never)]` skeleton funneled the hot
submit/settle path through a fn-pointer (`callq *(reg)`) and hit E0502 aliasing.
This change does the **opposite**: it out-lines a **cold, rarely-taken**
constructor away from the hot path. There is no fn-pointer, no hot-path
indirection, no borrow restructuring. The hot path (already-promoted push_back)
ends up *shorter* (no probe loop), not longer. It is the #1207 reviewer-endorsed
salvage direction ("out-line the cold large-stack body"), applied to a different
function.

### 4.3 Expected gain + decision procedure

push_back probe = 61.4% × 5.94% ≈ **3.65 pp**; ensure_cos_interface_runtime
probe = 25.3% × 1.12% ≈ **0.28 pp**. Combined ceiling ≈ **~3.9 pp** total CPU on
this profile — the single largest reducible line item on the whole -P48 -p5210
CoS-on profile. The true number is whatever the post-change live annotate shows.

**Decision procedure (resolves Codex/SMR/AGY F1 — Change B mandatory-ness is
measured, not assumed):**
1. Land A1 + A2 alone. `objdump`/annotate `cos_queue_push_back`,
   `cos_queue_push_front`, `promote_to_flow_fair`, `ensure_cos_interface_runtime`,
   and `ensure_cos_interface_runtime_cold`.
2. If push_back has no probe and a < 1 KB frame AND no probe reappears in any
   per-packet caller → A-only is sufficient; B becomes optional cleanup.
3. If the 352 KB probe merely relocated into `promote_to_flow_fair` AND that
   function is reachable per-packet on best-effort queues (it is, on 1↔2-flow
   transitions, though rare with #1735 hysteresis), OR if any hot path still
   probes → **Change B is mandatory**, implement the `MaybeUninit` constructor.
4. Re-measure live A/B per §2 method.

**Ship gate (all three reviewers converge): ≥ 1 pp** net total-CPU reduction at
zero fairness/correctness risk is worth shipping (it's free codegen).
**PLAN-KILL-acceptable exit:** if the post-change annotate shows the probe is
genuinely irreducible (LLVM keeps the frame for an unavoidable reason) OR net win
< ~1 pp, KILL with the evidence — measured-gain gate, not a hope.

## 5. Correctness / fairness invariants preserved

- No change to any byte/finish/vtime/active-count/lease/V_min arithmetic.
- `flow_fair() == true ↔ flow_fair_state.is_some()` invariant untouched.
- Exact-queue eager promotion (admission.rs:526) path semantics identical; only
  the constructor's stack materialization site moves.
- #1735 lazy best-effort promote/demote behavior identical (`promote_to_flow_fair`
  body byte-identical, only its inline attribute changes).
- The fairness-regimes CoV contract (`docs/fairness-regimes.md`) is unaffected —
  this is a codegen-only change with zero selection-order impact.

## 6. Validation plan

1. **Differential / property tests:** the existing `push.rs`/`pop_tests.rs`/
   `tests.rs`/`v_min_tests.rs` (≈ 4800 LOC of CoS queue tests) must pass
   byte-for-byte. `promote_to_flow_fair` is exercised by the best-effort
   promotion tests; assert they still pass. No new behavior to test — assert
   absence of behavior change.
2. **Codegen proof:** post-build `objdump`/`perf annotate` of BOTH
   `cos_queue_push_back` AND `ensure_cos_interface_runtime` MUST show no
   `__rust_probestack`/`sub $0x…,%r11` loop and a small frame (target < 1 KB).
   Verify the relocated frame (if Change B is skipped) lives only in the
   `_cold` callees. miri the `new_boxed` constructor. Capture before/after into
   `evidence/`.
3. **Live A/B:** re-run the §2 method (perf record under -P48 -p5210). Gate:
   push_back self-time drops materially AND no probe re-appears elsewhere.
4. **Full CoS smoke matrix** (per repo policy): v4 + v6 × push + `-R` ×
   CoS-on + CoS-off, once-per-configured-class (5201-5211), on the loss
   userspace cluster. No throughput regression, no per-class CoV regression
   vs the structural ceiling.
5. `cargo test` (userspace-dp) + `make test` green; miri on the touched module
   if practical.

## 7. Risk register

| risk | severity | mitigation |
|---|---|---|
| LLVM re-inlines / the win doesn't materialize | med | gate on post-change annotate; KILL exit in §4.3 |
| probe relocates to `promote_to_flow_fair` but that path is hot on best-effort queues | low | best-effort promote fires once per 1↔2-flow transition with #1735 hysteresis; not per-packet. Change B removes it entirely if needed |
| `#[inline(never)]` pessimizes the cold promote path | negligible | promote is ~once per queue lifetime |
| scope creep into candidates #1-#4 | med | this plan KILLs #1-#3, DEFERs #4 to its own PR |

## 8. Scope boundary

IN:
- `userspace-dp/src/afxdp/cos/queue_ops/push.rs` — `#[cold] #[inline(never)]` on
  `promote_to_flow_fair` (Change A1).
- `userspace-dp/src/afxdp/cos/builders.rs` — split out
  `ensure_cos_interface_runtime_cold` (Change A2).
- `userspace-dp/src/afxdp/types/cos.rs` — `FlowFairState::new_boxed` `MaybeUninit`
  constructor (Change B, mandatory per §4.3 if A relocates rather than
  eliminates), and callers at admission.rs:526 / fairness.rs / test_support.rs.
- Docs: stack-probe gotcha + `#[cold] #[inline(never)]` rationale in
  `queue_ops/README.md` / module headers; the engineering-style hot-path note.

OUT: flow-hash caching, structural-compare bypass, descriptor-indexed queuing
(KILLed §3), min-bucket heap (DEFERed §3), any `TxRequest`/`CoSPendingTxItem`
schema change, any service.rs skeleton change (#1207).

## 9. PLAN-KILL conditions (explicit)

KILL the whole issue (no code) if any of:
- post-change annotate shows both probes are not removable (LLVM keeps the
  frames for an unavoidable reason) — irreducible codegen.
- removing them yields < ~1 pp net total-CPU win on the live A/B — churn > gain.
- the only remaining lever after the codegen win is candidate #4 (min-bucket),
  which is its own gated PR, so #1755 itself closes as "codegen win shipped,
  residual is #4-follow-up" rather than staying open.

## 10. Open questions for reviewers

1. Is Change A (out-line `promote_to_flow_fair`) sufficient, or is Change B
   (heap constructor) required to guarantee the by-value 352 KB return never
   lands in a hot frame after future inlining churn?
2. Is the ~2 pp net-CPU KILL gate the right bar given this is the single largest
   line item, or should it be lower (≥1 pp) because it's zero-risk codegen?
3. Should candidate #4 (min-bucket heap) be folded in now (it's the only *real*
   algorithmic per-packet cost left) or strictly deferred? Argument for defer:
   it touches the selection key and needs its own CoV-differential gate.

## 11. Recommendation

PLAN-READY for §4 (codegen stack-probe elimination) as the single tractable,
high-confidence, fairness-neutral lever. PLAN-KILL the three schema/hash
candidates (§3). PLAN-DEFER the min-bucket heap to a follow-up. This converts
the "biggest but highest-risk" framing into "the biggest line item happens to be
the lowest-risk fix, and the headline candidates are the trap."
