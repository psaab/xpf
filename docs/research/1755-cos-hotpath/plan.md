# #1755 — CoS exact-guarantee hot-path CPU reduction (Path A of #1752)

**Status: v1 (DRAFT — pending 3-reviewer round).**

**Recommendation: PLAN-READY for a single, narrow, fairness-neutral codegen
lever — eliminate the 352 KB stack-probe frame from `cos_queue_push_back`.
PLAN-KILL the issue's four headline candidate sub-levers (flow-hash caching,
structural-compare bypass, descriptor-indexed queuing) as not-the-dominant-cost
and/or fairness-perturbing — they are the #1207/#1545 trap. One secondary lever
(O(1)/heap min-bucket) is PLAN-DEFER pending its own measured case.**

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

## 4. The chosen lever — remove the 352 KB stack-probe frame from `cos_queue_push_back`

Single, narrow, **fairness-neutral by construction** (it changes only where a
352 KB temporary is materialized; it does not touch any vtime, finish-time,
bucket, active-count, V_min, or lease arithmetic).

### 4.1 Design

Two complementary, independently-validatable changes; ship the minimal one that
the post-change annotate proves sufficient.

**Change A (primary): `#[inline(never)]` on `promote_to_flow_fair`** (push.rs:77).
Pulls the `FlowFairState::new()` by-value return frame out of
`cos_queue_push_back` into `promote_to_flow_fair`'s own (cold, ~once-per-queue)
frame. `maybe_promote_best_effort` stays `#[inline]` (its hot path is just the
`is_some()` short-circuit + the SSE key compare); only the genuinely-cold
`promote_to_flow_fair` body is out-lined. Add `#[cold]` to match the existing
`cookie_reply`/`nat_exception` pattern.

**Change B (belt-and-suspenders, only if A alone doesn't clear the probe):**
give `FlowFairState` a `Box`-returning constructor that builds the arrays
directly on the heap and avoids the 352 KB by-value stack return entirely
(`Box::new_zeroed` + field init, or per-field heap init). This removes the giant
frame from `promote_to_flow_fair` and `admission.rs:526` too, not just relocates
it. Lower priority because the build-time site is off the hot path and Change A
already gets the hot-path win; include only if the post-A annotate still shows a
probe in any hot caller.

### 4.2 Why this is not the #1207 trap

#1207 was killed because its `#[inline(never)]` skeleton funneled the hot
submit/settle path through a fn-pointer (`callq *(reg)`) and hit E0502 aliasing.
This change does the **opposite**: it out-lines a **cold, rarely-taken**
constructor away from the hot path. There is no fn-pointer, no hot-path
indirection, no borrow restructuring. The hot path (already-promoted push_back)
ends up *shorter* (no probe loop), not longer. It is the #1207 reviewer-endorsed
salvage direction ("out-line the cold large-stack body"), applied to a different
function.

### 4.3 Expected gain

If the probe is fully removed and push_back's remaining self-time tracks its
non-probe instructions, push_back drops from 5.94% toward ~2.3% self-time — a
**~3.6 percentage-point** total-CPU reduction on this profile (≈ the single
largest line item on the whole -P48 -p5210 CoS-on profile). This is the honest
ceiling for Change A alone; the true number is whatever the post-change live
annotate shows. **PLAN-KILL-acceptable exit:** if the post-change annotate shows
the probe re-appears in another hot caller (push_front, or an inlined service
path) such that net total CPU does not drop ≥ ~2 pp, or if LLVM reorganizes and
the win evaporates, KILL with the evidence — this is a measured-gain gate, not a
hope.

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
2. **Codegen proof:** post-build `objdump`/`perf annotate` of
   `cos_queue_push_back` MUST show no `__rust_probestack`/`sub $0x…,%r11` loop
   and a small frame (target < 1 KB). Capture before/after into `evidence/`.
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

IN: `userspace-dp/src/afxdp/cos/queue_ops/push.rs` (inline attrs), optionally
`userspace-dp/src/afxdp/types/cos.rs` (`FlowFairState` Box constructor) for
Change B. Docs: a note in `queue_ops/README.md` (or the module header) recording
the stack-probe gotcha + the `#[cold] #[inline(never)]` rationale.

OUT: flow-hash caching, structural-compare bypass, descriptor-indexed queuing
(KILLed §3), min-bucket heap (DEFERed §3), any `TxRequest`/`CoSPendingTxItem`
schema change, any service.rs skeleton change (#1207).

## 9. PLAN-KILL conditions (explicit)

KILL the whole issue (no code) if any of:
- post-change annotate shows the probe is not removable (LLVM keeps the 352 KB
  frame for an unavoidable reason) — irreducible codegen.
- removing it yields < ~2 pp net total-CPU win on the live A/B — churn > gain.
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
