# #1920 — poll_descriptor/mod.rs over the 2000-LOC modularity threshold

**Revision:** v1 (research draft, pre-review)
**Branch:** `research/1920-poll-descriptor-split` (off origin/master `62c1ddc66`)
**Status:** RESEARCH — PLAN-KILL is an explicitly-allowed outcome.
**Target:** `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, 3122 file lines /
3054 production LOC (the `#[cfg(test)] mod` begins at line 3055).

> Reviewers: this is the single hottest loop in the dataplane. The audit's
> proposed shape (`rx/parser/decap/forward/retry/tx`) is **the exact split
> that was PLAN-KILLED twice already** (#946 Phase-2 and the #1327 stages-12+
> verdict). Read §3 and §4 before §6 — the central question is not "how to
> split" but "is ANY non-cosmetic split available, and is it worth the churn
> on the hottest loop." Do not soft-pass.

---

## 1. Issue framing

`poll_binding_process_descriptor` (lines 110–3054) is a single ~2945-LOC
function whose body is one `while let Some(desc) = received.read()` loop. The
audit (agy-010 Part II.1) flagged the file at 2858 LOC; it has since regrown to
3054 production LOC. The audit proposed
`poll_descriptor/{mod.rs, rx.rs, parser.rs, decap.rs, forward.rs, retry.rs,
tx.rs}` and asserted the split "reduces L1-i thrashing."

The file already underwent **two** prior decomposition efforts:

- **#1327** (`6b9989f96`, dropped flat file → directory module): extracted the
  hot flow-cache fast path into `flow_cache_hit::stage_flow_cache_hit`
  (`#[inline(always)]`, `cargo asm` proven to emit no `call` edge), and earlier
  #946 Phase-1 extracted 7 early stages into `poll_stages.rs`. The #1327 plan's
  recorded verdict: **"Step 1 is the structural ceiling"** — 5 stage-12+
  extraction candidates evaluated, **all blocked by mutable-locals coupling**;
  the matrix is preserved in `docs/pr/1327-poll-descriptor-stages/plan.md`.
- **#1697** (`6b9989f96` merge `#1704`, dropped mod.rs 2858→2437): extracted
  the COLD/exception bodies — `cookie_reply.rs`, `nat_exception.rs`,
  `filter.rs` — using `#[cold] #[inline(never)]` placement so the hot loop's
  bytes are not interleaved with rare exception code. The #1697 plan explicitly
  states the **#946 Phase-2 PLAN-KILL** — *"the loop is order-coupled and
  cannot be split"* — and notes **"PLAN-KILL if the only available split is
  cosmetic file-motion of the hot path."**

So #1920 is the third pass at the same file. The file regrew +685 production
lines since #1697 (2437 → 3122 file lines), **entirely from feature work inside
the order-coupled hot loop body**: #1861 (transactional forward+reverse session
install), #1852 (fragment-aware NAT), #1885/#1902 (decap-aware LocalDelivery),
#1912 (MissingNeighbor outer-hop rekeying), #1913 (policy-deny gating). None of
this is new self-contained cold surface that the #1697 mechanism could lift.

## 2. The perf claim — REFUTED, dropped

The audit's **"reduces L1-i thrashing"** claim is **false as stated and is
dropped from this plan.** Splitting `.rs` files *within the same crate* does
not by itself change codegen: LLVM inlines across modules in the same crate/CGU
under the project's release profile. Module boundaries are a source-organization
construct, not a codegen boundary. The only mechanisms that move bytes out of
the hot loop's I-cache footprint are inlining *hints*
(`#[inline]`/`#[inline(always)]`/`#[inline(never)]` + `#[cold]`), and those are
applied to *functions*, independent of which file the function lives in. #1697
already applied that discipline to the cold exception bodies.

Therefore this plan makes **no perf claim**. Any extraction here is
**modularity-only** and must be proven **codegen-NEUTRAL** (§7). This is the
honest framing the issue demands. A plan that ships an unproven I-cache win is
itself a PLAN-KILL signal.

## 3. Why the audit's proposed shape is not viable

The proposed `rx/parser/decap/forward/retry/tx` boundaries imply extracting
*sections of one loop iteration's body* into helper functions. The loop body is
**order-coupled** and **mutable-locals-coupled**, which makes those sections
non-liftable as pure code-motion:

### 3.1 `continue` is loop control, not block exit

There are 21 `continue;` sites in the loop body, at indent depths 24–52 (deeply
nested inside `match`/`if let` arms). `continue` is loop control — it cannot
survive a move into a separate function. Extraction forces converting every
`continue` into a control-flow enum return (`Consumed`/`FallThrough`) that the
caller re-dispatches, exactly as #1327 did for the *one* block that was cleanly
liftable. That conversion is **logic-bearing restructuring, not code-motion** —
it violates the issue's "pure code-motion increments" requirement for every
section except a genuinely self-contained `continue`-terminated block.

### 3.2 The mutable-locals web

After the flow-cache fast path the slow path is a single expression
`let mut decision = if let Some(flow) … { … }` (line 295+) that threads these
`let mut` locals through the rest of the iteration, each written in one region
and **read after** in a later region:

| Local | Init | Written | Read-after (blocker) |
|---|---|---|---|
| `decision` | 295 | 445, 728–760, 1731, 1754 | 1002, 1070, 1152, 1348+, 2061+ (forward build), 2145+ (cache) |
| `flow_cache_owner_rg_id` | 286 | 358, 741, 1065, 1804 | 1070, 1152, 1708 |
| `session_ingress_zone` | 285 | 357, 830 | 813, 1071 |
| `apply_nat_on_fabric` | 287 | 359 | 1072, 1163 |
| `flow_cache_install_failed` | 294 | 318, 1585 | 1145 (gates cache insert) |
| `debug` | 282 | 354, 829, 1065 | 382, 992 |
| `meta` | 136 | 193 (`&mut`) | ubiquitous, 197+ |
| `owned_packet_frame` | 164 | 262, 521, 2078 (`.take()`) | 166, 280, 1072, 2078 |

Any `forward`/`parser`/`decap` boundary cuts through this web: the extracted fn
would have to take `&mut` to several of these AND return several of them, which
(a) is a borrow-checker minefield (#1327 v2→v3 already hit `&mut BindingWorker`
won't compile because `binding.xsk.rx.receive()` holds a live borrow — the fix
was to pass disjoint sub-struct fields, which only worked for the *one*
flow-cache block), and (b) is not code-motion. This is the #1327 verdict and the
#946 Phase-2 verdict restated against the current file.

### 3.3 Independent confirmation

An independent hostile read of the full loop body (instructed to *prove
blockers, not assume liftability*) evaluated 9 candidate regions
(A=DNAT/NAT64 pre-routing 558–614, B=input-filter/route-table 649–675,
C=HA resolution 676–710, D=session-hit policy/zone 757–832,
E=local-delivery caching 849–912, F=embedded-ICMP NAT reversal 913–1058,
G=session-miss decision-build 1062–1156, H=session-miss install 1145–1700,
I=flow-cache population 2134–2169). **Verdict on all nine: BLOCKED-BY-COUPLING
or COSMETIC-ONLY.** The strongest candidate (F, embedded-ICMP, self-contained
control flow) still fails because it conditionally mutates `recycle_now` then
falls through, so the caller's epilogue must preserve it — not a clean
`Consumed`/`FallThrough` boundary. The flow-cache population (I) reads
`flow_cache_install_failed` set 1000+ lines earlier — the cache decision is not
local to the cache block. **Nothing cleanly liftable remains.**

## 4. The only honest non-KILL path: narrow #1697-style cold extraction

If reviewers want a non-KILL outcome, the *only* defensible one is a repeat of
the #1697 mechanism on **NEW cold surface added since #1697** — NOT a hot-loop
split. One candidate exists:

- **The MissingNeighbor arm (≈ lines 2397–2620, ~220 LOC, #1651/#1769/#1771/
  #1912).** This is a cold per-packet path (only runs on a forwarding decision
  whose next-hop neighbor is unresolved — i.e. session-miss + ARP/NDP-pending).
  It does the dead-host fast-fail gate, OUTER-hop neigh keying, kernel ARP
  probe, #1769 resolver enqueue (throttled), and the #1771 §2.2 per-key
  pending_neigh buffer admission, then `continue`. It already calls the
  `try_enqueue_resolver` module-local helper (lines 80–110).

  **Liftability assessment (must be proven, not assumed, in the engineer
  phase):** the arm reads `decision`, `meta`, `binding.pending_neigh`,
  `binding.resolver_enqueue_throttle`, `worker_ctx`, and computes its own locals
  (`next_hop`, `neigh_if`, `outer_if_distinct`, `tunnel_marked`,
  `throttle_key`). It is `continue`-terminated (it does not fall through to the
  forward/reinject tail on the buffered path). **IF** its only outward write is
  through `binding` sub-fields + scratch (not the `decision`/`flow_cache_*`
  locals read by the tail), it is a `#[cold] #[inline(never)]` extraction
  candidate in the #1697 mold. **IF it writes any of the §3.2 tail-read locals,
  it is BLOCKED** — and then there is no non-KILL path and the plan is a KILL.

  This extraction would move ~220 cold lines, dropping mod.rs to ~2835 LOC —
  **still over the 2000 threshold and barely under the audit's original
  2858.** That is the crux of the cost/benefit the reviewers must weigh: a
  high-risk touch of the hottest loop for a sub-threshold modularity win that
  does not even clear the bar that triggered the issue.

## 5. Recommendation (author's pre-review position): PLAN-KILL

The author's position entering review is **PLAN-KILL**, for these reasons:

1. The audit's proposed shape is the twice-killed hot-loop split (§3); it is not
   pure code-motion and is a borrow-checker / logic-bearing restructure.
2. The perf premise is false (§2); the win is modularity-only.
3. The only non-cosmetic remaining extraction (the MissingNeighbor cold arm,
   §4) (a) may itself be coupling-blocked, and (b) even if liftable, leaves the
   file at ~2835 LOC — **still over threshold**, so it does not resolve the
   issue, it just shaves it. A modularity refactor that doesn't clear the
   modularity threshold is not worth touching the hottest loop in the
   dataplane.
4. The file's regrowth is feature-driven (#1861/#1852/#1885/#1912/#1913), all
   inside the order-coupled body. The right long-term answer is a *unified
   decision-pipeline state machine* refactor (the #1327 "far larger
   undertaking" note) — that is a design project with its own risk budget and
   smoke matrix, not a file-split, and should be its own issue if pursued.

**PLAN-KILL is not a failure of this research — it is the correct, evidence-
backed outcome consistent with the #946 and #1327 verdicts.** The threshold
heuristic (`docs/engineering-style.md`) is explicitly *"a smell,"* not a
mechanical mandate to split a function whose decomposition is architecturally
blocked.

## 6. Multiple-path options (for reviewer adjudication)

- **Path A — PLAN-KILL (author's recommendation).** Close #1920 not-planned
  per the plan-kill protocol; record the §3/§4 evidence and the standing #946/
  #1327 verdicts in the close comment; if the unified-pipeline refactor is ever
  desired, file it as a NEW design issue with its own smoke budget.
- **Path B — narrow MissingNeighbor cold extraction (only if §4 liftability is
  PROVEN codegen-neutral).** One commit, `#[cold] #[inline(never)]` sibling
  module `retry.rs` (the one audit name that maps to a real cold block), the
  arm moved verbatim, `objdump`-proven that the hot loop's bytes are unchanged
  and that the cold body is now a `call` edge (no inlining back in). Accept that
  the file stays > 2000 LOC and the issue is only *reduced*, not *resolved*.
  This path is defensible ONLY if all four reviewers agree the modularity/cold-
  surface win justifies the hot-loop touch despite not clearing threshold.
- **Path C — REJECTED.** The audit's full `rx/parser/decap/forward/tx` split.
  Refuted in §3; do not pursue.

## 7. Codegen-neutrality bar (binding on Path B if chosen)

Per the #1755 codegen-proof discipline (`objdump` the local release binary —
`perf annotate` over `incus exec` returns empty without a TTY):

1. Build base and post-extraction release binaries:
   `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build --release`.
2. `objdump -d --no-show-raw-insn` the symbol for
   `poll_binding_process_descriptor` (and `try_enqueue_resolver`) before vs
   after; the hot-loop body must be byte-identical except for the moved cold
   arm becoming a `call <retry::…>` edge.
3. `nm --print-size --size-sort` the extracted cold fn must appear as its own
   symbol (proves `#[inline(never)]` took — no inlining back into the hot CGU).
4. No new bounds checks, no stack-frame growth on the hot fn, no `__rust_-
   probestack` introduced (verify with `objdump | grep probestack` on the hot
   symbol).
5. **If any of 2–4 regresses and cannot be neutralized, Path B becomes a
   PLAN-KILL.**

## 8. Test plan (binding on Path B)

- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build --release` clean.
- `cargo test --release` — full userspace-dp suite.
- 5× flake run on `poll_descriptor::*` and any neighbor/resolver tests
  (`try_enqueue_resolver_tests`, pending_neigh, neighbor_resolver_*).
- `go test ./pkg/dataplane/userspace/`.
- Full smoke matrix is parent-coordinated (serialized loss cluster): v4+v6 ×
  push+reverse × CoS-off+on + per-class. This IS the forwarding path — no
  exceptions. Because Path B touches the MissingNeighbor/ARP-pending cold path,
  the smoke must specifically exercise a cold-connect (fresh ARP) flow, not just
  warm steady-state iperf3.

## 9. Risks

- **Hot-loop codegen regression** (Path B): the moved arm's locals
  (`next_hop`, `neigh_if`, computed mid-arm) must survive the move without the
  compiler re-laying-out the hot fn's frame. Mitigated by §7 objdump gate; an
  unfixable regression = KILL.
- **Borrow-checker split** (Path B): the arm holds `&mut binding.pending_neigh`
  + `&mut binding.resolver_enqueue_throttle` while the outer loop holds
  `binding.xsk.rx.receive()`'s borrow (the #1327 v3 trap). The extracted fn must
  take disjoint sub-struct fields, not `&mut BindingWorker`.
- **Sub-threshold result** (Path B): leaves file > 2000 LOC; does not resolve
  the issue. This is itself an argument for Path A.
- **Smoke flake on the cold path**: cold-connect/ARP timing is noisier than warm
  iperf3 (see #1769/#1782); a transient cold-connect blip must be distinguished
  from a real regression (≥3× repro per `feedback_runnable_repro_before_…`).

## 10. Reviewers

3-way hostile plan review: Codex + AGY + Claude SMR. The plan-KILL recommendation
must be *attacked* (is there a liftable block §3 missed? is §4 actually
liftable, making Path B viable and §5 wrong?), not rubber-stamped. Convergence
on Path A (KILL) or Path B (proven-liftable narrow extraction) is the exit.

## 11. Decision log

- v1 (this doc): author recommends **PLAN-KILL (Path A)**. Perf claim refuted
  and dropped. Audit shape (Path C) refuted via §3 + independent hostile read.
  Path B (narrow MissingNeighbor cold extraction) surfaced as the only non-KILL
  option but flagged sub-threshold and possibly coupling-blocked — pending
  reviewer adjudication of §4 liftability.
