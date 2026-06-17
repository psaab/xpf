# #1920 — poll_descriptor/mod.rs over the 2000-LOC modularity threshold

**Revision:** v3 (CONVERGED — 3-way PLAN-KILL: Codex PLAN-KILL-CORRECT,
Claude SMR PLAN-KILL-CORRECT, AGY PLAN-KILL-CORRECT after round-2 withdrawal
of its round-1 PLAN-NEEDS-WORK dissent)
**Branch:** `research/1920-poll-descriptor-split` (off origin/master `62c1ddc66`)
**Status:** RESEARCH COMPLETE — **PLAN-KILL (Path A)**, 3-way converged.
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
dropped from this plan.** Splitting `.rs` files *within the same crate* does not
by itself change codegen. Module boundaries are a source-organization construct,
not a codegen boundary: the function `poll_binding_process_descriptor` compiles
to the same symbol whatever file it lives in. The only mechanism that moves
bytes out of the hot loop's I-cache footprint is the inlining *hint*
`#[cold] #[inline(never)]` applied to a genuinely-cold *function* — which is
**orthogonal to a file split** (you can apply it without moving the file, and
moving the file does nothing without it). #1697 already applied that discipline
to the cold exception bodies. So the audit's "L1-i" rationale is a non-sequitur:
the file split is not the lever.

(Round-1 precision, Codex: do NOT argue this from "same CGU / LLVM inlines
across modules." The production profile has **no `[profile.release]`** in
`userspace-dp/Cargo.toml` and no workspace-root profile, so `codegen-units`
is the default **16** and LTO is **off** — an unannotated cross-module call is
NOT guaranteed to inline. AGY's round-1 counter-claim that `codegen-units=1`
forces thinLTO is factually wrong; verified against `userspace-dp/Cargo.toml`
and `Makefile:44`. The refutation stands on the orthogonality argument above,
not on any CGU-count assumption.)

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

## 4. The candidate non-KILL path — evaluated and BLOCKED

The `/research` framing asked whether a #1697-style cold extraction of **NEW
cold surface added since #1697** (NOT a hot-loop split) could be a non-KILL
Path B. Two candidates were proposed and BOTH are blocked on the actual source
(adjudicated round-1: AGY claimed both liftable; Codex + Claude SMR refuted both
by reading the code):

- **The MissingNeighbor arm (#1651/#1769/#1771/#1912) — BLOCKED.** The arm is a
  `match` arm opening at **line 2242** (not 2397; AGY's narrow 2397–2620 slice
  is hand-picked to start *after* the coupling). At the arm top it computes
  `(from_zone_id, to_zone_id)` (2248+) and runs the #1913 policy-deny gate which
  **writes `decision.resolution.disposition = PolicyDenied` at 2374–2375** then
  `continue` at 2388 — a write to a §3.2 tail-read local. The full arm
  (2242–2981, ~740 LOC) is **non-terminal**: it falls through into the shared
  disposition/reinject tail that reads `decision.resolution` (2989), `meta`
  (2991), re-checks `decision.resolution.disposition` (3006), and feeds
  `meta`/`decision` into `maybe_reinject_slow_path_from_frame` (3013–3014), with
  `recycle_now=false` set mid-arm (2959). Extracting it requires a return-value
  redesign that re-dispatches the disposition + recycle state — that is
  logic-bearing restructuring, NOT code-motion. BLOCKED.

- **The embedded-ICMP NAT-reversal block (Region F, 913–1062) — BLOCKED.** This
  is the `if is_embedded_icmp_error { … }` half of an `if / else if` chain whose
  sibling (`} else if decision.resolution.disposition == ForwardCandidate {` at
  1062) immediately writes `flow_cache_owner_rg_id` (1066). The `if` body reads
  `flow`/`meta`/`from_zone`/`to_zone`/`decision`, conditionally mutates
  `recycle_now`, and **falls through** ("fall through to slow-path", 1059–1061).
  Extracting one branch of an if/else-if behind an outcome enum is again
  logic-bearing restructuring. BLOCKED / COSMETIC.

- **LOC arithmetic (Codex correction).** Even setting coupling aside: removing
  the *whole* MissingNeighbor arm (740 LOC) leaves ~2313 production LOC; removing
  the narrow 224-line slice leaves ~2829. **No achievable boundary clears the
  2000-LOC threshold** that triggered the issue. A modularity refactor that
  cannot resolve the modularity threshold — at the cost of a high-risk touch of
  the hottest dataplane loop and a logic-bearing if/else restructure — is not a
  defensible trade. **There is no viable Path B.**

## 5. Recommendation (author's pre-review position): PLAN-KILL

The author's position entering review is **PLAN-KILL**, for these reasons:

1. The audit's proposed shape is the twice-killed hot-loop split (§3); it is not
   pure code-motion and is a borrow-checker / logic-bearing restructure.
2. The perf premise is false (§2); the win is modularity-only.
3. Both candidate cold extractions (MissingNeighbor arm; embedded-ICMP block,
   §4) are **coupling-blocked** — each writes a §3.2 tail-read local and/or is a
   non-terminal branch of an if/else-if chain, so extraction is a logic-bearing
   return-value redesign, not code-motion. And even ignoring coupling, **no
   achievable boundary clears the 2000-LOC threshold** (§4 LOC arithmetic), so
   no extraction *resolves* the issue. A modularity refactor that cannot clear
   the modularity threshold is not worth touching the hottest loop in the
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

- **Path A — PLAN-KILL (converged recommendation).** Close #1920 not-planned
  per the plan-kill protocol; record the §3/§4 evidence and the standing #946/
  #1327 verdicts in the close comment; if the unified-pipeline refactor is ever
  desired, file it as a NEW design issue with its own smoke budget.
- **Path B — narrow cold extraction (MissingNeighbor or embedded-ICMP).
  CLOSED.** Round-1 adjudication (Codex + Claude SMR against the source) proved
  both candidate blocks are coupling-blocked (write a §3.2 tail-read local /
  non-terminal if-else-if branch), and that no boundary clears the 2000-LOC
  threshold anyway (§4). Not viable.
- **Path C — REJECTED.** The audit's full `rx/parser/decap/forward/tx` split.
  Refuted in §3; the twice-killed hot-loop decomposition.

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

- v1: author recommended **PLAN-KILL (Path A)**. Perf claim refuted and dropped.
  Audit shape (Path C) refuted via §3 + independent hostile read. Path B (narrow
  cold extraction) surfaced as the only non-KILL option, flagged sub-threshold
  and possibly coupling-blocked — pending reviewer adjudication.
- v2 (round-1 convergence): **Codex `019ed638-…` → PLAN-KILL-CORRECT** (+2
  factual corrections, both applied). **Claude SMR r1 → PLAN-KILL-CORRECT**
  (adjudicated the Codex/AGY conflict against the source). **AGY
  `adversarial-review-mqi8dngo-clmkj8` → PLAN-NEEDS-WORK (reject-kill, expand
  Path B) — REFUTED on the code**: AGY's two "cleanly liftable" blocks both
  write a §3.2 tail-read local / are non-terminal if-else-if branches (§4), and
  AGY's `codegen-units=1`/thinLTO premise is factually false (§2,
  `userspace-dp/Cargo.toml` has no profile → default `codegen-units=16`, LTO
  off). Net: 2-of-3 reviewers KILL-CORRECT; AGY's dissent rests on two
  source-refuted claims. **Converged outcome: PLAN-KILL (Path A).** Path B
  closed; no boundary clears the 2000-LOC threshold and both candidates are
  coupling-blocked.
