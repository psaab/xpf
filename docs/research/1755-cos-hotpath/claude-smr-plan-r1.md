# Claude SMR hostile plan review — #1755 v1 (round 1)

Reviewing as domain SMR (CoS scheduler), CPU-architecture, and SW-design
reviewer. Hostile posture: try to break the plan, not confirm it.

## Verdict: PLAN-READY (with two findings to address in v2)

The plan correctly refuses the umbrella doc's candidate list and instead
annotates to a concrete reducible op. The core finding is sound and I
independently re-derived it from the evidence.

## What I verified

1. **The probe is real and dominant.** `evidence/pushback-annotate.txt`:
   `sub $0x56000,%r11` + the `sub $0x1000,%rsp` / `movq $0x0,(%rsp)` /
   `cmp %r11,%rsp` loop carrying 10.98+7.23+43.23 = 61.4% of push_back's
   local samples. This is unambiguously `__rust_probestack` for a 352 KB
   frame. Not a misread.

2. **The control is clean.** push_front = 0x58 frame, no probe
   (objdump). The only structural delta is the promotion path. Attribution
   is airtight — this is rare for a perf finding and is the plan's strength.

3. **The exact path never promotes at runtime.** admission.rs:526 eager
   promote at build; push.rs:44 short-circuits on `is_some()`. So on the
   profiled path the 352 KB frame is 100% dead weight. Confirmed.

4. **Fairness-neutrality.** Change A moves only where a temporary is
   materialized. No selection/vtime/finish arithmetic touched. The
   `flow_fair ↔ is_some` invariant is untouched. I cannot construct a CoV
   or correctness perturbation from an inline-attribute change on a cold
   constructor. This is genuinely the lowest-risk lever on the whole
   #1752 umbrella.

5. **Not the #1207 trap.** #1207 died on hot-path fn-ptr indirection +
   E0502. This out-lines a cold body; the hot path gets *shorter*. Opposite
   hazard class. Correct.

## Findings

### F1 (MAJOR → must verify before /engineer, not a KILL): RVO / NRVO may already defeat Change A

`FlowFairState::new()` is a separate symbol (`nm` shows it un-inlined). The
352 KB frame in push_back is the *caller-side* slot for `new`'s by-value
return that is then moved into `Box::new(...)`. `#[inline(never)]` on
`promote_to_flow_fair` relocates the *call* but the return-slot for
`FlowFairState::new` still has to live *somewhere* — and if LLVM places the
`Box::new` allocation + the `new()` return-slot in `promote_to_flow_fair`'s
frame, Change A works; if the move is elided into the heap allocation
directly, even better. BUT there is a real chance the current codegen is
push_back reserving the slot precisely because `Box::new(new())` does NOT
get placement-RVO into the heap box (Rust has no guaranteed placement-new).
In that case Change A relocates the probe to `promote_to_flow_fair` (cold,
fine for exact, but fires on best-effort 1↔2-flow transitions). The plan
already flags this as the Change-B trigger — good — but the v2 should state
the **decision procedure explicitly**: build with Change A only, annotate,
and if any hot caller still probes, Change B (heap constructor) is
mandatory, not optional. The "ship the minimal one" framing understates
that Change B may be the only one that actually works. Sharpen §4.1.

### F2 (MINOR): the ~2 pp KILL gate vs the headline "19%"

The issue is sold as a ~19% lever; this plan delivers ~3.6 pp from the
single biggest line item and KILLs the rest. That is the honest outcome and
the plan says so, but the §9 KILL condition "< ~2 pp net win → KILL the
whole issue" is slightly too aggressive for a *zero-risk* codegen change.
If it lands 1.5 pp at zero fairness/correctness risk, that is still worth
shipping. Recommend: lower the ship bar to ≥1 pp for the codegen change
specifically (it's free), and reserve the "KILL the issue" language for the
case where the probe is genuinely irreducible (0 pp). The plan's Q2 already
asks this — resolve it toward ≥1 pp.

### F3 (NIT): candidate #4 deferral is correct but document the residual

After the codegen win, the min-bucket O(N) scan (§2.3, ~1.5-2%) is the
largest *algorithmic* residual and the only thing matching the issue's
original "per-packet enqueue/dequeue" framing. The plan defers it correctly
(it touches the selection key → needs a CoV-differential gate). Make sure
the closing #1755 comment files the min-bucket heap as an explicit
follow-up issue so the residual isn't lost.

## Bottom line

PLAN-READY. The lever is correct, the attribution is unusually airtight, and
the KILL of the headline candidates is well-evidenced (the flow-hash
per-queue-seed soundness argument alone is decisive). Address F1 (make
Change B's necessity a measured decision, not optional) and F2 (≥1 pp ship
bar for free codegen) in v2.
