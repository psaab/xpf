# Claude SMR — Hostile Plan Review R1: #4404 poll_descriptor decomposition

Reviewing `docs/research/4404-polldesc-decompose/plan.md` v1 against
`origin/master` `03a92b49c`. Adversarial posture: try to kill it; pass only what
survives.

## VERDICT (R1): PLAN-NEEDS-REVISION → PLAN-READY on v2

The **cold-arm scope is sound and the gate is precedent-backed**, so I do **not**
kill it. But v1 has **one dispositive design error** (F1) that makes the §5.3
signatures un-compilable as written, and two under-specifications (F2, F3) that
must be fixed before this is handed to `/engineer`. With F1–F3 addressed the
plan is PLAN-READY for inc A–C. Phase 3 remains correctly PLAN-KILL-acceptable.

## F1 (BLOCKING) — §5.3 signatures are wrong: the arms contain `continue`, so they cannot return a bare `SessionDecision`

I bucketed all 35 `scratch_recycle.push(desc.addr)` sites by arm. They are **not
centralizable in the caller** as §7.1 claims — they live *inside* the arms:

- SESSION-MISS (1374–3580): **14** push sites (1389, 1404, 1640, 1783, 1807,
  2044, 2100, 2253, 2279, 2319, 2799, 2887, 2988, 3086)
- MissingNeighbor (4369–5411): **4** (4625, 4726, 4840, 5088)
- FLOWLESS/glue (3581–3908): **5**; SESSION-HIT: **4**

Every sampled site is the pattern `scratch_recycle.push(desc.addr); continue;` —
an early **drop-and-advance-to-next-descriptor** exit (verified at 1389, 1640,
2253, 2799, 3086, 4625, 5088). An extracted `fn resolve_session_miss(...) ->
SessionDecision` **cannot `continue` the caller's `while let` loop** — this does
not compile. §5.3 as written is invalid.

**Required fix (v2):** extracted cold-arm fns must return a control-flow enum,
e.g.
```rust
pub(super) enum ArmOutcome {
    DropRecycle,               // caller: scratch_recycle.push(desc.addr); continue;
    Proceed(SessionDecision),  // caller: fall through to forward-build
}
```
and each in-arm `push(desc.addr); continue;` becomes `return
ArmOutcome::DropRecycle;`. The **only** push+continue site after extraction is
the caller's single `match outcome { DropRecycle => { push; continue } }`.

**This actually *strengthens* the single-recycle story** (§7.1 should be
rewritten): post-extraction the recycle push is centralized to *one* caller
site, so the invariant becomes *more* auditable, not less — the opposite of
what v1 §7.1 implies. BUT the transformation of the 18 in-arm drop exits into
`return DropRecycle` is a **non-trivial, must-be-exhaustive** rewrite: a single
missed site = a leaked or double-recycled descriptor with **no unit test** to
catch it. v2 must (a) list this as an explicit audited step, (b) note the 4
`recycle_now = false` handoffs (2568, 2930, 4276, 5375) are the *fall-through*
(not `continue`) drop paths and map to a **third** `ArmOutcome` variant
(`ProceedNoRecycle` / a `recycle` flag on `Proceed`) — v1 misses this entirely.

## F2 (MAJOR) — the `recycle_now = false` fall-through paths are unaccounted for

There are 4 `recycle_now = false` sites (2568, 2930 in SESSION-MISS; 4276 in
FORWARD-BUILD; 5375 in MissingNeighbor). These are drops that **fall through to
the epilogue** (`if recycle_now { push }`) rather than `continue`-ing — i.e. the
descriptor's frame was *handed off* (e.g. pushed to `scratch_forwards` as a
rewritten forward, or buffered in a pending-neighbor slot) and must **not** be
recycled. 2930 and 4276 sit right after `scratch_forwards.push(request)` (the
forward was enqueued; the frame is owned by TX now). The `ArmOutcome` enum in F1
must model this ownership-transfer case distinctly from `DropRecycle`, or the
extraction will either double-free (recycle a frame handed to TX) or leak. v1's
model (`recycle_now` mutated by arms, push in caller) is closer for *these* 4
sites than for the 18 `continue` sites — so the correct v2 design is a **hybrid**
the plan must state explicitly, not the uniform "push stays in caller" of §7.1.

## F3 (MAJOR) — the borrow spike (Q1) must gate inc B *before* PLAN-READY is claimed for it, and F1 makes it harder

The `ArmOutcome::Proceed(SessionDecision)` return + `&mut binding` + `&mut
sessions` + `&mut ctx` param set is *more* borrow-contended than v1's §5.2
assumed, because the arm now both mutates `binding.scratch.scratch_forwards`
(the forward push at 2929/3086-area) **and** installs into `sessions`
(`install_with_protocol_with_origin` at 1462, 3046, 3324) **and** reads
`worker_ctx.forwarding`. v1 §7.3 flags this but then §1 declares PLAN-READY for
inc B anyway. That is inconsistent: **inc B cannot be declared implementable
until the compile spike (Q1) passes.** v2 should downgrade inc B to
"PLAN-READY-pending-spike" and make inc A (FLOWLESS — fewest install/forward
sites, existing test seam) the only unconditionally-ready increment.

## F4 (MINOR, accept) — cold classification is CORRECT

I independently confirm the arms are genuinely cold, *not* the #4409(b)
amortized-hot trap: established flows exit at `stage_flow_cache_hit` (870) →
`continue`, so SESSION-MISS/MissingNeighbor/FLOWLESS run **per-new-flow /
per-neighbor-miss**, never per-packet on an established stream. The plan's
distinction from #4409(b) (§8, §10) is valid: #4409(b) died because
`gc_expired_chunked` ran on *every* allocate; nothing here is per-packet-on-hit.
This is the crux that keeps the plan alive, and it holds.

## F5 (MINOR, accept) — the gate is credible but the plan must name the asm symbol resolution risk

The `cargo asm` hot-BB-diff is the #1697-shipped gate, so it is not hand-waving.
BUT: `poll_binding_process_descriptor` is `pub(super)` with one caller and may
be **inlined into that caller**, so `cargo asm poll_binding_process_descriptor`
may not resolve a standalone symbol. #1697 hit and solved this (Q2 acknowledges
it). v2 should state the fallback (`objdump -d` on the release `.o`, or a
`#[inline(never)]` pin on the loop fn *for the asm-capture build only*) so the
gate is executable on day one, not discovered mid-inc-B. Not blocking, but name
it.

## F6 (accept) — value framing is honest

v1 correctly refuses to promise a runtime/binary win (no LTO, cu=16) and rests
on navigability/auditability + the §9 zero-throughput gate. It also honestly
states the fn only falls to ~1,300 LOC (still >threshold-for-one-fn but a 73%
cut and −3,200 cold LOC from the hot CGU). I accept this as sufficient value
*given the gate guarantees zero regression* — the downside is bounded to
reviewer time. A reviewer who weights "readability-only = never worth hot-path
risk" would KILL here; I do not, because (a) #1697 is a *shipped* project
precedent that a cargo-asm-gated cold-outline of THIS fn clears that bar, and
(b) a 4,796-LOC/15-responsibility fn whose safety invariants are buried in it is
itself a correctness liability, not merely ugly.

## Required for v2 (to reach PLAN-READY)
1. **F1:** rewrite §5.3 signatures to return an `ArmOutcome` control-flow enum;
   rewrite §7.1 to state recycle becomes centralized to one caller `match` site
   with the 18-site `return DropRecycle` transformation as an audited step.
2. **F2:** model the 4 `recycle_now=false` ownership-transfer fall-throughs as a
   distinct `ArmOutcome` variant (frame handed to TX / pending-neighbor — do NOT
   recycle).
3. **F3:** downgrade inc B/C to "PLAN-READY-pending Q1 borrow spike"; inc A
   (FLOWLESS) is the only unconditionally-ready increment.
4. **F5:** name the asm-symbol-resolution fallback in §9.

Phase 3 stays PLAN-KILL-acceptable (unchanged — correct).
