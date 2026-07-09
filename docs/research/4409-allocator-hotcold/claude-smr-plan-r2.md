# Claude SMR — plan review r2 (convergence) — #4409(b)

This round weighs Codex's r1 PLAN-KILL against my r1 PLAN-READY-WITH-NITS and
records where I land after taking Codex's points seriously rather than defending
my draft.

## Verdict: PLAN-KILL (converged with Codex)

I move from "PLAN-READY-WITH-NITS, value is a taste call" to **PLAN-KILL**. Codex
surfaced one argument I under-weighted (the perf invariant is unproven AND the
proposed gate cannot prove it), and combined with the shared premise/value
concerns that both reviewers independently reached, the change as scoped does not
clear the bar. Details:

### Codex point I accept as decisive #1 — the perf invariant is UNPROVEN
My r1 SMR argued "gc_expired_chunked is not an inline candidate today, so moving
it is free." That was an ASSERTION about codegen, not a proof. Codex is right:
- `gc_expired_chunked` is called on the hot path (allocator.rs:911 every
  non-persistent allocation; :1231 periodic release).
- With `ALLOCATION_GC_BUDGET = 8`, the chunk loop has a small constant trip count;
  an optimizer that inlines the callee could constant-fold it. Whether that
  happens today is unknown — neither of us measured it.
- The crate has no `[profile.release]` (codegen-units=16, no LTO), so which CGU a
  function lands in is exactly the kind of thing a module move perturbs.

The plan's ONLY justification is readability. Taking on ANY unproven codegen risk
on the SNAT allocation hot path to buy readability is a bad trade. The plan should
have *proven* codegen-equivalence up front (mandatory asm/objdump diff of
`allocate_translation` before/after), not deferred it to an "asm OR bench" gate.

### Codex point I accept as decisive #2 — the proposed gate was defective
I already flagged (r1 N2) that `benches/snat_allocator.rs` REIMPLEMENTS the
allocator shape rather than exercising the real `PortAllocator`, so it cannot
validate this refactor — but I framed that as "downgrade the bench to optional."
Codex is sharper and correct: that means the asm compare is the ONLY valid gate
and must be MANDATORY. A plan whose sole risk (perf) can only be closed by one
specific gate, and which instead offered a menu including an instrument that
provably can't measure it, has not de-risked itself.

### Shared point both reviewers reached independently — value/premise
- The "hot/cold" premise is dead post-#2852/#4676 (the GC is amortized-hot). Both
  of us said so without prompting.
- ~180 LOC moved, no runtime/binary/contention win, and `snapshot` — the ONE
  genuinely-cold production method — stays in allocator.rs, so the change does not
  even deliver the "separate stats" half of the issue's ask.
- There is a genuinely cleaner seam available (`AddressOccupancy`, a
  self-contained lock-free type at allocator.rs:406, or the #4559 deterministic-NAT
  block) that both reviewers named as the better target.

### Codex's extra catch that reinforces the kill
The byte-identical "retained lines unedited" rule collides with a REQUIRED doc
fix: allocator.rs:75 states the GC constants/private types "stay fully private to
this file", which becomes FALSE once `allocator/gc.rs` exists. So even the
"pure code-motion, zero body edits" selling point is not quite true — the header
contract comment must change too. Small, but it chips at the one thing the plan
had going for it (a perfectly clean diff).

## What I still stand by from r1
- The visibility design is CORRECT and would have been the plan's best feature
  (Codex agreed). If a future extraction of a genuinely-cold or genuinely-separable
  unit is pursued, the child-module + descendant-access pattern is the right tool
  and needs zero field widening.
- Lock discipline and the hybrid-layout legality are fine.
- The nits (cfg-gate `Ordering`, stale header comment) are real.

None of that rescues the change: correct mechanics on a low-value, stale-premise,
unproven-perf refactor still nets out as "don't do this now."

## Convergent recommendation (both reviewers)
PLAN-KILL part (b) **as scoped** (hot/cold GC split). Do NOT open a PR. Concretely:
1. Treat #4409(b) as obsoleted by #2852 (lock-free bitmap) + #4676 (chunked GC):
   the "cold config/stats/GC" god-struct it described no longer exists.
2. If `allocator.rs` (still 1797 LOC) is to be decomposed, file a FRESH, narrower
   issue targeting a genuinely cohesive seam — the self-contained `AddressOccupancy`
   type (cleanest; no shared-field access) or the #4559 deterministic-NAT block —
   and require a MANDATORY asm/codegen-equivalence gate on `allocate_translation`
   as an entry condition, since any of these touch hot code.
3. Parts (a) (tests split, already largely done) and (c) (source.rs parse/driver
   split) are UNAFFECTED by this kill and remain independently driveable.

Do not apply a `plan-kill` label to the whole #4409 issue — it is multi-part and
(a)/(c) are still live. Scope the kill to (b) in the issue comment.
