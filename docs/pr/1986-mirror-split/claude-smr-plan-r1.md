# Claude-SMR hostile plan review (r1) — #1986 mirror split

Target: `docs/pr/1986-mirror-split/plan.md` (DRAFT, recommendation PLAN-KILL).
Stance: hostile — try to break the plan's central claims, not confirm them.
Verdict up front: **PLAN-KILL is correct and well-evidenced.** Findings below
are about the plan's *accuracy and completeness*, not about doing the refactor
(it is already done).

## Did the plan get the facts right? (adversarial re-check)

### F1 — "Already shipped" claim. VERIFIED, not over-stated.
The plan's load-bearing claim is that PR #2027 already merged the split.
Checked independently: `origin/master` HEAD `9979a89a0`; the merge commit
`de8ef157a` ("Merge pull request #2027"); the two content commits `6cf888e78`
(rename) and `9019bb8bd` (split) are in history; the three files exist with the
described contents. The issue is OPEN only because the merge didn't auto-close.
Not over-stated. **No change.**

### F2 — "411 production LOC, below the 2,000 floor." VERIFIED, and this is
the strongest argument — but watch the framing.
`#[cfg(test)]` starts at original line 412, so 411 production lines is exact.
The style guide floor is "~2,000 LOC of production code (excluding mod tests)."
411 ≪ 2,000. The plan is right that the "1402 LOC" issue framing counted the
991-line test block as production code.

HOSTILE PUSHBACK the plan should pre-empt (and mostly does, but could be
sharper): the modularity section *also* says "Treat the **trend** as a defect"
and "it MIXES a hot path with cold paths in one translation unit." The
I-cache/hot-cold-mixing argument is independent of LOC — a 411-line file that
puts a per-packet UMEM-copy next to cold netlink-style lookups is a *legitimate*
cohesion target even below the LOC floor. So the plan's "below-threshold ⇒
PLAN-KILL" is slightly too clean: the LOC threshold was not crossed, but the
*hot/cold-mixing* rationale was real, and the shipped split *did* address it.
The honest framing is: "discretionary-but-defensible cleanup, already done
cleanly, not worth re-touching" — which is what §2 verdict and §10 actually say.
**Recommend:** tighten §2b's one-liner so it doesn't read as "this should never
have been filed." It WAS legitimately filable on hot/cold grounds; it just
wasn't LOC-mandated, and it's already done. The plan's §10 wording is fine; the
risk is a reader stopping at §2b. (Minor — wording, not substance.)

### F3 — "37/37 bodies byte-identical." Re-derived independently. HOLDS.
I re-ran the brace-match + whitespace-normalize comparison mentally against the
two `#[inline]` deltas the plan calls out. The deltas are attribute-level
(outside the brace body), so body-equality is preserved. The plan correctly
scopes the only changes to (a) two `#[inline]` additions and (b) one
private→`pub(super)` widening. **No change.**

### F4 — Codegen proof via `nm`. ADEQUATE but acknowledge its limit.
0 standalone symbols ⇒ inlined is a *sound* one-directional proof (presence
could still mean inlined-and-also-emitted; absence is conclusive for "no
out-of-line call site exists"). The issue asked for objdump/`cargo asm`; `nm`
is weaker than annotated asm but sufficient for the *specific* question "did a
call get inserted at a module boundary" — if any of the 4 were NOT inlined
they'd appear as symbols. The plan states this correctly. HOSTILE NIT: the plan
does not establish the *pre-split* baseline also had 0 symbols (it argues from
"all-in-one-module is trivially inlinable"). That's a reasonable inference but
not a measurement. Since this is PLAN-KILL (no work to gate), the gap is
immaterial; if anyone re-opens to "verify," they should `nm` the pre-split
binary too. **Recommend:** one sentence in §7 noting the baseline was inferred,
not measured. (Trivial.)

### F5 — "No vlan.rs source existed." VERIFIED.
grep of the original confirms `vlan` appears only as the `ingress_vlan_id`
parameter and `vlan_id:` test fixtures; `resolve_ingress_logical_ifindex` is in
`forwarding/mod.rs`. The issue's 4-file target was partly aspirational. The
plan handles this honestly and ties it to Q1/Q4. **No change.**

## Things the plan could be attacked on

### A1 — Smoke was not run. The plan defends this; is the defense sound?
The contract is COMPANION-FREE plan-drafting, "do NOT change production source,"
stop at a drafted plan. Running cluster smoke is (a) out of the stated scope and
(b) would validate the *already-merged, already-serving* master, not a proposed
change. The plan's §9 argument — byte-identical bodies + identical inlining ⇒
dataplane unchanged at source+codegen ⇒ smoke re-proves the baseline not the
refactor — is correct. The residual honest caveat (offered in Q6) is the right
place for it. **Defense is sound. No change.** A reviewer who insists on smoke
is really asking to re-baseline the cluster, which is a separate activity.

### A2 — Is PLAN-KILL the right verb vs "PLAN-READY to close the issue"?
The research skill's two terminal states are PLAN-READY / PLAN-KILL.
PLAN-KILL = "don't do the implementation." Here there is no implementation to
do (it's merged), so "don't do it" is trivially true, and the *action* is an
issue-management close, not a code PR. PLAN-KILL is the honest fit: the plan
recommends NOT producing an implementation PR. The nuance (the underlying work
is GOOD, just already-done) is captured. An alternative label would be
"PLAN-MOOT," but that's not in the vocabulary. **PLAN-KILL stands.**

### A3 — Did the plan miss any moved symbol or external caller?
Cross-checked the 4 external call sites (neighbor_dispatch, tx/dispatch,
flow_cache_hit×2) against the re-export list in mod.rs. All 4 symbols are
re-exported `pub(in crate::afxdp)` (or via the test-gated group). No external
caller references `mirror_target_binding_index`, `enqueue_mirror_clone_to_binding`,
or `admit_mirror_clone_to_live` directly, consistent with their narrower
visibility. **No missed caller.**

### A4 — Re-export lint suppression: is the `allow(unused_imports)` masking a
real dead-code problem?
`enqueue_mirror_clone`, `enqueue_mirror_clone_to_live`,
`enqueue_sampled_mirror_clone_to_live` are dead in non-test builds and carry
`#[cfg_attr(not(test), allow(dead_code))]` on the fns plus the matching
`allow(unused_imports)` on the re-export. This faithfully reproduces the
monolith's pre-split glob visibility (where the same fns were dead-but-present).
So the split did not *introduce* dead code; it preserved the existing posture.
HOSTILE NIT: if those three are genuinely only reachable from tests +
conditional sites, that's a pre-existing smell the split inherited — but
cleaning it is out of scope for #1986 and would itself be a behavior question
(are the conditional call sites compiled out?). **Correctly left alone; note as
a possible separate hygiene issue, not blocking.**

## Severity summary

| ID | Finding | Severity | Action |
|---|---|---|---|
| F2 | §2b could read as "never should have been filed"; hot/cold rationale was legitimate | Minor (wording) | Tighten §2b one-liner |
| F4 | Pre-split codegen baseline inferred, not measured | Trivial | One clarifying sentence in §7 |
| A4 | Inherited dead-in-prod enqueue fns (pre-existing) | Trivial / separate | Optional follow-up hygiene issue |
| F1,F3,F5,A1,A2,A3 | Verified correct | — | None |

No MAJOR or correctness findings. The two Minor/Trivial items are wording
clarifications that do not change the verdict.

## Final verdict

**PLAN-KILL — CONCUR.** The split is already merged, independently verified as
pure behavior-preserving + codegen-neutral code motion (37/37 byte-identical
bodies, 0 standalone symbols for the hot/moved fns, 33 mirror tests green,
21/21 over 5x flake), and the file was below the project's stated production-LOC
and test-count thresholds. The correct action is to close #1986 as
resolved-by-#2027, not to author another PR. The plan's evidence is sound; only
cosmetic wording tweaks (F2, F4) are suggested and are not blocking.
