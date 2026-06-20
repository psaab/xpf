# Claude-SMR hostile self-review — #2005 session-split plan (round 1)

Reviewer stance: maximally adversarial. The plan recommends PLAN-KILL ("already
shipped in #2028") and asserts the split is codegen-neutral on the dataplane's
hottest module. Both claims are exactly the kind of thing that gets rubber-
stamped and then bites. I am trying to break them.

Severity legend: BLOCKER (plan is wrong / unsafe) / MAJOR (must address before
acting) / MINOR (tighten) / NIT.

---

## A. Attack the PLAN-KILL itself

### A1 (BLOCKER candidate → resolved): "Is the split actually merged, or did the agent confuse a draft/closed PR?"
Hostile take: agents routinely misread `gh pr list` and call a draft "merged."
Check: PR #2028 `state:MERGED`, `mergedAt:2026-06-19T06:24:30Z`,
`headRefName:refactor/2005-session-decompose`; merge commit `7b01afeb5` is an
ancestor of the worktree base `9979a89a0`
(`git merge-base --is-ancestor 04bb75ebb HEAD` → true). The six `#2005`
extraction/doc commits are physically present on the master line and the four
files exist with the claimed LOC. **Verdict: resolved, the merge is real.** Not
a blocker.

### A2 (MAJOR → resolved): "The issue says `src/session/mod.rs` but CLAUDE.md and the brief say `src/afxdp/session/mod.rs` — did the agent split/verify the WRONG module?"
This is the single most likely way this whole pass is garbage. There are two
candidates: `userspace-dp/src/session/mod.rs` (918 LOC now) and
`userspace-dp/src/afxdp/session_glue/mod.rs`. Check: the issue body's own path
is `userspace-dp/src/session/mod.rs` and its verified-LOC line cites that exact
path at 1604 LOC; PR #2028's changed files are all under
`userspace-dp/src/session/`. The `afxdp/session` reference in the brief/CLAUDE.md
points at `session_glue` (the synced-side Arc<Mutex> tables), a *different*
structure the README explicitly distinguishes. **Verdict: the plan verified the
correct module.** The plan should — and does — call out the path discrepancy so
the reader isn't tripped by it. Good. Not a blocker, but keep the callout.

### A3 (MAJOR): "PLAN-KILL on a still-OPEN issue is suspicious — maybe the maintainer reopened it deliberately because #2028 was incomplete/reverted."
Hostile: an OPEN issue after a merged PR can mean the work was found wanting and
the issue intentionally kept open. Did the plan rule that out? It asserts the
issue is "OPEN only because auto-close didn't fire." Evidence for the benign
reading: the issue has 0 comments (no reopen rationale, no defect report), the
PR was not reverted (the split commits are live and the tree builds), and the
title still matches the original ask verbatim. There is no positive evidence of
deliberate reopening. Evidence is **consistent with** benign-no-autoclose but
does not *prove* it. **Action for the plan: it already flags this as Open
Question #1/#2 and recommends confirming with the campaign owner before closing.
That is the right hedge.** Downgrade to MINOR: the plan correctly does not
unilaterally close the issue; it recommends the owner confirm. Acceptable.

### A4 (MINOR): churn-vs-benefit framing is asserted, not quantified.
The plan says "re-doing is pure churn." True, but it should state the concrete
downside of the *recommended* action (close) vs the *rejected* action (re-do):
re-do = touching 1600 LOC of the hottest module twice through review for an
already-achieved 918-LOC result. The plan's §8 covers the close-side risks.
Fine. NIT-level.

## B. Attack the codegen-neutrality claim (the real hot-path bar)

### B1 (BLOCKER candidate → downgraded MAJOR): "'Modules are codegen-neutral' is a textbook claim. Prove it for THIS binary, don't recite it."
This is the crux and the plan must not get a pass for hand-waving. The structural
argument (§4.1: Rust modules are namespacing, whole-crate codegen, no new
translation unit, no new crate) is *correct* — and critically the plan
distinguishes a same-crate submodule split (codegen-neutral) from a new-crate
split (a real boundary that WOULD need `#[inline]`/LTO care). That distinction
is the load-bearing one and the plan gets it right.

BUT: the plan's own §4.4 concedes the gold-standard artifact this project
demands — an `objdump`/`nm` before-after of the release binary, the #1755
method — is **absent from #2028**. So the plan is recommending we *accept*
codegen-neutrality on a hot path on a structural argument + preserved
`#[inline]` + an oracle that tests *behavior* (not codegen). The oracle suite
proves the split didn't change *results*; it does NOT prove the split didn't
change *cost* (a lost inline, an added stack frame, a spilled register would
all pass the oracle and still regress pps/CPU). The #1755 and #1763 history is
precisely "behavior identical, cost regressed."

**This is the one genuinely soft spot.** Mitigation the plan offers (§6.1/§6.2:
local release-binary objdump/nm + probestack grep) is exactly the right
instrument and is cheap. **Resolution: the plan must present §6.1/§6.2 not as
"optional confirmation" but as the recommended pre-close gate, OR explicitly
record that the campaign owner accepted behavior-parity as sufficient for a
same-crate code-motion split.** As written, §6 leans "optional." For a hot path
with this repo's scar tissue, I'd harden the wording. Downgrade to MAJOR with a
concrete fix: re-rank §6.1/§6.2 to "recommended before close."

Caveat the plan already states and I confirm: a raw whole-`.text` byte diff is
the WRONG test — the inliner legitimately renames/merges anonymous symbols and
reorders code across a move even when cost is identical. The correct check is
(a) no new `__rust_probestack` in `session::*`, (b) hot methods still present /
still inlined where they were, (c) no surprise large stack subtraction. The
plan says exactly this. Good — it would have been a trap to demand byte-identity
of compiled output.

### B2 (MAJOR → resolved): "Did the move silently flip a `&self` to `&mut self` or add a `clone`/alloc on a hot path?"
A borrow-shape or allocation change is the classic code-motion regression and
would pass the oracle. Check performed by the plan: it verified the
in-place-refresh methods (the `&mut self` single-writer set) stayed in `mod.rs`
and that the move added no `Vec`/`Box`/`String`. I independently confirm the
hot read path (`lookup` family) and per-tick GC (`expire_stale_entries`) moved
as-is. The plan's evidence here is method-relocation + preserved signatures.
**One residual:** the plan asserts "no method signature gained or lost
`&mut`/`&`" but the only signature change it actually verified is
`push_to_wheel`'s visibility (`fn` → `pub(in crate::session)`), which does NOT
touch the receiver. It did not exhaustively diff every moved signature's
receiver. Realistically a code-motion PR that changed a receiver would have
failed to compile against existing callers, and #2028's body claims a
function-body diff. **Verdict: low residual risk; to fully retire it, the
pre-close step should `git show d118c1006 d8ed334b9 04bb75ebb` and eyeball that
each moved `fn` line is identical modulo the one documented widening.** The plan
should add that one-liner to §6. MINOR→MAJOR-adjacent; cheap to close.

### B3 (MINOR): `#[inline]` preserved ≠ inlined-the-same.
The plan leans on "`#[inline]` attributes preserved." Correct and necessary,
but `#[inline]` is a *hint*; the compiler's actual inlining decision can shift
if surrounding code or optimization fuel changes. Across a pure code-motion
within one crate the inputs to that decision are unchanged, so in practice it
holds — but the only way to *know* is §6.1/§6.2. This reinforces B1: the symbol
check is the proof, the attribute-preservation is necessary-not-sufficient. The
plan should not over-sell preserved `#[inline]` as a codegen guarantee. Tighten
the §4.2 wording from "the inliner's hint set is unchanged" (true but weak) to
"hint set unchanged; the actual inline decision is confirmed by §6.1/§6.2."

### B4 (MINOR): smoke/perf evidence for #2028 is unconfirmed.
PR #2028 body literally says "NEEDS LAB SMOKE ... before merge" yet it merged.
The plan flags this (§4.4 #2, Open Q #2). Good, but it should weight it: this
module is on the session-sync/failover path, so per CLAUDE.md `make
test-failover` is a HARD gate for "any change touching cluster/session
sync/failover." A code-motion split is exactly such a change. If that gate was
not run for #2028, the close should not happen until §6.3 runs it. The plan
mentions failover in §6.3 but should escalate it from "optional" to "required
if not already run for #2028." MAJOR-adjacent on process grounds.

## C. Methodology / hygiene

### C1 (resolved): repo hygiene.
Worktree `research/2005-session-split` off `origin/master`; no
checkout/stash/reset in the main checkout; gh run read-only from the worktree;
build run in the worktree. The one `cargo build` wrote only to the worktree's
`target/`. Compliant.

### C2 (MINOR): the plan relies on #2028's PR-body claims for body-byte-identity
without independently reproducing the body diff. It verified *structure* (impl
blocks, inline attrs, visibility, LOC, build, README) directly but took
"every moved body is byte-identical" from the PR author's word. For PLAN-KILL
this is acceptable (we're not re-doing the work, and the build+oracle would
catch a non-identical body that changed behavior). But B2's `git show` of the
three extraction commits would convert the last second-hand claim into a
first-hand one at trivial cost. Recommend folding into §6.

### C3 (NIT): no LOC-vs-threshold number was named beyond "comfortably under."
The plan says <1000–1500. Fine; 918 clears any reasonable bar. Could cite the
peer refactors' actual landing sizes if a precise threshold exists, but the
project threshold is informal, so "comfortably under" is honest.

## D. Did the plan miss anything the issue explicitly required?

Issue asks: behavior-preserving code motion; preserve #1752/#1855 invariants
byte-for-byte; gate on a `fused_diff_tests`-style oracle. The shipped #2028
did all three (in-place-refresh contract kept in mod.rs; in-place oracle suite
green incl. randomized + displaced-collision-reassert). The plan maps each
issue requirement to shipped evidence. **No requirement is unaddressed.** The
only thing the issue did NOT explicitly require but the project culture does —
the objdump/nm codegen proof and the failover smoke — are the two §6 items, and
they are the plan's honest residual. Good coverage.

---

## Verdict

**PLAN-KILL is correct.** The requested refactor is genuinely merged (#2028),
verified against the correct module, structurally codegen-neutral (same-crate
impl-block code motion, `#[inline]` preserved, in-place-refresh contract intact,
no new alloc), and validated by the behavior oracle. Re-authoring it would put
churn and regression risk on the hottest dataplane module for zero gain.

**Required tightening before the issue is closed (not before accepting the
PLAN-KILL):**
1. (from B1/B3) Re-rank §6.1/§6.2 — the local release-binary `objdump`/`nm`
   no-new-`__rust_probestack` + hot-method-present check — from "optional" to
   **recommended pre-close gate**, since behavior parity (oracle) does not prove
   cost parity and this repo has been bitten exactly there (#1755/#1763).
2. (from B2/C2) Add a `git show d118c1006 d8ed334b9 04bb75ebb` receiver/body
   eyeball to §6 to make the "no receiver flip, body-identical" claim first-hand.
3. (from B4) Escalate `make test-failover` (and the sustained-iperf3 smoke) to
   **required-if-not-already-run-for-#2028**, because this module is on the
   session-sync/failover path and that is a hard CLAUDE.md gate.

None of these block the recommendation; they harden the close. They are all
read-only / confirmation steps and change no production source.

**Overall: PLAN-READY to act on (the act being "verify §6, then close #2005 as
done-by-#2028"), conclusion PLAN-KILL for any new implementation work.**
