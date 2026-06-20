# Claude-SMR hostile self-review — plan r1 (#1997 + #2000)

Reviewer posture: hostile senior maintainer. Goal is to break the plan's central
claim ("both already fixed, verify-and-close") and to find any way the merged
fixes are actually wrong, incomplete, or the plan is over/under-claiming.
Verdict at the end.

---

## Attack 1 — "Already fixed" is the laziest possible /research outcome. Prove the merged code is actually on the base you reviewed, not a stale worktree.

`git -C` worktree was created from `origin/master` after `git fetch origin
master`; merge-base(HEAD, origin/master) == origin/master == `9979a89a0`
(verified in the transcript, both equal). The two fix commits `600d6ca8f` /
`dc1d17cc1` are ancestors of `9979a89a0` (they show in `git log --oneline -- debian/`
on this HEAD). The live `postrm` line 256 shows the OR-guard with both `-L`/`-e`
DROPIN arms; `postinst` line 113 shows `ln -sfnT "$CURRENT_DIR/$b"`. This is not
a stale-worktree hallucination — the fixes are on the base.
**Holds.** (This is the exact #1960 trap from memory — checked deliberately.)

## Attack 2 — The issues are OPEN. Maybe they were reopened because the fix was reverted or found broken in review. The plan assumes "merged == done".

Checked: both PRs `#2029`/`#2031` are MERGED (not closed-without-merge), merged
2026-06-19. No revert commit touches `debian/xpf.postrm` / `postinst` after the
merges (`git log --oneline -- debian/xpf.postrm debian/xpf.postinst` shows the
fix commits as the most recent debian touches; the only newer master commits are
#1387 DHCP DDNS, unrelated). The issues' `stateReason` is empty (not "reopened").
The simplest explanation — merge prose used `#NNNN` not `Fixes #NNNN`, so no
auto-close — is consistent with all evidence. The plan states this and does not
over-claim a GitHub state it didn't verify.
**Holds, but** the plan should not present "verify-and-close" as certain without
the parent confirming there is no out-of-band reason (e.g. a maintainer note on
the issue) the issues are deliberately held open. → Folded into Open Question 1.

## Attack 3 — The #1997 fix still has a crash window. Find it.

Steps: (1) repoint sbin→staged, (2) remove drop-in, (3) rm current. Crash points:
- before (1): guard (current present) re-fires → converges. OK.
- between (1)/(2): drop-in present → guard re-fires → converges. OK.
- between (2)/(3): drop-in GONE, current PRESENT → `[ -e CURRENT ]` re-fires →
  re-runs all idempotent steps → converges. OK.
- after (3): both gone → guard false → nothing to do (already converged). OK.
No window leaves a NON-convergent orphan. The one subtlety: step (1)'s
`repoint_owned_sbin_to_staged` after current is deleted — does `link_is_owned`
still match a link still naming `current/<bin>`? Yes: `link_is_owned` matches by
the link's TARGET STRING (`case "$_t" in "$CURRENT"/*`), which is the stored
symlink text, NOT a resolved path — so a dangling `-> .../current/xpfd` is still
"owned" and gets repointed to staged. The plan's Section 2.4 makes exactly this
point. **Holds.** No residual non-convergent window. Attack fails.

## Attack 4 — The #1997 OR-guard could fire SPURIOUSLY and tear down a hardened-to-hardened scenario.

The guard is `incoming_predates_hardened_layout "$2" && {current OR drop-in}`.
The version predicate is the GATE; the artifact-presence is only a second
condition. An upgrade or hardened→hardened downgrade has `$2 >= floor` →
`incoming_predates_hardened_layout` false → short-circuits before the artifact
test → no teardown. So adding the drop-in arm cannot cause a spurious teardown on
a non-pre-#1964 transition. The drop-in arm only widens re-entry WITHIN a
confirmed pre-#1964 downgrade. **Holds.** Attack fails.

## Attack 5 — #2000: recovering through `versions/current` could itself create a DANGLING link if `current` is mid-flip.

The recovery only runs when `[ -e "$CURRENT_DIR/$b" ]` — i.e. the target
resolves NOW. If `current` is mid-flip (atomic `mv -f`), the test either sees the
old or the new target (atomic), both of which have the binary; if `current` is
absent entirely (legacy), the else branch leaves the link absent. There is no
window where it creates a link to a non-existent target — the `-e` test is the
guard. Could `current/<bin>` exist at test time but be flipped away before the
`ln`? The flip repoints `current` (the dir symlink), not the individual
`current/<bin>` path text — the recovered link is `-> versions/current/<bin>`
(through the symlink), so it AUTOMATICALLY follows a later flip. That is the whole
point (no-op-shaped repoint). **Holds.** Attack fails.

## Attack 6 — #2000 leaves a newly-introduced binary's link absent. Is that actually safe, or does something hard-depend on the path existing pre-cut?

The plan flags this honestly (Section 6.3) as documented-intended but with an
operator-visible symptom. The risk is a wrapper/script that calls
`/usr/local/sbin/<newbin>` between apt-install and the rolling cut and gets
ENOENT. The systemd unit ExecStart is pinned to the CONCRETE version dir (not
the sbin link) per `flip.go` 6c, so the DAEMON itself is unaffected. The only
exposure is ad-hoc operator invocation of a brand-new binary that did not exist
in the prior version — by definition nothing in the prior deployment depended on
it. **Holds, low risk.** Correctly left as an Open Question, not a blocker.

## Attack 7 — The regression tests are tautological / don't actually run the real script.

Both suites ship an `oldbug_*_proves_nontautology` scenario that synthesizes the
PRE-FIX script (via awk over the real script) and asserts it exhibits the BUG —
so the core assertion is proven to discriminate. The PR bodies additionally claim
the assertion was run against `origin/master`'s actual pre-fix script and failed.
`postinst-test.sh` "runs the REAL postinst with layout paths rewritten to a temp
root" (not a reimplementation). I ran both under dash: green. **Holds.** Attack
fails. (This is the strongest part of the merged work.)

## Attack 8 — The plan recommends PLAN-DEFER, which is not one of the three required verdicts' usual meaning. Is this a cop-out?

The task requires PLAN-READY / PLAN-KILL / PLAN-DEFER. The honest state is: the
engineering work is DONE and merged, so neither PLAN-READY (implies "ready to
engineer") nor PLAN-KILL (implies "don't do it") fits. PLAN-DEFER, explicitly
redefined in-plan as "no engineering PR; verify-and-close", is the least-wrong
label and is clearly disambiguated. A reviewer could argue PLAN-KILL ("kill the
research because nothing to engineer") is cleaner. Either is defensible; the plan
picks DEFER and explains. **Acceptable, but** the ambiguity should be surfaced to
the parent so the disposition isn't mis-read as "deferred work". → Already in
headline + Open Question 1. Minor.

## Attack 9 — Did the plan miss an ADJACENT bug while declaring victory? (The real value of this research.)

The plan's Section 6 hunts residuals and finds 5, none blocking. Did the review
find a 6th the plan missed?
- `remove_runtime_dropin` does `rmdir "$(dirname "$DROPIN")" 2>/dev/null || true`.
  If the `.service.d` dir contains ONLY our drop-in, rmdir succeeds after rm.
  If a crash happens after `rm -f DROPIN` but before `rmdir`, the rerun's rm is a
  no-op and rmdir reaps the empty dir → converges. Fine.
- One genuinely-new observation: the `remove|purge` path calls
  `remove_runtime_dropin` UNCONDITIONALLY (not gated on version), so on a normal
  `apt remove` of a hardened package the drop-in is removed and daemon-reloaded
  even though `versions/` is LEFT (remove, not purge). Next `apt install`
  (reinstall) runs the postinst first-install seed ONLY if `$2` empty — but a
  reinstall-over-remove has `$2` empty (configure with no prior configured
  version after a remove) so the seed re-runs and re-creates current+sbin+drop-in.
  Convergent. No bug, but the plan could note remove-then-reinstall re-seeds. Trivial.
No missed blocking bug. **The plan's residual hunt is adequate.** Attack yields
only a trivia note (remove→reinstall re-seeds), not worth a plan change.

## Attack 10 — Is there an interaction between #1997's drop-in removal and #1981's staged-gen that the plan waved off too fast?

postrm downgrade does: (#1964 block) repoint/remove-dropin/rm-current, THEN
(separate #1981 block) `incoming_predates_staged_gen "$2" && rm -rf STAGED_GEN`.
The two blocks share no files (`STAGED_GEN=/var/lib/xpf/staged-gen` vs `DROPIN`
under `/etc/systemd` and `CURRENT` under `versions/`). The staged-gen rm is its
own idempotent `rm -rf`. No ordering coupling. The plan's Section 6.5 is correct
to call it orthogonal. **Holds.**

---

## Net assessment

The plan's central claim survives every attack: both fixes are on `origin/master`,
are correct (independently re-derived + dash-green + non-tautological tests), and
require no re-engineering. The residual-gap hunt is honest and complete; none of
the 5 residuals (or the 1 trivia note this review adds) is a blocker. The only
soft spot is the disposition LABEL ambiguity (PLAN-DEFER vs PLAN-KILL for
merged-work), which the plan surfaces rather than hides.

**SMR verdict: plan is ACCURATE and MERGE-READY as a research deliverable.**
- #1997: concur **PLAN-DEFER (verify-and-close)** — fix correct + convergent +
  tested; no engineering.
- #2000: concur **PLAN-DEFER (verify-and-close)** — fix correct + invariant-aligned
  + tested; no engineering.

Required follow-through (process, not code): parent confirms no out-of-band
reason the issues are held open, then closes them (optionally with `Fixes` via a
trivial doc PR if the project wants a paper trail). Section 6.2/6.3/T5 are
optional polish, file as new issues only if desired.

Residual reviewer caution: do NOT let a future maintainer-script change
re-introduce a `-> staged` sbin link on the upgrade path — I1 is the load-bearing
invariant and T5 is the cheapest insurance for it.
