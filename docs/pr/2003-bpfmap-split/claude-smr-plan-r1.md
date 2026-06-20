# Claude-SMR Hostile Plan Review — #2003 (round 1)

Reviewer stance: assume the plan is wrong until proven otherwise. The plan
claims PLAN-KILL because the work is already merged. A hostile reviewer's
job is to find the way that conclusion is a false positive — i.e. that the
issue is open because something is genuinely *not* done, or that the
drafter pattern-matched on a `#2003` comment without verifying real
provenance.

## Verdict

**PLAN-KILL is CORRECT and well-evidenced.** No MAJOR findings. Two MINOR
notes on precision. The drafter did the right verification and did not
fabricate the "already merged" claim.

## Attack 1 — "The `#2003` comment in mod.rs is aspirational/stale, not proof of merge."

A `// #2003: ...` comment plus `mod ha; mod metrics; mod pin;` could be a
WIP branch artifact that never merged, or a leftover plan stub. The drafter
did NOT rest on the comment. Independent corroboration in the plan:

- `git merge-base --is-ancestor 70d5516b7 origin/master` → true (the pin
  commit is an ancestor of the *fetched* origin/master, not a local WIP).
- Three named commits with real SHAs and full commit messages, each
  describing verbatim motion.
- `gh pr view 2026` → MERGED, merge commit `7c3905c9e`, merged 2026-06-19.
- The actual submodule files exist with content (155/244/95 LOC) and
  per-file doc headers.

This is layered ground-truth, not comment-trust. The MEMORY anti-pattern
[[feedback_verify_agent_branch_base]] (trusting a stale worktree) is
explicitly avoided: the worktree was built from a fresh
`git fetch origin master` and the merge-base check was run. PASS.

## Attack 2 — "The issue is OPEN; therefore work remains."

The seductive false positive. The plan's §3 nails the actual cause: PR
#2026's `closingIssuesReferences` is empty (verified via `gh pr view ...
--json closingIssuesReferences` → `[]`), i.e. the PR said `#2003` without a
`Closes` keyword, so GitHub left it dangling. The hostile counter would be:
"maybe the PR was reverted after merge." Refutation already in-plan: the
split files are physically present on the *current* `origin/master`
(`9979a89a0`, well after the `7c3905c9e` merge), and the three commits are
ancestors. A revert would have removed them. PASS.

## Attack 3 — "Suggested layout said pin.rs = 'sysfs dir cleanup + fd pinning'; shipped pin.rs has no dir-cleanup. That's a GAP — the issue's literal scope is unmet."

This is the strongest hostile angle and the plan addresses it head-on in
§2's deviation note. Hostile re-test: is there a "sysfs directory cleanup"
cluster still sitting in `mod.rs` that *should* have moved to `pin.rs`?
The plan asserts bpffs pin-directory lifecycle is owned in the coordinator,
not in `bpf_map/mod.rs`.

- WEAKNESS: the plan asserts this but the research transcript shows the
  reviewer read `mod.rs` in full and the file contains no directory-cleanup
  code (the 657-LOC residual is session-map publish/delete + conntrack
  mirror + struct mirrors). So the claim is supported by the full read, but
  the plan could have cited the absence more concretely (e.g. "grep for
  rmdir/remove_dir/unlink in mod.rs → none"). MINOR: tighten the evidence,
  but the conclusion (no orphaned cleanup cluster to extract) is sound.

Verdict on the deviation: the issue's layout was a *suggestion*
("Suggested layout"), and the shipped grouping (fd-pinning + pinned-path
reader = the only bpffs-path items) is more cohesive than the literal
3-bucket sketch. Splitting a non-existent cleanup cluster out would be
cargo-culting the issue text. NOT a gap. PASS.

## Attack 4 — "Behavior preservation is asserted from the PR body, not re-verified. The drafter trusted the PR author's self-report."

Partial hit. The plan leans on PR #2026's recorded `cargo test` results
rather than re-running them. Mitigations:

- The plan independently grep-verified the external explicit-path
  consumers (`OwnedFd` at worker_manager.rs:69-70 + bpf_maps.rs:5;
  `SESSION_PUBLISH_ERRORS_SHARED` at promote.rs:113 + forwarding/mod.rs:1136)
  resolve via the re-exports — that is the highest-risk part of a Rust
  visibility move and it was checked against live source, not the PR body.
- The task scope explicitly forbids production source changes and PRs;
  re-running `cargo build/test` in this research run is permitted but not
  required, and the plan correctly lists it as optional maintainer
  re-confirmation in §7.

MINOR: a PLAN-KILL that *also* ran `cargo build --release` in the worktree
(read-only w.r.t. source) would be airtight. Not doing so is defensible
given the merge is already smoke-clean and the change is pure code motion,
but it is the one place the plan substitutes the author's claim for a fresh
observation. Acceptable for a KILL; would be insufficient for a
PLAN-READY-to-implement.

## Attack 5 — "Rust has no import-cycle wall, so the task's central question is trivially dodged."

The task asked to verify the Go import-cycle wall (which killed #2002/#2004)
does not apply, AND to verify cohesion + behavior preservation. The plan
§8 states the cycle concern is N/A for an intra-crate `mod` split and —
more importantly — points to the merged, smoke-clean result as the
*empirical* proof that cohesion held (it compiled, tests passed, no
visibility widening needed). That is the right way to answer "would this
have worked": it did. PASS.

## Attack 6 — "657-LOC residual mod.rs still violates modularity discipline; the KILL hides remaining work."

Refuted by the plan §4 option B against `docs/engineering-style.md`: the
split threshold is ~2,000 LOC (act before ~3,000). 657 is comfortably
under, and even the *original* 1063 was under — #2003 was a
cohesion-driven backlog target, not a hard-threshold violation. Further
splitting would scatter coupled session-map logic. The plan does not hide
residual work; there is none mandated. PASS.

## Residual risk / what could still bite

- **Only real action is administrative** (close #2003 pointing at #2026).
  If the maintainer instead re-opens a "redo the split" effort off this
  issue, that would be wasted churn — the plan's §4/§8 explicitly guard
  against that misread. Good.
- **The draft comment must not claim the issue is auto-closeable by this
  run** — the run posts a comment only; closing is the maintainer's call.
  Plan §5 is correct on this.

## Required edits before this is final

None blocking. Optional tightening (MINOR, both non-blocking):
1. §2 deviation note: add the concrete "no dir-cleanup primitive in
   mod.rs" evidence (Attack 3).
2. §7: state plainly that this run did not execute `cargo build/test`
   (only static + git verification), so a maintainer re-run is the
   confirmation step (Attack 4).

## Bottom line

PLAN-KILL stands. The work shipped in PR #2026; #2003 is stale-open due to
a missing `Closes` keyword. The verification chain (fresh fetch +
merge-base ancestry + `gh pr view` MERGED + physical files + live
consumer-path grep) is sound and avoids the known stale-worktree and
comment-trust traps. The single deliverable is to close the issue.
