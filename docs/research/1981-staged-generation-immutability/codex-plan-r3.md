# Codex hostile plan review r3 (#1981)

**Verdict:** PLAN-NEEDS-MAJOR — narrowed to ONE precise hole: the same-version versions/<ver> replacement protocol (Codex r2-#2 core). All other r2 items accepted as fixed at plan level. Explicitly "not new scope."

Verbatim Codex output:

---

PLAN-NEEDS-MAJOR

r3 genuinely fixes the other called-out r2 items at plan level:

- Codex r2-#1: yes. The first B-aware deploy caveat is now honest and bounded in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/docs/research/1981-staged-generation-immutability/plan.md:207) and O4.
- Codex r2-#3/#4: yes. `Journal.SourceGeneration` plus GC protection of journal-referenced genids is the right invariant.
- Codex r2-#5: yes. The disk budget and publish-side free-space/ENOSPC behavior are now honest enough for engineer implementation.

The remaining major hole is Codex r2-#2: B-P3b detects same-version destination mismatch, but it does not define a safe replacement protocol for `versions/<ver>`.

Today `copyStaged` skips if `versions/<ver>` exists, then otherwise renames `.partial` to `versions/<ver>` ([cutover.go](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/cutover.go:512)). For a same-version reinstall, `versions/<ver>` may be the live `versions/current` target and the rollback target. If `.srcgen` differs, r3 says “force a fresh recopy,” but a non-empty directory cannot simply be renamed over; deleting or renaming it during COPY would violate the pure pre-STOP invariant and can strand `current`/rollback on a missing or replaced directory after a crash.

So `.srcgen` is a necessary identity stamp, but not sufficient. The plan needs one more precise invariant: how a mismatched existing `versions/<ver>` is replaced without mutating the live/rollback directory before the cut is committed, or else same-version reinstall must be explicitly refused/requires a distinct version key. This is not new scope; it is the unresolved core of the r2 same-version finding.
