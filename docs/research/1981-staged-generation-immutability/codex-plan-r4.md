# Codex hostile plan review r4 (#1981)

**Verdict:** PLAN-READY

Verbatim Codex output:

---

PLAN-READY

r4 closes the r3 hole. OPT1 is safe as specified: it refuses the same-version/different-genid case when `versions/<ver>` is `current` or `PreviousVersion`, so it avoids both `ENOTEMPTY` and any live/rollback-dir mutation. For stale non-live dirs, reusing the existing guarded delete at [cutover.go:605](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/cutover.go:605) is valid because that guard already protects `current` and rollback before `RemoveAll`.

It also preserves #1967: the refusal is pre-PREFLIGHT, daemon untouched, and the active helper-spawn race is avoided because the concrete live path described in [flip.go:30](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/flip.go:30) is never deleted. OPT2 is also structurally sound: generation-keyed dirs make the rename target fresh and push all identity resolution to FLIP.

Residual research-grade NITs:
- §7.8 should be split by selected option: under OPT1, live same-version/different-genid should assert pre-PREFLIGHT refusal, plus a separate stale non-live guarded-recopy test; under OPT2, assert fresh `<ver>-<genid>` publication.
- In B-P3b, spell “pre-PREFLIGHT refusal” as “no DB snapshot; preferably no journal write” to remove any implementation ambiguity.
