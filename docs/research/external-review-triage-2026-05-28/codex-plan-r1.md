I’ll treat this as a code-review pass over the triage, not a design review. I’m going to read the disputed sections and then pin each verdict against the current source with line-level evidence.
exec
/bin/bash -lc "sed -n '1,260p' docs/research/external-review-triage-2026-05-28/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/external-review-triage
 succeeded in 0ms:
# External codebase review (2026-05-28) — triage + prioritized action plan

**Revision**: r1
**Mode**: `/research` (research-only; STOP at PLAN-READY; no production code)
**Source**: `/tmp/latest-review.md` (576 lines: §1 bugs/security 1.1–1.10, §2 modularization 2.1–2.11, §3 test-coverage gaps)
**Verification base**: `origin/master` @ `0e5bb3812` (docs drift fixes #1639/#1644/#1645 via #1647)
**Reviewers**: Codex + AGY + Claude SMR (3-way at research; Copilot joins at `/engineer`)

---

## 1. Problem framing

An external static-analysis pass produced 10 bug/security findings (§1), 11
modularization opportunities (§2), and a test-coverage gap inventory (§3). The
job is **hostile triage**, not acceptance: verify each finding against
`origin/master` and the issue/PR history, then classify as REAL-actionable /
FALSE-POSITIVE / ALREADY-FILED / PLAN-KILLED / INTENTIONAL-BY-DESIGN. The
deliverable is a converged, prioritized action plan of only the REAL items.

The review's raw facts are mostly accurate where spot-checked (grep counts for
duplicated constants, `Result<_, String>`, `#[ignore]`d tests, missing
`proptest`/fuzz all verified true). The *framing/severity* is where it
over-reaches: several "CRITICAL/HIGH" bugs are documented contract guards,
stack-copy clones mislabeled as heap allocs, or not-yet-wired pending work.
The genuinely high-value NEW signal is §3 (server/ control-plane + worker
loop_body have zero unit tests).

## 2. Verified blast radius

| Claim | Review says | Verified at origin/master | Verdict |
|---|---|---|---|
| `unsafe` blocks in afxdp/ w/o SAFETY | ~180 | plausible; sampled lines are mmap raw-ptr derefs | discipline gap |
| `unreachable!()` in cos_classify | 6 (489/494/527/544/599/626) | confirmed; all match the *other* known 2-variant after constructing one | contract guards |
| service.rs unreachable | 2 (451/617) | confirmed `"prepared CoS queues do not drain local mirror clones"` | contract guards |
| dispatch unreachable | 1 (188) | confirmed `PendingForwardFrame::Prebuilt(_) => unreachable!()` | needs read |
| `stage_flow_cache_hit` params | 22 | 21 counted (close) | real |
