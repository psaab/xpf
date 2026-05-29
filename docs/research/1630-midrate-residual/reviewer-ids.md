# #1630 cause-2 (mid-rate residual) — reviewer task IDs

Research mode: 3-way plan review (Codex + AGY + Claude SMR). Copilot
joins at /engineer on the implementation PR.

Record task IDs here so continuations can fetch by id (per
`feedback_codex_session_loss_continuation`).

| Round | Reviewer | Task ID / Session | Verdict |
|-------|----------|-------------------|---------|
| r1 | Codex | codex exec (read-only sandbox), prompt /tmp/codex-1630-c2-r1.txt | **PLAN-NEEDS-MAJOR** (BLOCKING-1 head_len-not-quantum; BLOCKING-3 consumed≠TX; MAJOR-1/2/3; BLOCKING-2 HALLUCINATED waterfill — rejected w/ grep) |
| r1 | AGY | `adversarial-review-mpqbvucd-8txj5t` (succeeded; agy_result MCP timed out 3×) | result infra-blocked; investigation trace converged on the head_len park-basis defect → aligned PLAN-NEEDS-MAJOR (see agy-plan-r1.md) |
| r1 | Claude SMR | docs claude-smr-plan-r1.md | **PLAN-NEEDS-MAJOR** (concur Codex B1/B3 + M1/2/3; reject B2 with grep; +3 own: corrected-magnitude-unknown, 3-way bisection, H-TCP) |

| r2 | Codex | codex exec (read-only sandbox), prompt /tmp/codex-1630-c2-r2.txt | **PLAN-NEEDS-MAJOR** (BLOCKING-1 waterfill drain path EXISTS — v1/v2 wrong path AND v2 rejection wrong; BLOCKING-2 F-E worker-share busy-poll; BLOCKING-3 bisection unsound; MAJOR-1 max_total_leased formula; MAJOR-2 H-TCP byte-norm) |
| r2 | AGY | `adversarial-review-mpqcfeya-tvz2g7` (succeeded; full result returned) | **PLAN-NEEDS-MAJOR** (#3 bisection TX-contamination; #4 F-E busy-poll; #6 H-LEASE TOOTHLESS — epoch ceiling; #5 H-TCP pacing-dodge). **§2 "no-waterfill REJECTION VERIFIED" is a WRONG-TREE error** (grepped stale cwd e01472f4a) — retracted |
| r2 | Claude SMR | docs claude-smr-plan-r2.md | **PLAN-NEEDS-MAJOR** (self-corrected r1 wrong-tree error; concur Codex; derived waterfill Phase-1 boundary arithmetic showing solo 3g/6g never Phase-1-honored at 0.7) |

## r2 convergence

3-of-3 PLAN-NEEDS-MAJOR. Codex r1+r2 correct throughout (waterfill
exists). Claude SMR r1 wrong-tree error self-corrected at r2. AGY r2
returned a full verdict (PLAN-NEEDS-MAJOR) with valuable non-tree
findings (#3/#4/#6) BUT its §2 waterfill-rejection is a wrong-tree error
identical to Claude r1's — both grepped the stale main checkout
`e01472f4a`, not origin/master `0e5bb3812`. Verified definitively: `git
show origin/master:.../queue_service/mod.rs` has the waterfill dispatch
at :608 and the fn at :771; the stale checkout has neither. v3 re-grounds
on the waterfill selector (H-WATERFILL) and folds AGY #3/#4/#6.

## r1 convergence

2-of-3 decisive PLAN-NEEDS-MAJOR (Codex + Claude SMR, both quoted-line
evidence; AGY infra-blocked but trace-aligned). Per
`feedback_codex_infra_must_retry`: Claude SMR + Codex are both real and
decisive, satisfying "Claude SMR + one external real." Codex BLOCKING-2
(waterfill drain path) rejected as a verified hallucination — NOT folded
in. v2 folds B1/B3/M1/M2/M3 + the 3 Claude findings.
