# Reviewer task-ID ledger — #2079 (research)

| Round | Reviewer | ID / ref | Verdict |
|-------|----------|----------|---------|
| r1 | Claude SMR | claude-smr-plan-r1.md | PLAN-READY-WITH-NITS (1 MAJOR M1, refinements) |
| r1 | AGY (adversarial) | adversarial-review-mqmrffvn-smhd8t | REVISE (4 MAJOR + 1 MINOR; M1 shared-Arc double-count = critical correction) |
| r1 | Codex (codex-rescue agent) | agentId aab11e6c65bb05452 | PLAN-READY-WITH-NITS (8 findings; F1 dedup = converges with AGY M1) |
| r2 | Claude SMR | claude-smr-plan-r2.md | PLAN-READY (all r1 folds verified) |
| r2 | AGY (1st) | adversarial-review-mqmrr8na-n50emd | ENGINE TIMEOUT after full verification (no objection) — infra |
| r2 | AGY (retry) | adversarial-review-mqmrynjs-i3skz0 | PLAN-READY (all 5 r1 findings confirmed resolved) |
| r2 | Codex (1st) | agentId ab90b37ade3bef368 | INFRA-DROP (empty; after-first-job drop) |
| r2 | Codex (retry, fresh) | agentId a5710146c20086d4d | PLAN-REVISE (3 NEW MAJOR pseudocode + FOLD-5; all folded into r3) |
| r3 | Claude SMR | claude-smr-plan-r3.md | PLAN-READY (Codex NEW-1/2/3 + FOLD-5 verified resolved) |
| r3 | AGY | adversarial-review-mqms98o9-sjn241 | PLAN-READY (all 4 r2-folds confirmed resolved, no new issues) |
| r3 | Codex | agentId a4d0c901a2724e30d | PLAN-REVISE (confirmed all 4 r3 folds; 2 NEW MAJOR + 1 MINOR → folded into r4) |
| r4 | Claude SMR | claude-smr-plan-r4.md | PLAN-READY (Codex r3 #5/#6/#7 verified resolved) |
| r4 | AGY | adversarial-review-mqmsfhen-xkokuy | PLAN-READY (all 3 r3-folds confirmed, no new issues) |
| r4 | Codex | agentId a9f456c3813ea0c67 | PLAN-REVISE (confirmed all 3 r4 folds; 1 NEW MAJOR #4 + MINOR + NIT → folded into r5) |
| r5 | Claude SMR | claude-smr-plan-r5.md | PLAN-READY (Codex r4 #4/#5/#7 verified resolved) |
| r5 | AGY | adversarial-review-mqmsmreo-eadvka | PLAN-READY (config-derived inversion stress-tested, no new issues) |
| r5 | Codex | agentId ae09617e55b8e5564 | PLAN-REVISE (confirmed all r5 folds; 1 NEW MAJOR #1 rule-unreferenced-stuck-alarm + NIT → folded into r6) |
| r5 | Codex (fresh retry, cross-check of r5) | agentId aa74838bb97bb7ff7 | PLAN-REVISE (re-confirmed #1; +#2 gen-coherency MAJOR, +#3 stuck-pct MINOR → folded into r7) |
| r6 | Claude SMR | claude-smr-plan-r6.md | PLAN-READY (Codex r5 #1 verified resolved) |
| r6 | AGY | adversarial-review-mqmsy5w7-s7r6et | PLAN-READY (rule-referenced eligibility confirmed, no new issues) |
| r6 | Codex | agentId a5e91c91c6bb8319a | PLAN-READY-WITH-NITS (no MAJOR; 2 NITs: stale §9 row + defensive nil-skip → folded into r7) |
| r7 | Claude SMR | claude-smr-plan-r7.md | PLAN-READY (gen-coherency + stuck-pct + 2 NITs verified resolved) |
| r7 | AGY | adversarial-review-mqmt4uu2-n5ezju | PLAN-READY (all 4 r7 items confirmed, no new issues) |
| r7 | Codex | agentId aa98925183049577a | PLAN-REVISE (4 confirms; MAJOR #1 apply-window gen-skew + MINOR #2 nil-dp → folded into r8) |
| r7 | Codex (fresh retry, cross-check) | agentId aa0db8139112cf6e0 | PLAN-READY (full 12-point clean pass on r7 base; corroborates substance) |
| r8 | Claude SMR | claude-smr-plan-r8.md | PLAN-READY (coherent-view + nil-dp verified; commit-ordering re-traced) |
| r8 | AGY | adversarial-review-mqmtgce3-ao2bh6 | PLAN-REVISE (1 MAJOR: HelperCaughtUp must compare to view.Generation not publishedSnapshot → folded into r9) |
| r8 | Codex | agentId ac521b4e53a237581 | (running) |
| r9 | Claude SMR | claude-smr-plan-r9.md | PLAN-READY (HelperCaughtUp predicate fix verified; generation tracking re-traced) |
| r9 | AGY | (pending) | (pending) |
| r9 | Codex | (pending) | (pending) |

Copilot joins only at /engineer time on the implementation PR (4th reviewer).

Convergence trajectory: AGY PLAN-READY every round (r1 REVISE → r2-r6 READY).
Codex found ONE progressively-narrower real defect each round (r2 dedup → r3
nil/prune/comparator → r4 sample-vs-eligibility/syslog → r5 config-vs-snapshot →
r6-input config-vs-rule-referenced). Each was verified against source and folded.
The eligibility model is now exhausted (config-pools ⊋ rule-referenced = the
exact reportable set), so r6 should be the convergence round.

Infra note (`feedback_codex_infra_must_retry`): AGY r2-1st engine-timed-out
post-verification → retry PLAN-READY. Codex r2-1st infra-dropped → fresh-session
retry COMPLETED (slow, not dropped) with a substantive PLAN-REVISE — those were
REAL defects (nil-deref, prune-gap, clear-comparator, uint-cast-order), folded
into r3. r3 re-review dispatched for clean 3-way convergence (no infra excuse
relied on for the r3 gate).
