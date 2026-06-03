# #1756 reviewer task IDs

- **Codex** (foreground): bash job `b2s986uo4` — verdict **PLAN-READY
  (kill stands)**. Surfaced #1243 (5-worker dedicated-CPU PLAN-KILL,
  −17%), the #1244-era keep-6-workers +30% recipe, `poll-mode interrupt`
  correction, and manager.go/Nth-CPU nits. All incorporated in v2.
- **AGY** (background): `adversarial-review-mpymrg4q-rm2pj5` — verdict
  **PLAN-KILL-CORRECT**. 528%→500% core-capacity framing; worker-0
  funnel → ~45% degradation; softirq invariance → #739 is the right
  lever. Full doc at brain
  d32ab60a-d412-46c9-a22f-e8e812e92f02/adversarial_review_1756.md.
- **Claude SMR**: docs/research/1756-core-isolation/claude-smr-plan-r1.md
  — verdict **PLAN-KILL-CORRECT**.

Convergence: 3/3 PLAN-KILL on round 1. No reviewer found an overturning
counter-example.
