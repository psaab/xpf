# #1782 — research plan-review task IDs

Plan doc: `docs/research/1782-cold-start-stall-residual/plan.md`
Branch: `research/1782-cold-start-stall-residual`

## Round 1 (plan v1 `fa4d5d588`)
- **Codex**: `task-mq65m2g7-pe7b7l`
  - fetch: `node /home/ps/.claude/plugins/cache/openai-codex/codex/1.0.4/scripts/codex-companion.mjs result task-mq65m2g7-pe7b7l`
- **AGY**: `adversarial-review-mq65mj2b-nvp8kj`
  - fetch: `node /home/ps/.claude/plugins/cache/claude-code-agy/agy/0.1.0/scripts/agy-companion.mjs result adversarial-review-mq65mj2b-nvp8kj`
- **Claude SMR**: `claude-smr-plan-r1.md` — PLAN-NEEDS-MINOR (re-rank H2-root/H3-why-slow; add 800ms-pending × 3s-neg interaction + first-packet-buffered trace; make 2-PR capture-instrumentation sequencing explicit).
