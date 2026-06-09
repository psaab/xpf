# #1782 — research plan-review task IDs

Plan doc: `docs/research/1782-cold-start-stall-residual/plan.md`
Branch: `research/1782-cold-start-stall-residual`

## Round 1 (plan v1 `fa4d5d588`)
- **Codex**: `task-mq65m2g7-pe7b7l`
  - fetch: `node /home/ps/.claude/plugins/cache/openai-codex/codex/1.0.4/scripts/codex-companion.mjs result task-mq65m2g7-pe7b7l`
- **AGY**: `adversarial-review-mq65mj2b-nvp8kj`
  - fetch: `node /home/ps/.claude/plugins/cache/claude-code-agy/agy/0.1.0/scripts/agy-companion.mjs result adversarial-review-mq65mj2b-nvp8kj`
- **Claude SMR**: `claude-smr-plan-r1.md` — PLAN-NEEDS-MINOR (re-rank H2-root/H3-why-slow; add 800ms-pending × 3s-neg interaction + first-packet-buffered trace; make 2-PR capture-instrumentation sequencing explicit).

## Round 1 outcome
- Codex `task-mq65m2g7-pe7b7l`: **PLAN-NEEDS-MAJOR** — H1 per-binding not global; neg armed after pending-timeout (first pkt buffered); NEW H5 one-rep-pending sibling-SYN-drop; capture insufficient (need keyed contains + per-worker counters + pre-idle ip monitor); H2 loose.
- AGY `adversarial-review-mq65mj2b-nvp8kj`: **PLAN-READY** — verified dump-path/resolver/instrumentation; ruled out snapshot-regen (atomic apply); confirmed Option B safe / A re-opens #1651. (Missed H5 + per-binding — AGY-soft-pass.)
- Claude SMR: **PLAN-NEEDS-MINOR** — re-rank H2-root/H3-why-slow; first-pkt-buffered; 2-PR sequence.
- All folded into v2 `ef1496ef3`.

## Round 2 (plan v2 `ef1496ef3`)
- **Codex**: `task-mq6600fx-mjvpfq`
- **AGY**: `adversarial-review-mq6600qy-1jh8bl`
- **Claude SMR**: `claude-smr-plan-r2.md` — **PLAN-READY** (v2 folds all r1; no new findings).
