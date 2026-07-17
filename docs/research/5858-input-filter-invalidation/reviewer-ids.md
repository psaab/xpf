# #5858 plan-review reviewer ledger

Plan doc: `docs/research/5858-input-filter-invalidation/plan.md`
Branch: `research/5858-input-filter-invalidation`
Base: origin/master `5c68818f6`

| Round | Reviewer | Dispatch | Task/Agent ID | Verdict |
|---|---|---|---|---|
| r1 | Codex | adversarial plan review | codex-plan-r1.md (foreground rerun) | **PLAN-NEEDS-MAJOR** (6 BLOCKING) |
| r1 | AGY | adversarial plan review | agy jobs mroham1p / mrohj66i | INFRA-BLOCKED (headless, 2 retries failed) |
| r1 | Claude SMR | hostile plan review | claude-smr-plan-r1.md | PLAN-NEEDS-MINOR (SMR-3 later shown wrong by Codex) |

**r1 outcome:** Codex PLAN-NEEDS-MAJOR is the governing verdict. Codex verified (and I independently re-verified) that the
family-wide purge (v1/v2 Path A) breaks unrelated permitted SNAT flows (fresh-cursor PAT re-alloc, allocator.rs:540/602),
that `replicate_session_delete` is sibling-worker-only (session_glue:751) so cross-node deletes ride the bounded 4096
Close-delta ring, and that a validation/forwarding ArcSwap skew opens a one-iteration flow-cache bypass (loop_body:364 vs
:372). Plan pivots to **Path C — precise per-tuple re-evaluation** in v3.

Note: the initial codex:codex-rescue / agy:agy-rescue agent dispatches (ab247709eb49ee6de / a42b3248ebdc5c8ed) mis-fired (ran in a
separate runtime / explored their own guide); re-dispatched directly via the codex-companion `task` and the agy MCP
`agy_adversarial_review` above.
