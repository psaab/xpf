# #2387 plan-review reviewer ledger

3-way hostile plan review (Codex + AGY + Claude SMR). Copilot is NOT a research
reviewer (it joins the quad at `/engineer` on the code PR).

| Round | Reviewer | ID / location | Verdict |
|---|---|---|---|
| r1 | Claude SMR | `claude-smr-plan-r1.md` | PLAN-NEEDS-REVISION (caught the PBR reachability defect in my own v1) |
| r1 | AGY | job `adversarial-review-mr0wcll0-pk94mc` → `agy-plan-r1.md` | PLAN-NEEDS-MAJOR-REVISION |
| r1 | Codex | rescue agent (NOT infra-blocked) → `codex-plan-r1.md` | PLAN-NEEDS-MAJOR-REVISION |
| r2 | Claude SMR | `claude-smr-plan-r2.md` | PLAN-DEFER (converged) |
| r2 | AGY | job `adversarial-review-mr0wp66c-c5nu8h` → `agy-plan-r2.md` | PLAN-DEFER (converged) |
| r2 | Codex | rescue agent → `codex-plan-r2.md` | PLAN-NEEDS-REVISION → PLAN-DEFER after 2 wording fixes (landed in v4) |

**Convergence:** all three reviewers converge on PLAN-DEFER (Claude SMR + AGY at
v3; Codex conditionally at v3, unconditionally after the two §4c/§A.1 wording
fixes landed in v4). Full 3-of-3 — Codex was not infra-blocked in either round.

All three r1 reviewers independently escalated the same finding: the collision is
LIVE via PBR `then routing-instance`, not latent. All three confirmed §4c (NAT
coherence gap), §4d (HA-wire hard break), §7 (symmetric discriminator + inter-VRF
leaked corner) accurate. Codex additionally caught 3 citation errors (fixed in
v3). Codex ran successfully this round, so the review is full 3-of-3 (not the
2-of-3 Codex-infra-blocked fallback).
