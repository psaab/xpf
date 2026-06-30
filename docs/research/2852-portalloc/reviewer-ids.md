# #2852 reviewer ledger

Plan: `docs/research/2852-portalloc/plan.md` (v3).
Base: `origin/master` (re-verified `b3b8b6029`; `userspace-dp/src/nat/`
byte-identical to v1 base `9d00d219c`).

| Reviewer | File | Round verdict | Converged |
|----------|------|---------------|-----------|
| Claude-SMR | `claude-smr-plan-r1.md` | PLAN-NEEDS-MINOR (F1-F4) | — |
| Claude-SMR | `claude-smr-plan-r2.md` | PLAN-READY-pending-lab → PLAN-DEFER | yes |
| Codex (codex-cli 0.142.4) | `codex-plan-r1.md` | PLAN-NEEDS-MAJOR (F5 + F-BODY race + F1-F4 AGREE) | resolved in v3 |
| AGY (agy 1.0.14) | `agy-plan-r1.md` | PLAN-NEEDS-MAJOR (F5 + F6 + F7 + F1-F4 VALIDATED) | resolved in v3 |

Findings folded into v3:
- F1 conditional bit-clear / ABA (Claude-SMR; Codex+AGY AGREE)
- F2 keep lock-free FIFO recycle ring (Claude-SMR; Codex+AGY AGREE)
- F3 phase the work, lock-free bitmap first (Claude-SMR; Codex+AGY AGREE)
- F4 global-cap reserve/rollback discipline (Claude-SMR; Codex+AGY AGREE)
- **F5 lock-ordering deadlock — found independently by Codex AND AGY,
  missed by plan + Claude-SMR r1** (resolved: persist→flow everywhere,
  index from 5-tuple subset; Phase 1 has no two-lock path)
- F6 false sharing of shard mutexes (AGY) — `CachePadded`
- F7 duplicate-IP addr_index (AGY) — store addr_index in record
- F-BODY (Codex): review-race artifact (read mid-edit); body is complete
  in v3 — no real gap.

All three agree: §7.5 HA-reservation correction is correct; the bottleneck
is per-new-flow not per-packet; the design is sound; and the mandatory
loss-cluster lab gate + PLAN-KILL-if-not-measurable line must not be
weakened.

Terminal disposition: **PLAN-DEFER (plan-deferred-research)** — design
firm, /engineer-able, merge gated on the lab measurement.
