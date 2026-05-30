# #1692 reviewer task-id ledger

Research: instrument-first isolation of 3g/6g guarantee-rate under-protection.
Branch: research/1692-3g6g-guarantee-instr

| round | reviewer | task-id / artifact | verdict |
|-------|----------|--------------------|---------|
| r1 | Codex | /tmp/codex_1692_r1.out → codex-plan-r1.md (model: default ChatGPT) | PLAN-NEEDS-MAJOR |
| r1 | AGY | adversarial-review-mpsi7e9x-jihvpd | (pending) |
| r1 | Claude-SMR | claude-smr-plan-r1.md | PLAN-NEEDS-MAJOR |

## r1 convergence (Codex + Claude-SMR, pre-AGY)
Both independently flagged the CRITICAL defect: §4's `Σ share_i vs
class_rate` discriminator is mathematically constant
(`Σ my_share_i = cap` by construction, `rotate_epoch_v8.rs:306-312`),
so it cannot separate L1-by-design from L1-fixable. Additional converged
findings:
- L2 root-FCFS is confirmed DEAD by monotonic-sum logic (aggregate
  park_root=0 ⟹ every per-worker term = 0). Not "provisionally" dead.
- §4 L1-fixable row is internally contradictory (delivered≈share AND
  delivered<Σshare cannot both hold on the scoped workers).

Codex-only: `share_i` is a 200µs epoch gauge, not a window counter —
needs windowed normalization; `my_share` read needs the seqlock pattern
(`mod.rs:1561`), not a bare Relaxed load.

Claude-SMR-only: §4 is blind to per-worker DEMAND, so it aliases a gated
worker with a cwnd-starved one (the #1630 cause-2 transport-physics floor
— a fourth, PLAN-KILL outcome not in §7's enumeration).
