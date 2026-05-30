# #1692 reviewer task-id ledger

Research: instrument-first isolation of 3g/6g guarantee-rate under-protection.
Branch: research/1692-3g6g-guarantee-instr
Outcome: **PLAN-KILLED** (3-of-3 converged).

| round | reviewer | task-id / artifact | verdict |
|-------|----------|--------------------|---------|
| r1 (v1) | Codex | /tmp/codex_1692_r1.out → codex-plan-r1.md | PLAN-NEEDS-MAJOR |
| r1 (v1) | AGY | adversarial-review-mpsi7e9x-jihvpd | trace corroborated facts; verdict timed out |
| r1 (v1) | Claude-SMR | claude-smr-plan-r1.md | PLAN-NEEDS-MAJOR |
| r2 (v2) | Codex | /tmp/codex_1692_r2.out → codex-plan-r2.md | PLAN-NEEDS-MAJOR |
| r2 (v2) | AGY | adversarial-review-mpsiltqk-jhkdi6 → agy-plan-r2.md | PLAN-NEEDS-MAJOR |
| r3 (v2) | Claude-SMR | claude-smr-plan-r3.md | PLAN-KILL |

(AGY r1b adversarial-review-mpsieqw1-9zyjug also corroborated v2's facts;
verdict step timed out — AGY repeatedly times out emitting the final
verdict line in this environment, but its code-walk traces matched the
Codex + Claude-SMR findings on every run.)

## Convergent KILL (3-of-3)
The passive per-(class,worker) instrument cannot disambiguate L1 (v8
lease) / L3 (selector budget) / demand-bound, because:
1. L1↔L3 admit-alias: the queue-token gate L1 starves
   (`queue_service/mod.rs:879`) sits between `eligible_visits` (`:851`)
   and `phase1_admissions` (`:947`), so L1 produces the L3 fingerprint
   `p1_admit ≪ eligible_visits` (Codex r2 CRITICAL-1, verified).
2. L1↔demand-alias: TCP closed-loop pacing empties the CoS queue on a
   share-capped worker, so `backlog_i ≈ 0` aliases the demand-bound null
   (Codex r2 CRITICAL-2 + AGY r2 F1).
3. `share_integral_i` (the only L1-isolating column) is unmeasurable
   soundly — acquire-cadence rotation, multi-epoch caps, dimensional
   double-count (Codex r2 F2 + AGY r2 F2).
The three layers are serially coupled (L1 → queue.hot.tokens → L3) and
the independent demand signal is closed-loop; passive counters measure
the composition, not the parts. The #1211 lesson in instrument form.
