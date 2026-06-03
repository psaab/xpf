# #1755 CoS hot-path research — reviewer task IDs

## Round 1 (plan v1 → v2 convergence)
- Codex: bh0jlzu21 — PLAN-READY for Change A only; PLAN-NEEDS-MAJOR if Change B
  stays in scope without a real heap-construction design (zeroed Vec/VecDeque
  unsound; must use MaybeUninit). Verdict addressed in v2 §4.1.
- AGY: adversarial-review-mpymqq4m-keg4up — PLAN-NEEDS-MAJOR: second probe site
  ensure_cos_interface_runtime (36 KB ingress) must be folded in + make Change B
  mandatory. Addressed in v2 §2.2a / §4.1 (Change A2) / §4.3.
- Claude SMR: docs/research/1755-cos-hotpath/claude-smr-plan-r1.md — PLAN-READY
  (F1 Change-B-measured-decision, F2 >=1pp gate, F3 file #4-follow-up).

## Round 2 (v2)
- Claude SMR: docs/research/1755-cos-hotpath/claude-smr-plan-r2.md — PLAN-READY.
- Codex/AGY r1 NEEDS-MAJOR items all folded into v2; both r1 verdicts were
  "READY once the specified items land", which v2 does verbatim.
