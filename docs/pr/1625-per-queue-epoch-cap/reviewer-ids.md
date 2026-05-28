# Reviewer task IDs — #1625 per-queue epoch-cap

Each row: round / reviewer / task-id (Codex/AGY) or `inline` (Claude SMR).

## Plan-review rounds

| round | reviewer | task-id / status |
|-------|----------|------------------|
| r1    | claude-smr | docs/pr/1625-per-queue-epoch-cap/claude-smr-plan-r1.md |
| r1    | codex      | task-mppkt4ad-g3gtz0 (initial task-mppk1bcu-i49j50 was lost in broker session-mismatch) |
| r1    | agy        | adversarial-review-mppk1nwa-s66mo9 |

## Round-1 outcome

- Claude SMR r1: PLAN-NEEDS-MINOR (4 MEDIUM)
- AGY r1: PLAN-NEEDS-MAJOR (5 fatal findings)
- Codex r1: PLAN-NEEDS-MAJOR (6 fatal findings, including the dispositive
  v8-shared-lease-already-implements-this discovery)

## Round-2 (all three reviewers)

| round | reviewer | task-id / status |
|-------|----------|------------------|
| r2    | claude-smr | docs/pr/1625-per-queue-epoch-cap/claude-smr-plan-r2.md |
| r2    | codex      | task-mpplbjne-o3eye4 |
| r2    | agy        | adversarial-review-mpplbz0k-zo4swh |

## Round-2 outcome — 3-of-3 PLAN-KILL

- Claude SMR r2: PLAN-KILL (revised from r1)
- Codex r2: PLAN-KILL ("I am the second PLAN-KILL reviewer for `feedback_plan_kill_label_required`")
- AGY r2: PLAN-KILL ("Verdict: PLAN-KILL")

All three reviewers converged on the same dispositive evidence:
- `coordinator/mod.rs:1092-1126` allocates v8 shared lease for every exact queue.
- `rotate_epoch_v8.rs:215-225` computes the exact same `rate × elapsed_ns / 1e9` cap.
- `shared_cos_lease/mod.rs:1089-1092` enforces it in the primary acquire path.
- The mechanism PR-1625 proposes is structurally redundant with v8.

The actual root cause of #1614's ~20%/class equalization is more likely:
- `worker_fair_share` math at `rotate_epoch_v8.rs:230-235` (cap × flows / total_flows — uniform under uniform-flow fixture).
- Phase-2 lock-in scaffold bug in PR-1618 (positive remainder + Phase 2 never returns None → reset never reached).
- Smoke fixture `cos-iperf-config.set` does NOT enable `oversubscription-policy guarantee-rate` — the new waterfill code path isn't even being exercised.

