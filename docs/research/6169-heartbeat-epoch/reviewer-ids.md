# #6169 plan-review reviewer ledger

Research reviewers: Codex (`codex exec`, medium) + Claude SMR (in-conversation hostile).
AGY infra-down all rounds (2-of-2 documented per feedback_codex_infra_must_retry —
here Codex was healthy, so both active reviewers ran every round).

| Round | Plan | Codex | Claude SMR | Convergent takeaway |
|---|---|---|---|---|
| 1 | v1 | NEEDS-MAJOR | NEEDS-MAJOR (self-corrected from MINOR) | F2 session/counter lifetime + TLV desync missed by v1 |
| 2 | v2 | NEEDS-MAJOR | NEEDS-MAJOR (self-corrected from MINOR) | election-fence not a fence; key-derived discriminator; #5639 dep |
| 3 | v3 | NEEDS-MAJOR | NEEDS-MAJOR (self-corrected from MINOR) | volatile fence dies on crash → persist-before-emit |
| 4 | v4 | NEEDS-MAJOR | NEEDS-MAJOR (self-corrected from MINOR) | markerless dual-primary; far-future regress; async overwrite |
| 5 | v5 | NEEDS-MAJOR | NEEDS-MAJOR (self-corrected from READY) | one-way-partition dual-primary (fundamental) → choose consistency |
| 6 | v6 | NEEDS-MAJOR | NEEDS-MAJOR (self-corrected from READY-cond.) | advertise-before-actuation + wire contract → Stage-1 is full-HA-stack |

Outcome: core validated; Stage 0 PLAN-READY (cheap, no wire change); Stage 1
(wire epoch) not converged to clean PLAN-READY — recommend ship Stage 0, defer /
PLAN-KILL Stage 1 pending user cost/benefit (§13). PLAN-KILL of the mechanism is
NOT forced (Codex), but the availability cost/benefit is the user's call.
