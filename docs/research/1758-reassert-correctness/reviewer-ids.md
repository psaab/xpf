# #1758 reviewer task IDs

- Codex r1: `task-mpymyhqo-jv74ck` — verdict **PLAN-KILL as written**;
  REACHABLE confirmed; broadened collision set (NAT64, DNAT-shared-backend,
  non-bijective static NAT); counter is telemetry not resolution.
  `codex resume 019e8f98-4320-7ab3-a80b-ab57666683db`
- AGY r1: `adversarial-review-mpymy8em-e6adxr` — ran 52 steps, exited mid
  code-exploration without emitting a final verdict (step-budget /
  known AGY unreliability). Surfaced the dual reverse-entry install
  (`poll_descriptor:1376`) interaction, folded into §4a. Re-dispatch on v2.
  Brain: `/home/ps/.gemini/antigravity-cli/brain/d0d99cf8-b0bf-4ba3-b13d-164c4a42b1bf/`
- Claude SMR r1: `claude-smr-plan-r1.md` — PLAN-KILL (perf framing) /
  PLAN-READY (disposition).
