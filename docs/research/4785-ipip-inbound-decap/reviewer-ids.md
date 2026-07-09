# #4785 plan review — reviewer provenance

- **Codex** (hostile plan review): companion `task --background`, session shared.
  Attempt 1 `task-mrdtsx9q-5k37yl` (dropped while shared session busy),
  attempt 2 `task-mrdtz4pe-f9nhym`, attempt 3 `task-mrdu1lsg-k53783`
  (duplicate). `result` returns "No job found" while a job is still *running* —
  poll `status` for `completed` first, then fetch `result`.
- **Claude SMR** (hostile self-review): `claude-smr-plan-r<N>.md` in this dir.
- **AGY / gemini:** infra-down this session (2-of-3 convergence: Codex +
  Claude SMR), per the standing session note.
- **Copilot:** joins only at `/engineer` (not this /research phase).
