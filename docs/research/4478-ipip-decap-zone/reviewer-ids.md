# Reviewer ID ledger — #4478 research plan-review

2-of-3 (AGY/gemini infra-down this session; Copilot joins at /engineer).
Converged r1/r2 on **PLAN-KILL** (security framing invalid).

| Round | Reviewer | ID / file | Verdict |
|-------|----------|-----------|---------|
| r1 | Codex | task-mrdq23za-ebef2u (session 019f47b6-691a-7261-aa9b-ca9da490f8d8) | PLAN-KILL/DEFER |
| r1 | Claude-SMR | claude-smr-plan-r1.md | PLAN-REVISE |
| r1 | AGY | infra-down | n/a |
| r2 | Claude-SMR | claude-smr-plan-r2.md | PLAN-KILL (converges with Codex r1) |

## Note on the Codex r1 job registry

The Codex companion job registry evicted `task-mrdq23za-ebef2u` before poll
(`status`/`result` returned "No job found"), but the job COMPLETED and wrote its
full verdict to its log
(`.../jobs/task-mrdq23za-ebef2u.log`, "Final output: PLAN-KILL/DEFER"). Verdict
captured verbatim in the issue comment. No retry needed — the review completed.

## Codex r1 verdict (verbatim, key finding)

> PLAN-KILL/DEFER — the plan's crux is not verified against the production
> userspace path. It cites the legacy kernel tunnel constructor as if userspace
> IPIP creates `Iptun`, but the daemon sets `AnchorOnly=true` for the effective
> userspace dataplane before applying tunnels (daemon_run.go:117/148/159).
> `Apply` then takes `applyAnchorLocked` when `AnchorOnly` is set
> (tunnel.go:471), creating a persistent TUN anchor (tunnel.go:557). The
> `Iptun`/`Ip6tnl` branch the plan relies on is explicitly the legacy non-anchor
> path. If production userspace IPIP is already anchor-only, the current bug is
> likely "IPIP inbound is unsupported/broken or drops," not "kernel Iptun decaps
> fail-open." Severity M-1 is not justified until a baseline reproduces on the
> effective userspace dataplane.
