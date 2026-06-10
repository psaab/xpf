# Reviewer task-ID ledger — #1827 multi-WAN research

## Round 1 (plan v1, 003657586)

- Codex: `task-mq8el1x7-umm9hr` (hostile plan review, effort high)
- AGY: `adversarial-review-mq8ejo4w-90m0gs` (background adversarial review)
- Claude SMR: `claude-smr-plan-r1.md` — PLAN-NEEDS-REVISION

## Round 1 verdicts

- Codex `task-mq8el1x7-umm9hr`: PLAN-NEEDS-REVISION (10 findings; full-apply rejected, fib_generation unproven, pin-route transit hazard, FBF exposure, preferred-metric parity unverified, split PR-1, primary-only HA)
- AGY `adversarial-review-mq8ejo4w-90m0gs`: PLAN-NEEDS-REVISION (distance divergence + same-prefix non-determinism Criticals; full-apply rejected; pin-route isolation; FBF precondition; split real-ICMP; probe-on-both-from-node-local dissent)
- Claude SMR r1: PLAN-NEEDS-REVISION (actuation feedback loops Critical; standby probing broken on RETH; pin routes kernel-only; DHCP limitation; coalescing; content-hash test)

Plan v2 addresses all; preferred-metric semantics corrected against Juniper docs (injected route = preference 1/Static-1; preferred-metric = metric among injected routes).

## Round 2 (plan v2/v2.1, a24300ebe/9dbf2d599)

- Codex: `task-mq8f0ald-x9h2je` — PLAN-NEEDS-REVISION (pin-route multiplicity/ranges; named PublishRouteOverlaySnapshot API; complete assembleFRRConfig contract)
- AGY: `adversarial-review-mq8f0ig9-f1m1v7` — PLAN-READY with conditions (snapshot-before-bump ordering High; operator-commit overlay-wipe Medium; pin crash cleanup; 3s throttle)
- Claude SMR: `claude-smr-plan-r2.md` — PLAN-READY contingent on folds A/B (applied in v2.1)

v3 folds all round-2 findings.
