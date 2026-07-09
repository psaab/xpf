# Codex hostile plan-review r2 (#4455 HI-1)

Task: task-mrdrwt8t-ijcga5  |  Verdict: PLAN-KILL-WRONG (kill enforcement, but ship a narrow warn-only managed-FRR-mismatch advisory)

```
PLAN-KILL-WRONG

1. r2 materially folds C1-C8; I am not rejecting on those. See `docs/research/4455-hostinbound-mcast/plan.md:26`, `:53`, `:59`, `:35`, `:43`, `:287`, `:253`.

2. The terminal-state claim is false. r2 says #4454 “already makes the gap operator-visible” (`docs/research/4455-hostinbound-mcast/plan.md:165`, `:387`), but the shipped warning only fires when multicast tokens are present (`pkg/config/compiler_validate_warn.go:1657`, `:1680`, `:1687`). It explicitly warns nothing for no `protocols`/no host-inbound (`pkg/config/host_inbound_multicast_warn_4455_test.go:100`).

3. There is a valuable low-risk subset: WARN-only managed-FRR mismatch advisory for OSPF/OSPFv3/RIP interfaces whose effective zone/interface host-inbound tokens omit the protocol. r2 already defines the needed cross-check for future enforcement (`docs/research/4455-hostinbound-mcast/plan.md:308`), and the managed sources are real (`pkg/frr/policy_render.go:507`, `:612`, `:998`). This avoids nft/Rust/iifname/RETH/GRE risk while exposing the silent Junos-parity fail-open.
```
