# Codex — adversarial plan review r1 — #3630

Reviewer: Codex (codex:codex-rescue), commit 1ea5ed9f6.

## Verdict: PLAN-KILL (works-as-intended)

The decisive discriminator already exists: `policy_id == 0xFFFFFFFF`
(`DefaultPolicySentinelID`) is present on the synthetic default row in both REST
and gRPC with no optional-presence ambiguity. `is_default` is pure redundant
schema churn for a self-declared LOW issue.

## Findings (verbatim)

1. **PLAN-KILL. Works-as-intended.** REST sets `PolicyID:
   DefaultPolicySentinelID` (`pkg/api/security.go:315`) and `PolicyRule.PolicyID`
   is non-omitempty `uint32` (`pkg/api/types.go:188`) — always emitted. gRPC
   sets `PolicyId: proto.Uint32(DefaultPolicySentinelID)`
   (`pkg/grpcapi/server_show_zones.go:284`); field + sentinel documented at
   `proto/xpf/v1/xpf.proto:311` + `pkg/dataplane/types.go:420`. Every consumer
   already has a collision-proof discriminator. `is_default` is redundant.
2. Bool < enum, but moot under KILL. A `scope` enum duplicates info already in
   the enclosing `PolicyInfo` grouping + `*/*` labeling. Over-scope for LOW.
3. Do not emit `["any"]`: output break; `any` is not a safe token
   (address-book lookup precedence `pkg/policymatch/policymatch.go:736`;
   arbitrary book names incl. `any` `pkg/config/compiler_security.go:1166`).
   Empty non-excluded lists already mean match-any in the matcher
   (`pkg/policymatch/policymatch.go:698`) — documentation, not a wire fix.
4. Keeping `is_default` (inventory identity) distinct from `default_used` (match
   fall-through result) is structurally correct; renaming breaks the API for no
   gain (`pkg/api/types.go:475`, `proto/xpf/v1/xpf.proto:752`).
5. Text/Prometheus unchanged is defensible. **Plan factual error:** the
   Prometheus label is `rule`, not `policy` (`pkg/api/metrics_descriptors.go:155`).
6. **Plan factual error:** the plan claims REST inventory `policy_id` is
   `*uint32` — it is bare `uint32` (`pkg/api/types.go:188`); the pointer is only
   on `MatchPoliciesResult.PolicyID` (`pkg/api/types.go:465`). "Next free field
   = 21" is correct (`inactive = 20` last, `proto/xpf/v1/xpf.proto:332`).
7. **Invariant misstated.** Inventory is NOT always exactly-one default row:
   nil config returns empty on REST (`pkg/api/security.go:113`) and gRPC
   (`pkg/grpcapi/server_show_zones.go:102`), while match-policies returns
   `default_used=true` for nil config (`pkg/api/security.go:433`). Also proto3
   plain `bool` has no explicit presence, so old-server absence and `false` are
   indistinguishable — clients STILL need the sentinel as the primary
   discriminator, making `is_default` fully redundant.
