# Codex hostile plan-review — #4874 round 2 (task-mre583kl-a7b4d0, gpt-5.5, xhigh)

OVERALL: PLAN-READY-WITH-NITS

A1: keep
A2: fix
B: fix

1. LOW - B acquire guard precision: r3's semantic rule is right, but the implementation must not keep the narrow `wantNA && ...` shape from `pkg/dhcp/dhcp.go:1526`. PD-only clients have `wantNA=false` and can otherwise fall through to the default 1h lease at `pkg/dhcp/dhcp.go:1548`. Count live PDs regardless of `wantNA` when no IA_NA address is present.

2. LOW - B local PD state: after reconcile, `runDHCPv6` must update `committedPDs` to the reconciled set, not only on `len(prefixes)>0` as today at `pkg/dhcp/dhcp.go:1213`, `pkg/dhcp/dhcp.go:1259`, and `pkg/dhcp/dhcp.go:1295`. Otherwise the next RENEW can still echo a withdrawn prefix via `pkg/dhcp/renew.go:147`.

A2 closes the stale FRR/RA gap for the real terminal paths. `scheduleRecompile` only arms a `time.AfterFunc` at `pkg/dhcp/dhcp.go:1805`; `applyConfig` happens later through `onDHCPAddressChange`, so there is no inline `applySem` re-entry. I found no remaining lease/PD delete path outside the r3 A2 scope.
