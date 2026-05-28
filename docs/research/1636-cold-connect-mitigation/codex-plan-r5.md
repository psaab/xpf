# Codex plan review — round 5 (#1636)

**Task ID**: task-mppt4xl4-tf0zaj
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v5 @ `1016ccfca89f`

## VERDICT: PLAN-NEEDS-MINOR

## Findings (verbatim from Codex)

1. **New v5 issue: PR-3 sysctl validation is too narrow** if it only reads `/proc/sys/net/ipv4/neigh/default/retrans_time_ms`. `default` may not reflect effective values on already-created dataplane interfaces, and IPv6 NDP has its own `/proc/sys/net/ipv6/neigh/<iface>/retrans_time_ms`. For D=800ms, validate the effective per-interface IPv4 and IPv6 retrans timers for every relevant dataplane interface, and fail closed to 2000ms on missing, parse error, or any value `>250`.

## R4 check-list responses

1. HA demotion re-check: adequate, assuming the invariant tolerates the tiny check-to-fire race.
2. Generation bump admitted-only: adequate.
3. Disconnected log once-only: adequate.
4. §10 wording and sustained-loss caveat: adequate.
5. IPv6 NDP source confirmation: adequate.

## Recommendation

Iterate once to tighten the sysctl validation language, then proceed to `/engineer 1636` implementation. B/C are ready; D should stay gated on the fixed validation.

## Session

Codex session ID: 019e6fc6-da25-7c10-9f90-c75715bbb449
