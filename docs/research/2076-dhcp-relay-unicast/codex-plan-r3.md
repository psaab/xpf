# Codex Convergence Check r3 (#2076)

Dispatched via codex-rescue subagent (agentId ae40cd8ec0562dc92), 2026-06-20.

## Verdict

**PLAN-READY**

All five r2 residuals confirmed folded in r3, verified against source:

- **#6 (MTU formula):** changelog + §7.2 both use `20 + 8 + len(payload) >
  iface.MTU`; no contradictory `14+20+8` remains.
- **#7 (TOCTOU):** §7.2 explicitly states the TOCTOU is benign (interface error
  ENODEV/ENXIO → caught → broadcast fallback).
- **#9 (pkg/ra):** §6 precedent list is `lldp`, `garp`, `vrrp` — no `ra`.
- **#10 (giaddr source-IP policy):** matches source — `interfaceIPv4` returns
  first non-loopback IPv4 (relay.go:522-535); `runRelay` computes giaddr once via
  `resolveGIAddrWithRetry` (relay.go:271); per-send refreshes only ifindex+MAC.
- **#11 (citations):** `DHCPRelayGroup` at types_system.go:703;
  `compileDHCPRelay` at compiler_services.go:1073 — both cited correctly.

No new contradictions introduced by r3; no previously-resolved r1 findings
broken.
