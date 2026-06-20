# Claude SMR — Plan Review r3 (#2076)

**Posture:** hostile. r3 folds Codex's r2 residuals (all doc-quality + one
spec-clarity MAJOR). I returned PLAN-READY at r2; the r3 deltas do not change the
mechanism, so I re-confirm.

## Codex r2 residuals — resolution check
- **#10 (MAJOR, multi-address giaddr source IP):** RESOLVED. §7.2 now states the
  L2 source IP is the SAVED giaddr (interfaceIPv4 = first non-loopback,
  relay.go:522-535, computed once at runRelay:271), refreshed-per-send applies
  ONLY to ifindex+MAC, and the ciaddr-via-UDP fallback uses the same source. This
  is the only correct choice — the source IP must equal what the server saw as
  giaddr in the relayed request. Verified relay.go:522-535 selects
  first-non-loopback. Correct.
- **#6 (MTU formula contradiction):** RESOLVED. Both the changelog and §7.2 now
  use the L3 bound `20 + 8 + len(payload) > iface.MTU`; the misleading `14+20+8`
  full-frame figure is removed.
- **#7 (per-send TOCTOU not acknowledged):** RESOLVED. §7.2 explicitly states the
  TOCTOU is benign (interface error → broadcast fallback) and the lookup cost is
  negligible at DHCP reply volume — matches AGY's r2 analysis and my r1 N2.
- **#9 (stray pkg/ra in §6):** RESOLVED. Removed from the §6 rationale ("four
  places" → "lldp, garp, vrrp").
- **#11 (stale citations):** RESOLVED. types_system.go:703 / compiler_services.go:
  1073 corrected; the 1113-1114 interface-boundary cite was already correct
  (verified).

## My r1/r2 findings + the BLOCKERs: still resolved
No r3 change touched the fd-lifecycle (§7.3), the flat-set boundary fix (§7.4),
the ciaddr row (§7.1), the htype guard, the malformed-frame gate (§8.2), or the
HA test-failover gate (§7.6). All remain as folded.

## New-issue hunt on the r3 edits
None. The r3 edits are subtractive (removed a wrong figure + a wrong precedent)
and clarifying (source-IP policy, TOCTOU note, citation fixes). No new code-path
or design change.

## Verdict

**PLAN-READY.** The mechanism (option d) and every reviewer finding across r1/r2/
r3 are resolved. Recommend proceeding to /engineer.
