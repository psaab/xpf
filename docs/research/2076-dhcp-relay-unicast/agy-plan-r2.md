# AGY Adversarial Plan Review r2 (#2076)

Job: `adversarial-review-mqmrq32p-rk13f1` — succeeded 2026-06-20.

## Verdict

**PLAN-READY**

## Confirmation (all r1 findings resolved, no new issues)

1. fd use-after-close (BLOCKER) — RESOLVED: L2 sender TX-only, kept out of the
   cancel watcher (relay.go:308-327), closed idempotently via sync.Once after
   wg.Wait() (handleServerResponses, the sendReply caller, has exited).
2. flat-set overrides swallow (BLOCKER) — RESOLVED: `overrides` added to the
   compiler boundary (compiler_services.go:1113-1114).
3. malformed-frame defeats fallback (MAJOR) — RESOLVED: risk narrowed +
   byte-level construction checks + live wire-capture promoted to a blocking PR
   gate.
4. dynamic ifindex/MAC (MAJOR) — RESOLVED: per-send InterfaceByName (garp.go
   pattern); source IP from saved giaddr, not the zeroed packet field.
5. MTU/fragmentation (MAJOR) — RESOLVED: `20+8+len(payload) > iface.MTU` guard →
   UDP/broadcast fallback (kernel fragments).
6. ciaddr destination gap (MAJOR) — RESOLVED: flag0+yiaddr0+ciaddr!=0 → unicast
   to ciaddr via the standard UDP socket.
7. dual-AST compile coverage (MAJOR) — RESOLVED: both shapes tested via
   ParseSetCommand+SetPath in dual_ast_differential_test.go.
8. wrong schema line (MINOR) — RESOLVED: schema_routing.go:373-382.
9. pkg/ra precedent (MINOR) — RESOLVED: removed.

## AGY's answers to the new-issue probes
- ciaddr-via-UDP does NOT need a separate broadcast-flag check: the matrix is
  sequential and the flag1→broadcast rule precedes the ciaddr (flag0-only) rule.
- per-send re-resolution: syscall cost negligible (DHCP is low-frequency); TOCTOU
  failure mode is a Sendto error → safe broadcast fallback (reopen-on-error).
- close-after-wg.Wait() is correct: handleServerResponses is the only L2 sender
  and is joined by wg.Wait() before Close().
