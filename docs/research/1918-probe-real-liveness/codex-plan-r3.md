# Codex hostile plan review r3 — #1918 — task 019ed43e-77da-79a1-8894-8eb2cf5b22ea

Verdict: PLAN-NEEDS-WORK

F1-F6 all RESOLVED in r3. §5c source-bind API-correct (icmp.ListenPacket(network, source) ->
syscall.Bind, listen_posix.go:79-84). matches()/threading correct against tunnel.go:83-85,547.

NEW BLOCKING:
- Axis D (r3 form) commits state.Up before the netlink op and reverts only on LinkByName error,
  NOT on LinkSetUp/LinkSetDown error. Counterexample: dead peer -> Up=false committed ->
  LinkByName ok -> LinkSetDown transient error -> kernel stays up but Up==false so later dead
  ticks never retry (guard needs Up==true) -> permanent desync, violating the plan's own
  "no permanent desync" invariant. Fix: handle LinkSet* error -> revert/don't-commit + tests.
  [Fixed in r4 by commit-ONLY-on-netlink-success: Up is never written until LinkSet* returns nil.]
