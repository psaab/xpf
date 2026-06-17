# Codex hostile plan review r2 — #1918 — task-mqhoiw4d-1l8qwi

Verdict: PLAN-NEEDS-WORK

F1 RESOLVED (Seq+nonce, no ID), F3 RESOLVED, F6 RESOLVED. F2/F4/F5 PARTIAL.

NEW:
- NF1 (HIGH) — probe ignores tc.Source; unbound socket may pick a different egress source on a
  multi-homed host → probe success/failure non-representative of tunnel encap. [Converged with
  AGY r2 #5; folded as §5c in r3.]
- NF2 (MEDIUM) — Axis D flips Up under lock then reverts on LinkByName error; window where Apply
  reads optimistic Up (skipUp, tunnel.go:531-538) and acts before revert lands → kernel/state
  inconsistency. [Fixed in r4 by commit-after-success.]
- NF3 (HIGH) — same-name ifindex guard under-specified; action-time LinkByName reads the NEW
  link after recreate → guard passes → stale runner downs the replacement. Need generation token
  captured at startKeepalive. [Fixed in r4 by linkGen token.]
- NF4 (MEDIUM) — errno classification incomplete (ENOMEM, EAFNOSUPPORT/EPROTONOSUPPORT
  unclassified); ENOMEM could be held as structural. [Fixed in r4: complete table + UNRECOGNIZED
  -> TRANSIENT default.]
