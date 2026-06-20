# Codex r7-retry (fresh session) cross-check — #2079

Agent: aa0db8139112cf6e0 (~6.4 min). Reviewed r7 (the base for r8/r9).

## Verdict: PLAN-READY (12-point clean pass)

A fresh-session Codex independently validated the ENTIRE r7 design against source
with no findings — every dimension OK:
1. Forward design (parse/store only in source today). 2. Eligibility
rule-referenced (matches `nat.go:16` source-rule walk). 3. Dedup by pool name
(shared `Arc<PortAllocatorShared>` `allocator.rs:153`, `source.rs:282-289`).
4. Gen-coherency gate before per-pool numeric eval, prune outside it (gen fields
exist: `protocol.go:43,618`; Rust stamps gen only after accepting a snapshot,
`snapshot.rs:63`). 5. raise/clear/updatePct mutually exclusive. 6. nil/disabled
clear-all-and-return (`store.go:1573-1576`). 7. HOLD semantics explicit (gen-lag /
absent / bad-sample). 8. Prune config-eligibility based, emits clears. 9. Lock
discipline (syslog outside the alarm mutex; syslog takes its own mutex
`syslog.go:176-189`). 10. Both render sites. 11. Hard commit validation
0<clear<raise<=100. 12. uint64 underflow-safe arithmetic.

NOTE: this validated r7's structure. The original r7 pass (different session)
found the apply-window gen-skew (folded → r8); AGY r8 then refined the
`HelperCaughtUp` predicate (folded → r9). This clean 12-point pass corroborates
that the rest of the plan is solid.
