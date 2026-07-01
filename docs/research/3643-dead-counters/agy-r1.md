# AGY adversarial plan review — #3643 r1

Job: adversarial-review-mr1zq1au-fxheaq

## Final Verdict
- PLAN-NEEDS-MAJOR if the POPULATE (§5A) path is pursued.
- PLAN-READY if the HIDE (§5B) path is chosen instead (Phase 1 + drop/clean metrics).

## Key findings / required changes

1. Hot-Path HashMap Performance Bottleneck (POPULATE §5A): the helper receives a
   stable u16 zone id in [1,65533], so it must resolve a slot on 100% of packets.
   A ZoneCounterSlotMap HashMap::get lookup would severely throttle forwarding.
   REQUIRED CHANGE: use a flat lookup table zone_slots: [u8; 65536] (64 KB direct
   array) for O(1) resolution.

2. Missing Clear IPC Path (POPULATE §5A): Go-side offset clears are insufficient;
   ClearAllCounters must send a new clear_zone_counters control IPC so cleared
   values do not snap back on the next 1 s status poll (mirror ClearNATRuleCounters
   / policycounters.go:163).

3. Choosing the fork: per-zone metrics are largely redundant given per-policy
   (#2118) and per-interface counters, so HIDE (§5B) is the recommended path — it
   resolves the REST-500, CLI warnings, and Prometheus alert storm with zero code
   complexity and zero hot-path overhead.
