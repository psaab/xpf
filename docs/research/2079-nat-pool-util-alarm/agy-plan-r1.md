# AGY adversarial plan review r1 — #2079

Job: adversarial-review-mqmrffvn-smhd8t

## Verdict: REVISE

Close to viable but structural flaws: pool-metrics aggregation (false alarms),
control-socket contention via implicit I/O, config-validation gaps, state leak
on dynamic reconfiguration.

### CRITICAL: none

### MAJOR
1. **Double-counting UsedPorts on shared allocators (false alarms).** Rules
   referencing the same pool share the same `PortAllocator` via
   `Arc<PortAllocatorShared>` (verified: `nat/source.rs:283 existing.clone()`,
   `allocator.rs:153-156 shared: Arc<PortAllocatorShared>`, `#[derive(Clone)]`).
   Each rule's `snapshot()` returns the SAME pool total. Summing across rules
   (as plan §6.2 proposed) double/triple-counts → premature alarms. **FIX:
   DEDUPE by pool name (take the value once), do NOT sum.**
2. **Implicit blocking socket I/O in the monitor loop.**
   `Daemon.userspaceDataplaneStatus()` → `m.Status()` issues a blocking
   `ControlRequest{Type:"status"}` over the control socket whenever the helper
   is running (verified `manager.go:1852`). Plan's "no I/O" claim is wrong.
   **FIX: add `LastStatus() ProcessStatus` cached accessor returning
   `m.lastStatus` under lock; the statusLoop already refreshes it at 1Hz.**
3. **Stuck active alarms on pool removal/rename (state leak).** The loop only
   visits pools in the current config; a deleted/renamed pool's active alarm is
   never revisited and stays rendered forever. **FIX: prune `activeAlarms` keys
   absent from the current config every tick.**
4. **Missing compile-time threshold validation.** raise==0 fires immediately
   (util >= 0 always true); raise<=clear breaks hysteresis. A bare
   `pool-utilization-alarm;` stanza compiles to raise=0/clear=0 (verified
   `compiler_nat.go:336 &PoolUtilizationAlarmConfig{}`). **FIX: hard commit-time
   validation — require raise>clear, both in valid range — in the existing NAT
   validation block (`compiler_nat.go:369+`).**

### MINOR
5. **uint16 capacity underflow.** `PortHigh - PortLow + 1` on uint16 underflows
   if misconfigured. **FIX: validate PortHigh>=PortLow and AddressCount>0,
   compute in uint64.**

All five findings independently re-verified against worktree source.
