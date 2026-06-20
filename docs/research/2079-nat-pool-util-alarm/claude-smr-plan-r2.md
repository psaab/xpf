# Claude SMR — Hostile Plan Review r2 — #2079

Reviewer: Claude SMR (hostile). Reviewing plan.md r2 after folding the r1 3-way
review.

## Verdict: PLAN-READY

All r1 findings (mine + AGY's + Codex's) are correctly folded, and the single
correctness-critical correction — DEDUPLICATE rather than SUM `UsedPorts` across
rules sharing a pool — is now mandated in the design and backed by the verified
shared-`Arc<PortAllocatorShared>` evidence (`allocator.rs:154`,
`source.rs:282-290`). The remaining items are non-blocking implementation
discretion. This is implementable as-is.

## r1 → r2 fold verification (each independently checked)

- **AGY M1 / Codex F1 (the key fix):** §6.2 + §6.1 pseudocode now dedup by pool
  name (`byPool[s.PoolName] = s`) and take one entry — explicitly "do NOT sum".
  Correct: I re-confirmed the shared Arc means all entries for a pool carry the
  identical `UsedPorts`, so one value is right and summing would double-count.
  RESOLVED.
- **AGY M2:** §2b + §6.1 now mandate a new `Manager.LastStatus()` cached accessor
  (no socket I/O) instead of `Status()` (which I verified does
  `requestLocked(ControlRequest{Type:"status"})` at `manager.go:1852`). RESOLVED.
- **AGY M3:** §6.1 loop now prunes `activeAlarms` keys absent from the snapshot.
  RESOLVED.
- **AGY M4 / SMR m1 / Codex F7:** §6.2 + §10 now mandate a hard commit-time check
  `0 < clear < raise <= 100` at `compiler_nat.go:369+`, rejecting the bare
  `pool-utilization-alarm;` (raise=0) case I and AGY both flagged. RESOLVED.
- **AGY M5 / Codex F4:** capacity math guards `PortHigh < PortLow` and
  `AddressCount == 0`, computes in uint64. RESOLVED.
- **Codex F2:** §6.3 + §7 now name BOTH render sites (gRPC
  `server_show_security_text.go:308` AND local-CLI `cli_show_security.go:1788`)
  with a shared formatter. RESOLVED (I verified both functions exist).
- **SMR M1:** §6.3 now states the count-in-summary / body-in-detail convention.
  RESOLVED.
- **SMR m3:** deterministic pools skipped in r1. RESOLVED.
- **SMR F-OK3 / Codex F3:** the dead-counter note now states `nat_port_counters`
  is never incremented (seed-only) and the existing Prometheus/CLI surfaces are
  already garbage. RESOLVED + scoped as follow-up.
- **Codex F5/F8:** §11/§2b line refs corrected (statusLoop `process.go:393`).
  RESOLVED.

## New issues from the r2 edits — none MAJOR

### NIT (carry into /engineer, not blocking)
- **n1 — deterministic-skip cfg lookup must use comma-ok form.** §6.1 detects
  deterministic pools via `cfg...SourcePools[poolName].Deterministic != nil`. If
  a pool is in the dataplane snapshot but already deleted from the active config
  (transient during a commit), `cfg...SourcePools[poolName]` returns the nil
  zero-value `*NATPool` and `.Deterministic` would nil-deref. Engineer must use
  `if p, ok := cfg.Security.NAT.SourcePools[poolName]; ok && p.Deterministic !=
  nil { skip }`. Pools absent from config are pruned anyway (AGY M3 step), so the
  alarm path can also just skip any snapshot pool not in config. One-line guard.
- **n2 — `RuleName` label dropped on dedup.** The existing Prometheus gauge keys
  on `{pool,rule}`; the alarm registry keys on pool only (correct — Junos alarm
  is per-pool). Just ensure the syslog/alarm message reports the pool name (not a
  rule), to avoid operator confusion when a pool spans rules. Cosmetic.
- **n3 — capacity from the deduped entry:** when taking one entry, capacity
  (`AddressCount`, `PortLow/High`) must come from THAT SAME entry (they are
  pool-intrinsic and identical across entries, so any is fine — just don't mix an
  AddressCount from one row with UsedPorts from another). The pseudocode already
  uses `s` consistently; flagging so the engineer keeps it that way.

## Standing assessment
Path B remains the right recommendation; PLAN-KILL correctly rejected. No
dataplane/wire change, no new control-socket traffic, HA-neutral. The plan is
converged from my side: **PLAN-READY**, with n1-n3 as engineer-time notes.
