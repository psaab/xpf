# Codex hostile plan review r10 — #2079

The original r10 agent (ad6d71ffb69e9ad95) wedged in the after-first-job broker
synthesis hang; a fresh-session retry (ac8f3852129726977, ~4 min) COMPLETED.

## Verdict (retry): PLAN-READY — "No findings."

A full clean pass with source verification:
- r10 closes the generation-gate bug: the monitor is sourced from a proposed
  Go-only `appliedSnapshot`/`AppliedNATView` (plan.md:391-419, 616-631), NOT
  `lastSnapshot` or `publishedSnapshot` (manager.go:100-162). The helper already
  echoes `last_snapshot_generation` (protocol.go:601-684; snapshot.rs:63-65) → NO
  Rust change required.
- Rationale matches source: FIB/neighbor paths bump
  `lastSnapshot.Generation`/`publishedSnapshot` without a full apply
  (manager.go:1163-1166, 1303-1312); Rust `bump_fib` only updates
  `last_fib_generation` (snapshot.rs:150-169); full `apply_snapshot` is the ONLY
  path that updates `last_snapshot_generation` (snapshot.rs:14-65). Implementation
  must hook the Go apply_snapshot callsites: manager.go:688-704, 796-810, 950-963;
  process.go:352-367.
- HOLD/clear coherent: `!Available` and `!HelperCoherent` return before any
  raise/clear/prune (plan.md:419-429); §6.4 retains active alarms so clears are
  DEFERRED to the next coherent tick (plan.md:577-596).
- Earlier invariants re-checked against source: rule-derived status
  (status.rs:9-34; nat.go:11-23), shared-allocator dedup (source.rs:281-290),
  both render sites (server_show_security_text.go:304-361;
  cli_show_security.go:1788-1847), parsed thresholds + planned validation slot
  (compiler_nat.go:334-369; types_security.go:232-255), old metrics/show-NAT
  counter paths left out of scope (metrics_nat.go:12-40), syslog severities exist
  (syslog.go:14-18, 173-204).

This is the convergence verdict. Combined with the r7-retry's earlier full
12-point PLAN-READY, Codex has independently validated the entire design.
