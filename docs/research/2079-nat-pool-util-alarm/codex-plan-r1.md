# Codex hostile plan review r1 — #2079

Agent: codex-rescue aab11e6c65bb05452 (64.7K tokens, 57 tool uses)

## Verdict: PLAN-READY-WITH-NITS

Architecturally sound, load-bearing claims verified. No CRITICAL/MAJOR.

## Findings (all re-verified against worktree source)
1. **MINOR — aggregation mechanism misstated (the key one).** `PortAllocator`
   is `Clone` but wraps `Arc<PortAllocatorShared>` (`allocator.rs:154,162`).
   Rules sharing a pool get the SAME Arc via the dedup map
   (`source.rs:202,282-290`), so both rules' `snapshot().used_ports` read the
   SAME live state → identical UsedPorts. Plan's "sum UsedPorts by pool" is
   WRONG (double-counts). Correct: **deduplicate by pool_name, take any one
   entry's UsedPorts (or max — they are identical).** [converges with AGY M1]
2. **MINOR — missed CLI render site.** There is a parallel
   `CLI.showSecurityAlarms` at `pkg/cli/cli_show_security.go:1788` (invoked from
   `cli_show_security_dispatch.go:332`) distinct from the gRPC
   `Server.showSecurityAlarms` (`server_show_security_text.go:308`). NAT pool
   alarm state must be injected into BOTH or local-CLI diverges from gRPC/remote.
   Plan §6.3/§7 only mention the gRPC site. [verified: both exist]
3. **MINOR — `nat_port_counters` is not merely "non-authoritative", it is never
   incremented post eBPF-retirement.** Only `SeedNATPortCounters` writes it (a
   random seed at startup); neither `userspace-xdp/src/lib.rs` nor
   `userspace-dp/src/` increment it. `ReadNATPortCounter` returns the random
   seed, not utilization. Strengthens the "do not use it" decision.
4. **MINOR — capacity edge case `PortLow > PortHigh`.** Guard explicitly (uint
   underflow) — matches the reference guard `allocator.rs:711-720`. [converges
   with AGY M5]
5. **NIT — §11 line refs:** statusLoop is `process.go:393`, NOT `manager.go:393`
   (which is `userspaceHAController`). `manager.go:110/1094/1840` correct.
6. **NIT — §10.Q3 should be RESOLVED (to dedup), not left open with a wrong lean.**
7. **NIT — §10.Q1 hard-error vs ValidateConfig-warning:** plan conflates the two
   mechanisms; pick one (commit hard-reject like `ErrEBPFDataplaneRetired`, or a
   ValidateConfig warning).
8. **NIT — §2b "statusLoop ~line 393" misattributed to manager.go.**

Only Finding 1 has implementation-correctness impact; Finding 2 causes output
divergence if missed. Path B + 1Hz-reuse + showSecurityAlarms site all verified
appropriate.
