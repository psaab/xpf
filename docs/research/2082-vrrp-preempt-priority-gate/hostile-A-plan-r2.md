# Hostile reviewer A — plan re-review r2 (A2), #2082

OVERALL: PLAN-NEEDS-WORK (3 of 4 r1 points fully closed; ONE real new blocker)

Closed: lock discipline (snapshot list complete vs getPriority inputs);
integration honesty (smoke is preempt=false, scripts assert no-preempt,
test-failover no-regression-only, run-loop unit test authoritative); nil-localIP
genuinely moot (IP tie-break dropped, strict `>` RFC 5798 §6.4.2-correct, no
peer-IP field). New section-6 invariants verified against source (off-by-one
line cites 371/372, 728/727 are cosmetic).

BLOCKER (new, r1's own concern resurfaced): §7's "run `run()` briefly under a
stop channel" alternative is BROKEN — `run()` preamble unconditionally
`go vi.receiver()` (instance.go:305) → `vi.conn.SetReadDeadline` on nil conn
(instance.go:445) → nil-pointer panic in a background goroutine that crashes the
test process. An implementer who picks that option hits a panic and falls back
to a helper-only test, re-opening the gap.

Required: (1) delete the "run run() briefly" alternative; bind the wiring tests
to an extracted `stepBackup()` single-iteration seam (or mandate stubbing the
receiver / afPacketFD); state the panic hazard. (2) minor: add
cfg.AdvertiseInterval to the §5 snapshot. (3) cosmetic: fix line cites.

[r3 closes all three: stepBackup seam, AdvertiseInterval snapshot, cites fixed.]

Agent: general-purpose hostile-reviewer-A2 (agentId a1e8bc9d72e61738c).
