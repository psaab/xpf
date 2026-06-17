# Reviewer ID Ledger — #1915

Track Codex task IDs + AGY review IDs per round.

| Round | Reviewer | Task/Review ID | Verdict |
|-------|----------|----------------|---------|
| r1 | Codex | codex exec (read-only, fg bg b8r2e8w1j) | PLAN-NEEDS-WORK (line-num fix; arch sound) |
| r1 | AGY | adversarial-review-mqho4q3q-4nwwav | PLAN-NEEDS-WORK (PacketConn testability; startup-retry; VRRP; Kea) |
| r1 | Claude SMR | claude-smr-plan-r1.md | PLAN-NEEDS-WORK (liveness-chain F2; watcher-last F3; remove-default F4; cite vrfListenConfig) |
| r2 | Codex | (pending) | (pending) |
| r2 | AGY | (pending) | (pending) |
| r2 | Claude SMR | (pending) | (pending) |

## r1 findings → r2 disposition
- Codex daemon line 640-641 → 877-878: FIXED in §1.
- AGY §2.5 PacketConn (no *net.UDPConn assert): ADOPTED (Axis A, §5.2).
- AGY §3.3 startup dead-relay: ADOPTED as Axis C1 retry.
- AGY §3.2 VRRP-Backup dup-relay: DEFER to follow-up (Axis D), documented.
- AGY §3.1 / SMR F6 / Codex Kea :67: OPEN Q4 (commit-check vs follow-up).
- SMR F2 liveness chain (close BOTH conns before wg.Wait): ADOPTED §4/§5.4.
- SMR F3 watcher started last: ADOPTED §5.3.
- SMR F4 remove default: no-op: ADOPTED §5.6.
- SMR F1/F5 cite vrfListenConfig + REUSEPORT-after-device-filter: ADOPTED §5.1/Axis A.
- AGY §2.1/2.2/2.3 confirmed (REUSEPORT demux, watcher race-free, wg ordering): noted.
