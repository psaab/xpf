# Reviewer ID Ledger — #1915

| Round | Reviewer | Task/Review ID | Verdict |
|-------|----------|----------------|---------|
| r1 | Codex | codex exec (bg b8r2e8w1j) | PLAN-NEEDS-WORK (line-num; arch sound) |
| r1 | AGY | adversarial-review-mqho4q3q-4nwwav | PLAN-NEEDS-WORK |
| r1 | Claude SMR | claude-smr-plan-r1.md | PLAN-NEEDS-WORK |
| r2 | Codex | codex exec (bg b1yopk19r — companion redirect ate stdout, empty file; superseded by r3) | NO-OUTPUT |
| r2 | AGY | adversarial-review-mqholbr3-q9code | PLAN-NEEDS-WORK (cross-cancel; hot-spin; late-iface; SO_BROADCAST) |
| r2 | Claude SMR | claude-smr-plan-r2.md | PLAN-READY |
| r3 | Codex | codex exec (fg, /tmp/codex-1915-r3.out) | PLAN-NEEDS-WORK (cancel-before-wait BLOCKER + test/loop align + C1 re-resolve) |
| r4 | Codex | (pending) | (pending) |
| r4 | AGY | (pending) | (pending) |
| r4 | Claude SMR | (pending) | (pending) |

## r3 (Codex) findings → r4 disposition
- BLOCKER: §5.5 defer cancel() runs AFTER wg.Wait() (or return skips wait).
  FIXED: main loop in inner func; defer cancel() fires before outer wg.Wait().
- #2 one-sided-error test vs loop policy contradiction: FIXED — read-loop error
  contract made explicit (exit only on cancel/ErrClosed; transient errors
  continue); test uses ErrClosed not arbitrary error.
- #3 C1 caches iface (stale Index on disappear/recreate): FIXED — re-resolve
  InterfaceByName each attempt.
- nits: stale ReadFromUDP in Stop test (FIXED → ReadFrom); §10 OPEN/NEW labels
  (FIXED → RESOLVED).
- Codex confirmed (non-blockers): daemon wiring at 877-878; PacketConn has no
  *net.UDPConn dependency; SO_BROADCAST on client conn (correct); watcher
  ownership + started-after-both-conns correct; mid-retry cancel unwinds clean.
