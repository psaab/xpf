# Claude SMR — plan review r3, #2082

Stance: confirm r3 closes the r2 blocker (A2 + AGY: nil-`conn` receiver panic)
without introducing a new flaw.

## The r2 blocker

A2 and AGY independently found: §7's "run `run()` briefly" unit-test path panics
— `run()` preamble unconditionally `go vi.receiver()` (`instance.go:305`) →
`vi.conn.SetReadDeadline(...)` on nil `conn` (`instance.go:445`) → nil-pointer
panic crashing the test. Verified against source: confirmed real.

## r3 fix — `stepBackup()` seam

r3 §7 deletes the "run `run()` briefly" alternative and binds the wiring tests
to an extracted `stepBackup(masterDownTimer, advertTimer *time.Timer)` single-
iteration method that both `run()` and the test call. Verified the extraction is
mechanically clean: the `StateBackup` select body (`instance.go:351-374`) uses
only `vi.stopCh`, `vi.rxCh`, `vi.preemptNowCh` (instance fields) +
`masterDownTimer`/`advertTimer` (already `run()` locals → method params). No
hidden dependency.

Why this closes the blocker: the test calls `stepBackup(...)` directly and never
calls `run()`, so the receiver goroutine is never spawned → no nil-`conn` panic.
The fail-soft chain inside `becomeMaster()` (addVIPs Warn+return, sendPacket nil
on rawConn==nil, sendGARP fail-soft + suppressGARP in the test) means
`stepBackup` taking the becomeMaster branch does not panic. To select the
`preemptNowCh` case deterministically, the test pre-loads `preemptNowCh`
(buffered cap-1) via `triggerPreemptNow()` before calling `stepBackup` — the
select then takes that case immediately (the other cases — stopCh, rxCh,
timers — are empty/unfired). Sound.

A2's preferred resolution was exactly this seam (over stubbing a dummy socket);
AGY offered both the seam and the socket-stub; r3 takes the seam (cleaner — no
fake fd lifecycle to manage). Either is correct; the seam is the better choice.

## r3 also folded (non-blocking refinements)

- §5: `cfg.AdvertiseInterval` added to the snapshot list (A2 minor); RLock-not-
  Lock in the gate helper + optional fold-the-relock (AGY). Correct and cheap.
- Cosmetic line cites corrected (372, 727).

## New-flaw hunt on r3

- The `stepBackup` extraction is behavior-preserving: it is the same select body,
  same cases, same actions — only hoisted into a method. `run()` calls it in the
  `StateBackup` arm exactly where the inline body was. No semantic change to the
  state machine. ✓
- No new lock taken in the seam beyond what the inline body already did. ✓
- The test deterministically hits the `preemptNowCh` case by pre-loading the
  buffered channel; no race with empty rxCh/stopCh/timers. ✓

## Verdict

r3 closes the only r2 blocker with the reviewer-preferred mechanism, folds the
minor refinements, and introduces no new flaw. All four reviewers' substantive
findings (reachability, RFC compliance, lock discipline, integration honesty,
invariants, test wiring, harm-is-real-and-self-healing, correct fix layer) are
now satisfied.

OVERALL: PLAN-READY.
