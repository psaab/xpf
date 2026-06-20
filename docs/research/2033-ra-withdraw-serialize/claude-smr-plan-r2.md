# Claude SMR — hostile plan review r2 (#2033)

Verdict: **PLAN-READY-WITH-NITS** — the r2 design is correct and my r1
CRITICAL/MAJOR findings are all resolved. I re-traced the new single-channel +
`mode` handshake and the goodbye-on-every-graceful-exit property; both hold. I
keep two MINOR nits and re-flag one item the plan should make a hard decision
on (Q3) before /engineer, but none block PLAN-READY. I held this to
PLAN-READY-WITH-NITS rather than clean PLAN-READY specifically because the
`mode` CAS semantics (R1c/Q3) is a genuine design choice the plan currently
defers — that is the one thing /engineer must pin.

## Re-verification of r1 findings (all resolved)

- **C1 (W2 window):** RESOLVED. §2 W2 now correctly states the ~100 ms burst
  window and that a post-burst RS sleep is caught by the existing `stopCh`
  re-check. Accurate against `ra.go:106-107` + `sender.go:164-168`.
- **C2 (T1 tautology):** RESOLVED. §9 T1 now forces the interleave by blocking
  the injected RS sleep channel until after `Withdraw`, with a conn-level seam
  and a `seq`-ordered recorder. Deterministic, not flaky.
- **M1 (link toggle):** RESOLVED → I12. Promoted to a constraint.
- **M2 (W3 data race):** RESOLVED → W3 is ordering-only; `-race` scoped to
  W4/S2. §2 W3 and §9 T2 corrected.
- **M3 (conn-close ordering for hard stop):** RESOLVED → I9 states the
  behavior change explicitly and confirms `Clear`/`Apply`-remove still send no
  goodbye (mode=hard).
- **m1/m3 wording:** RESOLVED (S1 reworded async; Path B W2 inconsistency
  fixed).

## Re-verification of the NEW r2 design (independent trace)

**Memory-model correctness of `signalStop` → owner.** `signalStop` does
`mode.CAS(...)` (atomic store) THEN `stopOnce.Do(close(stopCh))`. The owner
wakes on `<-stopCh` and then reads `mode.Load()`. Go memory model: the close
of a channel happens-before a receive that returns because the channel is
closed; the atomic store precedes the close in program order on the same
goroutine, so it is visible to any goroutine that observes the close. ✔
Correct. (Even without the atomic, the close-as-release would publish a prior
plain write; the atomic is belt-and-suspenders and also serves the CAS
first-writer-wins.) No reordering hazard.

**Can `select` still skip the goodbye?** No. The owner has exactly one
shutdown signal (`stopCh`); `select` cannot "choose" hard-vs-graceful because
the branch is the same (`case <-stopCh: finishShutdown(); return`). The
goodbye-or-not decision is made AFTER the select by reading `mode`. The r1
two-channel race (where `select` could pick the hard channel) is structurally
gone. ✔

**Does every graceful return call `finishShutdown`?** I traced all returns in
the §5 `run()` sketch:
  1. after `burstInterruptible()`: `if s.draining() { s.finishShutdown(); return }` ✔
  2. `case <-s.stopCh:` → `finishShutdown(); return` ✔
  3. `case _, ok := <-rsCh:` `!ok` → `finishShutdown(); return` ✔ (NIT n1 below)
  4. RS nested `case <-s.stopCh:` → `finishShutdown(); return` ✔
There is no graceful exit that bypasses `finishShutdown`, and `finishShutdown`
only emits the goodbye when `mode == modeGraceful`, so a hard stop never sends
one. ✔ (This is the property R1/C1 from r1 was about; it now holds by
construction.)

**Interruptible burst.** `burstInterruptible` checks `draining()` before each
send and selects on `stopCh` for the inter-send delay. A withdraw during
startup → owner's `signalStop` sets mode + closes stopCh → the burst's next
`draining()`/select sees it → burst stops → `run` checks `draining()` and
calls `finishShutdown`. ✔ A legit start (`mode==modeNone`) emits all 3. ✔

**WithdrawOnce claim.** I4 now claims under `m.mu`. ✔ closes the
Apply-vs-WithdrawOnce window Codex flagged.

## MINOR nits (non-blocking)

n1 — **`rsCh` close path (case 3) emits a goodbye on a non-graceful trigger?**
In `run()`, `case _, ok := <-rsCh: if !ok { finishShutdown(); return }`. `rsCh`
is closed by `rsReceiver` when its `ReadFrom` errors and `stopCh` is closed
(`sender.go:191-197/187`). So `rsCh` closing implies `stopCh` already closed —
mode is already set, and `finishShutdown` does the right thing (goodbye iff
graceful). BUT: `rsReceiver` can also `return` (closing `rsCh`) on a transient
non-stop path? Re-read `sender.go:186-209`: the receiver only returns when
`stopCh` is closed (the `select { case <-stopCh: return; default: continue }`).
So `rsCh` close ⟺ shutdown. ✔ No spurious goodbye. The plan should add one
sentence asserting this invariant (rsCh closes only after stopCh) so the
implementer doesn't accidentally make rsReceiver exit on a bare read error.

n2 — **`burstCh` (ResendBurst) during draining.** If `ResendBurst` fires its
buffered `burstCh` send and a withdraw arrives, the owner could service
`burstCh` (emitting a burst) instead of noticing stopCh. The §5 sketch's
`burstInterruptible` checks `draining()` first, so even if `burstCh` is
selected during draining, the burst short-circuits immediately. ✔ But the plan
should state that `select` ties between `burstCh` and `stopCh` are harmless
because `burstInterruptible` re-checks `draining()`. (Add to I11.)

## RE-FLAG (decide before /engineer, not a blocker)

D1 — **`mode` CAS first-writer-wins (R1c / Q3).** The plan documents that a
`Clear` (hard) racing a `Withdraw` (graceful) can skip the goodbye, and calls
it "acceptable." I half-agree: the only callers that race are teardown paths,
and on a daemon shutdown a missing goodbye is harmless (the link goes away).
BUT in the HA demotion path, the relevant call is `Withdraw`/`WithdrawInterfaces`
on BACKUP transition (`daemon_ha.go:958-1078`) — is there any path where a
`Clear`/`Apply` runs concurrently with that demotion `Withdraw`? If yes,
first-writer-wins could drop the demotion goodbye (the exact bug we are
fixing!). The plan should either (a) prove the demotion `Withdraw` cannot race
a `Clear`/`Apply` for the same sender (likely — both go through the daemon's
serialized config/HA path), or (b) make graceful upgrade a pending hard stop.
Recommend (a) with a one-line justification, or (b) if the call paths are not
provably serialized. This is the single item /engineer must resolve.

## D1 investigation result (folded into plan r2 same round)

I verified the daemon call paths rather than leaving D1 open:
- `ra.Clear` (`daemon_apply.go:1024`) and `ra.Apply`
  (`daemon_apply.go:1019`, `daemon_ha.go:911/1055`) run under `d.applySem`.
- `clearRethServicesForRG` → demotion `Withdraw`/`WithdrawInterfaces`
  (`daemon_ha.go:958-960`) is called from the VRRP event-handler goroutine
  (`daemon_ha.go:448/672`, `daemon_ha_vip.go:191`) which does NOT hold
  `applySem`.
So the demotion `Withdraw` (graceful) and a config-apply `Clear` (hard) CAN
reach the same sender's `signalStop` concurrently. First-writer-wins would let
a `Clear` drop the demotion goodbye — the bug. **Resolution (now in plan §5 +
I13 + R1c + Q3): `signalStop` makes graceful UPGRADE hard (never downgrade).**
The only residual is a sub-µs window if the owner already read `modeHard`
before the upgrade store; best-effort goodbye is acceptable there (the new
primary's RA is the real recovery). This was a *real* hazard the r1 design
would have shipped — caught by tracing the daemon, not assuming serialization.

## Conclusion

**PLAN-READY** (D1 now resolved in-plan; n1→I14, n2→I15 folded). The
architecture (Path A single-owner, single-channel + `mode` with
graceful-upgrades-hard, interruptible burst, owner-emitted goodbye, conn-level
test seam, atomic WithdrawOnce claim, no-link-toggle) is correct, the
invariants are complete, and the test plan is a real regression guard. Path A
confirmed over Path B. My only remaining ask is that /engineer add a test for
the graceful-upgrades-hard race (T7 already covers it) and confirm the residual
sub-µs window is acceptable (Q3).
