# Claude SMR — hostile plan review r4 (#1915)

Reviewer: Claude SMR. Posture: HOSTILE final-rev verification.

## Verdict: PLAN-READY.

r4 fixes the only outstanding blocker (Codex r3's cancel-before-wait ordering)
and the two secondary alignments. I re-traced the corrected concurrency shape
hostilely; it is mechanically sound. No remaining blockers.

## Codex r3 blocker — verified fixed

The bug Codex found was real and subtle: in Go, `defer cancel()` at
`runRelay`'s function scope runs at `runRelay` *return*, which is AFTER any
explicit `wg.Wait()`. r4's fix (scope the main loop in an inner func, `defer
cancel()` inside it) is correct because:

- The inner func's `defer cancel()` runs when the **inner func** returns.
- `wg.Wait()` is written AFTER the inner-func call in `runRelay`'s body.
- Therefore `cancel()` (from main-loop exit) executes BEFORE control reaches
  `wg.Wait()`. The watcher observes `ctx.Done()`, closes both conns, the
  response loop's `ReadFrom` returns `ErrClosed`, the response goroutine
  returns, `wg.Done()`, and `wg.Wait()` completes. No hang.
- Symmetric case: if the RESPONSE goroutine exits first (its `defer cancel()`),
  the main inner-func loop's `ReadFrom` is unblocked by the watcher close →
  inner func returns → outer `wg.Wait()` (response goroutine already done) →
  returns. No hang, no premature-done.
- `done` (closed by Apply's wrapper `defer close(relay.done)`) now closes only
  after `runRelay` returns, which is after `wg.Wait()` — true join (G3). GOOD.

The alternative the plan notes (`defer wg.Wait()` then `defer cancel()`, LIFO
runs cancel first) is also correct; the inner-func form is clearer and is the
recommended shape. Both are sound.

## Codex r3 #2 (test vs loop policy) — verified consistent
The read-loop error contract is now explicit: exit ONLY on `ctx.Err()!=nil` OR
`errors.Is(err, net.ErrClosed)`; transient errors log+continue. The
`TestRunRelay_OneSidedExitNoHang` test now uses `net.ErrClosed` (close the
fake serverConn) rather than an arbitrary error — so it actually triggers the
return→cancel→cross-close path. Test and implementation contract agree. GOOD.

One hostile sub-check: is "transient errors continue" safe from hot-spin? Yes
— a transient non-ErrClosed error that PERSISTS (e.g. permanent ENETDOWN)
would log-spam, but ENETDOWN-class errors on a closed/downed socket surface as
`ErrClosed` once the conn is closed by the watcher on interface teardown; and a
genuinely-persistent readable-but-erroring socket is not a known UDP failure
mode (UDP recv errors are per-datagram, e.g. connrefused ICMP, which are
transient). The contract is acceptable. (If an implementer wants belt-and-
suspenders, a consecutive-error counter could cap log volume — non-blocking
nit, already implied by the Logging Rules "no slog.Info in loop" + slog.Warn
throttling.)

## Codex r3 #3 (C1 stale Index) — verified fixed
C1 now re-resolves `net.InterfaceByName` on every attempt (no cached
`*net.Interface`), so a disappear/recreate under the same name picks up the
new Index. GOOD.

## Full re-trace of the converged design (hostile, end-to-end)
- Defect 1 (EADDRINUSE): A1 ListenConfig.Control sets REUSEADDR+REUSEPORT+
  BINDTODEVICE pre-bind, mirroring vrfListenConfig. N listeners coexist;
  BINDTODEVICE partitions the REUSEPORT group → no double-relay. CORRECT.
- Defect 2 (Stop/reapply hang): close-on-cancel watcher closes both conns;
  cross-cancellation via inner-func defer cancel(); WaitGroup true-join;
  ErrClosed/ctx exit, no hot-spin. CORRECT.
- Startup readiness (C1): retry wraps InterfaceByName+interfaceIPv4, ctx-
  cancelable, re-resolves each attempt, done-channel safe on mid-retry cancel.
  CORRECT.
- SO_BROADCAST: on the client conn (the one writing 255.255.255.255:68). Fixes
  a pre-existing silent broadcast-reply drop. CORRECT.
- Testability: net.PacketConn (no concrete assert) + injectable factory +
  full-interface fake. CORRECT.
- Scope discipline: VRRP-Backup dup-relay and Kea-:67 deferred to follow-ups
  with documented rationale; file-split out of scope. CORRECT.

## NITS (non-blocking)
- N1: consider a consecutive-error log throttle in the read loop (Logging
  Rules). Optional.
- N2: pin the C1 retry interval at /engineer time (plan says "e.g. 5s").

## Bottom line
All findings across r1-r3 resolved. The cancel-before-wait fix is correct. The
design is the minimal, in-repo-proven, fully-tested fix for both filed defects
plus two latent bugs (dead-relay-on-boot, dropped-broadcast). PLAN-READY from
Claude SMR. Convergence on Codex r4 + AGY r4 confirming.
