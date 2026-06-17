# AGY adversarial review r4 (#1915) — adversarial-review-mqhpunsa-3f7xdd

## Verdict: PLAN-READY

All previously flagged issues verified resolved; no remaining blockers.

### 1. §5.5 Cancel/Wait ordering & goroutine join — CORRECT
The r4 plan scopes the main loop inside a synchronous inner function to
guarantee context cancellation occurs BEFORE joining the response goroutine via
`wg.Wait()`.

- Inner-func `defer cancel()` guaranteed to fire before outer `wg.Wait()`: an
  anonymous func called synchronously (`func(){...}()`) executes fully and runs
  its deferred funcs (cancel) immediately on return, before the next outer
  statement. CONFIRMED.
- No remaining hang path: cancel → watcher wakes on `<-ctx.Done()` → closes
  both conns → response loop `ReadFrom` returns `net.ErrClosed` →
  `errors.Is(err, net.ErrClosed)` true → returns → `wg.Done()` → `wg.Wait()`
  satisfied.
- No premature-done: `relay.done` closed in the wrapper's `defer close`; since
  `runRelay` blocks on `wg.Wait()` at its tail and cannot return until that
  completes, the response goroutine is joined before the wrapper closes
  `relay.done`. CONFIRMED.

### 2. Read-loop error contract & test alignment — CONSISTENT
- Contract: continue on transient errors; exit immediately on socket close or
  ctx cancel: `if ctx.Err() != nil || errors.Is(err, net.ErrClosed) { return }`.
- `TestRunRelay_OneSidedExitNoHang` forces the fake conn to return
  `net.ErrClosed` (not a transient error), keeping test and contract aligned.

### 3. C1 dynamic interface resolution — CORRECT
The startup retry re-resolves `InterfaceByName` every iteration (no cached
`*net.Interface`/Index), so a deleted+recreated dynamic interface resolves with
its new Index.

### Conclusion
Mechanically sound; handles concurrency and socket lifecycle correctly; ready
for implementation.
