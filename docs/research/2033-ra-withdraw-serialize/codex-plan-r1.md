VERDICT: NEEDS-REVISION

1. CRITICAL — Path A can skip the goodbye entirely. The sketch sends `withdrawCh` non-blocking, then closes `stopCh` (`plan.md:183-191`). But `stopCh` is the hard-stop/no-goodbye path in `run()` (`pkg/ra/sender.go:145-146`). If the withdraw send hits `default`, or if both channels are ready, `select` can take `stopCh` and exit without lifetime-0 RA. Same problem exists in the RS nested select. This breaks the core invariant.

2. CRITICAL — Path A misses the startup-burst normal-send path. Current `run()` calls `sendStartupBurst()` before entering the select loop (`pkg/ra/sender.go:132-134`), and the burst itself does not check `stopCh` (`pkg/ra/sender.go:176-182`). The plan’s Path A sketch keeps that shape (`plan.md:151-154`). A withdraw during startup can still emit normal RAs after withdrawal begins. This is not structurally serialized.

3. MAJOR — W2 is materially misdescribed. The plan says an RS sleep can produce a normal RA up to ~500ms after the goodbye finishes because `stopCh` is not closed until after goodbye (`plan.md:47-54`). But that means the post-sleep check does help once goodbye has returned: `Withdraw()` sends goodbye then immediately calls `stop()` (`pkg/ra/ra.go:104-107`), and `stop()` closes `stopCh` (`pkg/ra/sender.go:120-125`); the RS path checks `stopCh` after sleep (`pkg/ra/sender.go:161-168`). W2 is reachable only if the sleep ends before `stopCh` closes, mostly during the goodbye burst or in the tiny gap before `stop()`, not “~500ms after the goodbye finishes.”

4. MAJOR — S1 is real, but “guaranteed ordering inversion before goodbye” is overstated. `WithdrawOnce()` calls `s.start()` then `s.sendGoodbyeRA()` (`pkg/ra/ra.go:167-173`), and `start()` only launches `go s.run()` (`pkg/ra/sender.go:115`). The startup burst is asynchronous, so normal RAs are possible before, during, or after the goodbye, but not guaranteed before it. The goodbye-only path is the right fix direction.

5. MAJOR — The running guard in `WithdrawOnce` is only point-in-time. It checks `m.senders` under `m.mu`, releases the lock, then opens/sends on a temporary sender (`pkg/ra/ra.go:154-173`). A real sender can start after that check via `Apply()` (`pkg/ra/ra.go:31-89`), so the plan’s “don’t clobber a live primary” invariant is not actually guaranteed. The plan needs a re-check/claim protocol before the standalone goodbye.

6. MAJOR — W3 is overclaimed as a Go data race. Concurrent normal/goodbye `WriteTo` is a real ordering problem (`pkg/ra/sender.go:215`, `pkg/ra/sender.go:231`), but `ndp.Conn.WriteTo` mostly marshals local buffers and delegates to `ipv6.PacketConn.WriteTo`; Go documents `net.PacketConn` methods as concurrently callable (`/usr/lib/go-1.24/src/net/net.go:317-320`). Do not promise `-race` will catch W3. W4 is the real race: `sendRA` writes `lastRA` (`pkg/ra/sender.go:220`) while `Status()` reads it (`pkg/ra/ra.go:244-245`).

7. MAJOR — The test seam is under-specified. A writer seam alone does not let T1 deterministically drive `time.NewTimer`, `time.Sleep`, `rand.IntN`, or the local `rsCh` created inside `run()` (`pkg/ra/sender.go:136-141`, `pkg/ra/sender.go:161-162`). As written, T1 risks being flaky or not exercising W2 at all. The plan needs explicit timer/random/RS injection, or a smaller deterministic unit around the owner loop.

8. MINOR — Path B’s W2 claim is not a lie if implemented exactly as sketched. Since the RS sleep occurs before `sendRA()` (`pkg/ra/sender.go:161-169`), a flag check inside `sendRA()` after the sleep can suppress the post-sleep normal RA. But Path B still needs every `lastRA` read, including the RS rate-limit read (`pkg/ra/sender.go:157`), covered by the same synchronization story.

Path C is still correctly rejected: there is a real HA-facing bug surface here. But the current plan’s strongest race claim and recommended handshake are not production-ready.

Codex session ID: 019ee265-4559-7000-b3f2-2244f98ff046
Resume in Codex: codex resume 019ee265-4559-7000-b3f2-2244f98ff046
