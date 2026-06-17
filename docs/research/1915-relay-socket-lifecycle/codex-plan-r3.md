Verdict: PLAN-NEEDS-WORK

Round 3 hostile review of docs/research/1915-relay-socket-lifecycle/plan.md

Summary:
The A1 socket direction is right, the client/server conn distinction is right, and the daemon reachability citation is correct on this checkout. I am not ready to call the plan implementation-ready because the cross-cancellation/WaitGroup section still has a liveness ambiguity that can recreate the exact Stop()/reapply hang or let Stop() return before the response goroutine is joined.

Blocking finding:

1. Cross-cancellation ordering is underspecified and the pseudocode is unsafe.

Evidence:
- plan.md:307-311 says `runRelay` owns a `sync.WaitGroup` and waits before returning so `close(relay.done)` only happens after both loops exit.
- plan.md:468-473 says both loops MUST `defer cancel()` because otherwise `wg.Wait()` becomes the new hang.
- plan.md:475-487 shows the response goroutine deferring cancel, then `defer cancel()` in `runRelay`, then an explicit `wg.Wait()` after the main read loop.
- plan.md:490-492 says `cancel()` from either loop drives both sockets closed and then `wg.Wait()` terminates.

Why this is still a blocker:
In Go, a function-level `defer cancel()` does not run before a later explicit `wg.Wait()`. If the main read loop exits by `break` and execution reaches `wg.Wait()`, the main-loop cancel has not fired yet, so the response goroutine can remain blocked in `ReadFrom` and `wg.Wait()` hangs. If the main read loop exits by `return`, `defer cancel()` fires, but the explicit `wg.Wait()` is skipped, so `relay.done` can close before the response goroutine is actually joined. Both outcomes violate the plan's own G3/true-join invariant.

Required plan fix:
Spell the ordering explicitly. Acceptable shapes include:

```go
wg.Add(1)
go func() {
    defer wg.Done()
    defer cancel()
    handleServerResponses(rctx, serverConn, conn, ir)
}()

func() {
    defer cancel()
    for {
        // main ReadFrom loop; return from this inner function on exit
    }
}()
wg.Wait()
```

or an equivalent defer stack where `wg.Wait` is deferred before `cancel`, so LIFO runs `cancel()` before `wg.Wait()`. The plan should state this invariant directly: main-loop exit must cancel the shared context before the runner waits for the response goroutine.

Secondary issues to clean up before /engineer:

2. The one-sided-error test conflicts with the stated read-loop policy.

Evidence:
- plan.md:504-512 returns only when `ctx.Err() != nil` or `errors.Is(err, net.ErrClosed)`, otherwise logs and continues.
- plan.md:584-587 says `TestRunRelay_OneSidedErrorNoHang` should make the response goroutine's fake `ReadFrom` return a non-cancel error immediately and expect cross-cancellation.

As written, that fake error would be logged and retried, not returned, so no deferred cancel fires. Either the test should use `net.ErrClosed` with `ctx.Err()==nil`, or the loop policy should say persistent non-cancel read errors are fatal and return. Do not leave the test and implementation contract contradictory.

3. C1 is directionally correct but the sample does not quite "wrap BOTH" on every attempt.

Evidence:
- plan.md:337-341 requires the retry loop to wrap both `net.InterfaceByName` and `interfaceIPv4`.
- plan.md:343-354 caches `iface` after the first successful `InterfaceByName` and does not re-run `InterfaceByName` while only `interfaceIPv4` is failing.

For normal "interface exists but IPv4 appears later", this works because `Interface.Addrs()` re-queries netlink. For a dynamic interface that appears, disappears, and is recreated under the same name, the cached `Interface.Index` can become stale. If the plan wants the strong AGY r2 invariant, resolve `InterfaceByName` each retry or reset `iface=nil` after address lookup failure.

Confirmed non-blockers / positive checks:

- Daemon wiring is exactly at pkg/daemon/daemon_run.go:877-878 in this checkout:
  `d.dhcpRelay = dhcprelay.NewManager()` then `d.dhcpRelay.Apply(ctx, cfg.ForwardingOptions.DHCPRelay)`.
- The `net.PacketConn` approach does not miss an actual `*net.UDPConn` dependency in current `relay.go`. Current concrete uses are `ReadFromUDP`, `WriteToUDP`, and `SyscallConn`; the proposed factory moves sockopts into `ListenConfig.Control`, and `ReadFrom`/`WriteTo` cover the I/O. The read source address is only logged at relay.go:243,261,315,332. `pkt.IsBroadcast()` is on the parsed DHCP packet at relay.go:345, not on the conn.
- The broadcast socket option is placed on the correct socket. Current code writes broadcast replies through `clientConn.WriteToUDP` at relay.go:352 after choosing `net.IPv4bcast` at relay.go:346. The plan says to set `SO_BROADCAST` on the client conn's Control at plan.md:196-204 and again in the factory call at plan.md:428-433.
- The watcher closing both conns is the right ownership model, and starting it after both conns exist is right. The blocker is not premature close; it is the exact ordering of main-loop cancel relative to `wg.Wait()`.
- The close-on-cancel retry unwinds cleanly before socket creation: plan.md:359-362 correctly notes that mid-retry cancel returns before any socket, watcher, or WaitGroup exists, so the wrapper closes `relay.done`.

Other nits:

- plan.md:566-569 still says fake `ReadFromUDP`; after the `net.PacketConn` conversion this should say `ReadFrom`.
- plan.md:666-686 still labels Kea coexistence and C1 policy questions as OPEN/NEW even though the DoD chooses README/follow-up and includes C1. That is editorial, not the reason for this verdict.

Bottom line:
Do not hand this to /engineer until §5.5 is rewritten with a mechanically correct cancel-before-wait shape and the one-sided-error test is made consistent with the read-loop contract. After that, I would expect this to converge to PLAN-READY.
