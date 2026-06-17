# Claude SMR — hostile plan review r2 (#1915)

Reviewer: Claude SMR. Posture: HOSTILE re-verification of r2.

## Verdict: PLAN-READY.

r2 resolves every r1 finding and the r2 self-found `SO_BROADCAST` gap is
correctly scoped. I hostilely re-walked the concurrency contract, the C1 retry
interaction with the `done` channel, and the PacketConn switch. No remaining
blockers. Two NITS below are non-blocking and can be handled at /engineer time.

## r1 findings — verified resolved

- **F2 (liveness chain)**: §4 Axis B liveness invariant + §5.4 now state the
  watcher closes BOTH conns and that `wg.Wait()` depends on `serverConn` close.
  Resolved.
- **F3 (watcher last)**: §5.3 "start the cancel watcher LAST, only after BOTH
  conns created." Resolved.
- **F4 (remove default:)**: §5.6 commits to removing it with the rewritten
  loop shown. Resolved (no more equivocation).
- **F1/F5 (cite precedent + REUSEPORT mechanism)**: §5.1 cites
  `vrfListenConfig` (heartbeat_manager.go:74) and grpcapi/server.go:179; the
  Axis A serverConn note has the BINDTODEVICE-before-REUSEPORT-fanout kernel
  reasoning; D2 promoted to MUST-test. Resolved.
- **F6 (Kea :67)**: §10 Q4 — open, with a recommended disposition
  (commit-check vs follow-up). Acceptable to leave as a reviewer-decision in a
  research plan; it does not block the socket-lifecycle fix.

## r2 new items — hostile check

### C1 retry × `done` channel (the thing most likely to be wrong) — CORRECT
Traced it: `Apply` builds `ir{done: make(chan struct{})}` then
`go func(){ defer close(relay.done); runRelay(rctx, ...) }()` (relay.go:118).
The C1 retry loop lives at the TOP of `runRelay`, BEFORE any socket or
goroutine or WaitGroup exists. If `ctx` cancels mid-retry, the retry
`select { case <-ctx.Done(): return; case <-time.After(...): }` returns,
`runRelay` returns, the deferred `close(relay.done)` fires, and `Stop()`'s
`<-ir.done` unblocks immediately. There is NO half-initialized state to leak
because nothing has been created yet. This is the correct ordering and the
plan's §5.3 "watcher started last / early returns have nothing to close"
covers it. No deadlock, no leak. GOOD.

### SO_BROADCAST self-find — CORRECT and well-scoped
Confirmed independently: relay.go:346 writes `net.IPv4bcast:68` and there is
ZERO `SO_BROADCAST` anywhere in `pkg/` (grep clean). Linux `sendto()` to the
limited broadcast returns `EACCES` without it, so broadcast OFFER/ACK to a
client with the broadcast flag set is dropped TODAY (silent warning at
relay.go:353). Fixing it in the same `Control` body (factory `broadcast=true`
on the client conn) is the right call — it is one sockopt and the alternative
ships a still-broken broadcast path. The plan correctly notes the broadcast
write is on the CLIENT conn (relay.go:352 `conn.WriteTo`), not serverConn, so
`SO_BROADCAST` belongs on the client listener. Factory signature updated to
carry `broadcast bool`. GOOD.

### PacketConn switch — no concrete-type dependency remains
Hostile audit of every concrete `*net.UDPConn` use in the current relay.go:
- `conn.ReadFromUDP` (230) → `ReadFrom` (returns `net.Addr`; src only logged).
- `serverConn.WriteToUDP(data, srv)` (280) → `WriteTo` (`srv` is `*net.UDPAddr`
  = `net.Addr`). OK.
- `clientConn.WriteToUDP(data, dst)` (352) → `WriteTo`. OK.
- `serverConn.ReadFromUDP` (302) → `ReadFrom`. OK.
- `conn.SyscallConn()` (192) → DELETED (sockopts move into `Control`).
- `pkt.IsBroadcast()` (345) is on the parsed DHCP packet, NOT the conn —
  unaffected by the conn type. GOOD.
No `SetReadDeadline` is needed (B1 uses Close, not deadline), so the
`net.PacketConn` interface (which lacks per-direction deadline methods but DOES
have `SetReadDeadline`) is sufficient either way. The switch is clean.

## NITS (non-blocking, /engineer-time)

- **N1 (nit)**: §5.1 factory returns `net.PacketConn` but the default impl's
  `lc.ListenPacket` already returns `net.PacketConn` — fine. Just ensure the
  fake test conn implements the FULL `net.PacketConn` interface
  (`ReadFrom/WriteTo/Close/LocalAddr/SetDeadline/SetReadDeadline/SetWriteDeadline`).
  A `struct{ net.PacketConn }` embed + overrides of `ReadFrom/Close` is the
  least-effort fake. Mention in §6 to avoid a flailing test author.
- **N2 (nit)**: the C1 retry interval/jitter is unspecified ("e.g. 5s"). Pin a
  value at /engineer time and use `slog.Warn` once + `slog.Debug` per retry per
  the project Logging Rules (the plan already says this — just make sure the
  implementer honors "no slog.Info in a loop"). The retry loop is NOT
  per-packet so `slog.Debug` per retry is fine.

## Bottom line
All r1 findings resolved; the r2 SO_BROADCAST find is a genuine pre-existing
bug correctly folded in; the C1/done-channel and PacketConn/broadcast
interactions are correct on a hostile re-trace. PLAN-READY from Claude SMR.
Convergence depends on Codex r2 + AGY r2 confirming.
