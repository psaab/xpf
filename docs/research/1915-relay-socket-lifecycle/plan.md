# Plan of Action — #1915 DHCP relay socket lifecycle

- **Issue**: #1915 — DHCP relay: multi-interface groups fail (EADDRINUSE) and
  `Stop()`/reapply can hang (blocking `ReadFromUDP`, no close-on-cancel)
- **Revision**: r3 (post round-2: AGY r2 cross-cancel/hot-spin/late-iface +
  SO_BROADCAST; Claude SMR r2 PLAN-READY; awaiting r3 confirm)
- **Branch**: `research/1915-relay-socket-lifecycle`
- **Scope mode**: `/research` — STOP at PLAN-READY. No PR, no production code.

---

## 1. Problem statement

`pkg/dhcprelay/relay.go` runs one relay goroutine per interface
(`Manager.Apply` → `runRelay`). Two confirmed defects make the relay broken
for any realistic multi-interface group and make config reapply / shutdown
unreliable.

### Defect 1 — multi-interface groups fail past the first interface (HIGH)

`runRelay` (relay.go:182-188) binds the client-facing listener with:

```go
listenAddr := &net.UDPAddr{IP: net.IPv4zero, Port: relayPort} // 0.0.0.0:67
conn, err := net.ListenUDP("udp4", listenAddr)
```

then applies `SO_BINDTODEVICE` *after* the bind (relay.go:192-202) via
`conn.SyscallConn()`. `net.ListenUDP` exposes **no pre-bind `Control` hook**,
so neither `SO_REUSEADDR` nor `SO_REUSEPORT` is set before the `bind(2)`
call. Two interfaces in the same (or different) relay group both want
`0.0.0.0:67`; the **second** `bind` returns `EADDRINUSE`. `SO_BINDTODEVICE`
applied after the failed bind cannot rescue it.

Result: a relay group with N>1 interfaces starts only the *first* listener and
logs `dhcp-relay: listen failed` for the rest. The relay silently serves one
interface.

The standard isc-dhcp-relay pattern is per-interface `0.0.0.0:67` listeners
coexisting via `SO_REUSEADDR` + `SO_REUSEPORT` (set before bind) +
`SO_BINDTODEVICE` (so each socket only receives that interface's traffic).

### Defect 2 — `Stop()`/reapply can hang indefinitely (HIGH)

`runRelay`'s read loop (relay.go:223-238):

```go
for {
    select {
    case <-ctx.Done():
        return
    default:        // non-blocking — falls through immediately
    }
    n, srcAddr, err := conn.ReadFromUDP(buf) // blocks with NO deadline
    ...
}
```

The `select` has a `default:` so it never blocks; after one cheap check the
goroutine parks in `ReadFromUDP` with no read deadline. Nothing closes `conn`
on cancellation — `defer conn.Close()` only runs when `runRelay` *returns*,
but `runRelay` is wedged in the blocking read. `Manager.Stop()`
(relay.go:146-159) does `ir.cancel(); <-ir.done`, and `done` is only closed
after `runRelay` returns. So `Stop()` — and every `Apply()`, which begins with
`m.Stop()` (relay.go:64) — **blocks until a DHCP packet happens to arrive on
that interface**. On a quiet interface this is unbounded.

The server-response goroutine (relay.go:218-220 →
`handleServerResponses` blocking on `serverConn.ReadFromUDP`) has the same
defect *and* is **untracked**: no `WaitGroup`, no join. On cancel it leaks
until a server packet arrives (or forever).

`ctx` cancellation alone unblocks neither read; only closing the socket (or a
read deadline) does.

### Wiring / reachability

- `pkg/daemon/daemon_run.go:877-878` (verified against `origin/master` in this
  worktree):
  `d.dhcpRelay = dhcprelay.NewManager(); d.dhcpRelay.Apply(ctx, cfg.ForwardingOptions.DHCPRelay)`.
  (The issue body cited 763-764; an earlier r1 draft cited 640-641 from a
  *dirty* main checkout whose uncommitted edits shifted line numbers. The
  canonical clean-tree location is 877-878 — corrected per Codex r1.)
- **`Apply` is called exactly ONCE, at daemon start** (daemon_run.go:878).
  There is no commit-driven reapply for the relay today, and no `Stop()` on
  shutdown. This has a consequence beyond Defect 2: an interface that is not
  yet ready at boot (no IPv4 address — `interfaceIPv4` fails at
  relay.go:174) makes `runRelay` log-and-return permanently; the relay for
  that interface is **dead forever** because nothing re-runs `Apply` (see
  §4 Axis C — startup readiness, raised by AGY r1 3.3).
- `relay.go:102` iterates `group.Interfaces` → multi-interface groups are
  operator-reachable via `set forwarding-options dhcp-relay group <g>
  interface <if>` (compiler at `pkg/config/compiler_services.go:608`).
- `Apply` is invoked once at daemon start today. Reapply-on-commit is not
  currently wired for the relay (only the start-time call exists), but
  `Apply` already calls `Stop()` first, so the hang is reachable the moment a
  second `Apply`/`Stop` is ever issued (and any future commit-driven reapply
  would hit it). Defect 2 also bites **daemon shutdown** if shutdown ever
  calls `Stop()` — and even if it does not, the leaked blocking goroutines
  prevent clean teardown in tests and any future graceful-stop path.

### Config types (grounding)

`pkg/config/types_system.go:428-445`:

```go
type DHCPRelayConfig struct {
    ServerGroups map[string]*DHCPRelayServerGroup
    Groups       map[string]*DHCPRelayGroup
}
type DHCPRelayGroup struct {
    Name string; Interfaces []string; ActiveServerGroup string
}
```

So a single group can carry many interfaces; the per-interface `0.0.0.0:67`
collision is the common case, not an edge case.

---

## 2. Goals / non-goals

**Goals**

- G1: A relay group with N>1 interfaces starts **all N** listeners without
  `EADDRINUSE`.
- G2: `Stop()` (and the `Stop()` inside `Apply()`) returns within a bounded
  time with **no packets in flight** — deterministic teardown.
- G3: The server-response goroutine is tracked and joined; no goroutine leak
  across `Apply`/`Stop` cycles.
- G4: Lifecycle is unit-testable without root or real NICs — an injectable
  packet-conn factory so tests assert "two listeners, no collision" and
  "Stop bounded with zero packets".

**Non-goals**

- N1: No behavioral change to Option 82 insert/strip, giaddr, hop count, or
  the relay forwarding semantics.
- N2: No DNS resolution for server addresses (still literal IPs — README
  contract unchanged).
- N3: The audit's suggested file split (manager/socket/runner/packet/stats)
  is **optional and explicitly out of scope** for the fix PR. The
  socket-lifecycle correctness is the substance. (Splitting can be a
  follow-up refactor issue.)
- N4: No IPv6 / DHCPv6 relay (the agent is v4-only today).
- N5: No commit-driven reapply wiring change — that is a separate concern;
  this fix only makes `Apply`/`Stop` *safe* to call repeatedly.

---

## 3. Affected code

| File | Change |
|------|--------|
| `pkg/dhcprelay/relay.go` | socket creation via `ListenConfig.Control`; program to `net.PacketConn` (`ReadFrom`/`WriteTo`); close-on-cancel watcher (closes both conns, started last); WaitGroup join for the response goroutine; bounded ctx-cancelable giaddr-retry (Axis C1); injectable `packetConnFactory` seam; remove the `default:` no-op. |
| `pkg/dhcprelay/sockopt_linux.go` | add `SO_REUSEADDR`+`SO_REUSEPORT` setters (the pre-bind control body). |
| `pkg/dhcprelay/relay_test.go` | new lifecycle + multi-interface regression tests using the injected factory. |
| `pkg/dhcprelay/README.md` | document the REUSEPORT+BINDTODEVICE listener model + bounded-Stop contract. |

No changes to `pkg/daemon`, `pkg/cli`, or `pkg/config` — the `Manager`
public API (`NewManager`, `Apply`, `Stats`, `Stop`) is preserved.

---

## 4. Design — Path Options

Two orthogonal design axes, each with options. The recommendation is at the
end of each axis; the combined recommended design is in §5.

### Axis A — how the sockets are created (fixes Defect 1)

**A1 — `net.ListenConfig.Control`, programmed to `net.PacketConn` (RECOMMENDED).**
Use `net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error}`
and call `lc.ListenPacket(ctx, "udp4", "0.0.0.0:67")`. Inside `Control`, run
`c.Control(fd -> setsockopt)` to set `SO_REUSEADDR`, `SO_REUSEPORT`, and
`SO_BINDTODEVICE` **before** the runtime calls `bind`. This is the idiomatic
Go way, keeps netpoller integration, and `SetReadDeadline` remains available.

**In-repo precedent (this is NOT speculative):** the codebase already does
exactly A1 twice:
- `pkg/cluster/heartbeat_manager.go:74` `vrfListenConfig` — sets
  `SO_REUSEADDR`+`SO_REUSEPORT`+`SO_BINDTODEVICE` inside `Control`, then
  `lc.ListenPacket(ctx, "udp4", addr)` (heartbeat_manager.go:38,46). Its
  empty-device branch (no `SO_BINDTODEVICE` when `vrfDevice == ""`) maps
  **directly** onto the relay's `serverConn`, which needs no BINDTODEVICE.
- `pkg/grpcapi/server.go:179-184` — `SO_REUSEADDR`+`SO_REUSEPORT` in `Control`.
The relay's default factory should mirror `vrfListenConfig`'s shape.

**FOUND GAP — `SO_BROADCAST` (pre-existing, fix opportunistically here).**
On the reply path `handleServerResponses` writes to `255.255.255.255:68`
(`net.IPv4bcast`, relay.go:346) when the client requested broadcast. On Linux,
`sendto()` to the limited broadcast `255.255.255.255` returns `EACCES` unless
`SO_BROADCAST` is set on the socket. The ORIGINAL code (`net.ListenUDP`) does
NOT set it either — so broadcast OFFER/ACK delivery to a client that set the
broadcast flag is **already broken today** (silent `send to client failed`
warning at relay.go:353). This refactor routes the **client conn** (the one
that does the broadcast write) through the factory `Control`, which is the
natural place to add `SO_BROADCAST`. The plan therefore **adds `SO_BROADCAST`
to the client conn's `Control`**. (No `grep` hit for `SO_BROADCAST` anywhere
in `pkg/` confirms it is currently unset — verified.) This is in scope because
the fix is one sockopt in the same `Control` body and the alternative is
shipping a relay that still drops broadcast replies. NOTE: the broadcast write
is on the CLIENT conn (`conn.WriteTo`, relay.go:352), not `serverConn` — so
`SO_BROADCAST` belongs on the client listener.

**CRITICAL (per AGY r1 §2.5): program `runRelay`/`handleServerResponses` to the
`net.PacketConn` interface, NOT the concrete `*net.UDPConn`.** Because all
three sockopts are set inside `ListenConfig.Control`, there is **no need for
any post-creation type assertion** in `runRelay` at all. Use the interface
methods `ReadFrom(buf) (n, net.Addr, err)` and `WriteTo(buf, addr)` instead of
`ReadFromUDP`/`WriteToUDP`. This is what makes G4 (mockable factory) actually
work: a test factory can return a fake `net.PacketConn` whose `ReadFrom`
blocks until `Close()`, with zero real sockets and no root. The r1 plan's
"type-assert to `*net.UDPConn`" was a real testability defect — REMOVED.

- The `*net.UDPAddr` destinations for `WriteTo` (servers, client broadcast)
  satisfy `net.Addr` directly — no conversion needed.
- Pros: minimal blast radius, netpoller intact, `SetReadDeadline` available,
  **fully mockable** (no concrete-type leak), in-repo proven.
- Cons: `SO_BINDTODEVICE` inside `Control` requires the ifname before bind —
  trivial (`ir.ifaceName`). Switching `ReadFromUDP`→`ReadFrom` means the
  source addr is `net.Addr` not `*net.UDPAddr`; the relay only logs `srcAddr`
  (relay.go:243,261,315,332) so this is cosmetic — no behavioral dependency
  on the concrete addr type. Verify no code path does a `*net.UDPAddr`
  field-access on the read source (it does not).

**A2 — manual `socket()` + `setsockopt` + `bind()` + `os.NewFile` +
`net.FilePacketConn`.**
Open a raw `unix.Socket(AF_INET, SOCK_DGRAM, ...)`, set all three sockopts,
`unix.Bind`, then wrap with `net.FilePacketConn` to regain netpoller-backed
reads.

- Pros: total control over ordering; no reliance on `ListenConfig` internals.
- Cons: more code, more error paths, dup-fd subtleties (`net.FilePacketConn`
  dups the fd; must close the original), easier to get wrong. No advantage
  over A1 for this use case. **Rejected** unless A1 is shown infeasible.

**Axis A recommendation: A1.** The whole reason Defect 1 exists is that the
*old* code used `net.ListenUDP` (no Control hook); `ListenConfig.Control` is
the exact, minimal correction.

Note: the `serverConn` (relay.go:206, bound to `giaddr:0`) does **not** need
REUSEPORT — it binds a unique ephemeral port per interface (confirmed by Codex
r1). It still needs the same cancelable-read treatment (Axis B) AND should be
routed through the same factory (with `reusePort=false`, `ifaceName=""`) so the
test seam covers it too. It is not part of the EADDRINUSE fix.

**Why REUSEPORT does not cause double-relay (kernel mechanism, confirmed by
AGY r1 §2.1):** when multiple sockets are bound to wildcard `0.0.0.0:67` with
`SO_REUSEPORT`, the Linux socket-lookup algorithm discards candidate sockets
whose `SO_BINDTODEVICE` does **not** match the incoming packet's
`skb->dev->ifindex` *before* computing the REUSEPORT load-balancing hash. So a
broadcast ingressing interface A has exactly one eligible socket (the one bound
to device A). The hard invariant: **every client-facing socket MUST have
`SO_BINDTODEVICE` set**; a client socket without it would join the REUSEPORT
group unfiltered and steal/load-balance other interfaces' packets. The default
factory enforces this (BINDTODEVICE whenever `ifaceName != ""`); the D2 test
asserts it (now a MUST — see §6).

### Axis B — how `Stop()` unblocks the blocking reads (fixes Defect 2)

**B1 — `conn.Close()` from `Stop()`/cancel, runner owns both sockets
(RECOMMENDED).**
Have `interfaceRelay` hold references to both `*net.UDPConn` (client conn +
server conn). On cancel, a small watcher goroutine (started by the runner) or
`Stop()` itself closes both conns. A blocked `ReadFromUDP` returns immediately
with a `net.ErrClosed`/`use of closed network connection` error; the loop sees
`ctx.Err() != nil` and returns. This is deterministic and packet-independent.

- Implementation detail: spawn `go func(){ <-ctx.Done(); conn.Close(); serverConn.Close() }()`
  inside `runRelay` *after* both conns exist. The existing `defer
  conn.Close()`/`defer serverConn.Close()` remain (double-close on a
  `*net.UDPConn` is safe — returns `ErrClosed`, idempotent). The read loop's
  existing `if ctx.Err() != nil { return }` already handles the woken error.
- Pros: deterministic, zero added latency, no polling, no busy-wait. Standard
  Go idiom for cancelable blocking I/O.
- Cons: must make conn ownership explicit so the closer goroutine and the
  reader agree on lifetime. Need to guarantee the closer goroutine itself
  exits (it does: it waits on `ctx.Done()` once then returns).

**B2 — `SetReadDeadline` polling.**
Before each `ReadFromUDP`, call `conn.SetReadDeadline(time.Now().Add(250ms))`.
On timeout, loop back to the `select` and re-check `ctx.Done()`.

- Pros: no extra goroutine; conn can stay loop-local.
- Cons: adds up to one poll-interval of teardown latency; wakes the goroutine
  4×/s forever (minor but unnecessary); still needs the `default:` removed or
  reworked. Strictly worse than B1 for determinism. Acceptable fallback only
  if B1's closer-goroutine ownership proves awkward.

**B3 — `SetReadDeadline(time.Time{})`-style: set a deadline in the far future
then `SetReadDeadline(time.Now())` from `Stop()` to force an immediate
timeout.**
A variant of B1 that uses deadline-poke instead of `Close()` to wake the read.

- Pros: doesn't close the socket (could matter if you wanted to drain), no
  spurious periodic wakeups.
- Cons: same ownership requirement as B1 (`Stop` needs the conn handle) with
  no real advantage, since we *want* the socket closed on stop anyway.
  **Rejected** in favor of B1.

**Axis B recommendation: B1** — close-on-cancel. It is the textbook Go pattern
for unblocking netpoller reads and gives bounded, packet-independent `Stop()`.

### Goroutine tracking (part of Defect 2)

Replace the bare `go func(){ handleServerResponses(...) }()` with a
`sync.WaitGroup` owned by the runner; `runRelay` does `wg.Wait()` before
returning so `close(relay.done)` (in `Apply`'s wrapper) happens only after
*both* the read loop and the response goroutine have exited. This makes
`<-ir.done` in `Stop()` a true join of the whole interface relay.

**Liveness invariant (Claude SMR r1 F2; AGY r1 §2.3 independently verified the
ordering):** `wg.Wait()` only terminates if the response goroutine's
`ReadFrom` is unblocked, which only happens when the watcher closes
`serverConn`. So the watcher MUST close BOTH `conn` and `serverConn` on
cancel. If it closed only `conn`, `wg.Wait()` would hang forever — relocating
Defect 2, not fixing it. The full shutdown chain that MUST hold:

1. `Stop()` → `ir.cancel()`.
2. watcher wakes on `ctx.Done()`, closes `conn` AND `serverConn`.
3. main read loop's `ReadFrom` → `ErrClosed` → `ctx.Err()!=nil` → returns.
4. response goroutine's `ReadFrom` → `ErrClosed` → returns → `wg.Done()`.
5. `runRelay` runs `wg.Wait()` (joins response goroutine), then returns.
6. Apply wrapper's `defer close(relay.done)` fires.
7. `Stop()`'s `<-ir.done` unblocks — true join of both goroutines.

### Axis C — startup readiness / Apply-called-once (fixes the "dead relay" gap, AGY r1 §3.3)

`Apply` runs once at boot (daemon_run.go:878). If an interface lacks its IPv4
address at that instant (carrier wait, DHCP-learned address not yet bound,
late link bring-up by networkd), `interfaceIPv4` fails and `runRelay`
log-and-returns — the relay for that interface is **permanently dead**; no
later event re-runs `Apply`. This is a latent correctness gap distinct from
the two filed defects but in the same function, so it is in scope.

**C1 — bounded retry inside `runRelay` (RECOMMENDED).** The retry loop MUST
wrap BOTH `net.InterfaceByName` AND `interfaceIPv4` (AGY r2 Finding 4: a
dynamic interface — VLAN/tunnel — may not exist in the kernel yet when `Apply`
runs at boot; `InterfaceByName` failing outside the retry would re-create the
dead-relay bug). Structure:

```go
var iface *net.Interface
var giaddr net.IP
for {
    if iface == nil { iface, err = net.InterfaceByName(ifaceName) }
    if err == nil { giaddr, err = interfaceIPv4(iface) }
    if err == nil { break }
    select {
    case <-ctx.Done(): return            // Stop() during retry — clean exit
    case <-time.After(interval):         // e.g. 5s; retry
    }
}
```

Log `slog.Warn` once on first failure, `slog.Debug` per retry (project Logging
Rules — never `slog.Info` in a loop; the retry is not per-packet so `Debug` is
fine). The loop is `ctx`-cancelable so `Stop()` unwinds it promptly: nothing
(no socket, no goroutine, no WaitGroup) has been created yet, so a mid-retry
cancel just returns → the wrapper's `defer close(relay.done)` fires →
`Stop()`'s `<-ir.done` unblocks. Once both resolve, proceed to socket creation.

- Pros: self-heals the boot race with no external wiring; bounded; cancelable.
- Cons: a relay configured on an interface that NEVER gets an address spins a
  cheap 5s-interval goroutine forever (acceptable; it is one parked goroutine
  per misconfigured interface, and the operator config is wrong).

**C2 — defer readiness to a commit-driven reapply.** Wire the daemon to call
`Apply` again on config commit / interface-up events; rely on reapply to start
late relays.

- Pros: no retry loop; consistent with how other services reconcile.
- Cons: requires daemon-side wiring that does not exist today (N5 says we are
  not adding reapply wiring in this PR); and even with reapply, a transient
  boot race with no subsequent commit leaves the relay dead until the next
  commit. Larger blast radius. **Deferred** — file as a follow-up if C1's
  parked-goroutine cost is judged unacceptable.

**Axis C recommendation: C1** — bounded cancelable retry. It is local to
`runRelay`, requires no daemon wiring, and is `ctx`-safe so it composes with
the Axis B teardown. (If reviewers prefer to keep r2 strictly to the two filed
defects, C1 can be carved into its own commit within the same PR, or split to
a follow-up issue — see §10 Q6. The plan RECOMMENDS including C1 because it is
a few lines in the same function and the "dead relay on boot" failure is
operator-invisible.)

### Axis D — VRRP/HA backup-node duplicate relaying (AGY r1 §3.2)

AGY flags that on an HA pair, a relay running on a VRRP **Backup** node would
also receive segment broadcasts and relay duplicates to the server. Assessment:

- This is a **real but separate** concern, and the correct scope call is to
  **document + defer**, not fix here. Rationale:
  - The relay binds the *physical/logical* interface, not the RETH VIP. On the
    loss userspace cluster, dataplane interfaces are RETH members; whether the
    relay is even configured on a RETH interface in an HA deployment is a
    deployment question, not a code invariant.
  - Suppressing forwarding on Backup requires a VRRP-state hook
    (`pkg/vrrp` / `pkg/cluster` event subscription) — a meaningful new
    integration that is out of proportion to a socket-lifecycle bug fix, and
    risks the HA path (which mandates `make test-failover`).
  - DHCP itself tolerates duplicate relayed requests (servers dedupe on xid +
    chaddr; clients dedupe offers). The failure mode is extra traffic /
    occasional duplicate OFFER, not a broken lease — acceptable interim.
- **Decision**: §11 DoD does NOT require HA suppression. The plan documents
  the behavior (README + a code comment) and files a **follow-up issue** for
  "suppress DHCP relay forwarding on VRRP Backup interfaces" gated on
  `make test-failover`. This keeps #1915 a clean, smoke-free control-plane fix.
  Reviewers: confirm defer is acceptable (§10 Q5/Q7).

---

## 5. Recommended design (A1 + B1 + WaitGroup + C1)

Concrete shape (illustrative, not final code):

1. **Socket factory seam (for tests, G4).** Add an unexported function field
   on `Manager` (default = real impl; tests overwrite it):

   ```go
   type packetConnFactory func(ctx context.Context, ifaceName string,
       reusePort, broadcast bool, bindAddr *net.UDPAddr) (net.PacketConn, error)
   ```

   Default impl mirrors `vrfListenConfig` (heartbeat_manager.go:74): builds a
   `net.ListenConfig` whose `Control` sets `SO_REUSEADDR`+`SO_REUSEPORT` (when
   `reusePort`), `SO_BINDTODEVICE` (when `ifaceName != ""`), and `SO_BROADCAST`
   (when `broadcast` — for the client conn that writes to 255.255.255.255:68),
   then `lc.ListenPacket(ctx, "udp4", bindAddr.String())`. Returns the
   `net.PacketConn` **as-is — no `*net.UDPConn` assertion**.
   Client conn call: `factory(ctx, ifaceName, /*reuse*/true, /*bcast*/true, {0.0.0.0:67})`.
   Server conn call: `factory(ctx, "", /*reuse*/false, /*bcast*/false, {giaddr:0})`. Tests inject a
   factory returning a fake `net.PacketConn` whose `ReadFrom` blocks until
   `Close()`; this gives "two interfaces / no collision" and "Stop bounded"
   coverage with zero real sockets and no root.

2. **`runRelay` programs to `net.PacketConn`.** Local vars are
   `conn, serverConn net.PacketConn`. The read loops call
   `conn.ReadFrom(buf)` / `serverConn.ReadFrom(buf)` and writes call
   `serverConn.WriteTo(data, srv)` / `conn.WriteTo(data, dst)` where `srv`
   and `dst` are `*net.UDPAddr` (which satisfy `net.Addr`). The read source is
   `net.Addr` (only logged — no concrete-type access; verified against
   relay.go:243,261,315,332).

3. **Socket creation order (startup readiness first).**
   - Resolve `giaddr` via the Axis C1 bounded retry loop (ctx-cancelable).
   - client conn: `factory(ctx, ifaceName, /*reuse*/true, /*bcast*/true, {0.0.0.0:67})`.
   - server conn: `factory(ctx, "", /*reuse*/false, /*bcast*/false, {giaddr:0})`.
   - **Then, LAST (Claude SMR r1 F3), start the cancel watcher** — only after
     BOTH conns are successfully created. Every early-return path in
     `runRelay` that runs before this point (interface lookup, giaddr,
     client-conn create, server-conn create) therefore has nothing for the
     watcher to double-close, and `defer conn.Close()`/`defer
     serverConn.Close()` cover their own partial-init cleanup.

4. **Cancel watcher (B1) — closes BOTH conns:**

   ```go
   go func() { <-ctx.Done(); _ = conn.Close(); _ = serverConn.Close() }()
   ```

   Closing both is REQUIRED for the `wg.Wait()` liveness chain (§4 Axis B
   liveness invariant). Double-close is a safe idempotent no-op on
   `net.PacketConn` (returns `ErrClosed`); the read loops ignore post-cancel
   errors.

5. **WaitGroup + CROSS-CANCELLATION (G3; AGY r2 Finding 2).** Both the main
   read loop and the response goroutine MUST `defer cancel()` so that if
   **either** loop exits first on a non-cancel error, it cancels the shared
   `ctx`, which the watcher observes → closes BOTH conns → unblocks the peer
   loop. Without this, an early error in one loop leaves the other blocked in
   `ReadFrom` forever and `wg.Wait()` becomes the new hang.

   ```go
   // rctx already derived in Apply: rctx, cancel := context.WithCancel(ctx)
   // Pass `cancel` (or a context.CancelFunc) into runRelay.
   var wg sync.WaitGroup
   wg.Add(1)
   go func() {
       defer wg.Done()
       defer cancel()                 // exit of response loop cancels everyone
       handleServerResponses(rctx, serverConn, conn, ir)
   }()
   defer cancel()                     // exit of main read loop cancels everyone
   // ... main read loop ...
   wg.Wait()                          // joins the response goroutine
   ```

   The watcher (§5.4) already does `<-ctx.Done(); Close(conn); Close(serverConn)`,
   so `cancel()` from either loop drives both sockets closed. `wg.Wait()` then
   terminates because the response loop's `ReadFrom` is unblocked by the close.

6. **Read loop — REMOVE the `default:` no-op (Claude SMR r1 F4) + handle
   `ErrClosed` explicitly (AGY r2 Finding 3 — hot-spin guard).** The
   non-blocking `select { ...; default: }` was the original bug's fig leaf.
   The real cancellation is `Close()` waking `ReadFrom`. But the exit
   condition must NOT rely solely on `ctx.Err() != nil`: if the socket is
   closed while `ctx.Err()` is still `nil` (external close, fd invalidation,
   or the watcher's close racing the ctx-cancel observation), `ReadFrom`
   returns `net.ErrClosed` repeatedly and the loop spins hot. Return on EITHER
   condition:

   ```go
   for {
       n, src, err := conn.ReadFrom(buf)
       if err != nil {
           if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
               return // cancelled OR socket closed — stop, do not spin
           }
           slog.Warn("dhcp-relay: read error", ...); continue
       }
       ... // existing parse/relay logic, unchanged
   }
   ```

   Same treatment for `handleServerResponses`. No `SetReadDeadline`, no
   periodic wakeups — close-on-cancel is deterministic and spin-free.

7. **`sockopt_linux.go`** gains a `setReusePort(fd)` helper (`SO_REUSEADDR` +
   `SO_REUSEPORT`); keep `setBindToDevice`. (Both are invoked from the
   factory's `Control` body.)

8. **Public API unchanged.** `NewManager/Apply/Stats/Stop` signatures
   preserved; daemon + CLI untouched. The factory field is unexported and
   defaulted in `NewManager`, so no caller sees it.

### Open design decision for reviewers

- **D1**: Is the cancel-watcher goroutine (B1) cleaner than threading the conn
  handles up to `Stop()` and closing there? The watcher keeps conn ownership
  inside `runRelay` (no new `interfaceRelay` fields, no lock-ordering
  questions in `Stop`). The alternative stores `*net.UDPConn` on
  `interfaceRelay` and `Stop` closes them under `m.mu`. **Recommendation: the
  watcher** — fewer shared fields, no new lock interactions, and it ties conn
  lifetime to the same `ctx`/goroutine that created them. Reviewers should
  confirm this over the store-on-struct alternative.
- **D2 (RESOLVED — was open)**: REUSEPORT on `0.0.0.0:67` does NOT cause
  duplicate relay because the kernel filters by `SO_BINDTODEVICE` before
  REUSEPORT fanout (see Axis A serverConn note; AGY r1 §2.1 confirmed). The
  hard invariant — every client conn has BINDTODEVICE — is enforced by the
  factory (`ifaceName != ""`) and is now a **MUST-test** in §6 (the factory
  must be called with `reusePort=true` AND a non-empty `ifaceName` for every
  client listener).

---

## 6. Test plan (G4)

Unit tests in `relay_test.go`, no root, no real NICs, via the injected
factory. The fake conn must implement the FULL `net.PacketConn` interface
(`ReadFrom/WriteTo/Close/LocalAddr/SetDeadline/SetReadDeadline/
SetWriteDeadline`); the least-effort fake is `struct{ net.PacketConn }` (embed
a nil-or-stub) with `ReadFrom` (blocks on a channel until `Close`) and `Close`
(closes the channel, records called) overridden. `WriteTo` records the dst +
payload for the relay-forwarding assertions.

1. **`TestApply_MultiInterface_NoCollision`** (MUST) — factory records each
   `(ifaceName, bindAddr, reusePort)` request and returns a fake conn. Apply a
   group with 2 interfaces; assert two factory calls for `0.0.0.0:67` both
   with `reusePort=true` AND a **non-empty distinct `ifaceName`** (the D2
   BINDTODEVICE invariant) + both relays in `m.relays`, no error. The fake
   factory must NOT return EADDRINUSE — proving the design avoids the real-
   socket collision by construction (the real collision is exercised only by
   the optional root-gated test 6).
2. **`TestStop_BoundedNoPackets`** — start a relay whose fake conn's
   `ReadFromUDP` blocks until closed; call `Stop()`; assert it returns within
   a bounded deadline (e.g. `select` with 2s timeout) with **zero** packets
   delivered. Closing the fake conn must unblock the fake `ReadFromUDP`.
3. **`TestApply_Reapply_DoesNotHang`** — `Apply` twice (second triggers
   `Stop()` of gen 1); assert the second `Apply` returns bounded and gen-1
   goroutines are gone (response goroutine joined — check via a leak counter
   or the fake conn's close flag).
4. **`TestServerGoroutine_Joined`** — instrument the fake server conn; after
   `Stop()`, assert `handleServerResponses` returned (Done flag set) — proves
   the WaitGroup join.
5. **`TestRunRelay_StartupRetry`** (C1) — inject a resolver seam (covering BOTH
   `InterfaceByName` and `interfaceIPv4`) that returns "not ready" for the
   first K calls then succeeds; assert the relay does NOT die, eventually
   creates sockets, and `Stop()` during the retry wait returns promptly
   (ctx-cancel unwinds the retry `select`). Include a sub-case where the
   *interface itself* is missing for the first K calls (AGY r2 #4) — proves
   `InterfaceByName` is inside the retry.
6. **`TestRunRelay_OneSidedErrorNoHang`** (AGY r2 #2) — make the response
   goroutine's fake `ReadFrom` return a non-cancel error immediately; assert
   the main loop ALSO exits (via the shared `cancel()` → watcher → conn close)
   and `Stop()`/`done` completes bounded. Guards the cross-cancellation
   deadlock.
7. **`TestRunRelay_ClosedNoSpin`** (AGY r2 #3) — close the fake conn while
   `ctx` is NOT cancelled; assert the loop returns (does not spin) by counting
   `ReadFrom` calls stays bounded after close.
8. **(Optional, build-tagged/root) `TestRealReusePort_TwoListeners`** — on a
   host with two dummy interfaces, real `ListenConfig` binds two `0.0.0.0:67`
   sockets. Skipped by default (needs CAP_NET_RAW / root). Keep as a manual
   integration check, not in `make test`. This is the only test that
   exercises the *real* EADDRINUSE-vs-REUSEPORT kernel behavior; the unit
   tests prove the control-flow/wiring, this proves the syscall semantics.

Retain existing Option 82 / loopback tests unchanged.

**Validation gate**: `make test` (Go) green incl. new tests; `go vet`;
`golangci-lint` if wired. No smoke needed — this is control-plane Go with no
dataplane/AF_XDP/cluster interaction. (Confirm with reviewers that the
relay is not on the failover/VRRP path; it is not — it is a pure
forwarding-options service.)

---

## 7. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Concrete-type leak breaks mocking | Program to `net.PacketConn` (`ReadFrom`/`WriteTo`); NO `*net.UDPConn` assertion in `runRelay`. All sockopts set in `Control`, so no post-create assertion is needed (AGY §2.5). |
| Double-close of conn (defer + watcher) | `net.PacketConn.Close()` is idempotent (returns `ErrClosed`); read loops ignore post-cancel errors. Watcher started LAST so early-return paths have nothing to double-close (SMR F3). AGY §2.2 confirms Go's ref-counted FD wrapper makes double-close safe against fd reuse. |
| `wg.Wait()` becomes the NEW hang (only-`conn`-closed) | Watcher MUST close BOTH `conn` and `serverConn` (§4 liveness invariant, SMR F2). |
| `wg.Wait()` hangs on early one-sided error (no cross-cancel) | BOTH loops `defer cancel()` so either's exit cancels ctx → watcher closes both conns → peer unblocks (AGY r2 Finding 2). |
| Hot-spin on `ErrClosed` while `ctx.Err()==nil` | Loop returns on `ctx.Err()!=nil` OR `errors.Is(err, net.ErrClosed)` (AGY r2 Finding 3). |
| `InterfaceByName` failure bypasses C1 retry (dynamic VLAN/tunnel not yet created) | C1 retry wraps BOTH `InterfaceByName` AND `interfaceIPv4` (AGY r2 Finding 4). |
| REUSEPORT lets two sockets both receive a broadcast | Kernel discards BINDTODEVICE-mismatched candidates before REUSEPORT fanout (AGY §2.1). Hard invariant: every client conn has BINDTODEVICE — factory-enforced, D2 MUST-test. |
| Cancel-watcher goroutine leak | It waits on `ctx.Done()` exactly once then returns; `ctx` is always cancelled by `Stop()`/`Apply` (AGY §2.2 verified). |
| Dead relay on boot (no IPv4 yet, Apply runs once) | Axis C1 bounded ctx-cancelable retry loop around giaddr resolution (AGY §3.3). |
| Broadcast reply dropped (`EACCES` to 255.255.255.255:68) | Pre-existing — `SO_BROADCAST` never set. Add it to the client conn `Control` (factory `broadcast=true`). Found during r2. |
| Kea + relay both bind `:67` | Operationally mutually exclusive; commit-check or README note + follow-up (Q4). |
| VRRP-Backup duplicate relay | Documented; deferred to follow-up gated on `make test-failover` (Axis D / Q5). DHCP tolerates dup requests (xid/chaddr dedupe) — acceptable interim. |
| `SO_REUSEPORT` not available on the build target | Linux-only package (`sockopt_linux.go`); REUSEPORT is in `golang.org/x/sys/unix`. No portability concern (firewall is Linux). |
| Behavior regression in forwarding | No forwarding-path logic change; Option 82/giaddr/hop tests (N1) unchanged. `ReadFromUDP`→`ReadFrom` only changes the logged source addr type (`net.Addr`), never accessed concretely. |

---

## 8. Rollout / revert

Single self-contained PR touching only `pkg/dhcprelay`. Revert = revert the
commit; no migration, no config schema change, no persisted state. Behavior
before: 1 working listener per group + hang-on-quiet-stop. After: N working
listeners + bounded stop.

---

## 9. Alternatives considered (rejected)

- **A2 manual socket()** — more code, no benefit over `ListenConfig.Control`.
- **B2 read-deadline polling** — adds teardown latency + periodic wakeups;
  kept only as a fallback if B1 ownership is awkward (it is not).
- **B3 deadline-poke** — same ownership cost as B1, no benefit; we want the
  socket closed anyway.
- **File split (manager/socket/runner/packet/stats)** — out of scope per N3;
  separate refactor issue if desired.
- **Single shared `0.0.0.0:67` socket for all interfaces** — would need
  recvmsg `IP_PKTINFO` to demux ingress interface and lose per-interface
  BINDTODEVICE isolation + per-interface giaddr selection logic; larger
  rewrite, rejected.

---

## 10. Reviewer questions (status after r1)

1. **(RESOLVED r1, all 3)** cancel-watcher (B1) preferred over store-on-struct
   (D1). AGY §2.2 explicitly endorsed the watcher as race-superior (store-on-
   struct has a Stop-before-init hang window). Keeping B1.
2. **(RESOLVED r1, SMR F4)** the `default:` no-op is REMOVED. Close-on-cancel
   is the honest cancellation mechanism. (§5.6)
3. **(RESOLVED r1, AGY §2.5)** the injectable `net.PacketConn` factory is the
   primary test seam; the real-socket REUSEPORT test is optional/root-gated
   (test 6). Programming to `net.PacketConn` (not `*net.UDPConn`) is what makes
   the seam actually mockable.
4. **(OPEN — needs confirmation)** Kea/relay coexistence on `:67`. Codex, AGY
   §3.1, and SMR F6 all flagged this. AGY notes Kea does NOT set
   REUSEPORT/BINDTODEVICE so one service would fail `EADDRINUSE`. Plan position:
   they are operationally mutually exclusive; **the plan recommends adding a
   commit-check that rejects configuring `dhcp-relay` and `dhcp-server` (Kea)
   such that they bind the same interface's `:67`** — OR, if that is judged out
   of scope, documenting the conflict in README + filing a follow-up. Reviewers
   decide: commit-check in this PR vs follow-up. (Leaning: follow-up — it is a
   config-schema change orthogonal to the socket-lifecycle fix.)
5. **(RESOLVED → reframed as Axis D)** relay-on-VRRP-Backup duplicate relaying
   (AGY §3.2). Plan defers HA suppression to a follow-up issue gated on
   `make test-failover`; #1915 stays smoke-free. Reviewers: confirm defer is
   acceptable.
6. **(NEW)** Axis C1 startup-retry: include in this PR (recommended — same
   function, operator-invisible failure) or split to a follow-up? The plan
   recommends including it as its own commit within the PR.
7. **(NEW)** Is the parked-goroutine cost of C1 (one 5s-interval goroutine per
   never-addressed interface) acceptable, or should C1 cap total retries and
   then exit (turning "no address ever" into a logged permanent failure)? Plan
   leans: keep retrying (ctx-bounded) — an interface CAN get an address later
   (DHCP, manual config) and there is no reapply to restart it.

---

## 11. Definition of done (for the eventual /engineer pass)

- [ ] Multi-interface group starts all N listeners, each with REUSEPORT +
      non-empty BINDTODEVICE ifname (G1 + D2 invariant) — test 1 green.
- [ ] `Stop()` bounded with no packets (G2) — test 2 green.
- [ ] Response goroutine tracked + joined; reapply does not hang (G3) — tests
      3,4 green.
- [ ] Startup retry: late-addressed interface eventually binds; Stop during
      retry returns promptly (Axis C1) — test 5 green.
- [ ] `runRelay`/`handleServerResponses` programmed to `net.PacketConn` (no
      `*net.UDPConn` assertion); injectable factory seam in place (G4).
- [ ] `default:` no-op removed from both read loops.
- [ ] `SO_BROADCAST` set on the client conn (fixes pre-existing dropped
      broadcast OFFER/ACK to 255.255.255.255:68).
- [ ] Watcher started LAST (after both conns exist); closes BOTH conns.
- [ ] Cross-cancellation: both loops `defer cancel()`; early one-sided error
      does not hang `wg.Wait()` (AGY r2 #2).
- [ ] Loop returns on `ctx.Err()!=nil` OR `errors.Is(err, net.ErrClosed)` —
      no hot-spin (AGY r2 #3).
- [ ] C1 retry wraps `InterfaceByName` + `interfaceIPv4` (AGY r2 #4).
- [ ] `make test` green; `go vet` clean. (No smoke — control-plane only,
      off the HA/dataplane path; Axis D defers VRRP suppression.)
- [ ] README updated: REUSEPORT+BINDTODEVICE listener model, bounded-Stop
      contract, Kea-:67 mutual-exclusion note, VRRP-Backup duplicate-relay
      caveat.
- [ ] Public `Manager` API unchanged; daemon/CLI untouched.
- [ ] Follow-up issues filed: (a) VRRP-Backup relay suppression (gated on
      `make test-failover`); (b) commit-check for dhcp-relay/dhcp-server :67
      conflict — IF reviewers chose follow-up over in-PR (Q4/Q5).
- [ ] 4-way review (Codex + AGY + Claude SMR + Copilot) converged on the PR.

---

*r3 incorporates round-2 reviews: AGY r2 (cross-cancellation `defer cancel()`
in both loops; `errors.Is(net.ErrClosed)` hot-spin guard; `InterfaceByName`
inside the C1 retry; SO_BROADCAST made explicit in §5) + Claude SMR r2
(PLAN-READY; confirmed C1/done-channel + PacketConn/broadcast correctness).
Codex r2 pending re-dispatch. STOP at PLAN-READY on the final rev.*
