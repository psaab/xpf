# Plan of Action — #1915 DHCP relay socket lifecycle

- **Issue**: #1915 — DHCP relay: multi-interface groups fail (EADDRINUSE) and
  `Stop()`/reapply can hang (blocking `ReadFromUDP`, no close-on-cancel)
- **Revision**: r1 (DRAFT — pre first review round)
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

- `pkg/daemon/daemon_run.go:640-641`:
  `d.dhcpRelay = dhcprelay.NewManager(); d.dhcpRelay.Apply(ctx, cfg.ForwardingOptions.DHCPRelay)`.
  (The issue body cited lines 763-764; on current master the live wiring is
  640-641. Same call, same reachability — verified.)
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
| `pkg/dhcprelay/relay.go` | socket creation via `ListenConfig.Control`; cancelable reads; WaitGroup for the response goroutine; an injectable conn factory seam. |
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

**A1 — `net.ListenConfig.Control` (RECOMMENDED).**
Use `net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error}`
and call `lc.ListenPacket(ctx, "udp4", "0.0.0.0:67")`. Inside `Control`, run
`c.Control(fd -> setsockopt)` to set `SO_REUSEADDR`, `SO_REUSEPORT`, and
`SO_BINDTODEVICE` **before** the runtime calls `bind`. This is the idiomatic
Go way, keeps `*net.UDPConn` (so `ReadFromUDP`/`WriteToUDP`/`SetReadDeadline`
all still work unchanged), and keeps the netpoller integration. `ListenPacket`
returns `net.PacketConn`; type-assert to `*net.UDPConn`.

- Pros: minimal blast radius, keeps idiomatic conn type, netpoller intact,
  `SetReadDeadline` available for free, testable via a factory that wraps
  `lc.ListenPacket`.
- Cons: `SO_BINDTODEVICE` inside `Control` requires the ifname before bind —
  trivial, it is `ir.ifaceName`. Must assert `*net.UDPConn` (handle the
  unlikely assert failure).

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
REUSEPORT — it binds a unique ephemeral port per interface. It still needs the
same cancelable-read treatment (Axis B). Keep its creation as-is (or route it
through the same factory for test symmetry) but it is not part of the
EADDRINUSE fix.

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

---

## 5. Recommended design (A1 + B1 + WaitGroup)

Concrete shape (illustrative, not final code):

1. **Socket factory seam (for tests, G4).** Add an unexported function field
   on `Manager` (or a package-level var defaulting to the real impl):

   ```go
   type packetConnFactory func(ctx context.Context, ifaceName string,
       reusePort bool, bindAddr *net.UDPAddr) (net.PacketConn, error)
   ```

   Default impl builds a `net.ListenConfig` whose `Control` sets
   `SO_REUSEADDR`+`SO_REUSEPORT` (when `reusePort`) and `SO_BINDTODEVICE`
   (when `ifaceName != ""`), then `lc.ListenPacket`. Tests inject a factory
   returning in-memory/loopback conns to assert "two interfaces, no
   collision" and "Stop bounded".

2. **`runRelay` socket creation.**
   - client conn: `factory(ctx, ifaceName, /*reusePort*/true, {0.0.0.0:67})`.
   - server conn: `factory(ctx, "", /*reusePort*/false, {giaddr:0})`
     (no BINDTODEVICE, no REUSEPORT — unique ephemeral port).
   - assert both to `*net.UDPConn` where the loop needs `ReadFromUDP`.

3. **Cancel watcher.** After both conns exist:

   ```go
   go func() { <-ctx.Done(); conn.Close(); serverConn.Close() }()
   ```

4. **WaitGroup for response goroutine.**

   ```go
   var wg sync.WaitGroup
   wg.Add(1)
   go func() { defer wg.Done(); handleServerResponses(ctx, serverConn, conn, ir) }()
   // ... main read loop ...
   wg.Wait() // before runRelay returns
   ```

5. **Read loop.** Keep the `select { case <-ctx.Done(): return; default: }`
   as a cheap fast-path (it is harmless), but rely on `Close()` to unblock the
   read. The existing `if ctx.Err() != nil { return }` after a read error
   already handles the woken `ErrClosed`. Optionally drop the `default:`
   no-op since `Close()` is now the real cancellation mechanism — but keeping
   it is also fine and avoids a one-tick race where a packet arrives exactly
   as ctx cancels.

6. **`sockopt_linux.go`** gains `setReusePort(fd)` (`SO_REUSEADDR` +
   `SO_REUSEPORT`). Keep `setBindToDevice`.

7. **Public API unchanged.** `NewManager/Apply/Stats/Stop` signatures
   preserved; daemon + CLI untouched.

### Open design decision for reviewers

- **D1**: Is the cancel-watcher goroutine (B1) cleaner than threading the conn
  handles up to `Stop()` and closing there? The watcher keeps conn ownership
  inside `runRelay` (no new `interfaceRelay` fields, no lock-ordering
  questions in `Stop`). The alternative stores `*net.UDPConn` on
  `interfaceRelay` and `Stop` closes them under `m.mu`. **Recommendation: the
  watcher** — fewer shared fields, no new lock interactions, and it ties conn
  lifetime to the same `ctx`/goroutine that created them. Reviewers should
  confirm this over the store-on-struct alternative.
- **D2**: REUSEPORT on `0.0.0.0:67` means multiple sockets in the same group
  can receive the *same* broadcast if BINDTODEVICE were ever misapplied.
  Confirm BINDTODEVICE is always set on the client conn (it is, in the
  factory when `ifaceName != ""`) so each socket only sees its interface's
  traffic — no duplicate relaying. Add an assertion/test for this invariant.

---

## 6. Test plan (G4)

Unit tests in `relay_test.go`, no root, no real NICs, via the injected
factory:

1. **`TestApply_MultiInterface_NoCollision`** — factory records each
   `(ifaceName, bindAddr, reusePort)` request and returns a fake conn. Apply a
   group with 2 interfaces; assert two factory calls for `0.0.0.0:67` both
   with `reusePort=true` + correct ifnames, and **no** error / both relays in
   `m.relays`.
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
5. **(Optional, build-tagged/root) `TestRealReusePort_TwoListeners`** — on a
   host with two dummy interfaces, real `ListenConfig` binds two `0.0.0.0:67`
   sockets. Skipped by default (needs CAP_NET_RAW / root). Keep as a manual
   integration check, not in `make test`.

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
| `lc.ListenPacket` returns a non-`*net.UDPConn` | Type-assert with `ok`; on failure close + error log (cannot happen for udp4 but guard anyway). |
| Double-close of conn (defer + watcher) | `*net.UDPConn.Close()` is idempotent (returns `ErrClosed`); read loop already ignores post-cancel errors. Verified safe. |
| REUSEPORT lets two sockets in the same group both receive a broadcast | BINDTODEVICE on each client conn restricts to one interface; D2 test asserts no duplicate relaying. |
| Cancel-watcher goroutine leak | It waits on `ctx.Done()` exactly once then returns; `ctx` is always cancelled by `Stop()`/`Apply`. |
| `SO_REUSEPORT` not available on the build target | Linux-only package (`sockopt_linux.go`); REUSEPORT is in `golang.org/x/sys/unix`. No portability concern (firewall is Linux). |
| Behavior regression in forwarding | No forwarding-path code changes; tests N1 guard Option 82/giaddr/hop logic remains untouched. |
| Server conn also needs cancel | The watcher closes `serverConn` too; response goroutine's `ReadFromUDP` unblocks identically. |

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

## 10. Reviewer questions

1. Is the cancel-watcher goroutine (B1) preferred over storing `*net.UDPConn`
   on `interfaceRelay` and closing in `Stop()`? (§5 D1)
2. Should the `default:` no-op be removed from the read loop now that
   `Close()` is the real cancellation, or kept as a cheap fast-path? (§5.5)
3. Is the injectable-factory seam (`packetConnFactory` field/var) the right
   test seam, or would a real-`ListenConfig` + dummy-interface integration
   test (root-gated) be preferred as the primary guard? (§6)
4. Any reason the relay would ever need to coexist with the embedded DHCP
   *server* (`pkg/dhcpserver`/Kea) on `:67`? If so, REUSEPORT semantics across
   processes need a note. (Believed mutually exclusive — confirm.)
5. Confirm the relay is off the HA/failover/VRRP path so no smoke is required.

---

## 11. Definition of done (for the eventual /engineer pass)

- [ ] Multi-interface group starts all N listeners (G1) — test 1 green.
- [ ] `Stop()` bounded with no packets (G2) — test 2 green.
- [ ] Response goroutine tracked + joined (G3) — tests 3,4 green.
- [ ] Injectable factory seam in place (G4).
- [ ] `make test` green; `go vet` clean.
- [ ] README updated (REUSEPORT+BINDTODEVICE model, bounded-Stop contract).
- [ ] Public `Manager` API unchanged; daemon/CLI untouched.
- [ ] 4-way review (Codex + AGY + Claude SMR + Copilot) converged on the PR.

---

*Awaiting plan-review rounds (Codex + AGY + Claude SMR). STOP at PLAN-READY.*
