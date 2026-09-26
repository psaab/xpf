# pkg/lldp

IEEE 802.1AB Link Layer Discovery Protocol. Sends periodic LLDP frames
out unmanaged interfaces, receives neighbor announcements, and ages
entries by TTL. The received-neighbor table is bounded per interface so a
frame flood cannot exhaust memory (#4044).

## Entry points

- `Manager` — `lldp.go`.
- `Neighbor` — `lldp.go`. Chassis ID, port ID, TTL, system name and
  description.
- `New()` — `lldp.go`.
- `Apply(ctx context.Context, cfg *LLDPConfig) (unresolved []string)` —
  `lldp.go`. Reconcile-shaped: `Stop()`s the current generation before starting
  the new one, so calling it repeatedly is idempotent. A nil/disabled/empty
  config stops the service. Holds `lifecycleMu` across the whole transition so a
  concurrent `Stop()` cannot interleave (see **Apply/Stop concurrency** below).

  **Apply is PARTIAL, and says so (#6794).** Each configured interface is
  brought up independently and a failure skips just that one, so a call that
  "succeeded" can leave part of the generation dark. It returns the interfaces
  that failed NAME RESOLUTION — the recoverable half, where the NIC simply is
  not there yet (renamed a moment later by a `.link` file, created later as a
  VLAN/tunnel, or not yet up). It used to return nothing at all, which is what
  let the daemon's unchanged-config guard record an incomplete generation as
  converged and skip every reconcile that would have fixed it; recovery then
  needed a `protocols lldp` edit or a daemon restart. A SOCKET-setup failure
  (CAP_NET_RAW, bind) is deliberately NOT reported: it is logged and the
  interface skipped, but it does not self-heal within a process the way an
  absent NIC does, so surfacing it as retry debt would rebuild the whole
  generation on every later commit — wiping the neighbor table over a condition
  that will not change.
- `InterfaceResolvable(name string) bool` — `lldp.go` (#6794). Whether a
  configured interface name resolves to a kernel interface right now. Uses the
  SAME name conversion and the SAME lookup seam as `Apply`, deliberately: the
  daemon's recovery guard reads this to decide whether a previously-unresolved
  interface has appeared, and the apply acts on it, so a divergence between the
  two would mean either no recovery or endless re-`Apply`.
- `Stop()` — `lldp.go`. Holds `lifecycleMu`, then tears the generation down via
  the internal `stopLocked`.
- `Running()` — `lldp.go`. Reports whether a live generation has at least one
  active interface session. Used by the daemon's day-2 reconcile (#2372) and
  its tests to observe the start/stop transition.
- `ApplyCount()` — `lldp.go`. Number of `Apply()` calls. Test seam for the
  day-2 reconcile diff-guard (#2372) — an unrelated commit must not re-`Apply`.
- `Neighbors()` — `lldp.go`. Snapshot consumed by `show lldp
  neighbors`.

## Callers

`pkg/daemon`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

Standard library + `golang.org/x/sys/unix`, plus `pkg/linuxsock` (raw-socket
open) and `pkg/config` (the `LinuxIfName` slash->dash helper, see the
interface-name gotcha below).

## Socket lifecycle (#2035)

- Each enabled interface gets one `ifSession` (`lldp.go`) holding a bound
  RX `AF_PACKET` socket and a reused TX `AF_PACKET` socket. Sessions are
  created in `Apply()` and tracked on the `Manager`.
- The RX socket has **no `SO_RCVTIMEO`**: `rxLoop` blocks in `Recvfrom`
  indefinitely. `Stop()` (which runs on the daemon shutdown critical
  path, just before VRRP resignation) cancels the context, then
  `close()`s every session — `shutdown(SHUT_RDWR)` + `close` — which
  unblocks the parked `Recvfrom` immediately. This removed a 0–2s
  read-timeout tail from shutdown. Ordering is load-bearing:
  cancel → close fds → `wg.Wait()` (never wait before closing).
- `rxLoop` treats `EINTR`/`EAGAIN`/`EWOULDBLOCK` from `Recvfrom` as
  transient and retries immediately — a signal forwarded through the Go
  runtime must not silently terminate neighbor discovery on a long-running
  daemon. On any **other** recv error it distinguishes shutdown from an
  operational fault: if the context is cancelled it is the expected
  `Stop()` close-to-unblock and the loop returns; otherwise (the context
  is still live, e.g. the interface flapped down — `ENETDOWN`) the loop
  **backs off `rxErrorBackoff` (1s) and retries** rather than exiting.
  Nothing restarts `rxLoop` within a generation — it lives only for the life
  of the `Apply()` that started it (a config change re-`Apply()`s, which
  `Stop()`s the old generation and starts a fresh one) — so a permanent exit
  on a transient flap would silently kill neighbor discovery until the next
  `protocols lldp` commit or a daemon restart (the pre-`#2040` behavior; the
  old timeout-poll loop survived flaps by continuing). The
  backoff is interruptible: a concurrent `Stop()` cancels the context and
  the loop returns promptly instead of sleeping out the delay, and the
  closed fd makes any parked `Recvfrom` return so `Stop()` stays bounded.
- **Self-frame filter (`#2992`):** the RX socket is bound to `ETH_P_LLDP`,
  so the kernel loops this host's own transmitted LLDP advertisements back
  to the listener marked `PACKET_OUTGOING`. `recv` returns the
  `sll_pkttype` from the `Recvfrom` `sockaddr_ll`, and `rxLoop` drops any
  frame whose pkttype is `PACKET_OUTGOING` before parsing TLVs. Without this
  the firewall learns its own advertisement as a neighbor on every
  LLDP-enabled link, polluting `show lldp neighbors`. The EtherType and the
  well-known LLDP multicast destination are already kernel-filtered, so the
  loopback of our own transmissions is the only self-frame source; genuine
  inbound peer frames carry `PACKET_HOST`/`PACKET_MULTICAST`/`PACKET_BROADCAST`
  and are kept.
- The TX socket is opened once per interface in `newIfSession` and reused
  for every periodic advertisement (was previously opened+closed per
  frame).
- Construction goes through the `newIfSessionFn` seam so `socket_test.go`
  can inject a `socketpair(2)`-backed session and assert `Stop()` returns
  promptly with a parked RX goroutine, without `CAP_NET_RAW`.
- **Apply/Stop concurrency (`#5121`):** `Apply` (a config commit) and `Stop`
  (daemon shutdown) are lifecycle transitions that can run concurrently — the
  shutdown path (`pkg/daemon` `runShutdownSequence`) calls `lldpMgr.Stop()`
  **without** the `applySem` that `Apply` runs under, so a `SIGTERM` mid-commit
  races them. A dedicated `lifecycleMu` (distinct from the `mu` that guards the
  neighbor table / sessions) serializes the two: `Apply` holds it across the
  whole teardown-then-rebuild and `Stop` holds it across the teardown, so the
  `m.cancel` write/read, every `wg.Add(1)` vs `wg.Wait()`, and the session
  publish vs snapshot are atomic with respect to each other. Without it the
  race detector flags `m.cancel` and the `WaitGroup`, the `Add`/`Wait`
  interleave is a `WaitGroup` misuse (panic or a dropped join), and a `Stop`
  that snapshots the session set before `Apply` publishes a later interface's
  session leaves that RX goroutine parked in `recv` forever (hanging shutdown,
  leaking the socket). `Apply` calls the internal `stopLocked` (not `Stop`) to
  avoid re-acquiring the non-reentrant lock; `lifecycleMu` is never held by the
  TX/RX/expiry goroutines (they take only `mu`), so holding it across
  `wg.Wait()` cannot deadlock. Regression: `TestApplyStopLifecycleRace`
  (`lifecycle_mutex_5121_test.go`), RED under `go test -race` if the mutex is
  reverted.
- A socket setup / `CAP_NET_RAW` failure now surfaces at `Apply()` time
  (logged once, interface skipped) instead of silently per-frame.

## Day-2 reconcile (#2372)

The daemon owns the manager and reconciles it on every commit, not just at
boot. `Daemon.reconcileLLDP` (`pkg/daemon/daemon_apply.go`) is the single
source of truth: `daemon_run.go` calls it at boot and `applyConfigLocked`
calls it on every commit. An interface-set, `transmit-interval`, or
`hold-multiplier` change takes effect on commit without a daemon restart, and
a disabled/empty stanza `Stop()`s the running service.

Two properties keep this safe (#2372 review findings 3 + 6):

- **Construct-once.** The `Manager` is created exactly once, at boot
  (`daemon_run.go`, unconditionally — mirroring `dhcpRelay`), so the
  `d.lldpMgr` pointer is written before any handler runs. `reconcileLLDP`
  only ever calls `Apply()`/`Stop()` on it and NEVER reassigns the pointer.
  The `show lldp neighbors` gRPC/CLI handlers read `d.lldpMgr` lock-free on a
  handler goroutine, so a day-2 reassignment would be a data race on the
  pointer field — construct-once eliminates the write entirely. (A daemon that
  never enables LLDP allocates the manager but no sockets/goroutines.)
- **Change-guarded.** `Apply()` unconditionally `Stop()`s the current
  generation (closing every socket, joining goroutines, and wiping the
  neighbor table) before rebuilding. So `reconcileLLDP` compares the new
  effective LLDP config (`effectiveLLDPConfig`) against the last-applied one
  and calls `Apply()`/`Stop()` only when it actually changed. An unrelated
  day-2 commit (e.g. a firewall-policy change) therefore leaves a healthy LLDP
  generation untouched — `show lldp neighbors` does not blank and sockets do
  not churn. This matches the diff discipline of the adjacent
  `reconcileDHCPRelay` (#2348).

## Gotchas

- Uses AF_PACKET raw sockets — the daemon needs `CAP_NET_RAW`. Without
  it, session setup fails at `Apply()` time, the interface is skipped,
  and the neighbor table stays empty for it.
- **Config names are Junos display names; the socket needs the kernel
  name (#4049).** The `protocols lldp interface <name>` stanza carries a
  Junos name (`ge-0/0/0`, `reth0.50`), but xpfd renames the kernel device
  to dash form (`ge-0-0-0`) via its `.link` files. `Apply()` runs each
  config name through `config.LinuxIfName` (slash->dash) before
  `net.InterfaceByName` — a kernel ifname never contains a slash, so
  passing the raw Junos name failed the lookup and LLDP silently never
  opened a socket on the renamed data ports. `LinuxIfName` is a no-op on a
  name already in kernel form, so a non-renamed interface is unaffected.
  The lookup goes through the `interfaceByNameFn` seam so the resolution
  is unit-tested (`TestApplyResolvesKernelIfName`, `socket_test.go`)
  without a host device present.
- TTL countdown is per-neighbor; expired entries auto-purge from the
  `Neighbors()` snapshot on the `expiryLoop` 10s tick.
- **Immediate withdrawal on TTL=0 shutdown (#5123):** IEEE 802.1AB defines
  a TTL=0 LLDPDU as an explicit shutdown — the receiver must delete the
  neighbor at once, not age it out. `rxLoop` treats a parsed TTL of 0 as a
  withdrawal, not an advertisement: it computes the
  `ifname/chassis/port` key and calls `withdrawNeighbor` (`lldp.go`), which
  deletes that entry under `mu` and does **not** cache the frame. Without
  this, a shutdown frame was stored like any other neighbor with
  `ExpiresAt==now`, so the departed peer stayed in `Neighbors()` until the
  next ~10s `expiryLoop` tick. A TTL=0 frame for an unknown key is a no-op
  (no error, no spurious insert). The fix is the immediate delete, not a
  change to the reap cadence.
- The neighbor map is RWMutex-guarded. `Neighbors()` returns a copy, not
  a reference, so callers can iterate without holding the lock.
- `ParseTLVs` counts a mandatory TLV (Chassis ID, Port ID, TTL) as
  present only once its value parsed into a valid identifier — a non-empty
  Chassis/Port ID, a full 2-byte TTL. A truncated mandatory TLV (subtype
  byte alone, a MAC-subtype Chassis ID short of its 6-byte address, or a
  TTL under 2 bytes) leaves the corresponding flag unset, so the frame is
  rejected rather than cached under an empty `ifname//` key with TTL 0
  (#2551). A valid 2-byte TTL of 0 is a legitimate shutdown advert and is
  still accepted here (the gate is "the TLV parsed", not "TTL != 0"); the
  RX path then acts on that parsed TTL=0 by withdrawing the neighbor
  immediately (see the immediate-withdrawal note above, #5123).
- **Bounded neighbor table (#4044, #10898):** LLDP is unauthenticated L2 —
  any station on the segment can advertise arbitrary chassis-id / port-id
  pairs. The receive path caps the table at `maxNeighborsPerInterface` (64)
  **per local interface**, preventing an unbounded memory-growth flood. A
  refresh of an existing key updates in place. A new neighbor received at the
  cap replaces the entry with the oldest `LastSeen`, then is admitted in the
  same receive operation. Thus, after a flood stops, the first subsequent
  legitimate advertisement is admitted immediately rather than waiting for a
  spoofed neighbor's TTL to expire (which could be 65535 seconds). This policy
  bounds admission recovery to the next received neighbor frame; a continuing
  flood can cause LRU churn, but cannot grow the table. The full legal
  16-bit wire TTL is preserved, including 65535 seconds, so valid maximum-TTL
  peers are compatible and no TTL deviation is introduced. The effective
  global bound is 64 times the number of LLDP-enabled interfaces. A warning for
  full-table eviction is rate-limited to once per 60s per interface and the
  warning dampener is reset with the neighbor table in `Stop()`.
- **Control-char sanitization on receive (#4043):** LLDP is an
  unauthenticated L2 protocol — any device on the segment can craft a frame
  whose free-text TLVs carry ANSI escape sequences, CR/LF, or other control
  characters. `ParseTLVs` runs every operator-visible received string
  (system-name, system-description, port-description, port-id, and the
  non-MAC chassis-id) through `sanitizeTLVString` at the store boundary
  before it lands in the neighbor table, so both the expiry log line and the
  `show lldp neighbors` table read already-clean strings. Each Unicode
  control rune (C0 `0x00-0x1F` including ESC/CR/LF, DEL `0x7F`, and C1
  `0x80-0x9F`) is replaced by a space; a legitimate multi-byte UTF-8 name is
  preserved unchanged (`strings.Map` is rune-aware). A **raw invalid-UTF-8
  byte** (e.g. a bare `0x9B`, the 8-bit CSI introducer an 8-bit terminal acts
  on like `ESC[`) is folded to `U+FFFD`: it is not a control *rune*, so the
  fast-path skip now also gates on `utf8.ValidString` to force the
  `strings.Map` slow path for any invalid-UTF-8 input — an `IsControl`-only
  skip returned such a byte verbatim (#6482). This is the LLDP-receive
  counterpart of the #1798/#3900 free-text sanitizer and neutralizes
  terminal-escape spoofing (`show lldp neighbors`) and syslog log-injection (a
  forged/split log line) from a hostile neighbor.
