# pkg/linuxsock

Single source of truth for raw/datagram socket creation in xpfd, so that
`SOCK_CLOEXEC` is non-optional.

## Why this package exists

Go's `net` package sets `O_CLOEXEC` on every fd it creates. A raw
`unix.Socket(2)` does **not** — the fd is left inheritable. xpfd fork-execs
helpers constantly (`frr-reload.py`, `swanctl`, DHCP/script helpers), so any
inheritable raw `AF_PACKET` / raw-ICMP / datagram fd leaks into those children:
an fd leak **and** a security boundary issue (a child could read or inject raw
frames on the interface).

`#2476` fixed the VRRP receiver socket in isolation. `#2608` made the policy
structural: every sibling raw/datagram socket creation site (cluster GARP/NDP
bursts, LLDP rx/tx, HA fabric ICMP probes, userspace NAPI probes, DHCP-relay L2
send) now routes through `linuxsock.Socket`, which ORs `unix.SOCK_CLOEXEC` into
the type argument so the fd is created close-on-exec **atomically** at
`socket(2)` time. The atomic OR-into-type is deliberate: a separate
post-creation `fcntl(FD_CLOEXEC)` races a concurrent fork-exec between the two
syscalls, and an inherited fd in that window is exactly the leak being closed.

## Contract

- All raw/datagram socket creation under `pkg/` goes through
  `linuxsock.Socket(domain, typ, proto)`. Callers pass the **bare** type
  (`unix.SOCK_RAW`, `unix.SOCK_DGRAM`) — never `SOCK_CLOEXEC` themselves, and
  never `unix.Socket` directly.
- `canary_test.go::TestNoDirectUnixSocket` walks every production `.go` file
  under `pkg/` with `go/ast` and fails the suite on any direct `unix.Socket(...)`
  call outside the allowlist. A new socket added the wrong way fails loudly.
- Allowlist (justified direct callers): `linuxsock.Socket` itself (the wrapper),
  and `pkg/vrrp::openAfPacketReceiver` (the pre-#2476 site, which already ORs
  `SOCK_CLOEXEC` and is pinned by `pkg/vrrp/afpacket_cloexec_test.go`).

- Cancellable receive (#17231): `PpollRecv` wraps a bound raw socket fd
  plus a wake eventfd; `Recv` ppolls on both so `SignalStop` wakes a parked
  receive, and owners close only after joining the receiving goroutine
  (signal → join → close). `canary_test.go::TestNoDirectBlockingRecvfrom`
  fails on any direct `unix.Recvfrom` outside the primitive and nfqueue's
  poll-guarded reads.
