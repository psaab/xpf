package nftables

import (
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// TestRSTSuppressionSparesLiveSocketRSTLive16839 is the live-kernel
// regression test for #16839. The #15727 raw-priority chain matched
// `ct state invalid` alone, but at raw (-300) the OUTPUT conntrack hook
// (-200) has not run yet, so a live local socket's abortive RST --
// sourced FROM the protected interface-NAT address -- also reads
// INVALID and was dropped, and the peer never saw the reset. The
// pre-existing "tracked" control in the 15727 live test could not catch
// this: its client RST is sourced from the ephemeral client address
// (127.0.0.1), outside the rule's saddr scope as well as tracked, so it
// passes with or without the bug.
//
// This test installs the real xpf_dp_rst table and runs both cells
// against the protected address itself:
//
//   - Spurious cell (must still drop): SYNs to a closed port on the
//     protected address elicit the kernel's no-socket RST
//     (tcp_v4_send_reset via the wildcard-bound tcp_rst_sock control
//     mini-socket). The drop counter must move.
//   - Live-socket cell (must deliver, #16839): a server socket bound to
//     the protected address accepts a connection and aborts it with
//     SO_LINGER 0, emitting a genuine RST sourced from the protected
//     address. The client must observe ECONNRESET and the drop counter
//     must NOT move.
//
// Fail-on-revert: removing the socket-wildcard predicate from
// rstDropExprs makes the live-socket RST match `ct invalid` at raw and
// be dropped -- the client read then times out instead of resetting
// and the counter moves, failing both assertions. Inverting the
// wildcard value likewise fails (spurious cell stops counting, live
// cell starts).
//
// Needs CAP_NET_ADMIN for the netns; SKIPs otherwise (see
// enterPrivateNetns). Run with:
//
//	unshare -rn go test ./pkg/nftables/ -run TestRSTSuppressionSparesLiveSocketRSTLive16839 -count=1 -v
func TestRSTSuppressionSparesLiveSocketRSTLive16839(t *testing.T) {
	enterPrivateNetns(t)

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("lo link: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("bring lo up: %v", err)
	}
	snat := netip.MustParseAddr("127.0.0.2")
	addr, err := netlink.ParseAddr(snat.String() + "/8")
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	addr.Scope = int(netlink.SCOPE_HOST)
	if err := netlink.AddrAdd(lo, addr); err != nil {
		t.Fatalf("assign %s to lo: %v", snat, err)
	}

	if err := InstallRSTSuppression([]netip.Addr{snat}, nil); err != nil {
		t.Fatalf("InstallRSTSuppression: %v", err)
	}
	before, err := rstDropPackets()
	if err != nil {
		t.Fatalf("read counter before: %v", err)
	}
	t.Logf("counter before: packets=%d", before)

	// Spurious cell: SYN to a closed port on the protected address.
	dst := net.JoinHostPort(snat.String(), "44999")
	for range 3 {
		c, err := net.DialTimeout("tcp4", dst, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			t.Fatalf("dial %s unexpectedly succeeded (something is listening)", dst)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	var mid uint64
	for {
		mid, err = rstDropPackets()
		if err != nil {
			t.Fatalf("read counter after spurious RSTs: %v", err)
		}
		if mid > before || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("counter after spurious RSTs: packets=%d", mid)
	if mid <= before {
		t.Fatalf("rule counter did not move for conntrack-less RSTs: before=%d after=%d "+
			"— the socket-wildcard predicate must still admit the kernel's no-socket RST (#16839)", before, mid)
	}

	// Live-socket cell: server bound to the protected address aborts an
	// accepted connection with SO_LINGER 0. Its RST is sourced from
	// the protected address, belongs to a live full socket, and must
	// be delivered to the client (ECONNRESET), not dropped.
	ln, err := net.Listen("tcp4", net.JoinHostPort(snat.String(), "44998"))
	if err != nil {
		t.Fatalf("listen on protected address: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	cli, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial live-socket control: %v", err)
	}
	defer cli.Close()
	var srv net.Conn
	select {
	case srv = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not accept the live-socket connection")
	}
	// Let the connection settle so the abort emits a RST for an
	// established, conntrack-tracked connection.
	time.Sleep(200 * time.Millisecond)
	if tc, ok := srv.(*net.TCPConn); ok {
		if raw, err := tc.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				_ = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER,
					&syscall.Linger{Onoff: 1, Linger: 0})
			})
		}
		_ = tc.SetLinger(0)
	}
	_ = srv.Close()

	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, rerr := cli.Read(make([]byte, 16))
	if rerr == nil {
		t.Fatalf("client read unexpectedly succeeded after server abort (no RST, no data)")
	}
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatalf("client saw NO RST from the live socket on the protected address "+
			"(read timed out: %v) — the raw-priority rule dropped a live socket's RST (#16839)", rerr)
	}
	t.Logf("client observed RST from live socket: %v", rerr)

	time.Sleep(300 * time.Millisecond)
	after, err := rstDropPackets()
	if err != nil {
		t.Fatalf("read counter after live-socket RST: %v", err)
	}
	t.Logf("counter after live-socket RST: packets=%d", after)
	if after != mid {
		t.Fatalf("counter moved for a live socket's RST from the protected address: mid=%d after=%d "+
			"— socket-owned RSTs must not be dropped (#16839)", mid, after)
	}
}
