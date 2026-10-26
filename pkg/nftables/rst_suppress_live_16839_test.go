package nftables

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// TestRSTSuppressionSparesLiveSocketRSTLive16839 exercises both address
// families against the installed table. Each family must suppress a
// socketless kernel RST from the protected address and deliver a live,
// address-bound socket's RST to its peer.
//
// IPv4's spurious RST is backed by the wildcard-bound tcp_rst_sock control
// mini-socket. IPv6's socketless RST skb has no skb->sk, so nft_socket_eval
// BREAKs; #17868 adds an earlier live-socket return rule followed by a
// socketless drop rule. The per-family counter proves the socketless case
// still drops, while ECONNRESET and an unchanged counter prove a live RST
// survives.
//
// Needs CAP_NET_ADMIN for the netns; SKIPs otherwise (see enterPrivateNetns).
// Run with:
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

	families := []struct {
		name    string
		addr    netip.Addr
		prefix  string
		network string
	}{
		{name: "ipv4", addr: netip.MustParseAddr("127.0.0.2"), prefix: "/8", network: "tcp4"},
		{name: "ipv6", addr: netip.MustParseAddr("fd00::2"), prefix: "/128", network: "tcp6"},
	}
	for _, tc := range families {
		addr, err := netlink.ParseAddr(tc.addr.String() + tc.prefix)
		if err != nil {
			t.Fatalf("%s parse addr: %v", tc.name, err)
		}
		addr.Scope = int(netlink.SCOPE_HOST)
		if err := netlink.AddrAdd(lo, addr); err != nil {
			t.Fatalf("%s assign %s to lo: %v", tc.name, tc.addr, err)
		}
	}

	for _, tc := range families {
		t.Logf("testing %s RST suppression for %s", tc.name, tc.addr)
		exerciseRSTSuppressionFamily16839(t, tc.addr, tc.network)
	}
}

func exerciseRSTSuppressionFamily16839(t *testing.T, snat netip.Addr, network string) {
	t.Helper()
	var v4, v6 []netip.Addr
	if snat.Is4() {
		v4 = []netip.Addr{snat}
	} else {
		v6 = []netip.Addr{snat}
	}
	if err := InstallRSTSuppression(v4, v6); err != nil {
		t.Fatalf("InstallRSTSuppression: %v", err)
	}
	before, err := rstDropPackets()
	if err != nil {
		t.Fatalf("read counter before: %v", err)
	}
	t.Logf("counter before: packets=%d", before)

	// A SYN to a closed port elicits a socketless kernel RST from the
	// protected source address. It must be dropped in either family.
	dst := net.JoinHostPort(snat.String(), "44999")
	for range 3 {
		c, err := net.DialTimeout(network, dst, 500*time.Millisecond)
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
			t.Fatalf("read counter after socketless RSTs: %v", err)
		}
		if mid > before || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("counter after socketless RSTs: packets=%d", mid)
	if mid <= before {
		t.Fatalf("%s rule counter did not move for socketless RSTs: before=%d after=%d",
			network, before, mid)
	}

	// A live server bound to the protected address aborts an accepted
	// connection. Its full socket owns the RST, which must reach the client.
	ln, err := net.Listen(network, net.JoinHostPort(snat.String(), "44998"))
	if err != nil {
		t.Fatalf("listen on protected address %s: %v", snat, err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	cli, err := net.DialTimeout(network, ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial live-socket control: %v", err)
	}
	defer cli.Close()
	var srv net.Conn
	select {
	case srv = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not accept the live-socket connection")
	}
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
	if !errors.Is(rerr, syscall.ECONNRESET) {
		t.Fatalf("client read error = %v, want ECONNRESET from live socket", rerr)
	}
	t.Logf("client observed ECONNRESET from live socket: %v", rerr)

	time.Sleep(300 * time.Millisecond)
	after, err := rstDropPackets()
	if err != nil {
		t.Fatalf("read counter after live-socket RST: %v", err)
	}
	t.Logf("counter after live-socket RST: packets=%d", after)
	if after != mid {
		t.Fatalf("counter moved for live socket's RST from %s: mid=%d after=%d",
			snat, mid, after)
	}
}
