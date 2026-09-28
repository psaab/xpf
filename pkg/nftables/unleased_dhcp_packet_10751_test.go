package nftables

import (
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

// unleased_dhcp_packet_10751_test.go proves #10751 F8-A over REAL packets in
// a private netns: a first DHCPv6 ADVERTISE-shaped datagram (unicast UDP to
// the unleased unit's link-local :546) is admitted through the installed
// backstop table while anything else to the unit is dropped; the DHCPv4
// broadcast twin (directed broadcast :68) likewise arrives; and a failed
// atomic replacement retains the working acquisition ruleset. The daemon
// unit tests pin WHICH netdevs land in the spec; these tests pin what the
// installed rules DO to packets.

const unleasedTestNetdev10751 = "ge-0-0-9"

// mkUnleasedVeth10751 creates a veth pair in the test netns, renames the test
// end to a production-shaped netdev, brings both up, and returns the test
// end's kernel-assigned link-local (polled — addrconf is async). The address
// may still be DAD-tentative on return: sockets bind wildcard (bindable
// immediately) and the first positive exchange retries until DAD completes.
func mkUnleasedVeth10751(t *testing.T) (testLL net.IP) {
	t.Helper()
	la := netlink.NewLinkAttrs()
	la.Name = "vunlease0"
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: "vpeer0"}); err != nil {
		t.Fatalf("LinkAdd veth: %v", err)
	}
	testLink, err := netlink.LinkByName("vunlease0")
	if err != nil {
		t.Fatalf("LinkByName vunlease0: %v", err)
	}
	if err := netlink.LinkSetName(testLink, unleasedTestNetdev10751); err != nil {
		t.Fatalf("rename test end: %v", err)
	}
	testLink, err = netlink.LinkByName(unleasedTestNetdev10751)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", unleasedTestNetdev10751, err)
	}
	peerLink, err := netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("LinkByName vpeer0: %v", err)
	}
	if err := netlink.LinkSetUp(testLink); err != nil {
		t.Fatalf("LinkSetUp test end: %v", err)
	}
	if err := netlink.LinkSetUp(peerLink); err != nil {
		t.Fatalf("LinkSetUp peer end: %v", err)
	}
	return pollLinkLocal10751(t, unleasedTestNetdev10751)
}

func pollLinkLocal10751(t *testing.T, ifname string) net.IP {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		iface, err := net.InterfaceByName(ifname)
		if err != nil {
			t.Fatalf("InterfaceByName %s: %v", ifname, err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatalf("Addrs %s: %v", ifname, err)
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.IsLinkLocalUnicast() {
				return ip
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a link-local on %s", ifname)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// udpExchange10751 sends one datagram and reports whether a datagram arrives
// before the deadline. received=false with no error is a clean timeout (the
// DROP verdict); any other error fails the test.
func udpExchange10751(t *testing.T, recv *net.UDPConn, send func() error, timeout time.Duration) (received bool) {
	t.Helper()
	if err := send(); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := recv.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1500)
	_, _, err := recv.ReadFromUDP(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false
		}
		t.Fatalf("recv: %v", err)
	}
	return true
}

// udpExchangeRetry10751 repeats a send/recv round until a datagram arrives
// or the deadline passes: the first positive exchange on a fresh link-local
// races DAD (a tentative source fails the send; a tentative destination
// drops the inbound), so a single shot would flake. Send errors and
// timeouts retry; anything else fails immediately. Returns false only on a
// clean deadline with nothing ever received.
func udpExchangeRetry10751(t *testing.T, recv *net.UDPConn, send func() error, perTry, total time.Duration) (received bool) {
	t.Helper()
	deadline := time.Now().Add(total)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := send(); err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err := recv.SetReadDeadline(time.Now().Add(perTry)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		buf := make([]byte, 1500)
		if _, _, err := recv.ReadFromUDP(buf); err == nil {
			return true
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			lastErr = err
			continue
		} else {
			t.Fatalf("recv: %v", err)
		}
	}
	t.Logf("last exchange error before deadline: %v", lastErr)
	return false
}

func tableHasIIFNAME10751(t *testing.T, table string) bool {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables conn: %v", err)
	}
	tbl := &nftables.Table{Name: table, Family: nftables.TableFamilyINet}
	rules, err := c.GetRules(tbl, &nftables.Chain{Name: "input", Table: tbl})
	if err != nil {
		t.Fatalf("GetRules %s: %v", table, err)
	}
	for _, r := range rules {
		for _, e := range r.Exprs {
			if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyIIFNAME {
				return true
			}
		}
	}
	return false
}

// TestUnleasedDHCPAcquisitionThroughBackstop10751: the no-LL-at-S1 shape
// (spec carries NO destinations, only the v6 backstop — the link came up
// after the snapshot). An ADVERTISE-shaped datagram to the unit's
// link-local :546 must ARRIVE (the F8-A admit); anything else to the unit
// (:9999 listener, proving the verdict is the DROP and not a closed port)
// must NOT.
func TestUnleasedDHCPAcquisitionThroughBackstop10751(t *testing.T) {
	enterPrivateNetns(t)
	testLL := mkUnleasedVeth10751(t)
	in := NewNetlinkInstaller()
	if err := in.InstallHostInbound(HostInboundSpec{UnleasedV6: []string{unleasedTestNetdev10751}}); err != nil {
		t.Fatalf("backstop install: %v", err)
	}

	client, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 546})
	if err != nil {
		t.Fatalf("listen [::]:546: %v", err)
	}
	defer client.Close()
	junk, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 9999})
	if err != nil {
		t.Fatalf("listen [::]:9999: %v", err)
	}
	defer junk.Close()
	server, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 547})
	if err != nil {
		t.Fatalf("listen [::]:547: %v", err)
	}
	defer server.Close()

	advertise := &net.UDPAddr{IP: testLL, Port: 546, Zone: "vpeer0"}
	if !udpExchangeRetry10751(t, client, func() error {
		_, err := server.WriteToUDP([]byte("advertise"), advertise)
		return err
	}, 300*time.Millisecond, 10*time.Second) {
		t.Fatal("ADVERTISE-shaped datagram to [ll]:546 was dropped: the backstop deadlocks DHCPv6 acquisition (F8-A admit missing or shadowed)")
	}
	other := &net.UDPAddr{IP: testLL, Port: 9999, Zone: "vpeer0"}
	if udpExchange10751(t, junk, func() error {
		_, err := server.WriteToUDP([]byte("junk"), other)
		return err
	}, time.Second) {
		t.Fatal("datagram to [ll]:9999 arrived: the interface DROP is not denying non-DHCP traffic")
	}
}

// TestUnleasedDHCPv4BroadcastThroughBackstop10751: the dual-unleased shape.
// A directed-broadcast :68 datagram (OFFER-shaped — its destination is in
// NO set, proving the admit is daddr-independent) must ARRIVE; broadcast
// :80 to a bound listener must NOT (the v4 interface DROP).
func TestUnleasedDHCPv4BroadcastThroughBackstop10751(t *testing.T) {
	enterPrivateNetns(t)
	mkUnleasedVeth10751(t)
	testLink, err := netlink.LinkByName(unleasedTestNetdev10751)
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	peerLink, err := netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("LinkByName peer: %v", err)
	}
	mustAddrAdd10751(t, testLink, "192.0.2.2/24")
	mustAddrAdd10751(t, peerLink, "192.0.2.1/24")

	in := NewNetlinkInstaller()
	spec := HostInboundSpec{UnleasedV4: []string{unleasedTestNetdev10751}, UnleasedV6: []string{unleasedTestNetdev10751}}
	if err := in.InstallHostInbound(spec); err != nil {
		t.Fatalf("backstop install: %v", err)
	}

	offer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 68})
	if err != nil {
		t.Fatalf("listen :68: %v", err)
	}
	defer offer.Close()
	web, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 80})
	if err != nil {
		t.Fatalf("listen :80: %v", err)
	}
	defer web.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 0})
	if err != nil {
		t.Fatalf("sender bind: %v", err)
	}
	defer sender.Close()
	enableBroadcast10751(t, sender)

	bcast68 := &net.UDPAddr{IP: net.ParseIP("192.0.2.255"), Port: 68}
	if !udpExchange10751(t, offer, func() error {
		_, err := sender.WriteToUDP([]byte("offer"), bcast68)
		return err
	}, 3*time.Second) {
		t.Fatal("broadcast :68 was dropped: the v4 DHCP admit is missing or shadowed")
	}
	bcast80 := &net.UDPAddr{IP: net.ParseIP("192.0.2.255"), Port: 80}
	if udpExchange10751(t, web, func() error {
		_, err := sender.WriteToUDP([]byte("junk"), bcast80)
		return err
	}, time.Second) {
		t.Fatal("broadcast :80 arrived: the v4 interface DROP is not denying non-DHCP traffic")
	}
}

// TestUnleasedBackstopAtomicReplace10751: backstop→destination swap. A
// failed replacement (unrepresentable netdev — the plan fails CLOSED)
// retains the working acquisition ruleset; the succeeding lease re-render
// swaps the admit for destination DROPs with no stale iifname rule left.
func TestUnleasedBackstopAtomicReplace10751(t *testing.T) {
	enterPrivateNetns(t)
	testLL := mkUnleasedVeth10751(t)
	in := NewNetlinkInstaller()
	if err := in.InstallHostInbound(HostInboundSpec{UnleasedV6: []string{unleasedTestNetdev10751}}); err != nil {
		t.Fatalf("backstop install: %v", err)
	}
	client, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 546})
	if err != nil {
		t.Fatalf("listen [::]:546: %v", err)
	}
	defer client.Close()

	dialServer := func(t *testing.T) *net.UDPConn {
		t.Helper()
		s, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
		if err != nil {
			t.Fatalf("server bind: %v", err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	// Baseline acquisition retries (DAD); later probes are single-shot on
	// the proven path, each from a fresh tuple so no conntrack entry can
	// color the verdict.
	s := dialServer(t)
	dst := &net.UDPAddr{IP: testLL, Port: 546, Zone: "vpeer0"}
	if !udpExchangeRetry10751(t, client, func() error {
		_, err := s.WriteToUDP([]byte("advertise"), dst)
		return err
	}, 300*time.Millisecond, 10*time.Second) {
		t.Fatal("baseline acquisition: nothing received")
	}
	probe := func(t *testing.T, want bool, what string) {
		t.Helper()
		s := dialServer(t)
		if got := udpExchange10751(t, client, func() error {
			_, err := s.WriteToUDP([]byte("advertise"), dst)
			return err
		}, 3*time.Second); got != want {
			t.Fatalf("%s: received=%v, want %v", what, got, want)
		}
	}

	// Failed replacement: the plan rejects the 38-byte netdev before any
	// Flush, so the installed generation is untouched.
	err = in.InstallHostInbound(HostInboundSpec{UnleasedV6: []string{"this-name-is-far-too-long-for-linux"}})
	if err == nil || !strings.Contains(err.Error(), "15-byte") {
		t.Fatalf("invalid-netdev install err = %v, want the fail-closed iifname error", err)
	}
	probe(t, true, "acquisition after failed replacement")

	// Lease re-render: destinations replace the backstop. The same :546
	// datagram is now denied by the unzoned LL DROP (the admit is gone —
	// a stale admit would still match regardless of daddr).
	lease := HostInboundSpec{UnzonedV6: []string{testLL.String(), "2001:db8::9"}}
	if err := in.InstallHostInbound(lease); err != nil {
		t.Fatalf("leased re-render: %v", err)
	}
	probe(t, false, "dhcp-shaped traffic after lease (destination DROP owns :546)")
	if tableHasIIFNAME10751(t, HostInboundTableName) {
		t.Fatal("leased table still carries an iifname rule: the backstop did not fully swap for destinations")
	}
}

func mustAddrAdd10751(t *testing.T, link netlink.Link, cidr string) {
	t.Helper()
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("ParseAddr %s: %v", cidr, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("AddrAdd %s: %v", cidr, err)
	}
}

func enableBroadcast10751(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	}); err != nil {
		t.Fatalf("SyscallConn.Control: %v", err)
	}
	if opErr != nil {
		t.Fatalf("SO_BROADCAST: %v", opErr)
	}
}
