package nftables

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// gap_lifeline_exception_10751_test.go proves #10751 M1 over REAL packets
// in a private netns: with W lifeline+data shared and X data-only, the
// installed gap table admits W on lifeline ingress (exception ACCEPT),
// denies W on data ingress (bare DROP), denies X, and still policy-accepts
// unlisted destinations. The daemon unit tests pin WHICH values land in the
// spec (globals); this test pins what the installed rules DO per ingress
// path — nftables treats the daddr values opaquely, so the verdict logic
// is transport-agnostic.
//
// Transport is link-local unicast with Zone-pinned egress (the F8-A
// pattern): v4 unicast is undeliverable between veth ends in a userns
// netns here (a minimal /32 + static-ARP repro fails identically with no
// firewall installed — environmental, below ARP/routing), and unscoped
// global v6 short-circuits through the local table to the DOWN loopback
// instead of traversing the pair. The v4/v6-global exception rules are
// the same builder with a family parameter, proven bit-identical by the
// T1 parity cell plus the oracle placement test.

// mkNamedVeth10751 creates a veth pair, renames the test end, brings both
// up, and returns the test link.
func mkNamedVeth10751(t *testing.T, testName, tmpTest, peerName string) netlink.Link {
	t.Helper()
	la := netlink.NewLinkAttrs()
	la.Name = tmpTest
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: peerName}); err != nil {
		t.Fatalf("LinkAdd veth %s: %v", tmpTest, err)
	}
	testLink, err := netlink.LinkByName(tmpTest)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", tmpTest, err)
	}
	if err := netlink.LinkSetName(testLink, testName); err != nil {
		t.Fatalf("rename to %s: %v", testName, err)
	}
	testLink, err = netlink.LinkByName(testName)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", testName, err)
	}
	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", peerName, err)
	}
	if err := netlink.LinkSetUp(testLink); err != nil {
		t.Fatalf("LinkSetUp %s: %v", testName, err)
	}
	if err := netlink.LinkSetUp(peerLink); err != nil {
		t.Fatalf("LinkSetUp %s: %v", peerName, err)
	}
	return testLink
}

// TestGapLifelineExceptionBothIngress10751: the Opus8 R4-2 packet shape.
// W is configured on BOTH the lifeline and data test ends (shared
// topology); X and Y only on data. The gap (Uncovered {W,X}, Shared {W},
// lifelines {fxp0}) must admit W via lifeline, deny W via data, deny X,
// and admit unlisted Y (policy-accept sanity proving the table is not
// DROP-all). Sockets bind wildcard (fresh addresses are DAD-tentative)
// and the first positive retries until DAD completes.
func TestGapLifelineExceptionBothIngress10751(t *testing.T) {
	enterPrivateNetns(t)
	const (
		wNetdev = "fxp0"
		wAddr   = "fe80::5" // W: lifeline+data shared
		xAddr   = "fe80::9" // X: data-only newcomer
		yAddr   = "fe80::1" // Y: retained-covered, not in the gap
	)
	lifeLink := mkNamedVeth10751(t, wNetdev, "vunlease0", "vpeer0")
	dataLink := mkNamedVeth10751(t, unleasedTestNetdev10751, "vunlease1", "vpeer1")
	mustAddrAdd10751(t, lifeLink, wAddr+"/64")
	mustAddrAdd10751(t, dataLink, wAddr+"/64")
	mustAddrAdd10751(t, dataLink, xAddr+"/64")
	mustAddrAdd10751(t, dataLink, yAddr+"/64")

	in := NewNetlinkInstaller()
	spec := GapFenceSpec{
		UncoveredV6:     []string{wAddr, xAddr},
		SharedV6:        []string{wAddr},
		LifelineNetdevs: []string{wNetdev},
	}
	if err := in.InstallGapFence(spec); err != nil {
		t.Fatalf("gap install: %v", err)
	}

	listen := func(port int) *net.UDPConn {
		c, err := net.ListenUDP("udp6", &net.UDPAddr{Port: port})
		if err != nil {
			t.Fatalf("listen [::]:%d: %v", port, err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	wSock := listen(4000)
	xSock := listen(4001)
	ySock := listen(4002)
	lifeSender, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("lifeline sender bind: %v", err)
	}
	defer lifeSender.Close()
	dataSender, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("data sender bind: %v", err)
	}
	defer dataSender.Close()

	// Zones pin each datagram's egress link (required for link-locals;
	// also bypasses the local-table short-circuit, per F8-A).
	toWLife := &net.UDPAddr{IP: net.ParseIP(wAddr), Port: 4000, Zone: "vpeer0"}
	if !udpExchangeRetry10751(t, wSock, func() error {
		_, err := lifeSender.WriteToUDP([]byte("mgmt"), toWLife)
		return err
	}, 300*time.Millisecond, 10*time.Second) {
		t.Fatal("W via lifeline ingress was dropped: the gap exception is missing or shadowed (management lockout)")
	}
	toY := &net.UDPAddr{IP: net.ParseIP(yAddr), Port: 4002, Zone: "vpeer1"}
	if !udpExchange10751(t, ySock, func() error {
		_, err := dataSender.WriteToUDP([]byte("other"), toY)
		return err
	}, 3*time.Second) {
		t.Fatal("unlisted Y via data was dropped: the gap table is not accept-default")
	}
	// Drain retried-positive strays: the phase-1 retry may have left a
	// duplicate "mgmt" datagram in flight that would otherwise read back
	// here and fake a data-ingress arrival (flake).
	drainUDP10751(t, wSock)
	toWData := &net.UDPAddr{IP: net.ParseIP(wAddr), Port: 4000, Zone: "vpeer1"}
	if udpExchange10751(t, wSock, func() error {
		_, err := dataSender.WriteToUDP([]byte("probe"), toWData)
		return err
	}, time.Second) {
		t.Fatal("W via data ingress arrived: shared values are fail-open on data (day-2 hole)")
	}
	toX := &net.UDPAddr{IP: net.ParseIP(xAddr), Port: 4001, Zone: "vpeer1"}
	if udpExchange10751(t, xSock, func() error {
		_, err := dataSender.WriteToUDP([]byte("probe"), toX)
		return err
	}, time.Second) {
		t.Fatal("X via data ingress arrived: the gap bare DROP is not covering newcomers")
	}
}

// drainUDP10751 reads until a short quiet period proves no strays remain:
// a retried positive can leave a duplicate datagram in flight that would
// otherwise pollute a later negative on the same socket.
func drainUDP10751(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	buf := make([]byte, 1500)
	for i := 0; i < 10; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return
			}
			t.Fatalf("drain recv: %v", err)
		}
	}
}
