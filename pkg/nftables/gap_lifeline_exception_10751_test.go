package nftables

import (
	"net"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
	waitAddrsValid10751(t, map[string][]string{wNetdev: {wAddr}, unleasedTestNetdev10751: {wAddr, xAddr, yAddr}})

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
	bindSockToDevice10751(t, lifeSender, "vpeer0")
	dataSender, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("data sender bind: %v", err)
	}
	defer dataSender.Close()
	bindSockToDevice10751(t, dataSender, "vpeer1")

	// Egress is pinned by numeric scope id (resolved fresh via netlink),
	// never Go Zones: the process-global Zone cache goes stale across
	// netns recreations (same veth names, new ifindices) and flaps
	// sends. Numeric scope also bypasses the local-table short-circuit.
	oifLife := linkIndex10751(t, "vpeer0")
	oifData := linkIndex10751(t, "vpeer1")
	wIP, xIP, yIP := net.ParseIP(wAddr), net.ParseIP(xAddr), net.ParseIP(yAddr)
	if !udpExchangeRetryWant10751(t, wSock, func() error {
		return sendToScope10751(t, lifeSender, []byte("mgmt"), wIP, 4000, oifLife)
	}, []byte("mgmt"), 300*time.Millisecond, 10*time.Second) {
		t.Fatal("W via lifeline ingress was dropped: the gap exception is missing or shadowed (management lockout)")
	}
	if !udpExchangeRetryWant10751(t, ySock, func() error {
		return sendToScope10751(t, dataSender, []byte("other"), yIP, 4002, oifData)
	}, []byte("other"), 300*time.Millisecond, 10*time.Second) {
		t.Fatal("unlisted Y via data was dropped: the gap table is not accept-default")
	}
	if udpExchangeWant10751(t, wSock, func() error {
		return sendToScope10751(t, dataSender, []byte("probe-data"), wIP, 4000, oifData)
	}, []byte("probe-data"), time.Second) {
		t.Fatal("W via data ingress arrived: shared values are fail-open on data (day-2 hole)")
	}
	if udpExchange10751(t, xSock, func() error {
		return sendToScope10751(t, dataSender, []byte("probe"), xIP, 4001, oifData)
	}, time.Second) {
		t.Fatal("X via data ingress arrived: the gap bare DROP is not covering newcomers")
	}
}

// TestGapExceptionDiscriminatesVRFMembers10751 is Opus9's exact shape
// with a REAL VRF: fxp0 (true lifeline) and fxp1 (non-lifeline) enslaved
// in vrf-mgmt, W shared across fxp0, fxp1, and a data interface (fxp1
// carries W purely for L3 deliverability — VRF slaves deliver only
// locally-assigned destinations — while lifeline status comes from the
// interface NAME), X data-only. The gap (Uncovered {W,X}, Shared {W},
// lifelines {em0,fxp0} — NO vrf-mgmt blanket) must admit W via fxp0
// (sdifname recovers the slave where iifname shows the master), deny W
// via fxp1, deny W via data, and deny X. Listeners: vrf-bound for
// enslaved ingress (unbound sockets cannot receive it — VRF socket
// isolation), unbound for data ingress. Two delivery controls pin the
// W-fxp1 negative: the exact W-via-fxp1 packet first WITHOUT any filter
// (in-fixture control — must arrive), plus unlisted Y2 via fxp1 after
// the install (transport control — must arrive).
func TestGapExceptionDiscriminatesVRFMembers10751(t *testing.T) {
	enterPrivateNetns(t)
	const (
		wAddr  = "fe80::5" // W: fxp0+data shared
		xAddr  = "fe80::9" // X: data-only newcomer
		y2Addr = "fe80::7" // Y2: fxp1-only unlisted (delivery control)
	)
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-mgmt"}, Table: 1000}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Fatalf("VRF add: %v", err)
	}
	master, err := netlink.LinkByName("vrf-mgmt")
	if err != nil {
		t.Fatalf("LinkByName vrf-mgmt: %v", err)
	}
	if err := netlink.LinkSetUp(master); err != nil {
		t.Fatalf("LinkSetUp vrf-mgmt: %v", err)
	}
	fxp0 := mkNamedVeth10751(t, "fxp0", "vunlease0", "vpeer0")
	fxp1 := mkNamedVeth10751(t, "fxp1", "vunlease1", "vpeer1")
	dataLink := mkNamedVeth10751(t, unleasedTestNetdev10751, "vunlease2", "vpeer2")
	if err := netlink.LinkSetMaster(fxp0, master); err != nil {
		t.Fatalf("enslave fxp0: %v", err)
	}
	if err := netlink.LinkSetMaster(fxp1, master); err != nil {
		t.Fatalf("enslave fxp1: %v", err)
	}
	mustAddrAdd10751(t, fxp0, wAddr+"/64")
	// W is also assigned to fxp1 PURELY for L3 deliverability: VRF
	// slaves deliver only locally-assigned destinations (no weak-host
	// here — verified: static ND plus off-link W timed out without any
	// firewall). Lifeline status comes from the interface NAME (fxp1 is
	// non-lifeline), and the verdict keys on ingress plus daddr VALUE,
	// so the exception still must deny it.
	mustAddrAdd10751(t, fxp1, wAddr+"/64")
	mustAddrAdd10751(t, fxp1, y2Addr+"/64")
	mustAddrAdd10751(t, dataLink, wAddr+"/64")
	mustAddrAdd10751(t, dataLink, xAddr+"/64")
	waitAddrsValid10751(t, map[string][]string{"fxp0": {wAddr}, "fxp1": {wAddr, y2Addr}, unleasedTestNetdev10751: {wAddr, xAddr}})

	vrfSock, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 4000})
	if err != nil {
		t.Fatalf("listen [::]:4000: %v", err)
	}
	defer vrfSock.Close()
	bindSockToDevice10751(t, vrfSock, "vrf-mgmt")
	dataSock, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 4001})
	if err != nil {
		t.Fatalf("listen [::]:4001: %v", err)
	}
	defer dataSock.Close()
	lifeSender, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("lifeline sender bind: %v", err)
	}
	defer lifeSender.Close()
	bindSockToDevice10751(t, lifeSender, "vpeer0")
	fxp1Sender, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("fxp1 sender bind: %v", err)
	}
	defer fxp1Sender.Close()
	bindSockToDevice10751(t, fxp1Sender, "vpeer1")
	dataSender, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("data sender bind: %v", err)
	}
	defer dataSender.Close()
	bindSockToDevice10751(t, dataSender, "vpeer2")
	// Numeric scope ids (never Go Zones: the process-global Zone cache
	// goes stale across netns recreations).
	oifLife := linkIndex10751(t, "vpeer0")
	oifFxp1 := linkIndex10751(t, "vpeer1")
	oifData := linkIndex10751(t, "vpeer2")
	wIP, xIP := net.ParseIP(wAddr), net.ParseIP(xAddr)
	// IN-FIXTURE DELIVERY CONTROL (Opus10 M1): the exact W-via-fxp1
	// packet with NO filter installed (fresh netns: no tables, policy
	// accept) MUST reach the VRF-bound listener. This rules out the
	// false-negative reading where strict VRF route lookup drops W on
	// fxp1 regardless of the filter — Y2 alone cannot, since it proves
	// fxp1 transport for a DIFFERENT address. Doubles as the vpeer1
	// source-readiness wait. Distinct payload: strays are ignored by
	// the content-checked exchanges below.
	if !udpExchangeRetryWant10751(t, vrfSock, func() error {
		return sendToScope10751(t, fxp1Sender, []byte("pre-w"), wIP, 4000, oifFxp1)
	}, []byte("pre-w"), 300*time.Millisecond, 10*time.Second) {
		dumpNetState10751(t)
		t.Fatal("W via fxp1 was dropped with NO filter installed: fxp1/W delivery broken (infra, not verdict)")
	}
	in := NewNetlinkInstaller()
	spec := GapFenceSpec{
		UncoveredV6:     []string{wAddr, xAddr},
		SharedV6:        []string{wAddr},
		LifelineNetdevs: []string{"em0", "fxp0"},
	}
	if err := in.InstallGapFence(spec); err != nil {
		t.Fatalf("gap install: %v", err)
	}
	if !udpExchangeRetryWant10751(t, vrfSock, func() error {
		return sendToScope10751(t, lifeSender, []byte("mgmt"), wIP, 4000, oifLife)
	}, []byte("mgmt"), 300*time.Millisecond, 10*time.Second) {
		dumpNetState10751(t)
		t.Fatal("W via enslaved fxp0 was dropped: the sdifname exception is missing or shadowed (management lockout)")
	}
	// Transport control for fxp1's link, kept alongside the pre-filter
	// exact-packet control above: unlisted Y2 must STILL arrive after
	// the install (policy accept), proving the gap did not break fxp1
	// transport generally.
	y2IP := net.ParseIP(y2Addr)
	if !udpExchangeRetryWant10751(t, vrfSock, func() error {
		return sendToScope10751(t, fxp1Sender, []byte("y2"), y2IP, 4000, oifFxp1)
	}, []byte("y2"), 300*time.Millisecond, 10*time.Second) {
		t.Fatal("Y2 via fxp1 link was dropped: fxp1-link delivery broken (infra, not verdict)")
	}
	// The discrimination negative: W-via-fxp1 must NOT arrive now. The
	// pre-filter control above proved this exact packet reaches LOCAL_IN
	// unfiltered, so a timeout here is the gap's DROP verdict — not a
	// route-lookup false negative.
	if udpExchangeWant10751(t, vrfSock, func() error {
		return sendToScope10751(t, fxp1Sender, []byte("probe-fxp1"), wIP, 4000, oifFxp1)
	}, []byte("probe-fxp1"), time.Second) {
		t.Fatal("W via non-lifeline fxp1 member arrived: the exception over-admits the management VRF")
	}
	sendUntilReady10751(t, func() error {
		return sendToScope10751(t, dataSender, []byte("warmup"), wIP, 4001, oifData)
	})
	if udpExchange10751(t, dataSock, func() error {
		return sendToScope10751(t, dataSender, []byte("probe"), wIP, 4001, oifData)
	}, time.Second) {
		t.Fatal("W via data ingress arrived: shared values are fail-open on data (day-2 hole)")
	}
	if udpExchange10751(t, dataSock, func() error {
		return sendToScope10751(t, dataSender, []byte("probe"), xIP, 4001, oifData)
	}, time.Second) {
		t.Fatal("X via data ingress arrived: the gap bare DROP is not covering newcomers")
	}
}

// bindSockToDevice10751 pins a socket to an ingress/egress device.
// Required on listeners for VRF-enslaved ingress: unbound sockets live
// in the default VRF and cannot receive it (kernel VRF socket
// isolation). Senders bind redundantly alongside Zones (belt and braces
// against Zone-handling flakes under load).
func bindSockToDevice10751(t *testing.T, conn *net.UDPConn, ifname string) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifname)
	}); err != nil {
		t.Fatalf("SyscallConn.Control: %v", err)
	}
	if opErr != nil {
		t.Fatalf("SO_BINDTODEVICE %s: %v", ifname, opErr)
	}
}

// waitAddrsValid10751 blocks until every listed address is assigned and
// past DAD (not tentative), so later verdicts observe firewall behavior
// rather than address-configuration races. Fatal on exhaustion (honest
// infra failure, never a silent vacuous pass).
func waitAddrsValid10751(t *testing.T, want map[string][]string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		missing := false
		for ifname, addrs := range want {
			link, err := netlink.LinkByName(ifname)
			if err != nil {
				t.Fatalf("LinkByName %s: %v", ifname, err)
			}
			got, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err != nil {
				t.Fatalf("AddrList %s: %v", ifname, err)
			}
			for _, wantAddr := range addrs {
				ok := false
				for _, a := range got {
					if a.IPNet != nil && a.IPNet.IP.String() == wantAddr && a.Flags&unix.IFA_F_TENTATIVE == 0 {
						ok = true
						break
					}
				}
				if !ok {
					missing = true
				}
			}
		}
		if !missing {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("addresses never became valid: %v", want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// sendUntilReady10751 repeats a throwaway send until the source path is
// usable (peer DAD complete), so a following single-shot verdict never
// FATALS on send errors. The throwaways carry a "warmup" payload the
// content-checked asserts discard; on negative legs they are dropped
// like any other probe.
func sendUntilReady10751(t *testing.T, send func() error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := send(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("source path never became usable")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// dumpNetState10751 is TEMPORARY flake diagnostics (remove after).
func dumpNetState10751(t *testing.T) {
	t.Helper()
	for _, args := range [][]string{
		{"link"},
		{"-6", "addr", "show"},
		{"-6", "route", "show", "table", "main"},
		{"-6", "route", "show", "table", "1000"},
		{"-6", "rule", "show"},
		{"-6", "neigh", "show"},
	} {
		out, _ := exec.Command("/sbin/ip", args...).CombinedOutput()
		t.Logf("ip %v:\n%s", args, out)
	}
}
