package nftables

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// input_barrier_lifeline_15286_test.go proves #15286 over REAL packets in a
// private netns: with the lifeline fxp0 and a declared zoned NON-lifeline
// fxp1 co-enslaved in vrf-mgmt, the lifeline-admitting early input barrier
// must admit host ingress via fxp0 (meta sdifname recovers the member behind
// the LOCAL_IN master) and must DENY the same host destination via fxp1.
// The pre-fix barrier admitted `iifname "vrf-mgmt"`, which matched BOTH
// members (their LOCAL_IN iifname is the master), so the fxp1 leg arrived.
//
// RED on the pre-fix shape: emit the pre-fix pair (an iifname rule naming
// the master plus the member iifname rule, no sdifname rule) instead of the
// fixed emitter and the fxp1 negative below arrives. The fix removes the
// master from the resolver set and adds the sdifname companion.
//
// Transport mirrors TestGapExceptionDiscriminatesVRFMembers10751:
// link-local unicast, VRF-bound listeners (unbound sockets cannot receive
// enslaved ingress), numeric scope ids (never Go Zones), and an in-fixture
// no-filter delivery control for the exact fxp1 packet so a negative is a
// filter verdict, not a route-lookup false negative.

func TestEarlyInputBarrierDiscriminatesVRFMembers15286(t *testing.T) {
	enterPrivateNetns(t)
	const (
		wAddr  = "fe80::5" // host destination assigned on fxp0 AND fxp1
		y2Addr = "fe80::7" // fxp1-only unlisted destination (transport control)
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
	if err := netlink.LinkSetMaster(fxp0, master); err != nil {
		t.Fatalf("enslave fxp0: %v", err)
	}
	if err := netlink.LinkSetMaster(fxp1, master); err != nil {
		t.Fatalf("enslave fxp1: %v", err)
	}
	// W on fxp1 purely for L3 deliverability (VRF slaves deliver only
	// locally-assigned destinations); lifeline status comes from the NAME.
	mustAddrAdd10751(t, fxp0, wAddr+"/64")
	mustAddrAdd10751(t, fxp1, wAddr+"/64")
	mustAddrAdd10751(t, fxp1, y2Addr+"/64")
	waitAddrsValid10751(t, map[string][]string{"fxp0": {wAddr}, "fxp1": {wAddr, y2Addr}})

	vrfSock, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 4000})
	if err != nil {
		t.Fatalf("listen [::]:4000: %v", err)
	}
	defer vrfSock.Close()
	bindSockToDevice10751(t, vrfSock, "vrf-mgmt")

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

	oifLife := linkIndex10751(t, "vpeer0")
	oifFxp1 := linkIndex10751(t, "vpeer1")
	wIP := net.ParseIP(wAddr)

	// No-filter delivery control: the exact W-via-fxp1 packet MUST arrive
	// unfiltered, or the negative below proves nothing.
	if !udpExchangeRetryWant10751(t, vrfSock, func() error {
		return sendToScope10751(t, fxp1Sender, []byte("pre-w"), wIP, 4000, oifFxp1)
	}, []byte("pre-w"), 300*time.Millisecond, 10*time.Second) {
		dumpNetState10751(t)
		t.Fatal("W via fxp1 was dropped with NO filter installed: fxp1/W delivery broken (infra, not verdict)")
	}

	in := NewNetlinkInstaller()
	// The resolver output for the default identity with a zoned fxp1
	// co-enslaved: lifeline members only, never the master (#15286).
	if err := in.InstallEarlyInputBarrierWithLifelineAdmit([]string{"em0", "fab0", "fab1", "fxp0"}); err != nil {
		t.Fatalf("barrier lifeline install: %v", err)
	}

	// Lifeline leg: W via enslaved fxp0 must arrive (sdifname exception).
	if !udpExchangeRetryWant10751(t, vrfSock, func() error {
		return sendToScope10751(t, lifeSender, []byte("mgmt"), wIP, 4000, oifLife)
	}, []byte("mgmt"), 300*time.Millisecond, 10*time.Second) {
		dumpNetState10751(t)
		t.Fatal("W via enslaved lifeline fxp0 was dropped: the sdifname lifeline admit is missing or shadowed (management lockout)")
	}
	// Transport control: unlisted Y2 via fxp1 is NOT a barrier admit either,
	// but the barrier chain is ACCEPT-by-exception only for lifelines — Y2
	// must fall to the DROP policy like any non-lifeline destination, so it
	// must NOT arrive. Its pre-install sibling W proved fxp1 transport; the
	// W negative below is therefore a verdict, and this leg additionally
	// pins that no fxp1 destination slips through on another address.
	y2IP := net.ParseIP(y2Addr)
	if udpExchangeWant10751(t, vrfSock, func() error {
		return sendToScope10751(t, fxp1Sender, []byte("y2"), y2IP, 4000, oifFxp1)
	}, []byte("y2"), time.Second) {
		t.Fatal("Y2 via non-lifeline fxp1 arrived: the barrier admits fxp1 destinations beyond the lifeline scope")
	}
	// The #15286 negative: W via non-lifeline fxp1 must NOT arrive. The
	// pre-filter control proved this exact packet reaches LOCAL_IN
	// unfiltered, and the iifname it presents there is the vrf-mgmt master
	// — only the removed master blanket could have accepted it pre-fix.
	if udpExchangeWant10751(t, vrfSock, func() error {
		return sendToScope10751(t, fxp1Sender, []byte("probe-fxp1"), wIP, 4000, oifFxp1)
	}, []byte("probe-fxp1"), time.Second) {
		t.Fatal("W via zoned non-lifeline fxp1 arrived: the barrier blanket-admits the vrf-mgmt master (#15286)")
	}
}
