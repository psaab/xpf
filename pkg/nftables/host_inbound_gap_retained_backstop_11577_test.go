package nftables

import (
	"context"
	"net"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// TestHostInboundGapRetainedBackstop11577 proves the later-priority gap table
// denies uncovered and previously-unobserved DHCP addresses without overriding
// the retained table's service decisions, including retained RIP multicast.
// The v6-only gap leg also guards the retained v4 addresses on the same ordinary
// and VRF-enslaved interfaces.
func TestHostInboundGapRetainedBackstop11577(t *testing.T) {
	enterPrivateNetns(t)
	regularHost := mkNamedVeth10751(t, "ge-0-0-1", "vhost0", "vpeer0")
	vrfHost := mkNamedVeth10751(t, "ge-0-0-2", "vhost1", "vpeer1")
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue"}, Table: 1001}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Fatalf("create vrf-blue: %v", err)
	}
	vrfLink, err := netlink.LinkByName("vrf-blue")
	if err != nil {
		t.Fatalf("find vrf-blue: %v", err)
	}
	if err := netlink.LinkSetUp(vrfLink); err != nil {
		t.Fatalf("bring up vrf-blue: %v", err)
	}
	addL3mdevLookupRule11577(t, syscall.AF_INET)
	addL3mdevLookupRule11577(t, syscall.AF_INET6)
	if err := netlink.LinkSetMaster(vrfHost, vrfLink); err != nil {
		t.Fatalf("enslave VRF host interface: %v", err)
	}

	testNS, err := netns.Get()
	if err != nil {
		t.Fatalf("get test netns: %v", err)
	}
	peerNS, err := netns.New()
	if err != nil {
		testNS.Close()
		t.Fatalf("create peer netns: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(testNS)
		_ = peerNS.Close()
		_ = testNS.Close()
	})
	if err := netns.Set(testNS); err != nil {
		t.Fatalf("return to test netns: %v", err)
	}
	for _, name := range []string{"vpeer0", "vpeer1"} {
		peer, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("find peer interface %s: %v", name, err)
		}
		if err := netlink.LinkSetNsFd(peer, int(peerNS)); err != nil {
			t.Fatalf("move peer interface %s: %v", name, err)
		}
	}
	if err := netns.Set(peerNS); err != nil {
		t.Fatalf("enter peer netns: %v", err)
	}
	for _, peer := range []struct {
		name  string
		addrs []string
	}{
		{name: "vpeer0", addrs: []string{"192.0.2.1/24", "2001:db8:1::1/64"}},
		{name: "vpeer1", addrs: []string{"198.51.100.1/24", "2001:db8:2::1/64"}},
	} {
		link, err := netlink.LinkByName(peer.name)
		if err != nil {
			t.Fatalf("find moved peer %s: %v", peer.name, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatalf("bring up moved peer %s: %v", peer.name, err)
		}
		for _, addr := range peer.addrs {
			mustAddrAdd10751(t, link, addr)
		}
	}
	waitAddrsValid10751(t, map[string][]string{
		"vpeer0": {"2001:db8:1::1"},
		"vpeer1": {"2001:db8:2::1"},
	})
	if err := netns.Set(testNS); err != nil {
		t.Fatalf("return to test netns: %v", err)
	}

	regularV4 := []string{"192.0.2.2", "192.0.2.3", "192.0.2.4"}
	regularV6 := []string{"2001:db8:1::2", "2001:db8:1::3", "2001:db8:1::4"}
	vrfV4 := []string{"198.51.100.2", "198.51.100.3", "198.51.100.4"}
	vrfV6 := []string{"2001:db8:2::2", "2001:db8:2::3", "2001:db8:2::4"}
	for _, addr := range []string{
		"192.0.2.2/24", "192.0.2.3/24", "192.0.2.4/24",
		"2001:db8:1::2/64", "2001:db8:1::3/64", "2001:db8:1::4/64",
	} {
		mustAddrAdd10751(t, regularHost, addr)
	}
	for _, addr := range []string{
		"198.51.100.2/24", "198.51.100.3/24", "198.51.100.4/24",
		"2001:db8:2::2/64", "2001:db8:2::3/64", "2001:db8:2::4/64",
	} {
		mustAddrAdd10751(t, vrfHost, addr)
	}
	waitAddrsValid10751(t, map[string][]string{
		"ge-0-0-1": {"2001:db8:1::2", "2001:db8:1::3", "2001:db8:1::4"},
		"ge-0-0-2": {"2001:db8:2::2", "2001:db8:2::3", "2001:db8:2::4"},
	})

	type surface struct {
		name   string
		v4     []string
		v6     []string
		lateV4 string
		lateV6 string
		device string
		host   netlink.Link
		vrf    bool
	}
	surfaces := []surface{
		{name: "ordinary", v4: regularV4, v6: regularV6, lateV4: "192.0.2.5", lateV6: "2001:db8:1::5", device: "ge-0-0-1", host: regularHost},
		{name: "vrf", v4: vrfV4, v6: vrfV6, lateV4: "198.51.100.5", lateV6: "2001:db8:2::5", device: "ge-0-0-2", host: vrfHost, vrf: true},
	}
	var listeners []*net.TCPListener
	for _, surface := range surfaces {
		device := surface.device
		if surface.vrf {
			device = "vrf-blue"
		}
		for i, addr := range surface.v4 {
			for _, port := range []int{22, 23} {
				listeners = append(listeners, listenTCPOnDevice11577(t, "tcp4", addr, port, device))
			}
			listeners = append(listeners, listenTCPOnDevice11577(t, "tcp6", surface.v6[i], 22, device))
			listeners = append(listeners, listenTCPOnDevice11577(t, "tcp6", surface.v6[i], 23, device))
		}
	}
	t.Cleanup(func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	})
	regularIface, err := net.InterfaceByName("ge-0-0-1")
	if err != nil {
		t.Fatalf("find regular interface for RIP multicast: %v", err)
	}
	ripListener, err := net.ListenMulticastUDP("udp4", regularIface, &net.UDPAddr{
		IP: net.ParseIP("224.0.0.9"), Port: 520,
	})
	if err != nil {
		t.Fatalf("listen for RIP multicast: %v", err)
	}
	t.Cleanup(func() { _ = ripListener.Close() })
	probeRIPMulticast := func(phase string) {
		t.Helper()
		if err := sendRIPMulticastFromPeer11577(peerNS); err != nil {
			t.Fatalf("%s send RIP multicast: %v", phase, err)
		}
		if err := ripListener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("%s set RIP receive deadline: %v", phase, err)
		}
		if _, _, err := ripListener.ReadFromUDP(make([]byte, 64)); err != nil {
			t.Fatalf("%s RIP multicast was not delivered: %v", phase, err)
		}
	}

	probe := func(network, address string, port int, want bool, phase, surface string) {
		t.Helper()
		timeout := 300 * time.Millisecond
		if want {
			timeout = time.Second
		}
		fullAddress := net.JoinHostPort(address, strconv.Itoa(port))
		err := tcpDialFromNetns11577Network(peerNS, network, fullAddress, timeout)
		if (err == nil) != want {
			t.Fatalf("%s %s %s:%d reachability = %v, want allowed=%v", phase, surface, network, port, err, want)
		}
	}
	checkSurface := func(phase string, coveredSSH, coveredOther, uncovered, newcomer bool) {
		t.Helper()
		for _, surface := range surfaces {
			probe("tcp4", surface.v4[0], 22, coveredSSH, phase, surface.name)
			probe("tcp4", surface.v4[0], 23, coveredOther, phase, surface.name)
			probe("tcp4", surface.v4[1], 22, uncovered, phase, surface.name)
			probe("tcp4", surface.v4[2], 22, newcomer, phase, surface.name)
			probe("tcp6", surface.v6[0], 22, coveredSSH, phase, surface.name)
			probe("tcp6", surface.v6[0], 23, coveredOther, phase, surface.name)
			probe("tcp6", surface.v6[1], 22, uncovered, phase, surface.name)
			probe("tcp6", surface.v6[2], 22, newcomer, phase, surface.name)
		}
	}
	checkLateAddress := func(phase string, want bool) {
		t.Helper()
		for _, surface := range surfaces {
			probe("tcp4", surface.lateV4, 22, want, phase, surface.name)
			probe("tcp6", surface.lateV6, 22, want, phase, surface.name)
		}
	}

	installer := NewNetlinkInstaller()
	if err := installer.InstallHostInbound(HostInboundSpec{}); err != nil {
		t.Fatalf("install empty transport-control table: %v", err)
	}
	checkSurface("empty-table control", true, true, true, true)

	coveredV4 := []string{regularV4[0], vrfV4[0]}
	coveredV6 := []string{regularV6[0], vrfV6[0]}
	retained := HostInboundSpec{
		Views: []HostInboundZoneView{{
			Zone: "wan", SystemServices: []string{"ssh"}, Protocols: []string{"rip"},
			IngressNetdevs: []string{"ge-0-0-1"},
			V4Addrs:        coveredV4, V6Addrs: coveredV6,
		}},
	}
	if err := installer.InstallHostInbound(retained); err != nil {
		t.Fatalf("install retained host-inbound policy: %v", err)
	}
	checkSurface("retained-table control", true, false, true, true)
	probeRIPMulticast("retained-table")

	gap := GapFenceSpec{
		UncoveredV4: []string{regularV4[1], vrfV4[1]},
		UncoveredV6: []string{regularV6[1], vrfV6[1]},
		UnleasedV4:  []string{"ge-0-0-1"}, UnleasedV6: []string{"ge-0-0-1"},
		UnleasedVRFSlavesV4: []string{"ge-0-0-2"}, UnleasedVRFSlavesV6: []string{"ge-0-0-2"},
		RetainedV4: coveredV4, RetainedV6: coveredV6,
	}
	if err := installer.InstallGapFence(gap); err != nil {
		t.Fatalf("install retained-address-scoped gap fence: %v", err)
	}
	checkSurface("dual-stack gap", true, false, false, false)
	probeRIPMulticast("dual-stack gap")

	// These lease addresses appear only after the gap table is active; the
	// interface backstop must also catch destinations absent from its snapshot.
	lateV6 := map[string][]string{}
	for _, surface := range surfaces {
		mustAddrAdd10751(t, surface.host, surface.lateV4+"/24")
		mustAddrAdd10751(t, surface.host, surface.lateV6+"/64")
		lateV6[surface.device] = []string{surface.lateV6}
	}
	waitAddrsValid10751(t, lateV6)
	for _, surface := range surfaces {
		device := surface.device
		if surface.vrf {
			device = "vrf-blue"
		}
		listeners = append(listeners,
			listenTCPOnDevice11577(t, "tcp4", surface.lateV4, 22, device),
			listenTCPOnDevice11577(t, "tcp6", surface.lateV6, 22, device),
		)
	}
	checkLateAddress("dual-stack post-install newcomer", false)

	if err := installer.DeleteTable(HostInboundGapTableName); err != nil {
		t.Fatalf("remove gap table for newcomer control: %v", err)
	}
	checkLateAddress("newcomer without gap", true)
	if err := installer.InstallGapFence(gap); err != nil {
		t.Fatalf("reinstall retained-address-scoped gap fence: %v", err)
	}
	checkLateAddress("reinstalled gap newcomer", false)

	gap.UncoveredV4 = nil
	if err := installer.InstallGapFence(gap); err != nil {
		t.Fatalf("install IPv6-only gap fence: %v", err)
	}
	checkSurface("IPv6-only gap", true, false, false, false)
	probeRIPMulticast("IPv6-only gap")
}

func listenTCPOnDevice11577(t *testing.T, network, address string, port int, device string) *net.TCPListener {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	listener, err := config.Listen(context.Background(), network, net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("listen on %s %s:%d bound to %s: %v", network, address, port, device, err)
	}
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		listener.Close()
		t.Fatalf("listener for %s %s:%d is %T, want *net.TCPListener", network, address, port, listener)
	}
	return tcpListener
}

func sendRIPMulticastFromPeer11577(ns netns.NsHandle) (result error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		return err
	}
	defer original.Close()
	if err := netns.Set(ns); err != nil {
		return err
	}
	defer func() {
		if err := netns.Set(original); err != nil && result == nil {
			result = err
		}
	}()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	if err != nil {
		return err
	}
	defer conn.Close()
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err := rawConn.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "vpeer0")
		if optionErr != nil {
			return
		}
		optionErr = unix.SetsockoptInet4Addr(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_IF, [4]byte{192, 0, 2, 1})
		if optionErr != nil {
			return
		}
		optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, 1)
	}); err != nil {
		return err
	}
	if optionErr != nil {
		return optionErr
	}
	_, err = conn.WriteToUDP([]byte("rip"), &net.UDPAddr{IP: net.ParseIP("224.0.0.9"), Port: 520})
	return err
}
