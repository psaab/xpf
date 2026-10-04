package nftables

import (
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// TestZonedDHCPLeaseAppearanceWindow11577 probes a benign TCP/22 connection
// to a DHCP address through a real veth in a private netns. The pre-lease
// enforcing-zone rules are installed first, then the local address appears;
// SSH must remain denied throughout the full two-second debounce interval and
// become admitted only after the address-scoped zone policy is atomically
// installed. FAIL-ON-REVERT: removing the persistent interface backstop lets
// the TCP handshake complete before the delayed address-scoped drop is loaded.
func TestZonedDHCPLeaseAppearanceWindow11577(t *testing.T) {
	enterPrivateNetns(t)
	mkUnleasedVeth10751(t)
	testLink, err := netlink.LinkByName(unleasedTestNetdev10751)
	if err != nil {
		t.Fatalf("LinkByName test interface: %v", err)
	}
	peerLink, err := netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("LinkByName peer: %v", err)
	}

	testNS, err := netns.Get()
	if err != nil {
		t.Fatalf("get test netns: %v", err)
	}
	peerNS, err := netns.New()
	if err != nil {
		testNS.Close()
		t.Fatalf("create probe netns: %v", err)
	}
	if err := netns.Set(testNS); err != nil {
		peerNS.Close()
		testNS.Close()
		t.Fatalf("restore test netns: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(testNS)
		peerNS.Close()
		testNS.Close()
	})
	if err := netlink.LinkSetNsFd(peerLink, int(peerNS)); err != nil {
		t.Fatalf("move probe veth into isolated peer netns: %v", err)
	}
	if err := netns.Set(peerNS); err != nil {
		t.Fatalf("enter isolated peer netns: %v", err)
	}
	peerLink, err = netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("find moved probe veth: %v", err)
	}
	mustAddrAdd10751(t, peerLink, "192.0.2.1/24")
	if err := netlink.LinkSetUp(peerLink); err != nil {
		t.Fatalf("bring up probe veth: %v", err)
	}
	if err := netns.Set(testNS); err != nil {
		t.Fatalf("return to test netns: %v", err)
	}

	installer := NewNetlinkInstaller()
	preLease := HostInboundSpec{
		Views:      []HostInboundZoneView{{Zone: "wan", SystemServices: []string{"ssh"}}},
		UnleasedV4: []string{unleasedTestNetdev10751},
	}
	if err := installer.InstallHostInbound(preLease); err != nil {
		t.Fatalf("install addressless zone backstop: %v", err)
	}

	// DHCP applies the address before its debounced address-change callback.
	mustAddrAdd10751(t, testLink, "192.0.2.2/24")
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 22})
	if err != nil {
		t.Fatalf("listen on leased host address: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.AcceptTCP()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	appearance := time.Now()
	for time.Since(appearance) < 2*time.Second {
		dialErr := tcpDialFromNetns11577(peerNS, "192.0.2.2:22", 120*time.Millisecond)
		if dialErr == nil {
			t.Fatalf("SSH TCP probe was admitted %s after DHCP address appearance, before policy reapply", time.Since(appearance))
		}
		if opErr, ok := dialErr.(*net.OpError); ok && !opErr.Timeout() {
			t.Fatalf("SSH TCP probe failed for a reason other than the enforcing drop: %v", dialErr)
		}
		time.Sleep(80 * time.Millisecond)
	}

	transitionStart := time.Now()
	postLease := HostInboundSpec{
		Views: []HostInboundZoneView{{
			Zone: "wan", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.2"},
		}},
		UnleasedV4: []string{unleasedTestNetdev10751},
	}
	if err := installer.InstallHostInbound(postLease); err != nil {
		t.Fatalf("install address-scoped policy after lease: %v", err)
	}
	publishedAfter := time.Since(appearance)
	dialErr := tcpDialFromNetns11577(peerNS, "192.0.2.2:22", time.Second)
	if dialErr != nil {
		t.Fatalf("SSH TCP probe remained denied after address-scoped policy apply (window %s, apply %s): %v", publishedAfter, time.Since(transitionStart), dialErr)
	}
	t.Logf("lease-transition probe: SSH denied for %s from address appearance through atomic policy apply; admitted after apply", publishedAfter)
}

// TestZonedDHCPBareMemberVLANVRFLeaseWindow11577 exercises a DHCP VLAN child
// selected from a bare RI member. The same pre-lease backstop must protect it
// before and after the real kernel VRF enslaving; once the new v4/v6 addresses
// are installed, the address-scoped SSH policy replaces the guard.
func TestZonedDHCPBareMemberVLANVRFLeaseWindow11577(t *testing.T) {
	enterPrivateNetns(t)
	hostParent := mkNamedVeth10751(t, "ge-0-0-1", "vhost0", "vpeer0")
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
	addL3mdevLookupRule11577(t, unix.AF_INET)
	addL3mdevLookupRule11577(t, unix.AF_INET6)
	hostVLAN := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-1.200", ParentIndex: hostParent.Attrs().Index},
		VlanId:    200,
	}
	if err := netlink.LinkAdd(hostVLAN); err != nil {
		t.Fatalf("create host VLAN child: %v", err)
	}
	hostVLANLink, err := netlink.LinkByName("ge-0-0-1.200")
	if err != nil {
		t.Fatalf("find host VLAN child: %v", err)
	}
	if err := netlink.LinkSetUp(hostVLANLink); err != nil {
		t.Fatalf("bring up host VLAN child: %v", err)
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
	peerParent, err := netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("find peer veth: %v", err)
	}
	if err := netlink.LinkSetNsFd(peerParent, int(peerNS)); err != nil {
		t.Fatalf("move peer veth: %v", err)
	}
	if err := netns.Set(peerNS); err != nil {
		t.Fatalf("enter peer netns: %v", err)
	}
	peerParent, err = netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("find moved peer veth: %v", err)
	}
	if err := netlink.LinkSetUp(peerParent); err != nil {
		t.Fatalf("bring up peer veth: %v", err)
	}
	peerVLAN := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Name: "vpeer0.200", ParentIndex: peerParent.Attrs().Index},
		VlanId:    200,
	}
	if err := netlink.LinkAdd(peerVLAN); err != nil {
		t.Fatalf("create peer VLAN child: %v", err)
	}
	peerVLANLink, err := netlink.LinkByName("vpeer0.200")
	if err != nil {
		t.Fatalf("find peer VLAN child: %v", err)
	}
	mustAddrAdd10751(t, peerVLANLink, "192.0.2.1/24")
	mustAddrAdd10751(t, peerVLANLink, "2001:db8:1::1/64")
	if err := netlink.LinkSetUp(peerVLANLink); err != nil {
		t.Fatalf("bring up peer VLAN child: %v", err)
	}
	waitAddrsValid10751(t, map[string][]string{"vpeer0.200": {"2001:db8:1::1"}})
	if err := netns.Set(testNS); err != nil {
		t.Fatalf("return to test netns: %v", err)
	}

	child := []string{"ge-0-0-1.200"}
	preLease := HostInboundSpec{
		UnleasedV4: child, UnleasedV6: child,
		UnleasedVRFSlavesV4: child, UnleasedVRFSlavesV6: child,
	}
	mustAddrAdd10751(t, hostVLANLink, "192.0.2.2/24")
	mustAddrAdd10751(t, hostVLANLink, "2001:db8:1::2/64")
	waitAddrsValid10751(t, map[string][]string{"ge-0-0-1.200": {"2001:db8:1::2"}})

	probes := []struct {
		network string
		address string
	}{
		{network: "tcp4", address: "192.0.2.2:22"},
		{network: "tcp6", address: "[2001:db8:1::2]:22"},
	}
	assertReachability := func(want bool) {
		t.Helper()
		for _, probe := range probes {
			err := tcpDialFromNetns11577Network(peerNS, probe.network, probe.address, 500*time.Millisecond)
			if (err == nil) != want {
				t.Fatalf("%s %s reachability = %v, want allowed=%v", probe.network, probe.address, err, want)
			}
		}
	}
	listeners := func(device string) []*net.TCPListener {
		t.Helper()
		v4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 22})
		if err != nil {
			t.Fatalf("listen on leased v4 address: %v", err)
		}
		v6, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("2001:db8:1::2"), Port: 22})
		if err != nil {
			v4.Close()
			t.Fatalf("listen on leased v6 address: %v", err)
		}
		bindTCPListenerToDevice11577(t, v4, device)
		bindTCPListenerToDevice11577(t, v6, device)
		return []*net.TCPListener{v4, v6}
	}
	vrfListeners := func() []*net.TCPListener {
		t.Helper()
		v4, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 22})
		if err != nil {
			t.Fatalf("listen on VRF v4 address: %v", err)
		}
		v6, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::"), Port: 22})
		if err != nil {
			v4.Close()
			t.Fatalf("listen on VRF v6 address: %v", err)
		}
		bindTCPListenerToDevice11577(t, v4, "vrf-blue")
		bindTCPListenerToDevice11577(t, v6, "vrf-blue")
		return []*net.TCPListener{v4, v6}
	}
	closeListeners := func(open []*net.TCPListener) {
		for _, listener := range open {
			_ = listener.Close()
		}
	}

	installer := NewNetlinkInstaller()
	if err := installer.InstallHostInbound(HostInboundSpec{}); err != nil {
		t.Fatalf("install empty transport-control table: %v", err)
	}
	open := listeners("ge-0-0-1.200")
	assertReachability(true)
	if err := installer.InstallHostInbound(preLease); err != nil {
		t.Fatalf("install pre-lease VLAN backstop: %v", err)
	}
	assertReachability(false)

	// A new DHCP address appears after the backstop install, then the VLAN child
	// is moved under the VRF. Both observations must remain guarded.
	mustAddrAdd10751(t, hostVLANLink, "192.0.2.3/24")
	mustAddrAdd10751(t, hostVLANLink, "2001:db8:1::3/64")
	waitAddrsValid10751(t, map[string][]string{"ge-0-0-1.200": {"2001:db8:1::2", "2001:db8:1::3"}})
	probes = append(probes,
		struct {
			network string
			address string
		}{network: "tcp4", address: "192.0.2.3:22"},
		struct {
			network string
			address string
		}{network: "tcp6", address: "[2001:db8:1::3]:22"},
	)
	listenerV4New, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("192.0.2.3"), Port: 22})
	if err != nil {
		t.Fatalf("listen on new v4 lease address: %v", err)
	}
	listenerV6New, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("2001:db8:1::3"), Port: 22})
	if err != nil {
		listenerV4New.Close()
		t.Fatalf("listen on new v6 lease address: %v", err)
	}
	bindTCPListenerToDevice11577(t, listenerV4New, "ge-0-0-1.200")
	bindTCPListenerToDevice11577(t, listenerV6New, "ge-0-0-1.200")
	open = append(open, listenerV4New, listenerV6New)
	assertReachability(false)

	if err := netlink.LinkSetMaster(hostVLANLink, vrfLink); err != nil {
		t.Fatalf("enslave VLAN child to vrf-blue: %v", err)
	}
	mustAddrAdd10751(t, hostVLANLink, "2001:db8:1::2/64")
	mustAddrAdd10751(t, hostVLANLink, "2001:db8:1::3/64")
	waitAddrsValid10751(t, map[string][]string{"ge-0-0-1.200": {"2001:db8:1::2", "2001:db8:1::3"}})
	closeListeners(open)
	open = vrfListeners()

	if err := installer.InstallHostInbound(HostInboundSpec{}); err != nil {
		t.Fatalf("install enslaved transport-control table: %v", err)
	}
	assertReachability(true)
	if err := installer.InstallHostInbound(preLease); err != nil {
		t.Fatalf("reinstall pre-lease VRF backstop: %v", err)
	}
	assertReachability(false)

	postLease := HostInboundSpec{
		Views: []HostInboundZoneView{{
			Zone: "wan", SystemServices: []string{"ssh"},
			V4Addrs: []string{"192.0.2.2", "192.0.2.3"},
			V6Addrs: []string{"2001:db8:1::2", "2001:db8:1::3"},
		}},
		UnleasedV4: child, UnleasedV6: child,
		UnleasedVRFSlavesV4: child, UnleasedVRFSlavesV6: child,
	}
	if err := installer.InstallHostInbound(postLease); err != nil {
		t.Fatalf("install address-scoped lease policy: %v", err)
	}
	assertReachability(true)
	closeListeners(open)

}

func tcpDialFromNetns11577Network(ns netns.NsHandle, network, address string, timeout time.Duration) error {
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	if err := netns.Set(ns); err != nil {
		original.Close()
		runtime.UnlockOSThread()
		return err
	}
	conn, dialErr := net.DialTimeout(network, address, timeout)
	if conn != nil {
		_ = conn.Close()
	}
	restoreErr := netns.Set(original)
	original.Close()
	runtime.UnlockOSThread()
	if restoreErr != nil {
		return restoreErr
	}
	return dialErr
}

func tcpDialFromNetns11577(ns netns.NsHandle, address string, timeout time.Duration) error {
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	if err := netns.Set(ns); err != nil {
		original.Close()
		runtime.UnlockOSThread()
		return err
	}
	conn, dialErr := net.DialTimeout("tcp4", address, timeout)
	if conn != nil {
		_ = conn.Close()
	}
	restoreErr := netns.Set(original)
	original.Close()
	runtime.UnlockOSThread()
	if restoreErr != nil {
		return restoreErr
	}
	return dialErr
}
func bindTCPListenerToDevice11577(t *testing.T, listener *net.TCPListener, device string) {
	t.Helper()
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatalf("get listener fd: %v", err)
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
	}); err != nil {
		t.Fatalf("control listener fd: %v", err)
	}
	if opErr != nil {
		t.Fatalf("bind listener to %s: %v", device, opErr)
	}
}

// Direct netlink VRF creation does not install the l3mdev lookup rules that
// iproute2 normally adds. Mirror those rules so this test exercises the same
// VRF routing behavior as the daemon's host.
func addL3mdevLookupRule11577(t *testing.T, family int) {
	t.Helper()
	req := nl.NewNetlinkRequest(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	msg := nl.NewRtMsg()
	msg.Family = uint8(family)
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Table = unix.RT_TABLE_UNSPEC
	msg.Type = nl.FR_ACT_TO_TBL
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(1000)))
	req.AddData(nl.NewRtAttr(nl.FRA_L3MDEV, nl.Uint8Attr(1)))
	if _, err := req.Execute(unix.NETLINK_ROUTE, 0); err != nil {
		t.Fatalf("install l3mdev lookup rule for family %d: %v", family, err)
	}
}
