package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	dhcpVRFInterface12127 = "fxp1"
	dhcpVRFMaster12127    = "vrf-mgmt"
	dhcpVRFHostLL12127    = "fe80::1212:2"
	dhcpVRFPeerLL12127    = "fe80::1212:1"
)

// TestHostInboundDHCPManagementVRFDelivery12127 drives the production daemon
// builder and netlink installer, then sends packets to addresses newer than the
// sampled snapshot, including an omitted IPv6 link-local destination. The
// main-table path carries the VRF-slave scopes through sdifname; iifname alone
// sees only vrf-mgmt at LOCAL_IN.
func TestHostInboundDHCPManagementVRFDelivery12127(t *testing.T) {
	enterPrivateNetns9813(t)
	peerNS := setupManagementVRFBackstopTopology12127(t)
	probes := newManagementVRFPacketProbes12127(t, peerNS, "192.0.2.3/24", "2001:db8:1212::3/64")
	installDaemonDHCPBackstopTestHooks12127(t, xnft.NewNetlinkInstaller())

	d := &Daemon{}
	d.earlyInputHandoffDone.Store(true)
	cfg := dhcpVRFConfig12127()
	snapshot := dhcpVRFSnapshot12127("192.0.2.2/24", "2001:db8:1212::2/64")
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return snapshot }
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("apply main host-inbound table: %v", err)
	}
	if err := nftInstaller.DeleteTable(xnft.HostInboundTableName); err != nil {
		t.Fatalf("remove main table for network-path positive control: %v", err)
	}
	assertManagementVRFPacketOutcome12127(t, probes, true)
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("reinstall main host-inbound table: %v", err)
	}
	assertManagementVRFPacketOutcome12127(t, probes, false)
}

// TestHostInboundDHCPManagementVRFColdBootProductionFence12127 exercises the
// daemon's cold-boot fallback end to end: the main install fails, config/snapshot
// builders derive the VRF-slave backstop, and the production fence builder sends
// it to a real netlink installer. Without a table the DHCP-local UDP probes are
// reachable; after the cold-boot fallback they must be denied through sdifname.
// This proves both daemon_nft.go's FenceSpec plumbing and BuildFenceAddrSets'
// VRF-slave propagation, rather than constructing a FenceSpec in the test.
func TestHostInboundDHCPManagementVRFColdBootProductionFence12127(t *testing.T) {
	enterPrivateNetns9813(t)
	peerNS := setupManagementVRFBackstopTopology12127(t)
	probes := newManagementVRFPacketProbes12127(t, peerNS, "192.0.2.4/24", "2001:db8:1212::4/64")
	mainFailure := errors.New("injected cold-boot retained-table failure")
	realInstaller := xnft.NewNetlinkInstaller()
	installDaemonDHCPBackstopTestHooks12127(t, &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return mainFailure },
		coldBootFence: func(spec xnft.FenceSpec) error {
			return realInstaller.InstallColdBootFence(spec)
		},
	})

	d := &Daemon{}
	d.earlyInputHandoffDone.Store(true)
	cfg := dhcpVRFConfig12127()
	snapshot := dhcpVRFSnapshot12127("192.0.2.2/24", "2001:db8:1212::2/64")
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return snapshot }

	// No table is initially installed, so this is an in-test positive control
	// proving the VRF-bound listeners and peer can exchange the DHCP-shaped UDP
	// probes before the production cold-boot fence takes ownership.
	assertManagementVRFPacketOutcome12127(t, probes, true)
	if err := d.applyHostInboundFilter(cfg); !errors.Is(err, mainFailure) {
		t.Fatalf("cold-boot apply error = %v, want the retained-table failure", err)
	}
	assertManagementVRFPacketOutcome12127(t, probes, false)
}

// TestHostInboundDHCPManagementVRFGapDelivery12127 exercises the day-2 gap
// path. The gap snapshot includes .3, while .4 and the link-local destination
// are live but absent from it. The explicit VRF link-local fallback must not
// rely on FIB destination classification.
func TestHostInboundDHCPManagementVRFGapDelivery12127(t *testing.T) {
	enterPrivateNetns9813(t)
	peerNS := setupManagementVRFBackstopTopology12127(t)
	probes := newManagementVRFPacketProbes12127(t, peerNS, "192.0.2.4/24", "2001:db8:1212::4/64")
	realInstaller := xnft.NewNetlinkInstaller()
	mainFailure := errors.New("injected retained-generation install failure")
	installDaemonDHCPBackstopTestHooks12127(t, &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return mainFailure },
		gapFence:    func(spec xnft.GapFenceSpec) error { return realInstaller.InstallGapFence(spec) },
	})

	d := &Daemon{}
	d.earlyInputHandoffDone.Store(true)
	d.hostInboundEnforced.Store(true)
	d.hostInboundCoveredAddrs = map[string]struct{}{
		hostInboundDropAddrKey('4', "192.0.2.2"):        {},
		hostInboundDropAddrKey('6', "2001:db8:1212::2"): {},
	}
	cfg := dhcpVRFConfig12127()
	snapshot := dhcpVRFSnapshot12127(
		"192.0.2.2/24", "192.0.2.3/24",
		"2001:db8:1212::2/64", "2001:db8:1212::3/64",
	)
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return snapshot }
	if err := d.applyHostInboundFilter(cfg); !errors.Is(err, mainFailure) {
		t.Fatalf("day-2 apply error = %v, want injected retained-generation failure", err)
	}
	if err := realInstaller.DeleteTable(xnft.HostInboundGapTableName); err != nil {
		t.Fatalf("remove gap table for network-path positive control: %v", err)
	}
	assertManagementVRFPacketOutcome12127(t, probes, true)
	if err := d.applyHostInboundFilter(cfg); !errors.Is(err, mainFailure) {
		t.Fatalf("reinstall gap table error = %v, want injected retained-generation failure", err)
	}
	assertManagementVRFPacketOutcome12127(t, probes, false)
}

func installDaemonDHCPBackstopTestHooks12127(t *testing.T, installer xnft.Installer) {
	t.Helper()
	origInstaller := nftInstaller
	origSamples := sampleHostInboundSnapshots
	origDelete := conntrackDeleteFilters
	origPostureWrite, origPostureRead := hostPostureWriteFile, hostPostureReadFile
	t.Cleanup(func() {
		nftInstaller = origInstaller
		sampleHostInboundSnapshots = origSamples
		conntrackDeleteFilters = origDelete
		hostPostureWriteFile, hostPostureReadFile = origPostureWrite, origPostureRead
	})
	nftInstaller = installer
	conntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) { return 0, nil }
	hostPostureWriteFile = func(string, []byte, os.FileMode) error { return nil }
	hostPostureReadFile = func(string) ([]byte, error) { return []byte("0"), nil }
}

func dhcpVRFConfig12127() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		dhcpVRFInterface12127: {
			Name: dhcpVRFInterface12127,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, DHCP: true, DHCPv6: true},
			},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{dhcpVRFInterface12127 + ".0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	return cfg
}

func dhcpVRFSnapshot12127(addrs ...string) []dpuserspace.InterfaceSnapshot {
	addresses := make([]dpuserspace.InterfaceAddressSnapshot, 0, len(addrs))
	for _, addr := range addrs {
		family := "inet"
		if strings.Contains(addr, ":") {
			family = "inet6"
		}
		addresses = append(addresses, dpuserspace.InterfaceAddressSnapshot{
			Family: family, Address: addr, Scope: int(netlink.SCOPE_UNIVERSE),
		})
	}
	return []dpuserspace.InterfaceSnapshot{{
		Name: dhcpVRFInterface12127 + ".0", Zone: "wan", LinuxName: dhcpVRFInterface12127,
		IsUnit: true, Addresses: addresses,
	}}
}

func setupManagementVRFBackstopTopology12127(t *testing.T) netns.NsHandle {
	t.Helper()
	testNS, err := netns.Get()
	if err != nil {
		t.Fatalf("get private test netns: %v", err)
	}
	peerNS, err := netns.New()
	if err != nil {
		testNS.Close()
		t.Skipf("cannot create peer netns: %v", err)
	}
	if err := netns.Set(testNS); err != nil {
		t.Fatalf("return to private test netns: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(testNS)
		_ = peerNS.Close()
		_ = testNS.Close()
	})

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: dhcpVRFInterface12127}, PeerName: "vpeer0"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create management DHCP veth: %v", err)
	}
	host, err := netlink.LinkByName(dhcpVRFInterface12127)
	if err != nil {
		t.Fatalf("find management DHCP veth: %v", err)
	}
	peer, err := netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("find peer veth: %v", err)
	}
	if err := netlink.LinkSetNsFd(peer, int(peerNS)); err != nil {
		t.Fatalf("move peer veth into isolated namespace: %v", err)
	}

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: dhcpVRFMaster12127},
		Table:     config.ManagementVRFTableID,
	}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Skipf("cannot create management VRF in this netns: %v", err)
	}
	vrfLink, err := netlink.LinkByName(dhcpVRFMaster12127)
	if err != nil {
		t.Fatalf("find management VRF: %v", err)
	}
	if err := netlink.LinkSetUp(vrfLink); err != nil {
		t.Fatalf("bring up management VRF: %v", err)
	}
	addManagementVRFL3mdevLookupRule12127(t, unix.AF_INET)
	addManagementVRFL3mdevLookupRule12127(t, unix.AF_INET6)
	if err := netlink.LinkSetMaster(host, vrfLink); err != nil {
		t.Fatalf("enslave DHCP interface to management VRF: %v", err)
	}
	if err := netlink.LinkSetUp(host); err != nil {
		t.Fatalf("bring up management DHCP interface: %v", err)
	}
	for _, cidr := range []string{
		"192.0.2.2/24", "192.0.2.3/24", "192.0.2.4/24",
		"2001:db8:1212::2/64", "2001:db8:1212::3/64", "2001:db8:1212::4/64",
		dhcpVRFHostLL12127 + "/64",
	} {
		addDHCPVRFAddress12127(t, host, cidr)
	}
	if err := inDHCPVRFNamespace12127(peerNS, func() error {
		peer, err := netlink.LinkByName("vpeer0")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return err
		}
		for _, cidr := range []string{"192.0.2.1/24", "2001:db8:1212::1/64", dhcpVRFPeerLL12127 + "/64"} {
			if err := addDHCPVRFAddressErr12127(peer, cidr); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("configure isolated DHCP probe peer: %v", err)
	}
	waitManagementVRFAddresses12127(t, peerNS)
	return peerNS
}
func addManagementVRFL3mdevLookupRule12127(t *testing.T, family int) {
	t.Helper()
	req := nl.NewNetlinkRequest(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	msg := nl.NewRtMsg()
	msg.Family = uint8(family)
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Table = unix.RT_TABLE_UNSPEC
	msg.Type = nl.FR_ACT_TO_TBL
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(unix.FRA_PRIORITY, nl.Uint32Attr(1000)))
	req.AddData(nl.NewRtAttr(unix.FRA_L3MDEV, nl.Uint8Attr(1)))
	if _, err := req.Execute(unix.NETLINK_ROUTE, 0); err != nil {
		t.Fatalf("install l3mdev lookup rule for family %d: %v", family, err)
	}
}

func inDHCPVRFNamespace12127(ns netns.NsHandle, fn func() error) (fnErr error) {
	original, err := netns.Get()
	if err != nil {
		return err
	}
	defer func() {
		if restoreErr := netns.Set(original); restoreErr != nil {
			fnErr = errors.Join(fnErr, restoreErr)
		}
		_ = original.Close()
	}()
	if err := netns.Set(ns); err != nil {
		return err
	}
	return fn()
}

func addDHCPVRFAddress12127(t *testing.T, link netlink.Link, cidr string) {
	t.Helper()
	if err := addDHCPVRFAddressErr12127(link, cidr); err != nil {
		t.Fatalf("add %s to %s: %v", cidr, link.Attrs().Name, err)
	}
}

func addDHCPVRFAddressErr12127(link netlink.Link, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ipNet.IP = ip
	return netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet})
}

func waitManagementVRFAddresses12127(t *testing.T, peerNS netns.NsHandle) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		hostReady := true
		for _, ip := range []string{"2001:db8:1212::2", "2001:db8:1212::3", "2001:db8:1212::4", dhcpVRFHostLL12127} {
			ready, err := managementVRFIPv6AddressReady12127(dhcpVRFInterface12127, ip)
			if err != nil {
				t.Fatalf("check host IPv6 address %s: %v", ip, err)
			}
			hostReady = hostReady && ready
		}
		peerReady := true
		if err := inDHCPVRFNamespace12127(peerNS, func() error {
			for _, ip := range []string{"2001:db8:1212::1", dhcpVRFPeerLL12127} {
				ready, err := managementVRFIPv6AddressReady12127("vpeer0", ip)
				if err != nil {
					return err
				}
				peerReady = peerReady && ready
			}
			return nil
		}); err != nil {
			t.Fatalf("check peer IPv6 addresses: %v", err)
		}
		if hostReady && peerReady {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for IPv6 addresses to finish DAD")
}

func managementVRFIPv6AddressReady12127(iface, address string) (bool, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return false, err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.IP.Equal(net.ParseIP(address)) && addr.Flags&unix.IFA_F_TENTATIVE == 0 {
			return true, nil
		}
	}
	return false, nil
}

type managementVRFPacketProbe12127 struct {
	name     string
	listener *net.UDPConn
	sender   *net.UDPConn
	dest     string
	zone     string
}

func newManagementVRFPacketProbes12127(t *testing.T, peerNS netns.NsHandle, v4CIDR, v6CIDR string) []managementVRFPacketProbe12127 {
	t.Helper()
	v4 := stringsBeforeSlash12127(v4CIDR)
	v6 := stringsBeforeSlash12127(v6CIDR)
	v4Listener := listenManagementVRFUDP12127(t, "udp4", v4)
	v6Listener := listenManagementVRFUDP12127(t, "udp6", v6)
	v6LLListener := listenManagementVRFUDP12127(t, "udp6", dhcpVRFHostLL12127+"%"+dhcpVRFInterface12127)
	v4Sender := newDHCPVRFPeerSender12127(t, peerNS, "udp4", "192.0.2.1")
	v6Sender := newDHCPVRFPeerSender12127(t, peerNS, "udp6", "2001:db8:1212::1")
	v6LLSender := newDHCPVRFPeerSender12127(t, peerNS, "udp6", dhcpVRFPeerLL12127)
	t.Cleanup(func() {
		_ = v4Listener.Close()
		_ = v6Listener.Close()
		_ = v6LLListener.Close()
		_ = v4Sender.Close()
		_ = v6Sender.Close()
		_ = v6LLSender.Close()
	})
	return []managementVRFPacketProbe12127{
		{name: "IPv4", listener: v4Listener, sender: v4Sender, dest: v4},
		{name: "IPv6", listener: v6Listener, sender: v6Sender, dest: v6},
		{name: "IPv6 link-local", listener: v6LLListener, sender: v6LLSender, dest: dhcpVRFHostLL12127, zone: "vpeer0"},
	}
}

func assertManagementVRFPacketOutcome12127(t *testing.T, probes []managementVRFPacketProbe12127, wantReachable bool) {
	t.Helper()
	for _, probe := range probes {
		probe := probe
		t.Run(probe.name, func(t *testing.T) {
			if err := probe.listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("set listener deadline: %v", err)
			}
			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-stop:
						return
					case <-ticker.C:
						_, _ = probe.sender.WriteToUDP([]byte("vrf-probe"), &net.UDPAddr{IP: net.ParseIP(probe.dest), Port: 2222, Zone: probe.zone})
					}
				}
			}()
			buf := make([]byte, 128)
			_, _, err := probe.listener.ReadFromUDP(buf)
			close(stop)
			<-done
			if wantReachable {
				if err != nil {
					t.Fatalf("positive control to %s:2222 did not reach the VRF-bound socket: %v", probe.dest, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("new DHCP address %s:2222 reached the VRF-bound socket; backstop is missing its sdifname scope", probe.dest)
			}
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				t.Fatalf("read result = %v, want timeout proving the packet was denied", err)
			}
		})
	}
}

func listenManagementVRFUDP12127(t *testing.T, network, address string) *net.UDPConn {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dhcpVRFMaster12127)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	packet, err := config.ListenPacket(context.Background(), network, net.JoinHostPort(address, "2222"))
	if err != nil {
		t.Fatalf("listen on %s:2222 bound to management VRF: %v", address, err)
	}
	conn, ok := packet.(*net.UDPConn)
	if !ok {
		packet.Close()
		t.Fatalf("listener for %s:2222 is %T, want *net.UDPConn", address, packet)
	}
	return conn
}

func newDHCPVRFPeerSender12127(t *testing.T, peerNS netns.NsHandle, network, source string) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	err := inDHCPVRFNamespace12127(peerNS, func() error {
		local := &net.UDPAddr{IP: net.ParseIP(source)}
		if local.IP.IsLinkLocalUnicast() {
			local.Zone = "vpeer0"
		}
		var localErr error
		conn, localErr = net.ListenUDP(network, local)
		return localErr
	})
	if err != nil {
		t.Fatalf("bind isolated %s sender: %v", network, err)
	}
	return conn
}

func stringsBeforeSlash12127(s string) string {
	for i := range s {
		if s[i] == '/' {
			return s[:i]
		}
	}
	return s
}
