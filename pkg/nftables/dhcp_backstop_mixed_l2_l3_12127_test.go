package nftables

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	mixedFrameNewV4       = "192.0.2.3"
	mixedFrameRetainedV4  = "192.0.2.2"
	mixedFramePeerV4      = "192.0.2.1"
	mixedFrameNewV6       = "2001:db8:1212::3"
	mixedFrameRetainedV6  = "2001:db8:1212::2"
	mixedFramePeerV6      = "2001:db8:1212::1"
	mixedFrameAnycastV6   = "2001:db8:1212::"
	mixedFrameV4Broadcast = "192.0.2.255"
	mixedFrameV6Group     = "ff02::1234"
	mixedFrameTestPort    = 4444
	mixedFrameMcastPort   = 5353
)

// TestDHCPBackstopMixedL2L3Frames12127 sends real raw Ethernet/IP/UDP frames
// through the main, cold-boot, and gap backstops. Firewall-local and subnet-router
// anycast IP destinations must be dropped even when sent in mixed L2 frames;
// genuine IP broadcast and multicast remain deliverable, and the retained
// main-table SSH permit survives the gap.
func TestDHCPBackstopMixedL2L3Frames12127(t *testing.T) {
	enterPrivateNetns(t)
	hostLink := mkNamedVeth10751(t, unleasedTestNetdev10751, "vhost0", "vpeer0")
	testNS, err := netns.Get()
	if err != nil {
		t.Fatalf("get test namespace: %v", err)
	}
	peerNS, err := netns.New()
	if err != nil {
		testNS.Close()
		t.Fatalf("create peer namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(testNS)
		_ = peerNS.Close()
		_ = testNS.Close()
	})
	if err := netns.Set(testNS); err != nil {
		t.Fatalf("restore test namespace: %v", err)
	}
	peerLink, err := netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("find peer interface: %v", err)
	}
	if err := netlink.LinkSetNsFd(peerLink, int(peerNS)); err != nil {
		t.Fatalf("move peer interface: %v", err)
	}
	if err := netns.Set(peerNS); err != nil {
		t.Fatalf("enter peer namespace: %v", err)
	}
	peerLink, err = netlink.LinkByName("vpeer0")
	if err != nil {
		t.Fatalf("find moved peer interface: %v", err)
	}
	if err := netlink.LinkSetUp(peerLink); err != nil {
		t.Fatalf("bring up moved peer interface: %v", err)
	}
	for _, cidr := range []string{mixedFramePeerV4 + "/24", mixedFramePeerV6 + "/64"} {
		mustAddrAdd10751(t, peerLink, cidr)
	}
	waitAddrsValid10751(t, map[string][]string{"vpeer0": {mixedFramePeerV6}})
	peerMAC := append(net.HardwareAddr(nil), peerLink.Attrs().HardwareAddr...)
	if err := netns.Set(testNS); err != nil {
		t.Fatalf("return to test namespace: %v", err)
	}
	hostLink, err = netlink.LinkByName(unleasedTestNetdev10751)
	if err != nil {
		t.Fatalf("find host interface: %v", err)
	}
	for _, cidr := range []string{
		mixedFrameRetainedV4 + "/24", mixedFrameNewV4 + "/24",
		mixedFrameRetainedV6 + "/64", mixedFrameNewV6 + "/64",
	} {
		mustAddrAdd10751(t, hostLink, cidr)
	}
	waitAddrsValid10751(t, map[string][]string{unleasedTestNetdev10751: {mixedFrameRetainedV6, mixedFrameNewV6}})
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644); err != nil {
		t.Fatalf("enable IPv6 forwarding for subnet-router anycast test: %v", err)
	}
	if err := netlink.LinkSetAllmulticastOn(hostLink); err != nil {
		t.Fatalf("enable multicast-frame reception: %v", err)
	}

	hostIface, err := net.InterfaceByName(unleasedTestNetdev10751)
	if err != nil {
		t.Fatalf("find host net.Interface: %v", err)
	}
	v4Receiver, err := net.ListenUDP("udp4", &net.UDPAddr{Port: mixedFrameTestPort})
	if err != nil {
		t.Fatalf("listen for IPv4 probes: %v", err)
	}
	defer v4Receiver.Close()
	v6Receiver, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: mixedFrameTestPort})
	if err != nil {
		t.Fatalf("listen for IPv6 probes: %v", err)
	}
	defer v6Receiver.Close()
	mcastReceiver, err := net.ListenMulticastUDP("udp6", hostIface, &net.UDPAddr{
		IP: net.ParseIP(mixedFrameV6Group), Port: mixedFrameMcastPort,
	})
	if err != nil {
		t.Fatalf("listen for IPv6 multicast control: %v", err)
	}
	defer mcastReceiver.Close()

	v4TCP := listenTCPOnDevice11577(t, "tcp4", mixedFrameRetainedV4, 22, unleasedTestNetdev10751)
	defer v4TCP.Close()
	v6TCP := listenTCPOnDevice11577(t, "tcp6", mixedFrameRetainedV6, 22, unleasedTestNetdev10751)
	defer v6TCP.Close()
	serveTCP12127(t, v4TCP)
	serveTCP12127(t, v6TCP)

	retainedView := []HostInboundZoneView{{
		Zone: "wan", SystemServices: []string{"ssh"},
		V4Addrs: []string{mixedFrameRetainedV4}, V6Addrs: []string{mixedFrameRetainedV6},
	}}
	mainSpec := HostInboundSpec{
		Views:      retainedView,
		UnleasedV4: []string{unleasedTestNetdev10751}, UnleasedV6: []string{unleasedTestNetdev10751},
	}
	gapMainSpec := HostInboundSpec{Views: retainedView}
	installer := NewNetlinkInstaller()
	modes := []struct {
		name           string
		install        func() error
		installGap     func() error
		retainedPermit bool
	}{
		{
			name:           "main",
			install:        func() error { return installer.InstallHostInbound(mainSpec) },
			retainedPermit: true,
		},
		{
			name: "cold-boot",
			install: func() error {
				return installer.InstallColdBootFence(FenceSpec{
					UnleasedV4: []string{unleasedTestNetdev10751}, UnleasedV6: []string{unleasedTestNetdev10751},
				})
			},
		},
		{
			name:    "coverage-gap",
			install: func() error { return installer.InstallHostInbound(gapMainSpec) },
			installGap: func() error {
				return installer.InstallGapFence(GapFenceSpec{
					UncoveredV4: []string{"192.0.2.4"}, UncoveredV6: []string{"2001:db8:1212::4"},
					UnleasedV4: []string{unleasedTestNetdev10751}, UnleasedV6: []string{unleasedTestNetdev10751},
					RetainedV4: []string{mixedFrameRetainedV4}, RetainedV6: []string{mixedFrameRetainedV6},
				})
			},
			retainedPermit: true,
		},
	}
	var packetID uint16 = 1
	for _, mode := range modes {
		if err := mode.install(); err != nil {
			t.Fatalf("install %s main rules: %v", mode.name, err)
		}
		if mode.installGap != nil {
			// Prove the mixed L2/L3 frames reach the listener with only the
			// retained-address main table installed. The gap leg below must be
			// what changes this delivery into a DROP.
			for _, family := range []struct {
				name, source, destination string
				ethType                   uint16
				receiver                  *net.UDPConn
			}{
				{name: "IPv4", source: mixedFramePeerV4, destination: mixedFrameNewV4, ethType: unix.ETH_P_IP, receiver: v4Receiver},
				{name: "IPv6", source: mixedFramePeerV6, destination: mixedFrameNewV6, ethType: unix.ETH_P_IPV6, receiver: v6Receiver},
			} {
				for _, layer2 := range []struct {
					name string
					mac  net.HardwareAddr
				}{
					{name: "broadcast", mac: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
					{name: "multicast", mac: mixedFrameMulticastMAC12127(family.ethType)},
				} {
					packetID++
					payload := []byte{byte(packetID >> 8), byte(packetID)}
					frame := mixedFrameUDP12127(family.ethType, peerMAC, layer2.mac,
						net.ParseIP(family.source), net.ParseIP(family.destination),
						40000+packetID, mixedFrameTestPort, packetID, payload)
					if err := sendMixedFrame12127(peerNS, "vpeer0", frame); err != nil {
						t.Fatalf("send pre-gap %s L2-%s frame: %v", family.name, layer2.name, err)
					}
					assertMixedFrameDelivery12127(t, family.receiver, true, payload,
						"coverage-gap main-only "+family.name+" unicast IP in L2-"+layer2.name)
				}
			}
			if err := mode.installGap(); err != nil {
				t.Fatalf("install %s fence: %v", mode.name, err)
			}
		}
		for _, family := range []struct {
			name, source, destination string
			ethType                   uint16
			receiver                  *net.UDPConn
		}{
			{name: "IPv4", source: mixedFramePeerV4, destination: mixedFrameNewV4, ethType: unix.ETH_P_IP, receiver: v4Receiver},
			{name: "IPv6", source: mixedFramePeerV6, destination: mixedFrameNewV6, ethType: unix.ETH_P_IPV6, receiver: v6Receiver},
		} {
			for _, layer2 := range []struct {
				name string
				mac  net.HardwareAddr
			}{
				{name: "broadcast", mac: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
				{name: "multicast", mac: mixedFrameMulticastMAC12127(family.ethType)},
			} {
				packetID++
				payload := []byte{byte(packetID >> 8), byte(packetID)}
				frame := mixedFrameUDP12127(family.ethType, peerMAC, layer2.mac,
					net.ParseIP(family.source), net.ParseIP(family.destination),
					40000+packetID, mixedFrameTestPort, packetID, payload)
				if err := sendMixedFrame12127(peerNS, "vpeer0", frame); err != nil {
					t.Fatalf("send %s L2-%s frame: %v", family.name, layer2.name, err)
				}
				assertMixedFrameDelivery12127(t, family.receiver, false, payload,
					mode.name+" "+family.name+" unicast IP in L2-"+layer2.name)
			}
		}
		packetID++
		anycastPayload := []byte{byte(packetID >> 8), byte(packetID)}
		anycast := mixedFrameUDP12127(unix.ETH_P_IPV6, peerMAC, hostIface.HardwareAddr,
			net.ParseIP(mixedFramePeerV6), net.ParseIP(mixedFrameAnycastV6),
			40000+packetID, mixedFrameTestPort, packetID, anycastPayload)
		if err := sendMixedFrame12127(peerNS, "vpeer0", anycast); err != nil {
			t.Fatalf("send L2-unicast UDP to IPv6 subnet-router anycast: %v", err)
		}
		assertMixedFrameDelivery12127(t, v6Receiver, false, anycastPayload,
			mode.name+" L2-unicast IPv6 subnet-router anycast")

		packetID++
		bcastPayload := []byte{byte(packetID >> 8), byte(packetID)}
		bcast := mixedFrameUDP12127(unix.ETH_P_IP, peerMAC,
			net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			net.ParseIP(mixedFramePeerV4), net.ParseIP(mixedFrameV4Broadcast),
			40000+packetID, mixedFrameTestPort, packetID, bcastPayload)
		if err := sendMixedFrame12127(peerNS, "vpeer0", bcast); err != nil {
			t.Fatalf("send real IPv4 broadcast control: %v", err)
		}
		assertMixedFrameDelivery12127(t, v4Receiver, true, bcastPayload, mode.name+" genuine IPv4 broadcast")

		packetID++
		mcastPayload := []byte{byte(packetID >> 8), byte(packetID)}
		mcastIP := net.ParseIP(mixedFrameV6Group)
		mcast := mixedFrameUDP12127(unix.ETH_P_IPV6, peerMAC,
			mixedFrameIPv6MAC12127(mcastIP), net.ParseIP(mixedFramePeerV6), mcastIP,
			40000+packetID, mixedFrameMcastPort, packetID, mcastPayload)
		if err := sendMixedFrame12127(peerNS, "vpeer0", mcast); err != nil {
			t.Fatalf("send real IPv6 multicast control: %v", err)
		}
		assertMixedFrameDelivery12127(t, mcastReceiver, true, mcastPayload, mode.name+" genuine IPv6 multicast")

		if mode.retainedPermit {
			for _, probe := range []struct{ network, address string }{
				{network: "tcp4", address: mixedFrameRetainedV4 + ":22"},
				{network: "tcp6", address: "[" + mixedFrameRetainedV6 + "]:22"},
			} {
				if err := tcpDialFromNetns11577Network(peerNS, probe.network, probe.address, time.Second); err != nil {
					t.Fatalf("%s retained SSH permit %s was lost: %v", mode.name, probe.address, err)
				}
			}
		}
	}
}

func serveTCP12127(t *testing.T, listener *net.TCPListener) {
	t.Helper()
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
}

func assertMixedFrameDelivery12127(t *testing.T, receiver *net.UDPConn, want bool, expected []byte, probe string) {
	t.Helper()
	if err := receiver.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("set %s read deadline: %v", probe, err)
	}
	buf := make([]byte, 256)
	n, _, err := receiver.ReadFromUDP(buf)
	if err == nil {
		if !want {
			t.Fatalf("%s reached the UDP listener; expected a backstop DROP", probe)
		}
		if !bytes.Equal(buf[:n], expected) {
			t.Fatalf("%s reached the UDP listener with payload %x; want %x", probe, buf[:n], expected)
		}
		return
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		if want {
			t.Fatalf("%s did not reach the UDP listener", probe)
		}
		return
	}
	t.Fatalf("receive %s: %v", probe, err)
}

func sendMixedFrame12127(ns netns.NsHandle, ifname string, frame []byte) (result error) {
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
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsMixedFrame12127(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrLinklayer{Ifindex: link.Attrs().Index, Protocol: htonsMixedFrame12127(unix.ETH_P_ALL), Halen: 6}
	copy(sa.Addr[:], frame[:6])
	return unix.Sendto(fd, frame, 0, sa)
}

func mixedFrameUDP12127(ethType uint16, sourceMAC, destinationMAC net.HardwareAddr, sourceIP, destinationIP net.IP, sourcePort, destinationPort, id uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	frame := make([]byte, 14)
	copy(frame[:6], destinationMAC)
	copy(frame[6:12], sourceMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethType)
	if ethType == unix.ETH_P_IP {
		ip := make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_UDP
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(udp)))
		binary.BigEndian.PutUint16(ip[4:6], id)
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
		copy(ip[12:16], sourceIP.To4())
		copy(ip[16:20], destinationIP.To4())
		binary.BigEndian.PutUint16(ip[10:12], checksumMixedFrame12127(ip))
		return append(append(frame, ip...), udp...)
	}
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, unix.IPPROTO_UDP, 64
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(udp)))
	copy(ip[8:24], sourceIP.To16())
	copy(ip[24:40], destinationIP.To16())
	pseudo := make([]byte, 40+len(udp))
	copy(pseudo[:16], ip[8:24])
	copy(pseudo[16:32], ip[24:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(udp)))
	pseudo[39] = unix.IPPROTO_UDP
	copy(pseudo[40:], udp)
	udpSum := checksumMixedFrame12127(pseudo)
	if udpSum == 0 {
		udpSum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], udpSum)
	return append(append(frame, ip...), udp...)
}

func checksumMixedFrame12127(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func mixedFrameMulticastMAC12127(ethType uint16) net.HardwareAddr {
	if ethType == unix.ETH_P_IP {
		return net.HardwareAddr{0x01, 0x00, 0x5e, 0x01, 0x02, 0x03}
	}
	return mixedFrameIPv6MAC12127(net.ParseIP(mixedFrameV6Group))
}

func mixedFrameIPv6MAC12127(ip net.IP) net.HardwareAddr {
	v6 := ip.To16()
	mac := net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0}
	copy(mac[2:], v6[12:16])
	return mac
}

func htonsMixedFrame12127(value uint16) uint16 {
	return value<<8 | value>>8
}
