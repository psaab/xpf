package snmp

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// TestSNMPInbandPollWithManagementVRF16781 is the #16781 defect cell: with
// fxp0 configured (so the agent pins its listener to vrf-mgmt), an in-band
// poll admitted on a data zone must still be answered from the polled
// in-band address, and the #11427 management leg must keep working.
//
// RED pre-fix: the only listener is SO_BINDTODEVICE-pinned to vrf-mgmt, so
// the in-band manager's GET to the trust address is never received and the
// read times out. The management subtest is the positive control — it
// passes pre- and post-fix, proving the harness itself can drive the agent.
func TestSNMPInbandPollWithManagementVRF16781(t *testing.T) {
	if os.Getenv("XPF_SNMP_INBAND_CHILD_16781") != "1" {
		mgmtNS, inbandNS, mgmtConn, inbandConn := snmpInbandFixture16781(t)
		defer mgmtNS.Close()
		defer inbandNS.Close()
		defer mgmtConn.Close()
		defer inbandConn.Close()

		if err := os.WriteFile("/proc/sys/net/ipv4/udp_l3mdev_accept", []byte("1"), 0644); err != nil {
			t.Skipf("cannot enable UDP VRF receive acceptance in the private netns: %v", err)
		}
		mgmtFile, err := mgmtConn.File()
		if err != nil {
			t.Fatalf("duplicate mgmt manager socket: %v", err)
		}
		defer mgmtFile.Close()
		inbandFile, err := inbandConn.File()
		if err != nil {
			t.Fatalf("duplicate inband manager socket: %v", err)
		}
		defer inbandFile.Close()
		cmd := exec.Command(os.Args[0], "-test.run=^TestSNMPInbandPollWithManagementVRF16781$", "-test.v")
		childEnv := make([]string, 0, len(os.Environ())+1)
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "XPF_SNMP_INBAND_CHILD_16781=") {
				childEnv = append(childEnv, entry)
			}
		}
		cmd.Env = append(childEnv, "XPF_SNMP_INBAND_CHILD_16781=1")
		cmd.ExtraFiles = []*os.File{mgmtFile, inbandFile}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated SNMP in-band scenario failed: %v\n%s", err, output)
		}
		t.Logf("isolated SNMP in-band scenario:\n%s", output)
		return
	}

	adopt := func(fd uintptr, name string) *net.UDPConn {
		f := os.NewFile(fd, name)
		if f == nil {
			t.Fatalf("%s socket was not passed to isolated child", name)
		}
		pc, err := net.FilePacketConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("adopt %s socket: %v", name, err)
		}
		conn, ok := pc.(*net.UDPConn)
		if !ok {
			pc.Close()
			t.Fatalf("%s socket type = %T, want *net.UDPConn", name, pc)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	mgmtConn := adopt(3, "mgmt-manager-udp")
	inbandConn := adopt(4, "inband-manager-udp")

	agent := NewAgentWithPaths(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	}, filepath.Join(t.TempDir(), "engineboots"), filepath.Join(t.TempDir(), "engine-id"))
	agent.SetVRFDevice(config.ManagementVRFDeviceName)
	if err := agent.Bind(context.Background()); err != nil {
		t.Fatalf("bind SNMP agent: %v", err)
	}
	t.Cleanup(agent.Stop)
	go agent.Serve()

	poll := func(t *testing.T, conn *net.UDPConn, serverIP string) {
		t.Helper()
		server := &net.UDPAddr{IP: net.ParseIP(serverIP), Port: 161}
		// Several polls: with SO_REUSEPORT in play a single datagram could
		// in principle land on either socket; every poll must be answered.
		for i := range 3 {
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			req := buildV2cGetRequest("public", 16781+i, oidSysDescr)
			if _, err := conn.WriteToUDP(req, server); err != nil {
				t.Fatalf("send poll %d to %s: %v", i, serverIP, err)
			}
			buf := make([]byte, maxPacketSize)
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("poll %d to %s was not answered: %v", i, serverIP, err)
			}
			if n == 0 || !peer.IP.Equal(server.IP) {
				t.Fatalf("poll %d reply peer/source = %v with %d bytes, want %s with a non-empty reply", i, peer, n, server.IP)
			}
		}
	}

	t.Run("management poll still answered via vrf-mgmt", func(t *testing.T) {
		poll(t, mgmtConn, "192.0.2.1")
	})
	t.Run("in-band poll answered from trust address", func(t *testing.T) {
		poll(t, inbandConn, "198.51.100.1")
	})
}

// snmpInbandFixture16781 builds the appliance netns with fxp0 enslaved to
// vrf-mgmt (192.0.2.1) and trust0 in the main table (198.51.100.1), plus two
// manager netnses: one reachable only via the management VRF, one in-band.
func snmpInbandFixture16781(t *testing.T) (netns.NsHandle, netns.NsHandle, *net.UDPConn, *net.UDPConn) {
	t.Helper()
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read network namespace: %v", err)
	}
	appliance, err := netns.New()
	if err != nil {
		original.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private appliance netns (needs CAP_NET_ADMIN): %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(original)
		_ = appliance.Close()
		_ = original.Close()
		runtime.UnlockOSThread()
	})

	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName}, Table: config.ManagementVRFTableID}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Skipf("cannot create management VRF: %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("bring management VRF up: %v", err)
	}
	mkVeth := func(name, peer string) {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: peer}); err != nil {
			t.Skipf("cannot create veth %s/%s: %v", name, peer, err)
		}
	}
	mkVeth("fxp0", "manager0")
	mkVeth("trust0", "inband0")

	byName := func(name string) netlink.Link {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("find %s: %v", name, err)
		}
		return link
	}
	fxp0 := byName("fxp0")
	trust0 := byName("trust0")
	manager0 := byName("manager0")
	inband0 := byName("inband0")

	managerNS, err := netns.New()
	if err != nil {
		t.Skipf("cannot create manager netns: %v", err)
	}
	if err := netns.Set(appliance); err != nil {
		t.Fatalf("restore appliance netns: %v", err)
	}
	if err := netlink.LinkSetNsFd(manager0, int(managerNS)); err != nil {
		managerNS.Close()
		t.Skipf("move manager veth into its netns: %v", err)
	}
	inbandNS, err := netns.New()
	if err != nil {
		managerNS.Close()
		t.Skipf("cannot create in-band manager netns: %v", err)
	}
	if err := netns.Set(appliance); err != nil {
		t.Fatalf("restore appliance netns: %v", err)
	}
	if err := netlink.LinkSetNsFd(inband0, int(inbandNS)); err != nil {
		inbandNS.Close()
		managerNS.Close()
		t.Skipf("move in-band veth into its netns: %v", err)
	}

	if err := netlink.LinkSetMaster(fxp0, vrf); err != nil {
		t.Fatalf("enslave fxp0 into vrf-mgmt: %v", err)
	}
	addAddr := func(link netlink.Link, cidr string) {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			t.Fatalf("assign %s: %v", cidr, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatalf("bring %s up: %v", link.Attrs().Name, err)
		}
	}
	addAddr(fxp0, "192.0.2.1/24")
	addAddr(trust0, "198.51.100.1/24")

	setupManager := func(ns netns.NsHandle, ifName, cidr, listenIP string) *net.UDPConn {
		if err := netns.Set(ns); err != nil {
			t.Fatalf("enter manager netns: %v", err)
		}
		link := byName(ifName)
		addAddr(link, cidr)
		lo := byName("lo")
		if err := netlink.LinkSetUp(lo); err != nil {
			t.Fatalf("bring manager loopback up: %v", err)
		}
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(listenIP)})
		if err != nil {
			t.Fatalf("listen on manager address %s: %v", listenIP, err)
		}
		return conn
	}
	mgmtConn := setupManager(managerNS, "manager0", "192.0.2.2/24", "192.0.2.2")
	inbandConn := setupManager(inbandNS, "inband0", "198.51.100.2/24", "198.51.100.2")

	if err := netns.Set(appliance); err != nil {
		mgmtConn.Close()
		inbandConn.Close()
		t.Fatalf("restore appliance netns after opening manager sockets: %v", err)
	}
	return managerNS, inbandNS, mgmtConn, inbandConn
}

// TestPktinfoParseOOB16781 pins the pure ancillary-data round trip: a
// received IP_PKTINFO/IPV6_PKTINFO yields ifindex+local-dst, and both reply
// oob arms source the response from the polled address. The main-table
// listener's arm (pinEgress=false) must leave the egress ifindex 0 so the
// kernel routes the reply (#17832) — echoing the received ifindex pins
// userspace-delivered replies onto the xpf-usp0 reinjection TUN. The
// VRF-bound listener's arm (pinEgress=true) must echo the ingress ifindex:
// its sendmsg route lookup needs the explicit oif (#17832 regression
// verification — with ifindex 0 the VRF leg fails ENETUNREACH).
func TestPktinfoParseOOB16781(t *testing.T) {
	v4 := parsePktinfo(pktinfoOOBForTest(t, true))
	if v4.ifindex != 7 || !v4.dst.Equal(net.ParseIP("198.51.100.1")) {
		t.Fatalf("v4 pktinfo = %+v, want ifindex 7 dst 198.51.100.1", v4)
	}
	assertReplyOOB17832(t, v4.oob(false), net.ParseIP("198.51.100.1"), 0)
	assertReplyOOB17832(t, v4.oob(true), net.ParseIP("198.51.100.1"), 7)
	v6 := parsePktinfo(pktinfoOOBForTest(t, false))
	if v6.ifindex != 9 || !v6.dst.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("v6 pktinfo = %+v, want ifindex 9 dst 2001:db8::1", v6)
	}
	assertReplyOOB17832(t, v6.oob(false), net.ParseIP("2001:db8::1"), 0)
	assertReplyOOB17832(t, v6.oob(true), net.ParseIP("2001:db8::1"), 9)
	if got := parsePktinfo(nil); got.ifindex != 0 || got.dst != nil || got.oob(false) != nil {
		t.Fatalf("empty oob pktinfo = %+v, want zero with nil reply oob", got)
	}
}

// assertReplyOOB17832 decodes a reply oob produced by pktinfo.oob and
// asserts the pinned source (Spec_dst for v4, Addr for v6) is the polled
// local address and the egress ifindex equals wantIfindex (0 = unpinned
// route lookup, #17832).
func assertReplyOOB17832(t *testing.T, oob []byte, want net.IP, wantIfindex int) {
	t.Helper()
	if oob == nil {
		t.Fatalf("reply oob for %s is nil", want)
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		t.Fatalf("parse reply oob for %s: %v", want, err)
	}
	for i := range msgs {
		m := &msgs[i]
		switch {
		case m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_PKTINFO:
			if len(m.Data) < unix.SizeofInet4Pktinfo {
				t.Fatalf("short IP_PKTINFO cmsg (%d bytes) for %s", len(m.Data), want)
			}
			info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&m.Data[0]))
			if info.Ifindex != int32(wantIfindex) {
				t.Fatalf("v4 reply oob egress ifindex = %d for %s; want %d", info.Ifindex, want, wantIfindex)
			}
			if got := net.IP(info.Spec_dst[:]); !got.Equal(want.To4()) {
				t.Fatalf("v4 reply oob source = %s, want %s", got, want)
			}
			return
		case m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_PKTINFO:
			if len(m.Data) < unix.SizeofInet6Pktinfo {
				t.Fatalf("short IPV6_PKTINFO cmsg (%d bytes) for %s", len(m.Data), want)
			}
			info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&m.Data[0]))
			if info.Ifindex != uint32(wantIfindex) {
				t.Fatalf("v6 reply oob egress ifindex = %d for %s; want %d", info.Ifindex, want, wantIfindex)
			}
			if got := net.IP(info.Addr[:]); !got.Equal(want) {
				t.Fatalf("v6 reply oob source = %s, want %s", got, want)
			}
			return
		}
	}
	t.Fatalf("reply oob for %s carries no pktinfo cmsg", want)
}

func pktinfoOOBForTest(t *testing.T, v4 bool) []byte {
	t.Helper()
	if v4 {
		var info unix.Inet4Pktinfo
		info.Ifindex = 7
		copy(info.Spec_dst[:], net.ParseIP("198.51.100.1").To4())
		copy(info.Addr[:], net.ParseIP("198.51.100.1").To4())
		return unix.PktInfo4(&info)
	}
	var info unix.Inet6Pktinfo
	info.Ifindex = 9
	copy(info.Addr[:], net.ParseIP("2001:db8::1").To16())
	return unix.PktInfo6(&info)
}
