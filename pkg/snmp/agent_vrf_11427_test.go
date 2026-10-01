package snmp

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// TestSNMPManagementVRFReplyAndTrap11427 reproduces the transport failure
// from #11427 with a manager reachable only through table 999. It re-execs
// while its locked thread is in the appliance namespace so all child runtime
// threads see the VRF device used by ListenConfig and Dialer.Control.
func TestSNMPManagementVRFReplyAndTrap11427(t *testing.T) {
	if os.Getenv("XPF_SNMP_VRF_CHILD_11427") != "1" {
		managerNS, managerConn := snmpVRFManagerFixture11427(t)
		defer managerNS.Close()
		defer managerConn.Close()

		if err := os.WriteFile("/proc/sys/net/ipv4/udp_l3mdev_accept", []byte("1"), 0644); err != nil {
			t.Skipf("cannot enable UDP VRF receive acceptance in the private netns: %v", err)
		}
		managerFile, err := managerConn.File()
		if err != nil {
			t.Fatalf("duplicate manager socket for isolated child: %v", err)
		}
		defer managerFile.Close()
		cmd := exec.Command(os.Args[0], "-test.run=^TestSNMPManagementVRFReplyAndTrap11427$", "-test.v")
		childEnv := make([]string, 0, len(os.Environ())+1)
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "XPF_SNMP_VRF_CHILD_11427=") {
				childEnv = append(childEnv, entry)
			}
		}
		cmd.Env = append(childEnv, "XPF_SNMP_VRF_CHILD_11427=1")
		cmd.ExtraFiles = []*os.File{managerFile}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated SNMP VRF scenario failed: %v\n%s", err, output)
		}
		t.Logf("isolated SNMP VRF scenario:\n%s", output)
		return
	}

	managerFile := os.NewFile(3, "manager-udp")
	if managerFile == nil {
		t.Fatal("manager UDP socket was not passed to isolated child")
	}
	managerPacketConn, err := net.FilePacketConn(managerFile)
	_ = managerFile.Close()
	if err != nil {
		t.Fatalf("adopt manager UDP socket: %v", err)
	}
	managerConn, ok := managerPacketConn.(*net.UDPConn)
	if !ok {
		managerPacketConn.Close()
		t.Fatalf("manager socket type = %T, want *net.UDPConn", managerPacketConn)
	}
	t.Cleanup(func() { managerConn.Close() })

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

	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 161}
	manager := managerConn.LocalAddr().(*net.UDPAddr)
	t.Run("poll reply uses management path and source", func(t *testing.T) {
		if err := managerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		request := buildV2cGetRequest("public", 11427, oidSysDescr)
		if _, err := managerConn.WriteToUDP(request, server); err != nil {
			t.Fatalf("send manager poll: %v", err)
		}
		buf := make([]byte, maxPacketSize)
		n, peer, err := managerConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("#11427: manager reachable only through vrf-mgmt did not receive an SNMP reply: %v", err)
		}
		if n == 0 || !peer.IP.Equal(server.IP) {
			t.Fatalf("reply peer/source = %v with %d bytes, want %s with a non-empty reply", peer, n, server.IP)
		}
	})

	t.Run("trap reaches management-only receiver", func(t *testing.T) {
		if err := managerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		target := net.JoinHostPort(manager.IP.String(), strconv.Itoa(manager.Port))
		if agent.trapSender == nil {
			t.Fatal("constructed agent has no trap sender")
		}
		pkt := agent.buildLinkTrapV1("public", target, true, 1, "fxp0")
		if got := decodeAgentAddr9123(t, pkt); !got.Equal(net.ParseIP("192.0.2.1")) {
			t.Fatalf("v1 agent-addr = %v, want management source 192.0.2.1", got)
		}
		if err := agent.trapSender(target, pkt); err != nil {
			t.Fatalf("#11427: trap to receiver reachable only through vrf-mgmt failed: %v", err)
		}
		buf := make([]byte, 64)
		n, peer, err := managerConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("#11427: management-only receiver did not receive trap: %v", err)
		}
		if n == 0 || !peer.IP.Equal(net.ParseIP("192.0.2.1")) {
			t.Fatalf("trap length/source = %d bytes from %v, want a non-empty trap from 192.0.2.1", n, peer)
		}
	})
}

// snmpVRFManagerFixture11427 builds two isolated routing contexts joined by a
// veth: the SNMP appliance owns fxp0 in vrf-mgmt/table 999; the manager lives
// outside that VRF, so an unbound UDP reply or trap has no main-table route.
func snmpVRFManagerFixture11427(t *testing.T) (netns.NsHandle, *net.UDPConn) {
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
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "fxp0"
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: "manager0"}); err != nil {
		t.Skipf("cannot create management veth: %v", err)
	}
	fxp0, err := netlink.LinkByName("fxp0")
	if err != nil {
		t.Fatalf("find fxp0: %v", err)
	}
	manager0, err := netlink.LinkByName("manager0")
	if err != nil {
		t.Fatalf("find manager veth: %v", err)
	}
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
	if err := netlink.LinkSetMaster(fxp0, vrf); err != nil {
		t.Fatalf("enslave fxp0 into vrf-mgmt: %v", err)
	}
	addr, err := netlink.ParseAddr("192.0.2.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(fxp0, addr); err != nil {
		t.Fatalf("assign management address: %v", err)
	}
	if err := netlink.LinkSetUp(fxp0); err != nil {
		t.Fatalf("bring fxp0 up: %v", err)
	}

	if err := netns.Set(managerNS); err != nil {
		t.Fatalf("enter manager netns: %v", err)
	}
	manager0, err = netlink.LinkByName("manager0")
	if err != nil {
		t.Fatalf("find moved manager veth: %v", err)
	}
	addr, err = netlink.ParseAddr("192.0.2.2/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(manager0, addr); err != nil {
		t.Fatalf("assign manager address: %v", err)
	}
	if err := netlink.LinkSetUp(manager0); err != nil {
		t.Fatalf("bring manager veth up: %v", err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find manager loopback: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("bring manager loopback up: %v", err)
	}
	managerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.2")})
	if err != nil {
		t.Fatalf("listen on manager address: %v", err)
	}
	if err := netns.Set(appliance); err != nil {
		managerConn.Close()
		t.Fatalf("restore appliance netns after opening manager socket: %v", err)
	}
	return managerNS, managerConn
}
