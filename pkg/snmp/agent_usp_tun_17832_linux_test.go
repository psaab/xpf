//go:build linux

package snmp

import (
	"context"
	"encoding/binary"
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

// Test class: N (netns-kernel). This cell builds a private network namespace
// (veth + TUN + per-netns sysctls) and self-re-execs the test binary for the
// agent leg, mirroring TestSNMPInbandPollWithManagementVRF16781. On the
// workstation it runs unprivileged under `unshare -Urn go test` only; without
// CAP_NET_ADMIN it skips (NOT-EXAMINED is the honest local outcome there).
// It never touches the initial namespace: netns isolation is asserted
// in-test on the locked fixture thread before any kernel mutation.

// TestSNMPUserspaceTUNPollAnswered17832 is the #17832 defect cell: an SNMP
// request the kernel receives through a write-only reinjection TUN (the
// xpf-usp0 shape of userspace AF_XDP local delivery) must still be answered
// on the wire. The request is injected into the TUN so the kernel sees
// ingress on the TUN while the datagram is addressed to the data-interface
// address 198.51.100.1 (trust0); the manager is reachable only through
// trust0. No management VRF is configured, so the agent runs the single
// unbound listener — exactly the default deployment that userspace
// forwarding appliances use.
//
// RED pre-fix: the reply's pktinfo echoes the received (TUN) ifindex as
// egress, so WriteMsgUDP strands the reply on the write-only TUN — the
// manager's poll times out. GREEN post-fix: the reply oob pins only the
// source, egress is a route lookup through trust0, and every poll is
// answered from 198.51.100.1.
func TestSNMPUserspaceTUNPollAnswered17832(t *testing.T) {
	if os.Getenv("XPF_SNMP_USP_CHILD_17832") != "1" {
		inbandNS, mgrConn, tunFile := snmpUSPTUNFixture17832(t)
		defer inbandNS.Close()
		defer mgrConn.Close()
		defer tunFile.Close()

		mgrFile, err := mgrConn.File()
		if err != nil {
			t.Fatalf("duplicate TUN manager socket: %v", err)
		}
		defer mgrFile.Close()
		cmd := exec.Command(os.Args[0], "-test.run=^TestSNMPUserspaceTUNPollAnswered17832$", "-test.v")
		childEnv := make([]string, 0, len(os.Environ())+1)
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "XPF_SNMP_USP_CHILD_17832=") {
				childEnv = append(childEnv, entry)
			}
		}
		cmd.Env = append(childEnv, "XPF_SNMP_USP_CHILD_17832=1")
		cmd.ExtraFiles = []*os.File{mgrFile, tunFile}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated SNMP userspace-TUN scenario failed: %v\n%s", err, output)
		}
		t.Logf("isolated SNMP userspace-TUN scenario:\n%s", output)
		return
	}

	// Child: runs in the appliance netns inherited from the locked fixture
	// thread that forked it (same argument as the #16781 cell).
	f := os.NewFile(3, "usp-manager-udp")
	if f == nil {
		t.Fatal("manager socket was not passed to isolated child")
	}
	pc, err := net.FilePacketConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("adopt manager socket: %v", err)
	}
	mgrConn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		t.Fatalf("manager socket type = %T, want *net.UDPConn", pc)
	}
	t.Cleanup(func() { mgrConn.Close() })
	tunFile := os.NewFile(4, "usp-reinject-tun")
	if tunFile == nil {
		t.Fatal("TUN fd was not passed to isolated child")
	}
	t.Cleanup(func() { tunFile.Close() })

	agent := NewAgentWithPaths(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	}, filepath.Join(t.TempDir(), "engineboots"), filepath.Join(t.TempDir(), "engine-id"))
	if err := agent.Bind(context.Background()); err != nil {
		t.Fatalf("bind SNMP agent: %v", err)
	}
	t.Cleanup(agent.Stop)
	go agent.Serve()

	mgrLocal, ok := mgrConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("manager local address = %T, want *net.UDPAddr", mgrConn.LocalAddr())
	}
	for i := range 3 {
		if err := mgrConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		req := buildV2cGetRequest("public", 17832+i, oidSysDescr)
		pkt := craftIPv4UDP17832(
			net.ParseIP("198.51.100.2"), mgrLocal.Port,
			net.ParseIP("198.51.100.1"), 161, req)
		if _, err := tunFile.Write(pkt); err != nil {
			t.Fatalf("inject poll %d into the reinjection TUN: %v", i, err)
		}
		buf := make([]byte, maxPacketSize)
		n, peer, err := mgrConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("poll %d injected via the reinjection TUN was not answered (reply pinned into the write-only TUN?): %v", i, err)
		}
		if n == 0 || !peer.IP.Equal(net.ParseIP("198.51.100.1")) {
			t.Fatalf("poll %d reply peer/source = %v with %d bytes, want 198.51.100.1 with a non-empty reply", i, peer, n)
		}
	}
}

// snmpUSPTUNFixture17832 builds the appliance netns: trust0 (198.51.100.1/24)
// facing an in-band manager netns (198.51.100.2/24 on inband0), plus the
// write-only reinjection TUN (no addresses, no routes — the xpf-usp0 shape).
// It returns the manager netns, the manager UDP socket and the TUN file (both
// fd-passed to the isolated child).
func snmpUSPTUNFixture17832(t *testing.T) (netns.NsHandle, *net.UDPConn, *os.File) {
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
	// Class-N isolation assert: the fixture must be inside its own netns
	// before any kernel mutation — never the initial (host) namespace.
	if cur, err := netns.Get(); err != nil || cur == original {
		t.Fatalf("class N cell is not namespace-isolated (cur=%v err=%v): refusing to mutate a shared namespace", cur, err)
	} else {
		cur.Close()
	}
	t.Cleanup(func() {
		_ = netns.Set(original)
		_ = appliance.Close()
		_ = original.Close()
		runtime.UnlockOSThread()
	})

	attrs := netlink.NewLinkAttrs()
	attrs.Name = "trust0"
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: "inband0"}); err != nil {
		t.Skipf("cannot create veth trust0/inband0: %v", err)
	}
	trust0, err := netlink.LinkByName("trust0")
	if err != nil {
		t.Fatalf("find trust0: %v", err)
	}
	trustAddr, err := netlink.ParseAddr("198.51.100.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(trust0, trustAddr); err != nil {
		t.Fatalf("assign 198.51.100.1/24: %v", err)
	}
	if err := netlink.LinkSetUp(trust0); err != nil {
		t.Fatalf("bring trust0 up: %v", err)
	}

	// The write-only reinjection TUN, under its production name so the
	// agent's isUserspaceReinjectTUN check sees exactly what it will see on
	// an AF_XDP-forwarding appliance. Production xpf-usp0 carries no route
	// to managers; a reply whose egress is pinned here can never leave.
	tunFile := openReinjectTUN17832(t, "xpf-usp0")
	usp0, err := netlink.LinkByName("xpf-usp0")
	if err != nil {
		t.Fatalf("find xpf-usp0: %v", err)
	}
	if err := netlink.LinkSetUp(usp0); err != nil {
		t.Fatalf("bring xpf-usp0 up: %v", err)
	}
	// The injected request's source (198.51.100.2) routes back via trust0,
	// not via the TUN it arrives on, so strict rp_filter would silently drop
	// it before the agent ever sees it; relax it exactly like the
	// production reinjection path does.
	for _, path := range []string{
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/xpf-usp0/rp_filter",
	} {
		if err := os.WriteFile(path, []byte("0"), 0644); err != nil {
			t.Skipf("cannot relax rp_filter on %s in the private netns: %v", path, err)
		}
	}

	managerNS, err := netns.New()
	if err != nil {
		t.Skipf("cannot create manager netns: %v", err)
	}
	if err := netns.Set(appliance); err != nil {
		t.Fatalf("restore appliance netns: %v", err)
	}
	inband0, err := netlink.LinkByName("inband0")
	if err != nil {
		t.Fatalf("find inband0: %v", err)
	}
	if err := netlink.LinkSetNsFd(inband0, int(managerNS)); err != nil {
		managerNS.Close()
		t.Skipf("move in-band veth into its netns: %v", err)
	}
	if err := netns.Set(managerNS); err != nil {
		t.Fatalf("enter manager netns: %v", err)
	}
	mgrAddr, err := netlink.ParseAddr("198.51.100.2/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(inband0, mgrAddr); err != nil {
		t.Fatalf("assign 198.51.100.2/24: %v", err)
	}
	if err := netlink.LinkSetUp(inband0); err != nil {
		t.Fatalf("bring inband0 up: %v", err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find manager loopback: %v", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatalf("bring manager loopback up: %v", err)
	}
	mgrConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.51.100.2")})
	if err != nil {
		t.Fatalf("listen on manager address: %v", err)
	}
	if err := netns.Set(appliance); err != nil {
		mgrConn.Close()
		t.Fatalf("restore appliance netns after opening manager socket: %v", err)
	}
	return managerNS, mgrConn, tunFile
}

// openReinjectTUN17832 attaches a new layer-3 TUN (no packet-info prefix)
// with the given name in the current netns and returns its file. Writing to
// the file makes the kernel receive the packet on the TUN — the same
// direction the userspace datapath uses to reinject AF_XDP host-inbound
// traffic through xpf-usp0.
func openReinjectTUN17832(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("cannot open /dev/net/tun (class N cell needs a TUN): %v", err)
	}
	req := struct {
		name  [unix.IFNAMSIZ]byte
		flags uint16
	}{flags: unix.IFF_TUN | unix.IFF_NO_PI}
	copy(req.name[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		f.Close()
		t.Skipf("TUNSETIFF %s: %v", name, errno)
	}
	return f
}

// craftIPv4UDP17832 builds the raw IPv4/UDP datagram written into the TUN to
// fake userspace delivery. The UDP checksum is left zero (the legal "no
// checksum" encoding for IPv4 UDP); the IP header checksum is computed.
func craftIPv4UDP17832(src net.IP, sport int, dst net.IP, dport int, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45 // IPv4, 20-byte header
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:], 0x1783)
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:], src.To4())
	copy(pkt[16:], dst.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		if i == 10 {
			continue // checksum field itself
		}
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[10:], ^uint16(sum))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:], uint16(sport))
	binary.BigEndian.PutUint16(udp[2:], uint16(dport))
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	copy(udp[8:], payload)
	return pkt
}
