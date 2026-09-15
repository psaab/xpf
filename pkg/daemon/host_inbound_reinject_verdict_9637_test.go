package daemon

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"golang.org/x/sys/unix"
)

// TestHostInboundReinjectTunVerdicts9637 is the F1 kernel-verdict witness
// for operator narrowing: packets arriving on the TRUSTED reinject TUN
// (xpf-usp0, gate-passed) to view addresses are ACCEPTED, while packets
// arriving on the DELEGATED TUN (xpf-usp1 — every D2/D3/D4/NAT-T shape)
// to the SAME addresses meet the destination rules and are DENIED. The Go
// render (oracle) is loaded into a real kernel table in a private netns;
// SYNs are written straight into held TUN fds (exactly how the userspace
// dataplane reinjects), so the iifname the chain judges is real.
//
// Cells: usp0→wan-ssh ACCEPT (authorized control); usp1→wan-ssh DENY at
// the owner-zone drop; usp1→unzoned DENY at the catch-all; v6 twins of
// the accept and the unzoned deny. Verdicts are read off the named
// counters (accept vs deny), not the wire — with no listener the RST
// never returns either way (xpf_dp_rst), which is why counters decide.
const netnsTunVerdict9637 = "XPF_NETNS_TUN_VERDICT_9637"

func TestHostInboundReinjectTunVerdicts9637(t *testing.T) {
	if os.Getenv(netnsTunVerdict9637) == "1" {
		hostInboundReinjectVerdictNetnsChild9637(t)
		return
	}
	if findNft() == "" {
		t.Skip("nft not found")
	}
	for _, tool := range []string{"unshare", "ip", "nsenter", "timeout", "bash", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0],
		"-test.run", "^TestHostInboundReinjectTunVerdicts9637$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), netnsTunVerdict9637+"=1")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "NETNS-TUN-STARTED-9637") {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("netns unavailable (%v): %s", err, out)
		}
		t.Fatalf("netns child never started (%v): %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-TUN-PASSED-9637") {
		t.Fatalf("tun-verdict cell failed inside the namespace (%v):\n%s", err, out)
	}
}

// tunIfreq is struct ifreq for TUNSETIFF (16-byte name + flags).
type tunIfreq9637 struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

func openTun9637(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	var req tunIfreq9637
	copy(req.name[:], name)
	req.flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		t.Fatalf("TUNSETIFF %s: %v", name, errno)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func ipChecksum(hdr []byte) {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(hdr[10:12], ^uint16(sum))
}

func tcpChecksumV4(tcp, src, dst []byte) {
	sum := uint32(6) + uint32(len(tcp))
	for _, b := range [][]byte{src, dst} {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	for i := 0; i+1 < len(tcp); i += 2 {
		if i == 16 {
			continue // checksum field itself
		}
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))
}

func tcpChecksumV6(tcp, src, dst []byte) {
	sum := uint32(len(tcp)) + 6
	for _, b := range [][]byte{src, dst} {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	for i := 0; i+1 < len(tcp); i += 2 {
		if i == 16 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(tcp[i:]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))
}

func synV4(src, dst string, sport uint16, seq uint32) []byte {
	s, d := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], s)
	copy(ip[16:20], d)
	ipChecksum(ip)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], 22)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	tcpChecksumV4(tcp, s, d)
	return append(ip, tcp...)
}

func synV6(src, dst string, sport uint16, seq uint32) []byte {
	s, d := net.ParseIP(src).To16(), net.ParseIP(dst).To16()
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 20)
	ip[6] = 6
	ip[7] = 64
	copy(ip[8:24], s)
	copy(ip[24:40], d)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], 22)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	tcpChecksumV6(tcp, s, d)
	return append(ip, tcp...)
}

func nftCounterMap9637(t *testing.T) map[string]uint64 {
	t.Helper()
	out, err := exec.Command(findNft(), "list", "table", "inet", xnft.HostInboundTableName).CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table: %v: %s", err, out)
	}
	m := map[string]uint64{}
	cur := ""
	for _, l := range strings.Split(string(out), "\n") {
		s := strings.TrimSpace(l)
		if strings.HasPrefix(s, "counter ") {
			f := strings.Fields(s)
			if len(f) >= 2 {
				cur = strings.TrimSuffix(f[1], "{")
				cur = strings.TrimSpace(cur)
			}
			continue
		}
		if cur != "" && strings.HasPrefix(s, "packets ") {
			var n uint64
			fmt.Sscanf(s, "packets %d", &n)
			m[cur] = n
			cur = ""
		}
	}
	return m
}

func expectCounterDelta9637(t *testing.T, name string, before, delta uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := nftCounterMap9637(t)[name]; got-before == delta {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("counter %s moved to %d, want exactly +%d from %d",
				name, nftCounterMap9637(t)[name], delta, before)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func hostInboundReinjectVerdictNetnsChild9637(t *testing.T) {
	fmt.Println("NETNS-TUN-STARTED-9637")
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
		}
	}
	run("ip", "link", "set", "lo", "up")
	// View + unzoned addresses are local (as on the firewall). Reverse-path
	// filtering would drop TUN arrivals whose source has no route via the
	// ARRIVAL device, so each outlet gets its own probe source routed via
	// itself — strict, loose and disabled rp_filter all pass, with no
	// sysctl writes (conf/all is host-global, not namespaced).
	for _, a := range []string{"10.0.61.1/32", "172.16.80.8/32", "10.0.99.1/32"} {
		run("ip", "addr", "add", a, "dev", "lo")
	}
	for _, a := range []string{"2001:db8:61::1/128", "2001:db8:99::1/128"} {
		run("ip", "addr", "add", a, "dev", "lo")
	}
	usp0 := openTun9637(t, xnft.HostInboundReinjectIfname)
	usp1 := openTun9637(t, xnft.HostInboundDelegatedIfname)
	for _, dev := range []string{xnft.HostInboundReinjectIfname, xnft.HostInboundDelegatedIfname} {
		run("ip", "link", "set", dev, "up")
	}
	run("ip", "route", "add", "10.0.61.100/32", "dev", xnft.HostInboundReinjectIfname)
	run("ip", "route", "add", "10.0.61.101/32", "dev", xnft.HostInboundDelegatedIfname)
	run("ip", "route", "add", "2001:db8:61::100/128", "dev", xnft.HostInboundReinjectIfname)
	run("ip", "route", "add", "2001:db8:61::101/128", "dev", xnft.HostInboundDelegatedIfname)
	views, unzonedV4, unzonedV6 := reinjectViews9637()
	payload := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, true)
	cmd := exec.Command(findNft(), "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v: %s", err, out)
	}

	reinject := xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptReinject)
	wanDeny := xnft.HostInboundDenyCounterName("wan", "ip")
	unzonedDenyV4 := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, "ip")
	unzonedDenyV6 := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, "ip6")
	write := func(f *os.File, pkt []byte) {
		t.Helper()
		if _, err := f.Write(pkt); err != nil {
			t.Fatalf("tun write: %v", err)
		}
	}
	seq := uint32(1000)

	// A1 (authorized ACCEPT control): gated-LocalDelivery-shaped arrival on
	// the trusted TUN is accepted to the view address.
	before := nftCounterMap9637(t)[reinject]
	write(usp0, synV4("10.0.61.100", "172.16.80.8", 40001, seq))
	seq++
	expectCounterDelta9637(t, reinject, before, 1)

	// D1 (D2/D3/D4b/NAT-T shape): the SAME packet arriving on the delegated
	// TUN meets the owner-zone destination deny, and the accept does not move.
	before, beforeDeny := nftCounterMap9637(t)[reinject], nftCounterMap9637(t)[wanDeny]
	write(usp1, synV4("10.0.61.101", "172.16.80.8", 40002, seq))
	seq++
	expectCounterDelta9637(t, wanDeny, beforeDeny, 1)
	if got := nftCounterMap9637(t)[reinject]; got != before {
		t.Fatalf("delegated arrival must not touch the accept counter, moved %d -> %d", before, got)
	}

	// D2: unzoned destination on the delegated TUN meets the catch-all.
	beforeDeny = nftCounterMap9637(t)[unzonedDenyV4]
	write(usp1, synV4("10.0.61.101", "10.0.99.1", 40003, seq))
	seq++
	expectCounterDelta9637(t, unzonedDenyV4, beforeDeny, 1)

	// A2/D3 v6 twins: trusted accept carries the v6 view address; the
	// unzoned v6 catch-all judges delegated arrivals.
	before = nftCounterMap9637(t)[reinject]
	write(usp0, synV6("2001:db8:61::100", "2001:db8:61::1", 40004, seq))
	seq++
	expectCounterDelta9637(t, reinject, before, 1)
	beforeDeny = nftCounterMap9637(t)[unzonedDenyV6]
	write(usp1, synV6("2001:db8:61::101", "2001:db8:99::1", 40005, seq))
	seq++
	expectCounterDelta9637(t, unzonedDenyV6, beforeDeny, 1)
	_ = seq

	fmt.Println("NETNS-TUN-PASSED-9637")
}
