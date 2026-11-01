//go:build linux

package fabricsegment

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TapSamplerKernelCells18719 names the kernel-path cells the
// test/fabricsegment/selftest-fabricsegment-kernel_18719.sh leg forces by
// name under `unshare -rn` with XPF_REQUIRE_NETNS=1.
var TapSamplerKernelCells18719 = []string{
	"TestTapSamplerOnARealSegment18719",
	"TestTapSamplerSurvivesParentDownUp18719",
	"TestTapSamplerBoundWhileParentDown18719",
	"TestTapSamplerParentRecreated18719",
}

// TestTapSamplerOnARealSegment18719 drives the real kernel path
// (newFilteredTap, bindTap, the cBPF filter, readTap, ObserveFrame) on veth
// pairs. It runs only in an otherwise EMPTY network namespace (only "lo"),
// so it can never add interfaces to a host's namespace. Elsewhere it skips,
// or fails under XPF_REQUIRE_NETNS=1 (make test-fabricsegment-kernel).
//
// What it pins:
//   - nothing is queued between socket creation and bind: a frame from a
//     foreign source on the fabric parent AND on another interface, both
//     delivered before bind, must not be counted (an ETH_P_ALL socket()
//     would queue both);
//   - after bind, the local and peer source MACs, an xpf synthetic source,
//     an IEEE 802.1 link-constrained frame (LLDP) and a foreign frame on
//     another interface are not counted, and a foreign broadcast on the
//     fabric is;
//   - the kernel filter, not only userspace, discards the local, peer and
//     synthetic sources: PACKET_STATISTICS counts exactly the two frames
//     that pass it (LLDP and the third host).
//
// What it cannot pin: production visibility. No XDP program is attached
// here; on a fabric parent the shim runs before AF_PACKET taps, and only
// what it passes to the kernel can be seen. That is the loss gate's
// positive control.
func TestTapSamplerOnARealSegment18719(t *testing.T) {
	requireEmptyNetns(t)
	fab, fabWire := vethPair(t, "xfs0", "xfs1")
	other, otherWire := vethPair(t, "xfs2", "xfs3")

	link := linkFor(fab, fabWire)
	preBindFab := mac(t, "18:e8:29:00:00:a1")
	preBindOther := mac(t, "18:e8:29:00:00:b1")
	lldpSpeaker := mac(t, "18:e8:29:00:00:c1")
	otherHost := mac(t, "18:e8:29:00:00:e1")
	thirdHost := mac(t, "18:e8:29:00:00:d1")
	synthetic := mac(t, "02:bf:72:00:01:00")

	// Witnesses are bound with ETH_P_ALL to each receiving interface. Once a
	// witness has read a frame, the kernel's receive pass for it is over, so
	// a socket that missed it cannot get it later.
	fabWitness := boundTap(t, fab.Attrs().Index)
	otherWitness := boundTap(t, other.Attrs().Index)

	fd, err := newFilteredTap(link)
	if err != nil {
		t.Fatalf("newFilteredTap: %v", err)
	}
	defer unix.Close(fd)

	sendFrame(t, fabWire.Attrs().Index, bcastMAC, preBindFab)
	sendFrame(t, otherWire.Attrs().Index, bcastMAC, preBindOther)
	awaitSource(t, fabWitness, preBindFab)
	awaitSource(t, otherWitness, preBindOther)

	if err := bindTap(fd, link); err != nil {
		t.Fatalf("bindTap: %v", err)
	}
	tracker := NewTracker(link, nil)
	stop := startReader(t, fd, tracker)
	defer stop()

	sendFrame(t, otherWire.Attrs().Index, bcastMAC, otherHost)
	sendFrame(t, fabWire.Attrs().Index, bcastMAC, link.PeerMAC)
	sendFrame(t, fabWire.Attrs().Index, bcastMAC, link.LocalMAC)
	sendFrame(t, fabWire.Attrs().Index, bcastMAC, synthetic)
	sendFrame(t, fabWire.Attrs().Index, lldpMAC, lldpSpeaker)
	// Last on the fabric: once it is counted, every earlier fabric frame on
	// this socket has been handled.
	sendFrame(t, fabWire.Attrs().Index, bcastMAC, thirdHost)

	awaitTracked(t, tracker, thirdHost)
	if got, want := trackedSources(tracker), []string{thirdHost.String()}; !equalStrings(got, want) {
		t.Fatalf("tracked sources = %v, want exactly %v", got, want)
	}
	stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		t.Fatalf("PACKET_STATISTICS: %v", err)
	}
	if stats.Packets != 2 {
		t.Fatalf("the kernel filter accepted %d frame(s), want 2 (LLDP and the third host); "+
			"local, peer and synthetic sources must be dropped in the kernel", stats.Packets)
	}
}

// TestTapSamplerSurvivesParentDownUp18719 (#18751 review BLOCKING 1): an
// admin down/up of the fabric parent reports ENETDOWN once on the bound
// socket. The reader must keep going, so a foreign frame after the parent
// is back still raises the alarm.
func TestTapSamplerSurvivesParentDownUp18719(t *testing.T) {
	requireEmptyNetns(t)
	fab, fabWire := vethPair(t, "xfs0", "xfs1")
	link := linkFor(fab, fabWire)
	fd := openTapT(t, link)
	defer unix.Close(fd)
	tracker := NewTracker(link, nil)
	var readErr error
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { defer close(done); readErr = readTap(ctx, fd, tracker) }()
	defer func() { cancel(); <-done }()

	before := mac(t, "18:e8:29:00:01:a1")
	sendFrame(t, fabWire.Attrs().Index, bcastMAC, before)
	awaitTracked(t, tracker, before)

	if err := netlink.LinkSetDown(fab); err != nil {
		t.Fatalf("link down: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := netlink.LinkSetUp(fab); err != nil {
		t.Fatalf("link up: %v", err)
	}
	awaitOperUp(t, fab.Attrs().Name)
	select {
	case <-done:
		t.Fatalf("the reader stopped across a parent down/up: %v", readErr)
	default:
	}
	after := mac(t, "18:e8:29:00:01:b1")
	sendFrame(t, fabWire.Attrs().Index, bcastMAC, after)
	awaitTracked(t, tracker, after)
}

// TestTapSamplerBoundWhileParentDown18719 (#18751 review BLOCKING 1): a tap
// bound while the parent is down sees ENETDOWN first and must start
// watching once the parent comes up.
func TestTapSamplerBoundWhileParentDown18719(t *testing.T) {
	requireEmptyNetns(t)
	fab, fabWire := vethPair(t, "xfs0", "xfs1")
	link := linkFor(fab, fabWire)
	if err := netlink.LinkSetDown(fab); err != nil {
		t.Fatalf("link down: %v", err)
	}
	fd := openTapT(t, link)
	defer unix.Close(fd)
	tracker := NewTracker(link, nil)
	stop := startReader(t, fd, tracker)
	defer stop()
	time.Sleep(300 * time.Millisecond)
	if err := netlink.LinkSetUp(fab); err != nil {
		t.Fatalf("link up: %v", err)
	}
	awaitOperUp(t, fab.Attrs().Name)
	src := mac(t, "18:e8:29:00:02:a1")
	sendFrame(t, fabWire.Attrs().Index, bcastMAC, src)
	awaitTracked(t, tracker, src)
}

// TestTapSamplerParentRecreated18719 (#18751 review): an UNREGISTERED parent
// unbinds the tap for good (ifindex -1, never re-hooked). The link must read
// as not running instead of watching nothing while looking clean, and after
// the fabric refresh re-keys it to the re-created parent a foreign frame
// raises the alarm again.
func TestTapSamplerParentRecreated18719(t *testing.T) {
	requireEmptyNetns(t)
	fab, fabWire := vethPair(t, "xfs0", "xfs1")
	link := linkFor(fab, fabWire)
	mon := NewMonitor(runTapSampler)
	mon.backoffMin, mon.backoffMax = 200*time.Millisecond, 200*time.Millisecond
	defer mon.Stop()
	mon.Update([]Link{link})
	before := mac(t, "18:e8:29:00:03:a1")
	waitUntil(t, 5*time.Second, "the first tap armed", func() bool { return mon.trackerFor(link) != nil })
	time.Sleep(300 * time.Millisecond) // let the sampler bind
	sendFrame(t, fabWire.Attrs().Index, bcastMAC, before)
	awaitTracked(t, mon.trackerFor(link), before)

	if err := netlink.LinkDel(fab); err != nil {
		t.Fatalf("delete the parent: %v", err)
	}
	waitUntil(t, 6*time.Second, "the link reads as not running after its parent was deleted", func() bool {
		for _, a := range mon.Alarms() {
			if strings.Contains(a, "watcher is not running") {
				return true
			}
		}
		return false
	})

	fab2, fabWire2 := vethPair(t, "xfs0", "xfs1")
	link2 := linkFor(fab2, fabWire2)
	mon.Update([]Link{link2}) // the fabric refresh re-keys to the new parent
	waitUntil(t, 5*time.Second, "the re-keyed tap armed", func() bool { return mon.trackerFor(link2) != nil })
	time.Sleep(300 * time.Millisecond)
	after := mac(t, "18:e8:29:00:03:b1")
	sendFrame(t, fabWire2.Attrs().Index, bcastMAC, after)
	awaitTracked(t, mon.trackerFor(link2), after)
}

func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

var (
	bcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	lldpMAC  = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
)

// netnsUnavailable is the ONE skip site of the kernel cells: under
// XPF_REQUIRE_NETNS=1 a missing prerequisite fails instead.
func netnsUnavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if os.Getenv("XPF_REQUIRE_NETNS") != "" {
		t.Fatalf("%s (XPF_REQUIRE_NETNS is set)", msg)
	}
	t.Skipf("fabric-segment kernel cell needs an empty private netns with CAP_NET_ADMIN/CAP_NET_RAW (unshare -rn): %s", msg)
}

func requireEmptyNetns(t *testing.T) {
	t.Helper()
	links, err := netlink.LinkList()
	if err != nil {
		netnsUnavailable(t, "cannot list links: %v", err)
		return
	}
	for _, l := range links {
		if l.Attrs().Name != "lo" {
			netnsUnavailable(t, "not an empty network namespace (found %q); run under unshare -rn", l.Attrs().Name)
			return
		}
	}
}

func linkFor(fab, wire netlink.Link) Link {
	return Link{
		Name:          "fab0",
		Parent:        fab.Attrs().Name,
		ParentIfindex: fab.Attrs().Index,
		LocalMAC:      fab.Attrs().HardwareAddr,
		PeerMAC:       wire.Attrs().HardwareAddr,
	}
}

func openTapT(t *testing.T, link Link) int {
	t.Helper()
	fd, err := openTap(link)
	if err != nil {
		t.Fatalf("openTap: %v", err)
	}
	return fd
}

func startReader(t *testing.T, fd int, tracker *Tracker) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = readTap(ctx, fd, tracker) }()
	return func() { cancel(); <-done }
}

func awaitTracked(t *testing.T, tracker *Tracker, src net.HardwareAddr) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, s := range trackedSources(tracker) {
			if s == src.String() {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("a foreign frame from %s was never counted (tracked: %v)", src, trackedSources(tracker))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func awaitOperUp(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := netlink.LinkByName(name)
		if err == nil && l.Attrs().OperState == netlink.OperUp {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not come back up", name)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func vethPair(t *testing.T, a, b string) (netlink.Link, netlink.Link) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: a}, PeerName: b}); err != nil {
		if errors.Is(err, unix.EPERM) {
			netnsUnavailable(t, "no CAP_NET_ADMIN: %v", err)
			return nil, nil
		}
		t.Fatalf("add veth %s/%s: %v", a, b, err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(a); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	var out [2]netlink.Link
	for i, name := range []string{a, b} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("link %s: %v", name, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("up %s: %v", name, err)
		}
		out[i] = l
	}
	return out[0], out[1]
}

func boundTap(t *testing.T, ifindex int) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("witness socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		t.Fatalf("witness timeout: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
		t.Fatalf("witness bind: %v", err)
	}
	return fd
}

func awaitSource(t *testing.T, fd int, src net.HardwareAddr) {
	t.Helper()
	buf := make([]byte, 128)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		if n >= 12 && net.HardwareAddr(buf[6:12]).String() == src.String() {
			return
		}
	}
	t.Fatalf("witness never saw a frame from %s", src)
}

const testEtherType = 0x88b5 // IEEE 802 local experimental

func sendFrame(t *testing.T, ifindex int, dst, src net.HardwareAddr) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("sender socket: %v", err)
	}
	defer unix.Close(fd)
	frame := make([]byte, 60)
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], testEtherType)
	sa := &unix.SockaddrLinklayer{Protocol: htons(testEtherType), Ifindex: ifindex, Halen: 6}
	copy(sa.Addr[:], dst)
	if err := unix.Sendto(fd, frame, 0, sa); err != nil {
		t.Fatalf("send from %s: %v", src, err)
	}
}

func trackedSources(tr *Tracker) []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	out := make([]string, 0, len(tr.sources))
	for k := range tr.sources {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestReadTapExitDoesNotTouchAReusedFD18719 (#18751 review BLOCKING 2): once
// readTap has returned, cancelling its context must not touch the fd
// number, which an unrelated socket may own by then. The old reader left a
// goroutine that called shutdown(fd) on cancel.
func TestReadTapExitDoesNotTouchAReusedFD18719(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := readTap(ctx, fd, NewTracker(testLink(t), nil)); err == nil {
		t.Fatal("readTap on an unconnected stream socket must fail")
	}
	unix.Close(fd)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	p, q := pair[0], pair[1]
	if p != fd { // put the reader's old fd number under the new socket
		if err := unix.Dup2(p, fd); err != nil {
			t.Fatalf("dup2: %v", err)
		}
		unix.Close(p)
		p = fd
	}
	defer unix.Close(p)
	defer unix.Close(q)
	cancel()
	time.Sleep(100 * time.Millisecond)
	for _, dir := range [][2]int{{q, p}, {p, q}} {
		if _, err := unix.Write(dir[0], []byte("x")); err != nil {
			t.Fatalf("write on the reused socket: %v", err)
		}
		buf := make([]byte, 1)
		if n, err := unix.Read(dir[1], buf); n != 1 || err != nil {
			t.Fatalf("read on the reused socket: n=%d err=%v (shut down by a stale reader)", n, err)
		}
	}
}

// TestKernelCellRegistryMatchesTheLeg18719: every cell here that needs the
// private netns is in TapSamplerKernelCells18719, and the make leg forces
// exactly that list, so a new kernel cell cannot sit skipped in `make test`.
func TestKernelCellRegistryMatchesTheLeg18719(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sampler_linux_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var needNetns []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "requireEmptyNetns" {
					needNetns = append(needNetns, fn.Name.Name)
					return false
				}
			}
			return true
		})
	}
	registry := append([]string(nil), TapSamplerKernelCells18719...)
	sort.Strings(needNetns)
	sort.Strings(registry)
	if !equalStrings(needNetns, registry) {
		t.Fatalf("cells calling requireEmptyNetns %v != TapSamplerKernelCells18719 %v", needNetns, registry)
	}
	leg, err := os.ReadFile("../../test/fabricsegment/selftest-fabricsegment-kernel_18719.sh")
	if err != nil {
		t.Fatal(err)
	}
	var forced []string
	for _, line := range strings.Split(string(leg), "\n") {
		if v, ok := strings.CutPrefix(line, "CELLS=\""); ok {
			forced = strings.Fields(strings.TrimSuffix(v, "\""))
		}
	}
	sort.Strings(forced)
	if !equalStrings(forced, registry) {
		t.Fatalf("the make leg forces %v, the registry lists %v", forced, registry)
	}
}
