package daemon

import (
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/linuxsock"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// #17231 acceptance: TestQ53ProxyARPCloseDoesNotUnblockRecv.
//
// Pre-fix, runProxyARPResponder parked in a bare unix.Recvfrom and the
// only wake was a watcher goroutine closing the fd on ctx.Done — which
// does not wake a Recvfrom already parked on Linux. Teardown was
// cancel+delete with no join, so on a silent link the goroutine and
// its bound AF_PACKET socket leaked indefinitely, and the first frame
// after cancel was answered from the stale snapshot through whatever
// socket then owned the reused fd number.
//
// Post-fix the responder receives through linuxsock.PpollRecv
// (ppoll + wake eventfd), stop() runs cancel → SignalStop → join on
// done, the loop owns the receiver Close (so close happens after the
// join), and the loop re-checks ctx after every successful recv
// before sending.
//
// Cells:
//   - TestQ53ProxyARPCloseDoesNotUnblockRecv: namespace-gated, REAL
//     AF_PACKET responder on a veth pair. SILENT arm: done must close
//     within 100ms of cancel and zero replies may follow. CHATTY arm
//     (positive control): a peer ARP request is answered while live,
//     then after cancel a further request gets zero replies.
//   - TestProxyARPResponderStopJoinsParkedRecv17231: deterministic,
//     no namespace. A socketpair-backed PpollRecv injected via
//     openARPReceiverFn parks the real loop; syncProxyARPResponders
//     removing the interface must join it (done closed), and a frame
//     delivered after the stop is never answered.

const proxyARP17231InnerEnv = "XPF_17231_PROXYARP_INNER"

// testNetnsFD17231 is the fd of the private netns created by
// enterPrivateNetns17231, for responder goroutines to enter (below).
var testNetnsFD17231 = -1

func enterPrivateNetns17231(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read current netns (%v)", err)
	}
	ns, err := netns.New()
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private netns — needs CAP_NET_ADMIN (run under `unshare -rn` or as root): %v", err)
	}
	testNetnsFD17231 = int(ns)
	t.Cleanup(func() {
		testNetnsFD17231 = -1
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
}

// runResponder17231 runs runProxyARPResponder on a goroutine pinned
// to a thread that has entered the test netns. A plain `go` goroutine
// runs on an arbitrary thread in the process's original netns, where
// the veth names do not resolve (measured: InterfaceByName returns
// "no such network interface" off the locked thread). Entering by fd
// keeps the socket open inside the private netns.
func runResponder17231(d *Daemon, ctx context.Context, ifName string, r *proxyARPResponder) {
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if testNetnsFD17231 >= 0 {
			_ = netns.Set(netns.NsHandle(testNetnsFD17231))
		}
		d.runProxyARPResponder(ctx, ifName, r)
	}()
}

// TestQ53ProxyARPCloseDoesNotUnblockRecv is the namespace-gated
// AF_PACKET acceptance test for #17231 (name preserved from the
// reporter's probe). The outer invocation re-executes the test binary
// under `unshare -rn` when not already privileged.
func TestQ53ProxyARPCloseDoesNotUnblockRecv(t *testing.T) {
	if os.Getenv(proxyARP17231InnerEnv) == "1" {
		runQ53ProxyARP(t)
		return
	}
	if os.Geteuid() == 0 {
		runQ53ProxyARP(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("acceptance skipped: unshare is not available")
	}
	cmd := exec.Command(unshare, "-rn", os.Args[0], "-test.run",
		"^TestQ53ProxyARPCloseDoesNotUnblockRecv$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), proxyARP17231InnerEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("private-netns proxyarp output:\n%s", out)
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") ||
			strings.Contains(string(out), "unshare:") {
			t.Skipf("acceptance skipped: cannot create private namespace: %v", err)
		}
		t.Fatalf("private-netns proxyarp acceptance failed: %v", err)
	}
}

func htons17231(v uint16) uint16 { return v<<8 | v>>8 }

func runQ53ProxyARP(t *testing.T) {
	enterPrivateNetns17231(t)

	const (
		localName = "xpf17231a"
		peerName  = "xpf17231b"
	)
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: localName}, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("acceptance skipped: cannot create veth pair: %v", err)
		}
		t.Fatalf("create veth pair: %v", err)
	}
	for _, name := range []string{localName, peerName} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatalf("raise %s: %v", name, err)
		}
	}
	var peerIface *net.Interface
	visDeadline := time.Now().Add(5 * time.Second)
	for {
		_, lerr := net.InterfaceByName(localName)
		pIface, perr := net.InterfaceByName(peerName)
		if lerr == nil && perr == nil {
			peerIface = pIface
			break
		}
		if time.Now().After(visDeadline) {
			t.Fatalf("veth ends not visible: local err=%v peer err=%v", lerr, perr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	poolIP := net.IP{10, 231, 0, 7}
	askerIP := net.IP{10, 231, 0, 174}
	askerMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	var replies atomic.Int32
	prevSend := arpReplySend
	arpReplySend = func(fd int, pkt []byte, addr unix.Sockaddr) error {
		replies.Add(1)
		return prevSend(fd, pkt, addr)
	}
	t.Cleanup(func() { arpReplySend = prevSend })

	newResponder := func() (*Daemon, *proxyARPResponder, context.Context) {
		d := &Daemon{arpResponders: newProxyARPResponders()}
		ctx, cancel := context.WithCancel(context.Background())
		r := &proxyARPResponder{
			cancel:   cancel,
			done:     make(chan struct{}),
			junosRef: localName,
			addrs:    map[string]struct{}{poolIP.String(): {}},
		}
		return d, r, ctx
	}
	waitPublished := func(r *proxyARPResponder) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			r.recvMu.Lock()
			ok := r.recv != nil
			r.recvMu.Unlock()
			if ok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("responder never published its receiver (socket open failed?)")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// SILENT arm (RED pre-fix): start, park on the silent link,
	// cancel, and done must close within 100ms with zero replies.
	dSilent, rSilent, ctxSilent := newResponder()
	runResponder17231(dSilent, ctxSilent, localName, rSilent)
	waitPublished(rSilent)
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	rSilent.stop()
	select {
	case <-rSilent.done:
	default:
		t.Fatal("stop returned but done is not closed — join is broken")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("silent responder done took %v after cancel, want <100ms (#17231)", elapsed)
	}
	if got := replies.Load(); got != 0 {
		t.Fatalf("silent arm sent %d replies, want 0", got)
	}

	// CHATTY arm (positive control): a peer ARP request for the pool
	// address is answered while live; after cancel, a further request
	// gets zero replies.
	peerFD, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons17231(unix.ETH_P_ARP)))
	if err != nil {
		t.Fatalf("peer socket: %v", err)
	}
	defer unix.Close(peerFD)
	if err := unix.Bind(peerFD, &unix.SockaddrLinklayer{
		Protocol: htons17231(unix.ETH_P_ARP),
		Ifindex:  peerIface.Index,
	}); err != nil {
		t.Fatalf("peer bind: %v", err)
	}

	dChatty, rChatty, ctxChatty := newResponder()
	runResponder17231(dChatty, ctxChatty, localName, rChatty)
	waitPublished(rChatty)

	frame := arpRequestFrame(askerMAC, askerIP, poolIP)
	dst := &unix.SockaddrLinklayer{Protocol: htons17231(unix.ETH_P_ARP), Ifindex: peerIface.Index, Halen: 6}
	copy(dst.Addr[:], net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	deadline := time.Now().Add(2 * time.Second)
	for replies.Load() == 0 {
		if err := unix.Sendto(peerFD, frame, 0, dst); err != nil {
			t.Fatalf("peer sendto: %v", err)
		}
		pollUntil := time.Now().Add(200 * time.Millisecond)
		for replies.Load() == 0 && time.Now().Before(pollUntil) {
			time.Sleep(5 * time.Millisecond)
		}
		if time.Now().After(deadline) {
			t.Fatal("chatty arm: live responder never answered the pool ARP request (positive control broken)")
		}
	}

	before := replies.Load()
	rChatty.stop()
	if err := unix.Sendto(peerFD, frame, 0, dst); err != nil {
		t.Fatalf("peer sendto after stop: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := replies.Load(); got != before {
		t.Fatalf("after cancel the stopped responder sent %d more repl(ies), want 0 (#17231)", got-before)
	}
}

// TestProxyARPResponderStopJoinsParkedRecv17231 is the deterministic
// join cell: a socketpair-backed receiver parks the real responder
// loop, removing the interface via syncProxyARPResponders must join
// it, and a frame delivered afterwards is never answered.
func TestProxyARPResponderStopJoinsParkedRecv17231(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	peerFD := fds[1]
	defer unix.Close(peerFD)
	wakeFD, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		unix.Close(fds[0])
		t.Fatalf("eventfd: %v", err)
	}
	recv := linuxsock.NewPpollRecvForTest(fds[0], wakeFD)

	prevOpen := openARPReceiverFn
	openARPReceiverFn = func(_ string) (*linuxsock.PpollRecv, int, net.HardwareAddr, error) {
		return recv, 42, net.HardwareAddr{0x02, 0xbf, 0x72, 0x16, 0x01, 0x00}, nil
	}
	t.Cleanup(func() { openARPReceiverFn = prevOpen })

	var replies atomic.Int32
	prevSend := arpReplySend
	arpReplySend = func(_ int, pkt []byte, addr unix.Sockaddr) error {
		replies.Add(1)
		return nil
	}
	t.Cleanup(func() { arpReplySend = prevSend })

	d := &Daemon{arpResponders: newProxyARPResponders()}
	cfg := proxyARPCfg("reth0.80", "172.16.80.7/32")
	d.syncProxyARPResponders(cfg, map[string][]string{"ge-0-0-2.80": {"reth0.80"}})
	r, ok := d.arpResponders.running["ge-0-0-2.80"]
	if !ok {
		t.Fatal("responder was not started by sync")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.recvMu.Lock()
		parked := r.recv != nil
		r.recvMu.Unlock()
		if parked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("responder never published its receiver")
		}
		time.Sleep(5 * time.Millisecond)
	}

	d.syncProxyARPResponders(cfg, map[string][]string{})
	select {
	case <-r.done:
	default:
		t.Fatal("sync returned without joining the parked responder — done not closed (#17231)")
	}
	if len(d.arpResponders.running) != 0 {
		t.Fatalf("running still holds %d entries after removal", len(d.arpResponders.running))
	}

	frame := arpRequestFrame(
		net.HardwareAddr{0x10, 0x66, 0x6a, 0x8b, 0x91, 0xa4},
		net.IP{172, 16, 80, 174}, net.IP{172, 16, 80, 7})
	_, _ = unix.Write(peerFD, frame)
	time.Sleep(200 * time.Millisecond)
	if got := replies.Load(); got != 0 {
		t.Fatalf("stopped responder answered %d frame(s) after join, want 0 (#17231)", got)
	}
}
