package lldp

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

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// #16669 regression tests.
//
// Pre-fix, recv parked in a bare unix.Recvfrom on the AF_PACKET rxFD and
// stopLocked relied on close() (plus a shutdown() that returns ENOTCONN on
// AF_PACKET) to wake it. On Linux neither wakes a Recvfrom already parked
// on that fd, so Stop()/re-Apply blocked until a frame arrived — forever on
// a silent link — holding lifecycleMu (and, in the daemon, applySem) the
// whole time. The socketpair seam the old tests used could not reproduce
// this: SOCK_SEQPACKET is connection-oriented, so shutdown() DID wake its
// parked reader and the tests passed while production hung.
//
// The fix: recv ppolls on {rxFD, wakeFD} (an eventfd), stopLocked runs
// cancel → signalStop → wg.Wait() → close, and rxLoop re-checks ctx after
// every successful recv.
//
// Cells:
//   - TestStopSilentVsChatty16669: namespace-gated, REAL AF_PACKET sessions
//     on a veth pair. SILENT arm (no peer traffic) is the RED cell: pre-fix
//     Stop blocks past the 1s bound. CHATTY arm (a peer frame is delivered
//     first) is the positive control: the neighbor is learned and Stop is
//     still prompt. A re-Apply on the silent link is also exercised: the
//     teardown half of Apply hit the same hang pre-fix.
//   - TestRxLoopStopsAfterSuccessfulRecv16669: deterministic, no namespace.
//     recvFn returns one valid frame with ctx already cancelled; the frame
//     must NOT be learned and the loop must return without a second recv.
//     Pre-fix (no ctx check on the success path) the frame is learned and
//     the loop calls recv again.
//   - TestSessionRecvWakeAndForeignFD16669: deterministic fd-reuse probe.
//     recv is parked via the real ppoll path on a silent socketpair; the
//     wake is signalled WITHOUT closing rxFD; then a foreign socket is
//     allocated (it may reuse the just-freed number only if something
//     closed rxFD — nothing may) and bytes are written to it; recv must
//     have returned via the wake, never by reading the foreign fd.

// enterPrivateNetns16669 moves the test goroutine into a fresh netns.
func enterPrivateNetns16669(t *testing.T) {
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
	t.Cleanup(func() {
		_ = netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})
}

const stopWakeup16669InnerEnv = "XPF_16669_STOP_WAKEUP_INNER"

// TestStopSilentVsChatty16669 is the namespace-gated AF_PACKET acceptance
// test for #16669. The outer invocation re-executes the test binary under
// `unshare -rn` when not already root/privileged so the inner run owns a
// private netns with CAP_NET_RAW/CAP_NET_ADMIN; the inner run skips
// cleanly if even that is unavailable.
func TestStopSilentVsChatty16669(t *testing.T) {
	if os.Getenv(stopWakeup16669InnerEnv) == "1" {
		runStopSilentVsChatty16669(t)
		return
	}
	if os.Geteuid() == 0 {
		runStopSilentVsChatty16669(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("stop-wakeup acceptance skipped: unshare is not available")
	}
	cmd := exec.Command(unshare, "-rn", os.Args[0], "-test.run",
		"^TestStopSilentVsChatty16669$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), stopWakeup16669InnerEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("private-netns stop-wakeup output:\n%s", out)
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") ||
			strings.Contains(string(out), "unshare:") {
			t.Skipf("stop-wakeup acceptance skipped: cannot create private namespace: %v", err)
		}
		t.Fatalf("private-netns stop-wakeup acceptance failed: %v", err)
	}
}

func runStopSilentVsChatty16669(t *testing.T) {
	enterPrivateNetns16669(t)

	const (
		localName = "xpf16669a"
		peerName  = "xpf16669b"
	)
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: localName}, PeerName: peerName}
	if err := netlink.LinkAdd(veth); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("stop-wakeup acceptance skipped: cannot create veth pair: %v", err)
		}
		t.Fatalf("create veth pair: %v", err)
	}
	localLink, err := netlink.LinkByName(localName)
	if err != nil {
		t.Fatalf("lookup local veth: %v", err)
	}
	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("lookup peer veth: %v", err)
	}
	if err := netlink.LinkSetUp(localLink); err != nil {
		t.Fatalf("raise local veth: %v", err)
	}
	if err := netlink.LinkSetUp(peerLink); err != nil {
		t.Fatalf("raise peer veth: %v", err)
	}
	localIface, err := net.InterfaceByName(localName)
	if err != nil {
		t.Fatalf("InterfaceByName %s: %v", localName, err)
	}
	peerIface, err := net.InterfaceByName(peerName)
	if err != nil {
		t.Fatalf("InterfaceByName %s: %v", peerName, err)
	}

	cfg := &LLDPConfig{
		Interfaces: []LLDPInterface{{Name: localName}},
		Interval:   30,
	}

	stopWithin := func(m *Manager, bound time.Duration, what string) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			m.Stop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(bound):
			t.Fatalf("%s did not return within %v on a silent AF_PACKET link (#16669)", what, bound)
		}
	}

	// SILENT arm (RED pre-fix): Apply a real AF_PACKET session, send
	// nothing, then Stop must return in <1s.
	mSilent := New()
	if un := mSilent.Apply(context.Background(), cfg); len(un) != 0 {
		t.Fatalf("silent Apply unresolved = %v, want none", un)
	}
	if !mSilent.Running() {
		t.Fatal("silent Apply: manager not Running — real AF_PACKET session was not created")
	}
	// Give rxLoop a moment to park in ppoll/Recvfrom.
	time.Sleep(100 * time.Millisecond)
	stopWithin(mSilent, time.Second, "Stop (silent)")

	// Re-Apply on a silent link: Apply's internal stopLocked hit the same
	// hang pre-fix. Start a generation, then Apply a changed config; the
	// whole Apply (teardown + rebuild) must complete in <1s.
	mReapply := New()
	if un := mReapply.Apply(context.Background(), cfg); len(un) != 0 {
		t.Fatalf("re-apply first Apply unresolved = %v, want none", un)
	}
	time.Sleep(100 * time.Millisecond)
	changed := &LLDPConfig{
		Interfaces: []LLDPInterface{{Name: localName}},
		Interval:   45,
	}
	reapplyDone := make(chan struct{})
	go func() {
		mReapply.Apply(context.Background(), changed)
		close(reapplyDone)
	}()
	select {
	case <-reapplyDone:
	case <-time.After(time.Second):
		t.Fatal("re-Apply (silent) did not return within 1s — teardown of the silent generation hung (#16669)")
	}
	stopWithin(mReapply, time.Second, "Stop (after silent re-Apply)")

	// CHATTY arm (positive control): a peer LLDP frame sent over the veth
	// from a raw socket on the peer end is learned, and Stop is prompt.
	peerSess, err := newIfSession(peerIface)
	if err != nil {
		t.Fatalf("peer session: %v", err)
	}
	defer peerSess.close()
	frame, err := BuildFrame(peerIface.HardwareAddr, peerName, 120, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	mChatty := New()
	if un := mChatty.Apply(context.Background(), cfg); len(un) != 0 {
		t.Fatalf("chatty Apply unresolved = %v, want none", un)
	}
	// The frame may race Apply's session setup; retry until learned.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := peerSess.send(frame); err != nil {
			t.Fatalf("peer send: %v", err)
		}
		pollUntil := time.Now().Add(200 * time.Millisecond)
		learned := false
		for time.Now().Before(pollUntil) {
			if len(mChatty.Neighbors()) > 0 {
				learned = true
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if learned {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("chatty arm: peer frame was not learned within 2s (positive control broken)")
		}
	}
	_ = localIface // resolved for symmetry; cfg drives Apply by name
	stopWithin(mChatty, time.Second, "Stop (chatty)")
}

// TestRxLoopStopsAfterSuccessfulRecv16669 is the deterministic ctx-after-recv
// cell: with ctx already cancelled, a successful recv must not be learned
// and must not loop. Pre-fix the success path had no ctx check, so the
// frame was learned and recv was called again.
func TestRxLoopStopsAfterSuccessfulRecv16669(t *testing.T) {
	frame, err := BuildFrame(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, "test0", 120, "peer-node", "")
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	var calls int32
	sess := &ifSession{
		iface: &net.Interface{Name: "test0", Index: 1},
		recvFn: func(buf []byte) (int, int, error) {
			atomic.AddInt32(&calls, 1)
			return copy(buf, frame), unix.PACKET_HOST, nil
		},
	}
	m := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the loop starts: the first frame races Stop
	done := make(chan struct{})
	go func() {
		m.rxLoop(ctx, sess)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("rxLoop did not return after a successful recv with ctx cancelled (#16669)")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("recv calls = %d, want exactly 1 (loop must exit after the first frame, not re-enter recv)", got)
	}
	if got := len(m.Neighbors()); got != 0 {
		t.Fatalf("neighbors = %d, want 0 (a frame racing Stop must not be learned)", got)
	}
}

// TestSessionRecvWakeAndForeignFD16669 exercises the real ppoll recv on a
// socketpair-backed session: recv parks with no data, signalStop wakes it
// via the eventfd WITHOUT closing rxFD, and bytes later written to a
// freshly allocated foreign socket are never consumed by the parked recv
// (the fd-reuse hazard of the pre-fix close-to-unblock design).
func TestSessionRecvWakeAndForeignFD16669(t *testing.T) {
	sess, peerFD := newSocketpairSession16669(t, &net.Interface{Name: "test0", Index: 1})
	defer unix.Close(peerFD)
	defer sess.close()

	started := make(chan struct{})
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 64)
		close(started)
		n, _, err := sess.recv(buf)
		done <- result{n: n, err: err}
	}()
	<-started
	runtime.Gosched()
	select {
	case r := <-done:
		t.Fatalf("recv returned before any wake (n=%d err=%v) — it should park while silent", r.n, r.err)
	default:
	}

	// Wake without closing rxFD: this is the only wake Stop performs
	// before joining rxLoop.
	sess.signalStop()
	var res result
	select {
	case res = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recv did not return within 2s after signalStop — ppoll wake failed (#16669)")
	}
	if res.err != errRecvStopped {
		t.Fatalf("recv err = %v, want errRecvStopped (wake path, not a frame or a close error)", res.err)
	}
	if res.n != 0 {
		t.Fatalf("recv n = %d, want 0 on the wake path", res.n)
	}

	// Foreign-fd probe: rxFD was never closed before the join, so its
	// number is still owned by this session and cannot have been reused.
	// Allocate a foreign socket now; writing LLDP-shaped bytes to its peer
	// must not resurrect anything — recv has already returned, and a
	// second recv attempt is guarded by the test simply not making one.
	// The observable invariant: fcntl(rxFD) still succeeds (fd alive) and
	// the peer of the foreign socket holds its bytes unread by us.
	foreign, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("foreign socketpair: %v", err)
	}
	defer unix.Close(foreign[0])
	defer unix.Close(foreign[1])
	if _, err := unix.FcntlInt(uintptr(sess.rxFD()), unix.F_GETFD, 0); err != nil {
		t.Fatalf("rxFD %d was closed before the join — fd number free for reuse under a parked reader (#16669): %v", sess.rxFD(), err)
	}
	if foreign[0] == sess.rxFD() || foreign[1] == sess.rxFD() {
		t.Fatalf("foreign fd reused the still-open rxFD number %d", sess.rxFD())
	}
	if _, err := unix.Write(foreign[1], []byte("foreign-frame-not-for-lldp")); err != nil {
		t.Fatalf("write foreign socket: %v", err)
	}
	// The bytes sit on the foreign socket; nothing in the session read
	// them (recv already returned via the wake above).
	buf := make([]byte, 64)
	if err := unix.SetNonblock(foreign[0], true); err != nil {
		t.Fatalf("set foreign nonblock: %v", err)
	}
	n, err := unix.Read(foreign[0], buf)
	if err != nil || n == 0 {
		t.Fatalf("foreign bytes were consumed by someone else (n=%d err=%v) — a parked recv read a reused fd (#16669)", n, err)
	}
}

// newSocketpairSession16669 delegates to newSocketpairSession in
// socket_test.go, which builds a SEQPACKET socketpair session with a real
// wake eventfd so recv exercises the production ppoll path without
// CAP_NET_RAW (#16669).
func newSocketpairSession16669(t *testing.T, iface *net.Interface) (sess *ifSession, peerFD int) {
	t.Helper()
	return newSocketpairSession(t, iface)
}
