package ra

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/psaab/xpf/pkg/config"
)

// writeRec is one recorded RA write: its router lifetime and a monotonic
// sequence number assigned in write order (NOT wall-clock — deterministic).
type writeRec struct {
	lifetime time.Duration
	seq      int
}

// fakeConn is an ndpConn test double. It records every WriteTo (lifetime +
// monotonic seq), serves injected Router Solicitations from a queue on
// ReadFrom, and counts how many live conns exist (so the <=1-live-conn-per-
// interface invariant can be asserted). All methods are safe for concurrent
// use, matching the real conn's documented WriteTo concurrency.
type fakeConn struct {
	mu     sync.Mutex
	writes []writeRec
	seq    int
	closed bool

	// rsQueue holds injected Router Solicitations (control message + source).
	// ReadFrom pops one per call; when empty it blocks until rsSignal fires or
	// the conn is closed, then returns a timeout error so the receiver polls
	// stopCh.
	rsQueue  []rsInject
	rsSignal chan struct{}

	// liveCounter, if non-nil, is incremented on construction (by the
	// listenFn) and decremented on Close — the invariant probe.
	liveCounter *int32
	liveMu      *sync.Mutex

	// beforeWrite, if non-nil, is invoked at the top of every WriteTo so a
	// test can block a specific send to force an interleave. Stored in an
	// atomic.Pointer and read without holding f.mu so the hook (which may
	// block) does not deadlock against the recording lock, and so concurrent
	// set-by-test / read-by-owner is race-free.
	beforeWrite atomic.Pointer[func(lifetime time.Duration)]

	// beforeClose, if non-nil, is invoked at the top of Close so a test can
	// hold the conn LIVE (block the owner's finishShutdown close) to probe the
	// stop->start window. Same race-free atomic.Pointer discipline.
	beforeClose atomic.Pointer[func()]

	// writeErr, if set, makes WriteTo return it WITHOUT recording the write —
	// simulating a send failure (e.g. interface down mid-withdraw) so a test
	// can prove finishShutdown leaves goodbyeEmitted=false on a failed graceful
	// goodbye, arming the manager's release-time backstop. Guarded by f.mu.
	writeErr error
}

// rsInject is one queued Router Solicitation: the received control message
// (carrying the IP Hop Limit once ipv6.FlagHopLimit is enabled) and the source
// address, so a test can drive the RFC 4861 §6.1.1 receive validation.
type rsInject struct {
	cm  *ipv6.ControlMessage
	src netip.Addr
}

func newFakeConn() *fakeConn {
	return &fakeConn{rsSignal: make(chan struct{}, 1)}
}

// setBeforeWrite installs (or clears, with nil) the WriteTo hook race-free.
func (f *fakeConn) setBeforeWrite(fn func(lifetime time.Duration)) {
	if fn == nil {
		f.beforeWrite.Store(nil)
		return
	}
	f.beforeWrite.Store(&fn)
}

// setBeforeClose installs (or clears, with nil) the Close hook race-free.
func (f *fakeConn) setBeforeClose(fn func()) {
	if fn == nil {
		f.beforeClose.Store(nil)
		return
	}
	f.beforeClose.Store(&fn)
}

func (f *fakeConn) WriteTo(m ndp.Message, _ *ipv6.ControlMessage, _ netip.Addr) error {
	ra, ok := m.(*ndp.RouterAdvertisement)
	if !ok {
		return nil
	}
	if hook := f.beforeWrite.Load(); hook != nil {
		(*hook)(ra.RouterLifetime)
	}
	f.mu.Lock()
	if f.writeErr != nil {
		err := f.writeErr
		f.mu.Unlock()
		return err
	}
	f.seq++
	f.writes = append(f.writes, writeRec{lifetime: ra.RouterLifetime, seq: f.seq})
	f.mu.Unlock()
	return nil
}

// setWriteErr makes every subsequent WriteTo fail (returning err, recording
// nothing) until cleared with nil.
func (f *fakeConn) setWriteErr(err error) {
	f.mu.Lock()
	f.writeErr = err
	f.mu.Unlock()
}

func (f *fakeConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return nil, nil, netip.Addr{}, errClosed{}
		}
		if len(f.rsQueue) > 0 {
			rs := f.rsQueue[0]
			f.rsQueue = f.rsQueue[1:]
			f.mu.Unlock()
			return &ndp.RouterSolicitation{}, rs.cm, rs.src, nil
		}
		f.mu.Unlock()
		// No RS queued: wait for a signal or a short tick, then return a
		// timeout so rsReceiver polls stopCh (matching the real read deadline).
		select {
		case <-f.rsSignal:
			continue
		case <-time.After(20 * time.Millisecond):
			return nil, nil, netip.Addr{}, errTimeout{}
		}
	}
}

// injectRS queues a VALID Router Solicitation from src: Hop Limit 255 (the
// on-link value RFC 4861 §6.1.1 requires). Callers pass a link-local or
// unspecified src so the RS passes receive validation and triggers an RA.
func (f *fakeConn) injectRS(src netip.Addr) {
	f.injectRSRaw(&ipv6.ControlMessage{HopLimit: 255}, src)
}

// injectRSRaw queues a Router Solicitation with a caller-chosen control message
// (nil = hop limit unavailable) and source, so a test can drive the RFC 4861
// §6.1.1 receive validation with a wrong hop limit or an off-link source.
func (f *fakeConn) injectRSRaw(cm *ipv6.ControlMessage, src netip.Addr) {
	f.mu.Lock()
	f.rsQueue = append(f.rsQueue, rsInject{cm: cm, src: src})
	f.mu.Unlock()
	select {
	case f.rsSignal <- struct{}{}:
	default:
	}
}

func (f *fakeConn) Close() error {
	if hook := f.beforeClose.Load(); hook != nil {
		(*hook)()
	}
	f.mu.Lock()
	already := f.closed
	f.closed = true
	f.mu.Unlock()
	// Wake any blocked ReadFrom.
	select {
	case f.rsSignal <- struct{}{}:
	default:
	}
	if !already && f.liveCounter != nil {
		f.liveMu.Lock()
		*f.liveCounter--
		f.liveMu.Unlock()
	}
	return nil
}

func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeConn) JoinGroup(netip.Addr) error       { return nil }
func (f *fakeConn) SetICMPFilter(*ipv6.ICMPFilter) error {
	return nil
}
func (f *fakeConn) SetControlMessage(ipv6.ControlFlags, bool) error { return nil }

func (f *fakeConn) snapshot() []writeRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]writeRec, len(f.writes))
	copy(out, f.writes)
	return out
}

// errTimeout / errClosed implement net.Error-ish Timeout() for isTimeout.
type errTimeout struct{}

func (errTimeout) Error() string { return "i/o timeout" }
func (errTimeout) Timeout() bool { return true }

type errClosed struct{}

func (errClosed) Error() string { return "use of closed connection" }
func (errClosed) Timeout() bool { return false }

// testCfg returns a minimal RA config for an interface.
func testCfg(iface string) *config.RAInterfaceConfig {
	return &config.RAInterfaceConfig{
		Interface:       iface,
		DefaultLifetime: 1800,
		MaxAdvInterval:  600,
		MinAdvInterval:  200,
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
	}
}

// fakeListen is the test harness wiring listenFn + ensureLinkLocalFn to fakes.
type fakeListen struct {
	mu       sync.Mutex
	conns    map[string]*fakeConn           // most-recent conn per interface
	allConns map[string][]*fakeConn         // EVERY conn ever opened per interface
	prehooks map[string]func(time.Duration) // installed at conn-creation time
	live     int32
	liveMu   sync.Mutex
}

// installFakeListen wires listenFn + ensureLinkLocalFn to fakes for the
// duration of the test and restores them on cleanup. getConn returns the
// fakeConn most recently opened for an interface name; liveCount returns the
// number of live (open) conns.
func installFakeListen(t *testing.T) (getConn func(string) *fakeConn, liveCount func() int32) {
	t.Helper()
	fl := newFakeListen(t)
	return fl.getConn, fl.liveCount
}

func newFakeListen(t *testing.T) *fakeListen {
	t.Helper()
	origListen := listenFn
	origEnsure := ensureLinkLocalFn

	fl := &fakeListen{
		conns:    map[string]*fakeConn{},
		allConns: map[string][]*fakeConn{},
		prehooks: map[string]func(time.Duration){},
	}

	ensureLinkLocalFn = func(*net.Interface) error { return nil }
	listenFn = func(iface *net.Interface, _ ndp.Addr) (ndpConn, netip.Addr, error) {
		fc := newFakeConn()
		fc.liveCounter = &fl.live
		fc.liveMu = &fl.liveMu
		fl.liveMu.Lock()
		fl.live++
		fl.liveMu.Unlock()
		fl.mu.Lock()
		if h := fl.prehooks[iface.Name]; h != nil {
			fc.setBeforeWrite(h) // attach BEFORE the owner can write
		}
		fl.conns[iface.Name] = fc
		fl.allConns[iface.Name] = append(fl.allConns[iface.Name], fc)
		fl.mu.Unlock()
		return fc, netip.MustParseAddr("fe80::1"), nil
	}

	t.Cleanup(func() {
		listenFn = origListen
		ensureLinkLocalFn = origEnsure
	})
	return fl
}

// preHook registers a WriteTo hook that is attached to the next conn opened for
// name, at conn-creation time, so it is in place before the owner's first
// write (avoids a race between start() and a post-start setBeforeWrite).
func (fl *fakeListen) preHook(name string, fn func(time.Duration)) {
	fl.mu.Lock()
	fl.prehooks[name] = fn
	fl.mu.Unlock()
}

func (fl *fakeListen) getConn(name string) *fakeConn {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	return fl.conns[name]
}

func (fl *fakeListen) liveCount() int32 {
	fl.liveMu.Lock()
	defer fl.liveMu.Unlock()
	return fl.live
}

// goodbyeCountFor sums lifetime-0 (goodbye) writes across EVERY conn ever
// opened for the interface — the owner's conn AND any standalone-goodbye conn
// the manager opened via sendOneGoodbye. The standalone goodbye emits
// goodbyeCount (3) lifetime-0 RAs on its own conn; an owner goodbye emits
// goodbyeCount on the owner's conn. "Exactly one goodbye event" therefore means
// exactly one conn carries goodbye writes (we assert both the per-conn count
// and that only a single conn emitted any).
// goodbyeAttribution renders, per conn generation for `name`, how many goodbye
// writes (lifetime == 0) it carries and whether it is `want` -- so a failure can
// say WHICH sender emitted rather than only that one did.
//
// #8031: goodbyeStats aggregates over fl.allConns[name], every generation. That
// is the right property for the assertions (the invariant is "nobody emitted"),
// but it makes a failure unattributable: `1 conns / 3 writes` is byte-identical
// whether the wedged owner emitted, a replacement did, or the reclaimer's
// LEGITIMATE post-close goodbye (#5094 -- "exactly one goodbye is emitted") was
// somehow observed early. Those need different fixes and the message could not
// tell them apart, which is why #8031 sat unreproduced with its evidence lost.
func (fl *fakeListen) goodbyeAttribution(name string, want *fakeConn) string {
	fl.mu.Lock()
	conns := append([]*fakeConn(nil), fl.allConns[name]...)
	fl.mu.Unlock()
	var b strings.Builder
	for i, c := range conns {
		n, total := 0, 0
		for _, w := range c.snapshot() {
			total++
			if w.lifetime == 0 {
				n++
			}
		}
		mark := ""
		if want != nil && c == want {
			mark = " <-- the WEDGED owner"
		}
		fmt.Fprintf(&b, "\n    conn[%d]: %d writes, %d goodbye%s", i, total, n, mark)
	}
	if b.Len() == 0 {
		return "\n    (no conns recorded for " + name + ")"
	}
	return b.String()
}

func (fl *fakeListen) goodbyeStats(name string) (totalGoodbyeWrites, connsWithGoodbye int) {
	fl.mu.Lock()
	conns := append([]*fakeConn(nil), fl.allConns[name]...)
	fl.mu.Unlock()
	for _, c := range conns {
		n := 0
		for _, w := range c.snapshot() {
			if w.lifetime == 0 {
				n++
			}
		}
		if n > 0 {
			connsWithGoodbye++
			totalGoodbyeWrites += n
		}
	}
	return
}

// fakeIfaceByName must be set because startLocked calls net.InterfaceByName.
// We can't stub that, so tests use a loopback-style interface that exists, or
// rely on the manager path that does NOT resolve a real interface. To keep
// these unit tests hermetic, we drive sender.start() directly with a synthetic
// *net.Interface (bypassing net.InterfaceByName) where possible, and use the
// Manager only in tests that go through real interface resolution via a name
// guaranteed to exist ("lo").

// startFakeSender builds a sender with a synthetic interface and the fake conn
// machinery, starts it, and returns it plus its fakeConn.
func startFakeSender(t *testing.T, getConn func(string) *fakeConn, name string) (*sender, *fakeConn) {
	t.Helper()
	iface := &net.Interface{Name: name, HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg(name), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Give the owner a moment to open the conn via listenFn.
	fc := waitConn(t, getConn, name)
	return s, fc
}

func waitConn(t *testing.T, getConn func(string) *fakeConn, name string) *fakeConn {
	t.Helper()
	for i := 0; i < 200; i++ {
		if fc := getConn(name); fc != nil {
			return fc
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("conn for %s never opened", name)
	return nil
}

// waitWrites blocks until fc has recorded at least n writes (or fails).
func waitWrites(t *testing.T, fc *fakeConn, n int) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if len(fc.snapshot()) >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("only %d writes recorded, want >=%d", len(fc.snapshot()), n)
}

// assertGoodbyeIsLast asserts the #2033 invariant: no lifetime>0 write has a
// seq greater than the FIRST lifetime-0 (goodbye) write. (Per Codex r3 MINOR
// #5 — asserting against the FIRST goodbye, not merely "last write is a
// goodbye," which a normal RA interleaved between goodbye packets would pass.)
func assertGoodbyeIsLast(t *testing.T, writes []writeRec) {
	t.Helper()
	firstGoodbye := -1
	for _, w := range writes {
		if w.lifetime == 0 {
			firstGoodbye = w.seq
			break
		}
	}
	if firstGoodbye < 0 {
		t.Fatalf("no goodbye (lifetime=0) RA was emitted; writes=%+v", writes)
	}
	for _, w := range writes {
		if w.lifetime > 0 && w.seq > firstGoodbye {
			t.Fatalf("normal RA (lifetime=%v, seq=%d) emitted AFTER the first goodbye (seq=%d); writes=%+v",
				w.lifetime, w.seq, firstGoodbye, writes)
		}
	}
}

// T1 — headline ordering proof under a FORCED bad interleave. An RS is queued
// and the owner enters the RS random-sleep branch; the test holds the in-flight
// normal RA WriteTo until AFTER the withdraw has been signalled, then releases
// it. The invariant (no lifetime>0 after the first goodbye) must hold: the
// in-flight normal RA precedes the goodbye because the goodbye is emitted by the
// owner on exit (finishShutdown), structurally after the loop.
func TestT1_GoodbyeIsLastUnderForcedRSInterleave(t *testing.T) {
	getConn, _ := installFakeListen(t)

	iface := &net.Interface{Name: "t1iface", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	cfg := testCfg("t1iface")
	// Fresh sender: getLastRA() is zero so the RS rate-limit gate passes and
	// the RS triggers a normal RA reply.
	s := newSender(cfg, iface)

	// Gate state: after the startup burst, the NEXT normal RA (the RS reply) is
	// blocked until `released` so we can interleave the withdraw with it.
	released := make(chan struct{})
	blocked := make(chan struct{})
	armNormalGate := make(chan struct{}) // closed once we want to start gating
	var gateOnce sync.Once

	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, getConn, "t1iface")
	// Let the startup burst complete so the next normal RA is the RS reply.
	waitWrites(t, fc, startupBurstCount)

	fc.setBeforeWrite(func(lifetime time.Duration) {
		if lifetime <= 0 {
			return // never block the goodbye
		}
		select {
		case <-armNormalGate:
			gateOnce.Do(func() {
				close(blocked)
				<-released
			})
		default:
			// burst writes (gate not armed yet) pass through
		}
	})

	// Push lastRA into the past so the RS rate-limit (minRAMulticastDelay)
	// passes and the RS produces a reply (the startup burst just set lastRA to
	// now, which would otherwise suppress the reply).
	s.setLastRA(time.Now().Add(-2 * minRAMulticastDelay))

	// Arm the gate, then inject an RS. The owner rate-checks (passes),
	// random-sleeps, then sendRA -> WriteTo hits the gate and blocks.
	close(armNormalGate)
	fc.injectRS(netip.MustParseAddr("fe80::2"))

	// Wait until the RS-reply normal RA is genuinely blocked in WriteTo.
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("RS-reply normal RA never reached the write gate")
	}

	// The in-flight normal RA is blocked. Signal graceful withdraw NOW.
	s.signalStop(modeGraceful)

	// Release the blocked normal RA, then join. The goodbye is emitted by the
	// owner on exit, structurally after this normal RA.
	close(released)
	<-s.stopped

	assertGoodbyeIsLast(t, fc.snapshot())
}

// T1b — companion micro-test: force a periodic-timer-style normal RA concurrent
// with the withdraw and assert the same seq-order property. We drive it by
// blocking a normal write and signalling stop while it is in flight.
func TestT1b_GoodbyeIsLastWithInFlightNormalRA(t *testing.T) {
	fl := newFakeListen(t)
	iface := &net.Interface{Name: "t1biface", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("t1biface"), iface)

	released := make(chan struct{})
	blocked := make(chan struct{})
	var once sync.Once

	// Pre-register the gate so it is attached before the owner's first burst
	// write (no race between start() and a post-start hook install).
	fl.preHook("t1biface", func(lifetime time.Duration) {
		if lifetime > 0 {
			once.Do(func() {
				close(blocked)
				<-released
			})
		}
	})

	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, fl.getConn, "t1biface")

	// The startup burst's first normal RA hits the gate.
	<-blocked
	// Now a normal RA is in flight (blocked). Signal graceful withdraw.
	s.signalStop(modeGraceful)
	// Release it; owner finishes burst (short-circuited by draining), then
	// finishShutdown emits the goodbye last.
	close(released)
	<-s.stopped

	assertGoodbyeIsLast(t, fc.snapshot())
}

// TestNegativeArm proves the test is NOT tautological: a "buggy" sender that
// emits a normal RA AFTER the goodbye must FAIL assertGoodbyeIsLast. We
// construct the bad write sequence directly (simulating the pre-#2033 behavior
// where a periodic RA followed the caller-emitted goodbye).
func TestNegativeArm_NormalRAAfterGoodbyeFails(t *testing.T) {
	bad := []writeRec{
		{lifetime: 1800 * time.Second, seq: 1}, // normal
		{lifetime: 0, seq: 2},                  // goodbye
		{lifetime: 1800 * time.Second, seq: 3}, // BUG: normal after goodbye
	}
	// Run assertGoodbyeIsLast in a sub-test that is EXPECTED to fail; capture
	// via a fake testing.T.
	ft := &fakeT{}
	assertGoodbyeIsLastOn(ft, bad)
	if !ft.failed {
		t.Fatal("negative arm did not fail: a normal RA after the goodbye must FAIL the invariant")
	}

	// And the good sequence must pass.
	good := []writeRec{
		{lifetime: 1800 * time.Second, seq: 1},
		{lifetime: 0, seq: 2},
		{lifetime: 0, seq: 3},
	}
	ft2 := &fakeT{}
	assertGoodbyeIsLastOn(ft2, good)
	if ft2.failed {
		t.Fatal("good sequence wrongly failed the invariant")
	}
}

// fakeT records whether Fatalf was called so the negative arm can assert the
// invariant predicate FAILS on a bad sequence without aborting the real test.
type fakeT struct{ failed bool }

func (f *fakeT) Helper()                       {}
func (f *fakeT) Fatalf(string, ...interface{}) { f.failed = true; panic(sentinelFatal{}) }

type sentinelFatal struct{}

// assertGoodbyeIsLastOn is assertGoodbyeIsLast against a minimal fatal-er so it
// can be exercised by the negative arm. It recovers the sentinel panic.
func assertGoodbyeIsLastOn(ft *fakeT, writes []writeRec) {
	// Recover ONLY our own Fatalf sentinel; re-raise anything else so a real
	// bug in this helper (e.g. a nil deref) is not silently swallowed.
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(sentinelFatal); !ok {
				panic(r)
			}
		}
	}()
	firstGoodbye := -1
	for _, w := range writes {
		if w.lifetime == 0 {
			firstGoodbye = w.seq
			break
		}
	}
	if firstGoodbye < 0 {
		ft.Fatalf("no goodbye")
		return
	}
	for _, w := range writes {
		if w.lifetime > 0 && w.seq > firstGoodbye {
			ft.Fatalf("normal after goodbye")
			return
		}
	}
}

// TestFinishShutdownGoodbyeSendOutcome proves finishShutdown records
// goodbyeEmitted EXACTLY when the goodbye actually went out: true on a clean
// send, false on a write failure. The false case is what arms the manager's
// release-time backstop (ra.go releaseDrain: !goodbyeEmitted -> standalone
// goodbye on a fresh conn). NON-TAUTOLOGY: against the pre-fix head
// (goodbyeEmitted set unconditionally after the send) the failure arm of this
// test reports goodbyeEmitted=true and fails — i.e. it pins the #2033
// sender.go:347 fix, not merely the current behavior.
func TestFinishShutdownGoodbyeSendOutcome(t *testing.T) {
	iface := &net.Interface{Name: "tgb", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}

	// Failed goodbye send -> emitted stays false so the backstop retries.
	sFail := newSender(testCfg("tgbfail"), iface)
	fcFail := newFakeConn()
	fcFail.setWriteErr(errors.New("simulated goodbye send failure"))
	sFail.conn = fcFail
	sFail.mode.Store(int32(modeGraceful))
	sFail.finishShutdown()
	if sFail.goodbyeEmitted.Load() {
		t.Fatal("goodbyeEmitted must stay FALSE when the goodbye send failed " +
			"(the manager backstop must retry on a fresh conn)")
	}

	// Successful goodbye send -> emitted true so the backstop suppresses.
	sOK := newSender(testCfg("tgbok"), iface)
	fcOK := newFakeConn()
	sOK.conn = fcOK
	sOK.mode.Store(int32(modeGraceful))
	sOK.finishShutdown()
	if !sOK.goodbyeEmitted.Load() {
		t.Fatal("goodbyeEmitted must be TRUE after a successful goodbye send")
	}
	// Sanity: the success path actually emitted goodbyeCount lifetime-0 writes.
	n := 0
	for _, w := range fcOK.snapshot() {
		if w.lifetime == 0 {
			n++
		}
	}
	if n != goodbyeCount {
		t.Fatalf("expected %d goodbye writes on success, got %d", goodbyeCount, n)
	}
}

// TestLiveConnInvariant proves at most one live NDP conn exists per interface
// across start/withdraw/restart cycles. Uses the Manager so the draining
// tombstone is exercised end-to-end. The interface name must resolve via
// net.InterfaceByName, so we use "lo".
func TestLiveConnInvariant(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	_, liveCount := installFakeListen(t)

	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}

	for cycle := 0; cycle < 10; cycle++ {
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("cycle %d Apply: %v", cycle, err)
		}
		// At most one live conn at any time.
		if lc := liveCount(); lc > 1 {
			t.Fatalf("cycle %d: %d live conns after Apply, want <=1", cycle, lc)
		}
		if err := m.Withdraw(); err != nil {
			t.Fatalf("cycle %d Withdraw: %v", cycle, err)
		}
		if lc := liveCount(); lc != 0 {
			t.Fatalf("cycle %d: %d live conns after Withdraw, want 0", cycle, lc)
		}
	}
}

// TestLiveConnInvariant_ConcurrentApplyWithdraw hammers Apply/Withdraw/
// WithdrawOnce/ResendBurst concurrently and asserts the live-conn count never
// exceeds 1 for the single interface. A design that allowed two live conns
// (e.g. starting a new sender while the old one is still draining) would trip
// the peak check.
func TestLiveConnInvariant_ConcurrentApplyWithdraw(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	_, liveCount := installFakeListen(t)

	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}

	stop := make(chan struct{})
	var peak int32
	var peakMu sync.Mutex
	recordPeak := func() {
		lc := liveCount()
		peakMu.Lock()
		if lc > peak {
			peak = lc
		}
		peakMu.Unlock()
	}

	var wg sync.WaitGroup
	worker := func(fn func()) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			fn()
			recordPeak()
		}
	}
	wg.Add(4)
	go worker(func() { _ = m.Apply(cfg) })
	go worker(func() { _ = m.Withdraw() })
	go worker(func() { m.WithdrawOnce(cfg) })
	go worker(func() { m.ResendBurst() })

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Drain to a known state.
	_ = m.Clear()

	peakMu.Lock()
	p := peak
	peakMu.Unlock()
	if p > 1 {
		t.Fatalf("peak live conns = %d, want <=1 (two live conns per interface)", p)
	}
	if lc := liveCount(); lc != 0 {
		t.Fatalf("leaked %d live conns after Clear", lc)
	}
}

// T3 — WithdrawOnce emits ONLY a goodbye (no startup burst) and never toggles
// the link. ensureLinkLocalFn is stubbed to record calls; we assert it is NOT
// invoked (the standalone path skips ensureLinkLocal entirely).
func TestT3_WithdrawOnceGoodbyeOnlyNoBurstNoLinkToggle(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	// Override ensureLinkLocalFn to record invocation (installFakeListen set it
	// to a no-op; wrap that to detect calls).
	var linkToggled bool
	prev := ensureLinkLocalFn
	ensureLinkLocalFn = func(i *net.Interface) error { linkToggled = true; return prev(i) }
	t.Cleanup(func() { ensureLinkLocalFn = prev })

	m := New()
	m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})

	fc := getConn("lo")
	if fc == nil {
		t.Fatal("no conn opened for WithdrawOnce")
	}
	writes := fc.snapshot()
	if len(writes) != goodbyeCount {
		t.Fatalf("WithdrawOnce wrote %d RAs, want exactly %d goodbyes", len(writes), goodbyeCount)
	}
	for _, w := range writes {
		if w.lifetime != 0 {
			t.Fatalf("WithdrawOnce emitted a lifetime>0 RA (%v) — startup burst leaked", w.lifetime)
		}
	}
	if linkToggled {
		t.Fatal("WithdrawOnce invoked ensureLinkLocal (link toggle) — violates I12 no-link-toggle")
	}
}

// T4a — WithdrawOnce skips a running sender (does not clobber a live primary).
func TestT4a_WithdrawOnceSkipsRunningSender(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fc := waitConn(t, getConn, "lo")
	waitWrites(t, fc, 1) // at least the first startup RA

	before := fc.snapshot()
	m.WithdrawOnce(cfg) // should be a no-op (sender running)
	after := fc.snapshot()

	for _, w := range after[len(before):] {
		if w.lifetime == 0 {
			t.Fatal("WithdrawOnce emitted a goodbye on a live primary's conn")
		}
	}
	_ = m.Clear()
}

// T5 — Apply with an identical config keeps the sender (no stop/start, no
// goodbye, same conn).
func TestT5_ApplyConfigEqualKeepsSender(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, liveCount := installFakeListen(t)

	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply1: %v", err)
	}
	fc1 := waitConn(t, getConn, "lo")

	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply2: %v", err)
	}
	fc2 := getConn("lo")
	if fc1 != fc2 {
		t.Fatal("config-equal Apply restarted the sender (new conn)")
	}
	if lc := liveCount(); lc != 1 {
		t.Fatalf("live conns = %d after config-equal Apply, want 1", lc)
	}
	for _, w := range fc1.snapshot() {
		if w.lifetime == 0 {
			t.Fatal("config-equal Apply emitted a goodbye")
		}
	}
	_ = m.Clear()
}

// T6 — Clear emits NO goodbye (modeHard). Clear() is the explicit no-goodbye
// primitive for a forced/unsafe stop; config-driven removal now withdraws
// gracefully instead (#5092, see config_removal_goodbye_5092_test.go).
func TestT6_ClearEmitsNoGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fc := waitConn(t, getConn, "lo")
	waitWrites(t, fc, 1)
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	for _, w := range fc.snapshot() {
		if w.lifetime == 0 {
			t.Fatal("Clear emitted a goodbye (lifetime=0); hard stop must not")
		}
	}
}

// T7 — idempotent / graceful-upgrades-hard. Both orderings must STILL produce
// a goodbye (graceful wins; never downgrade), and a double signalStop must not
// panic. Both signals are issued while the owner is PARKED at a write gate so
// the two Stores complete (happen-before) the owner reading mode in
// finishShutdown — testing the achievable, deterministic guarantee rather than
// the documented sub-µs residual (which only exists when the owner has already
// read modeHard before the upgrade Store; the manager serializes real callers
// via m.mu so that residual is not on the production demotion path).
func TestT7_GracefulUpgradesHard(t *testing.T) {
	run := func(name string, first, second shutdownMode) {
		fl := newFakeListen(t)
		release := make(chan struct{})
		parked := make(chan struct{})
		var once sync.Once
		// Park the owner at its FIRST write so both signalStops land before the
		// owner ever reads mode.
		fl.preHook(name, func(time.Duration) {
			once.Do(func() { close(parked); <-release })
		})

		iface := &net.Interface{Name: name, HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
		s := newSender(testCfg(name), iface)
		if err := s.start(); err != nil {
			t.Fatalf("[%s] start: %v", name, err)
		}
		fc := waitConn(t, fl.getConn, name)

		<-parked // owner is blocked in its first WriteTo
		s.signalStop(first)
		s.signalStop(second) // double signal must not panic (sync.Once)
		close(release)       // owner now proceeds; reads the arbitrated mode
		<-s.stopped

		assertGoodbyeIsLast(t, fc.snapshot())
	}

	run("t7a", modeHard, modeGraceful) // hard then graceful -> graceful wins
	run("t7b", modeGraceful, modeHard) // graceful then hard -> no downgrade
}

// T9 — startup burst preserved: a fresh start records exactly
// startupBurstCount normal RAs (before any periodic fire).
func TestT9_StartupBurstPreserved(t *testing.T) {
	getConn, _ := installFakeListen(t)
	iface := &net.Interface{Name: "t9", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("t9"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, getConn, "t9")
	waitWrites(t, fc, startupBurstCount)
	writes := fc.snapshot()
	// The first startupBurstCount writes must all be normal RAs.
	for i := 0; i < startupBurstCount; i++ {
		if writes[i].lifetime == 0 {
			t.Fatalf("burst write %d was a goodbye, want normal RA", i)
		}
	}
	s.stop()
}

// TestStatusReportsDraining verifies Status surfaces a draining interface with
// State "draining" (distinct from "active"). We hold a sender in finishShutdown
// by blocking its goodbye write, then snapshot Status while it drains.
func TestStatusReportsDraining(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, _ := installFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fc := waitConn(t, getConn, "lo")
	waitWrites(t, fc, 1)

	// Block the goodbye so the sender lingers in the draining tombstone.
	gate := make(chan struct{})
	fc.setBeforeWrite(func(lifetime time.Duration) {
		if lifetime == 0 {
			<-gate
		}
	})

	done := make(chan struct{})
	go func() { _ = m.Withdraw(); close(done) }()

	// Poll Status until the draining entry appears.
	var sawDraining bool
	for i := 0; i < 200; i++ {
		for _, info := range m.Status() {
			if info.Interface == "lo" && info.State == "draining" {
				sawDraining = true
			}
		}
		if sawDraining {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(gate)
	<-done

	if !sawDraining {
		t.Fatal("Status never reported the withdrawing interface as draining")
	}
	// After drain, no draining entry remains.
	for _, info := range m.Status() {
		if info.State == "draining" {
			t.Fatalf("draining entry lingered after Withdraw completed: %+v", info)
		}
	}
}

// configChanged returns a testCfg for iface with a DIFFERENT prefix so
// configEqual reports a change (forcing Apply down the replace path).
func configChanged(iface string) *config.RAInterfaceConfig {
	c := testCfg(iface)
	c.Prefixes = []*config.RAPrefix{
		{Prefix: "2001:db8:dead::/64", OnLink: true, Autonomous: true},
	}
	return c
}

// TestT2a_ChangedConfigApplyNeverTwoLiveConns is the #2033 MAJOR 1 regression.
// A changed-config Apply must STOP the old sender (close its conn) BEFORE
// opening the replacement conn — never two live conns for one interface. The
// old sender's conn.Close is held open via beforeClose; while it is held, a
// changed-config Apply runs and we assert the live-conn count never exceeds 1
// (i.e. the replacement conn is NOT opened until the old one is gone).
//
// NON-TAUTOLOGY: against the pre-fix code (startLocked(cfg) opens the new conn
// BEFORE s.stop() runs) the replacement conn is opened while the old is still
// live, so liveCount reaches 2 during the hold and this test FAILS.
func TestT2a_ChangedConfigApplyNeverTwoLiveConns(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, liveCount := installFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	old := waitConn(t, getConn, "lo")
	waitWrites(t, old, 1) // sender is up and writing

	// Hold the OLD sender's conn.Close open so the old sender stays live.
	release := make(chan struct{})
	closing := make(chan struct{})
	var once sync.Once
	old.setBeforeClose(func() {
		once.Do(func() { close(closing) })
		<-release
	})

	// Run the changed-config Apply concurrently; it must block stopping the old
	// sender (its owner is parked in beforeClose) and must NOT open a new conn
	// while the old is live.
	applyDone := make(chan error, 1)
	go func() {
		applyDone <- m.Apply([]*config.RAInterfaceConfig{configChanged("lo")})
	}()

	// Wait until the old sender's close is in flight (Apply has reached the
	// stop/join of the old sender).
	select {
	case <-closing:
	case <-time.After(2 * time.Second):
		t.Fatal("changed-config Apply never reached the old sender's close")
	}

	// While the old conn is held live, sample the live-conn count repeatedly.
	// With the fix it stays 1 (replacement not yet opened); pre-fix it is 2.
	for i := 0; i < 50; i++ {
		if lc := liveCount(); lc > 1 {
			t.Fatalf("two live conns during changed-config Apply (live=%d): "+
				"replacement opened before the old conn closed (#2033 MAJOR 1)", lc)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Release the old close; Apply completes and starts the replacement.
	close(release)
	select {
	case err := <-applyDone:
		if err != nil {
			t.Fatalf("changed-config Apply returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("changed-config Apply did not complete after releasing the old close")
	}

	// Exactly one live conn (the replacement) and no lingering tombstone.
	if lc := liveCount(); lc != 1 {
		t.Fatalf("after replace: live conns = %d, want 1", lc)
	}
	for _, info := range m.Status() {
		if info.State == "draining" {
			t.Fatalf("draining tombstone lingered after replace: %+v", info)
		}
	}
	_ = m.Clear()
}

// TestT2c_ReplaceStaysLiveNoGoodbye_WithdrawGoesDownWithGoodbye is the #2834
// make-before-break contract, asserting BOTH halves so the replace and withdraw
// paths can never collapse into one another:
//
//	REPLACE  (config changed, RA still served): Apply returns with EXACTLY one
//	         live conn (the replacement) and emits NO goodbye — no observable
//	         0-live-conn window, no prefix withdrawal. This is the bug #2834
//	         fixed: the replacement conn opens asynchronously, so before the fix
//	         Apply could return with the new conn not yet up (0 live conns = an
//	         IPv6-RA outage). Apply now waits (unlocked) for the replacement conn
//	         to come live before returning.
//
//	WITHDRAW (interface/prefix genuinely removed): a lifetime-0 goodbye IS
//	         emitted and the live-conn count drops to 0 — the #2033 behavior is
//	         preserved.
//
// NON-TAUTOLOGY: against the pre-#2834 code the REPLACE assertion (live==1
// immediately after Apply, no waiting in the test) fails with live==0.
func TestT2c_ReplaceStaysLiveNoGoodbye_WithdrawGoesDownWithGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	old := waitConn(t, fl.getConn, "lo")
	waitWrites(t, old, 1)

	// --- REPLACE: changed config, no gating. Apply must return make-before-break
	// with the replacement live. The test does NOT poll/wait afterward — the
	// guarantee is that Apply returned only once the replacement conn was up. ---
	if err := m.Apply([]*config.RAInterfaceConfig{configChanged("lo")}); err != nil {
		t.Fatalf("changed-config Apply: %v", err)
	}
	if lc := fl.liveCount(); lc != 1 {
		t.Fatalf("after replace: live conns = %d, want 1 (make-before-break: "+
			"Apply must return with the replacement RA conn live, #2834)", lc)
	}
	newConn := fl.getConn("lo")
	if newConn == old {
		t.Fatal("changed-config Apply did not open a new conn (no replace happened)")
	}
	// A config replace is NOT a withdrawal: no goodbye on either conn.
	if total, conns := fl.goodbyeStats("lo"); conns != 0 || total != 0 {
		t.Fatalf("config replace emitted a goodbye (%d conns, %d writes); a "+
			"replace must not withdraw the prefix (#2033 preserved)", conns, total)
	}

	// --- WITHDRAW: a genuine withdrawal still emits the lifetime-0 goodbye and
	// drops to 0 live conns (the #2033 behavior must not regress). ---
	if err := m.Withdraw(); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	for i := 0; i < 200; i++ {
		if fl.liveCount() == 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if lc := fl.liveCount(); lc != 0 {
		t.Fatalf("after withdraw: live conns = %d, want 0", lc)
	}
	total, conns := fl.goodbyeStats("lo")
	if conns == 0 || total == 0 {
		t.Fatalf("withdraw emitted no goodbye (%d conns, %d writes); a genuine "+
			"withdrawal must emit the lifetime-0 goodbye (#2033)", conns, total)
	}
}

// TestT7b_ManagerHardFirstThenGracefulStillGoodbye is the #2033 MAJOR 2
// regression. A Clear (hard) can acquire m.mu first, delete the sender, install
// a tombstone and signalStop(modeHard). A graceful Withdraw arriving afterward
// must STILL cause the goodbye to be emitted — claimGracefulLocked UPGRADES the
// still-draining hard sender to graceful, and signalStop's graceful-upgrades-
// hard guarantees the owner emits the goodbye in finishShutdown.
//
// We force the interleave deterministically by PARKING the owner in its startup
// burst (beforeWrite), i.e. BEFORE it ever reaches finishShutdown and reads its
// mode. While parked: Clear signals hard, then Withdraw upgrades to graceful —
// both Stores land before the owner reads the mode. Releasing the burst lets the
// owner finish, see draining, and read the upgraded graceful mode → goodbye.
//
// NON-TAUTOLOGY: against the pre-fix code (Withdraw bumps epoch + unlocks, then
// re-locks and sees no active sender → skips; Clear's hard tombstone is never
// upgraded) NO goodbye is emitted and this test FAILS.
func TestT7b_ManagerHardFirstThenGracefulStillGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)

	// Park the owner at its FIRST burst write, before it can reach the select
	// loop or finishShutdown (where the mode is read). Pre-registered so it is
	// in place before the owner's first write.
	release := make(chan struct{})
	parked := make(chan struct{})
	var once sync.Once
	fl.preHook("lo", func(lifetime time.Duration) {
		if lifetime > 0 {
			once.Do(func() { close(parked); <-release })
		}
	})

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fc := waitConn(t, fl.getConn, "lo")

	<-parked // owner is blocked in its first burst write (mode not read yet)

	// Clear (hard) first: deletes the sender, installs a hard tombstone,
	// signalStop(modeHard). Its join blocks on the parked owner, so run it in a
	// goroutine.
	clearDone := make(chan error, 1)
	go func() { clearDone <- m.Clear() }()

	// Then a graceful Withdraw for the same interface. With no active sender it
	// must find the draining (hard) sender and UPGRADE it to graceful. Poll
	// until the Clear has installed the tombstone (Withdraw's upgrade is a
	// no-op until then), then issue the Withdraw.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ts := false
		for _, info := range m.Status() {
			if info.Interface == "lo" && info.State == "draining" {
				ts = true
			}
		}
		if ts {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Clear never installed the draining tombstone")
		}
		time.Sleep(2 * time.Millisecond)
	}
	withdrawDone := make(chan error, 1)
	go func() { withdrawDone <- m.Withdraw() }()
	// Let the Withdraw acquire m.mu and upgrade the mode before we release.
	time.Sleep(50 * time.Millisecond)

	// Release the burst; the owner finishes it, sees draining, and reads the
	// upgraded graceful mode in finishShutdown → emits the goodbye.
	close(release)

	select {
	case <-clearDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Clear did not complete")
	}
	select {
	case <-withdrawDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Withdraw did not complete")
	}

	writes := fc.snapshot()
	var sawGoodbye bool
	for _, w := range writes {
		if w.lifetime == 0 {
			sawGoodbye = true
		}
	}
	if !sawGoodbye {
		t.Fatalf("no goodbye emitted: a graceful Withdraw racing a hard Clear "+
			"must still emit the goodbye (#2033 MAJOR 2); writes=%+v", writes)
	}
	assertGoodbyeIsLast(t, writes)
}

// TestT7c_WithdrawAfterDeadHardSenderEmitsStandaloneGoodbye is the #2033
// MAJOR-2 (dead-sender) regression: a graceful Withdraw that targets an
// interface whose sender has ALREADY finished its hard shutdown (finishShutdown
// ran, read modeHard, emitted NO goodbye) — but whose draining tombstone is
// still present — must STILL emit a goodbye. The dead sender cannot be
// "upgraded"; the manager must emit a STANDALONE goodbye instead.
//
// Determinism: Clear two interfaces. Gate interface B's conn.Close so
// clearLocked blocks in its join loop — clearLocked removes ALL tombstones only
// AFTER every join, so interface A's sender is fully stopped (goodbyeEmitted
// false) while A's tombstone is still present. The Withdraw of A then hits the
// dead-sender path and must emit a standalone goodbye for A.
//
// NON-TAUTOLOGY: against the current head (which only signalStop(graceful)-
// upgrades a draining sender, a no-op on a dead one, and has no standalone
// owes-a-goodbye fallback) A gets NO goodbye and this test FAILS.
func TestT7c_WithdrawAfterDeadHardSenderEmitsStandaloneGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()

	// Construct the dead-hard-tombstone state DIRECTLY (deterministic — no
	// dependence on Clear's nondeterministic per-interface release order): start
	// a "lo" sender, hard-stop it, wait until it is fully DEAD (goodbyeEmitted=
	// false, stopped closed), then install a drainEntry. This is exactly the
	// state a completed hard Clear leaves while its tombstone is still held.
	iface := &net.Interface{Name: "lo", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("lo"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, fl.getConn, "lo")
	waitWrites(t, fc, 1)
	s.signalStop(modeHard)
	select {
	case <-s.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("sender never stopped")
	}
	if s.goodbyeEmitted.Load() {
		t.Fatal("precondition: hard stop should not have emitted a goodbye")
	}

	// THIS test owns the dead entry's release. A racing graceful Withdraw flips
	// goodbyeWanted (it owns no release for an already-draining entry); then the
	// owner releases via releaseDrain. The dead sender cannot be upgraded, so a
	// STANDALONE goodbye must be emitted.
	m.mu.Lock()
	m.draining["lo"] = &drainEntry{sender: s, cfg: s.cfg}
	m.mu.Unlock()

	withdrawDone := make(chan error, 1)
	go func() { withdrawDone <- m.Withdraw() }()
	select {
	case <-withdrawDone: // flips goodbyeWanted; owns no release here
	case <-time.After(2 * time.Second):
		t.Fatal("Withdraw did not return")
	}

	m.mu.Lock()
	ep := m.epoch
	m.mu.Unlock()
	m.releaseDrain("lo", s, ep, nil)

	total, conns := fl.goodbyeStats("lo")
	if conns == 0 {
		t.Fatalf("no goodbye emitted for the withdrawn interface; a dead hard " +
			"sender must get a STANDALONE goodbye (#2033 MAJOR 2 dead-sender)")
	}
	if conns != 1 || total != goodbyeCount {
		t.Fatalf("expected exactly one goodbye event (1 conn, %d writes); got "+
			"%d conns, %d writes", goodbyeCount, conns, total)
	}
}

// TestT2b_WithdrawDuringRestartWindowEmitsGoodbye is the #2033 NEW-MAJOR
// regression: a graceful Withdraw that races the changed-config restart
// stop-to-start window (old sender hard-stopped, replacement not yet started)
// must emit a goodbye for the withdrawn interface — the route is being
// withdrawn, not replaced.
//
// Determinism: a changed-config Apply hard-stops the old sender, then BLOCKS
// opening the replacement conn (gate the replacement listen via a prehook on
// the NEW conn is not possible — the new conn is the one we want to block
// BEFORE creation; instead we gate the replacement's FIRST write so the
// replacement exists but a graceful Withdraw that bumps the epoch first aborts
// it). To exercise the true stop-to-start window we instead gate the OLD
// sender's Close so Apply's restart join blocks; while it blocks we issue the
// Withdraw (which finds the old, stopped-pending sender), then release.
//
// NON-TAUTOLOGY: against the current head a Withdraw racing the restart bumps
// the epoch, the restart aborts, and NO goodbye is emitted for the interface →
// this test FAILS.
func TestT2b_WithdrawDuringRestartWindowEmitsGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	old := waitConn(t, fl.getConn, "lo")
	waitWrites(t, old, 1)

	// Gate the OLD sender's Close so the changed-config Apply blocks in its
	// restart join (old sender stopped-pending, replacement not started — the
	// stop-to-start window).
	releaseOld := make(chan struct{})
	oldClosing := make(chan struct{})
	var once sync.Once
	old.setBeforeClose(func() {
		once.Do(func() { close(oldClosing) })
		<-releaseOld
	})

	applyDone := make(chan error, 1)
	go func() {
		applyDone <- m.Apply([]*config.RAInterfaceConfig{configChanged("lo")})
	}()

	select {
	case <-oldClosing:
	case <-time.After(2 * time.Second):
		t.Fatal("changed-config Apply never reached the old sender's close")
	}

	// In the stop-to-start window, a graceful Withdraw arrives. It must bump the
	// epoch (aborting the restart) AND guarantee a goodbye for the interface.
	withdrawDone := make(chan error, 1)
	go func() { withdrawDone <- m.Withdraw() }()
	time.Sleep(100 * time.Millisecond)

	// Release the old close so Apply's restart join completes (and then aborts
	// the start because the epoch changed).
	close(releaseOld)

	select {
	case err := <-applyDone:
		_ = err // may be nil; the restart is aborted, not an error
	case <-time.After(2 * time.Second):
		t.Fatal("changed-config Apply did not complete")
	}
	select {
	case <-withdrawDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Withdraw did not complete")
	}

	// The interface is withdrawn: exactly one goodbye event, and NO live sender
	// (the restart was aborted).
	total, conns := fl.goodbyeStats("lo")
	if conns == 0 {
		t.Fatalf("no goodbye emitted for the interface withdrawn during the " +
			"restart window (#2033 NEW MAJOR)")
	}
	if conns != 1 || total != goodbyeCount {
		t.Fatalf("expected exactly one goodbye event (1 conn, %d writes); got "+
			"%d conns, %d writes", goodbyeCount, conns, total)
	}
	m.mu.Lock()
	_, live := m.senders["lo"]
	m.mu.Unlock()
	if live {
		t.Fatal("a replacement sender was started despite the graceful Withdraw " +
			"aborting the restart")
	}
}

// TestT7d_ExactlyOneGoodbyeWhenUpgradeAndStandaloneCouldRace asserts that even
// when the graceful upgrade lands in time (owner emits the goodbye) the manager
// does NOT also emit a standalone goodbye — exactly one goodbye event total.
// This guards the exactly-once contract from the opposite side of T7c/T2b
// (which prove AT LEAST one): here we prove NOT MORE THAN one.
func TestT7d_ExactlyOneGoodbyeWhenUpgradeAndStandaloneCouldRace(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)

	// Park the owner in its burst so both a Clear (hard) and a Withdraw
	// (graceful upgrade) land before the owner reads its mode — the upgrade wins
	// and the owner emits exactly one goodbye; the manager must NOT add a
	// standalone.
	release := make(chan struct{})
	parked := make(chan struct{})
	var once sync.Once
	fl.preHook("lo", func(lifetime time.Duration) {
		if lifetime > 0 {
			once.Do(func() { close(parked); <-release })
		}
	})

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	_ = waitConn(t, fl.getConn, "lo")
	<-parked

	clearDone := make(chan error, 1)
	go func() { clearDone <- m.Clear() }()
	// Wait for Clear to install the tombstone.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ts := false
		for _, info := range m.Status() {
			if info.Interface == "lo" && info.State == "draining" {
				ts = true
			}
		}
		if ts {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Clear never installed the tombstone")
		}
		time.Sleep(2 * time.Millisecond)
	}
	withdrawDone := make(chan error, 1)
	go func() { withdrawDone <- m.Withdraw() }()
	time.Sleep(50 * time.Millisecond)
	close(release)

	select {
	case <-clearDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Clear did not complete")
	}
	select {
	case <-withdrawDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Withdraw did not complete")
	}

	total, conns := fl.goodbyeStats("lo")
	if conns != 1 || total != goodbyeCount {
		t.Fatalf("expected EXACTLY one goodbye event (1 conn, %d writes); got "+
			"%d conns, %d writes — a double goodbye (owner + standalone) is a bug",
			goodbyeCount, conns, total)
	}
}

// --- #2033 round-3: structural claim-and-hold race tests ---

// TestRace1_ConcurrentWithdrawsExactlyOneGoodbye: two concurrent Withdraws
// racing the SAME dead-hard tombstone must yield EXACTLY ONE goodbye (1 conn /
// goodbyeCount writes), not two. Two concurrent graceful Withdraws on the SAME
// interface serialize on m.mu in claimGracefulLocked: exactly one moves the
// active sender to a drainEntry and OWNS the release (sole emitter); the other
// finds the entry and only flips goodbyeWanted. claim-once via the single owner
// + goodbyeClaimed guarantees one goodbye even when both observe the dead sender
// (we hold the sender's conn.Close so it finishes its HARD-then-upgraded stop
// while both Withdraws are in flight, exercising the standalone backstop).
//
// NON-TAUTOLOGY: against head 141eefb5 each Withdraw appended an owned=false
// gracefulTarget and emitStandaloneGoodbye had no claim-once, so both opened a
// standalone conn → 2 conns / 6 writes → this test FAILS.
func TestRace1_ConcurrentWithdrawsExactlyOneGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()

	// Construct a held dead-hard tombstone for "lo" DIRECTLY (deterministic):
	// start, hard-stop, wait fully dead, install drainEntry — but do NOT set
	// goodbyeWanted yet; the racing Withdraws will set it.
	iface := &net.Interface{Name: "lo", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("lo"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, fl.getConn, "lo")
	waitWrites(t, fc, 1)
	s.signalStop(modeHard)
	select {
	case <-s.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("sender never stopped")
	}

	// THIS test owns the entry's release (mimicking the Clear/restart owner).
	// Two concurrent Withdraws flip goodbyeWanted; then the owner releases once.
	m.mu.Lock()
	m.draining["lo"] = &drainEntry{sender: s, cfg: s.cfg}
	m.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() { defer wg.Done(); _ = m.Withdraw() }()
	}
	wg.Wait() // both Withdraws have flipped goodbyeWanted (they own no release)

	// The single owner releases the entry: claim-once -> exactly one standalone.
	m.mu.Lock()
	ep := m.epoch
	m.mu.Unlock()
	m.releaseDrain("lo", s, ep, nil)

	total, conns := fl.goodbyeStats("lo")
	if conns != 1 || total != goodbyeCount {
		t.Fatalf("expected EXACTLY one goodbye (1 conn, %d writes); got %d conns, "+
			"%d writes — concurrent Withdraws double-sent (#2033 race 1)",
			goodbyeCount, conns, total)
	}
}

// TestRace3_ApplyDuringStandaloneEmitDefersNoClobber: while a standalone
// goodbye is mid-emit (its conn blocked in WriteTo), a concurrent Apply for the
// same interface must DEFER (the held drainEntry blocks it) — it must NOT start
// a live sender during the emit (no clobber, ≤1 live conn). After the standalone
// finishes, the Apply proceeds.
//
// NON-TAUTOLOGY: against head 141eefb5 emitStandaloneGoodbye held NO tombstone
// across the emit (check-then-act on m.senders), so the Apply could start a
// live sender during the emit → ≥2 live conns during the window → FAILS.
func TestRace3_ApplyDuringStandaloneEmitDefersNoClobber(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()

	// Gate the STANDALONE goodbye conn's first (lifetime-0) write so we can hold
	// the emit open. The standalone conn is opened by sendOneGoodbye; gate on
	// lifetime==0 (only the goodbye writes lifetime 0).
	standaloneBlocking := make(chan struct{})
	releaseStandalone := make(chan struct{})
	var sOnce sync.Once
	fl.preHook("lo", func(lifetime time.Duration) {
		if lifetime == 0 {
			sOnce.Do(func() { close(standaloneBlocking); <-releaseStandalone })
		}
	})

	// Construct the held dead-hard-tombstone state DIRECTLY (deterministic — no
	// dependence on Clear's per-interface release order): start a "lo" sender,
	// hard-stop it, wait until it is fully dead (goodbyeEmitted=false), install a
	// drainEntry{goodbyeWanted:true}. This is exactly the state a Clear-first +
	// graceful-Withdraw race produces.
	iface := &net.Interface{Name: "lo", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("lo"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, fl.getConn, "lo")
	waitWrites(t, fc, 1)
	s.signalStop(modeHard)
	select {
	case <-s.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("sender never stopped")
	}
	if s.goodbyeEmitted.Load() {
		t.Fatal("precondition: hard stop should not have emitted a goodbye")
	}
	m.mu.Lock()
	m.draining["lo"] = &drainEntry{sender: s, cfg: s.cfg, goodbyeWanted: true}
	ep := m.epoch
	m.mu.Unlock()

	// Release the held tombstone via releaseDrain (the sole owner). It must emit
	// the standalone WHILE holding the entry — the gated write blocks it there.
	relDone := make(chan struct{})
	go func() { m.releaseDrain("lo", s, ep, nil); close(relDone) }()

	select {
	case <-standaloneBlocking:
	case <-time.After(2 * time.Second):
		t.Fatal("standalone goodbye never reached its write gate")
	}

	// Concurrent Apply for "lo" must DEFER (held tombstone) — no live sender,
	// ≤1 live conn — for the whole emit window.
	applyDone := make(chan error, 1)
	go func() { applyDone <- m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}) }()
	for i := 0; i < 40; i++ {
		m.mu.Lock()
		_, live := m.senders["lo"]
		m.mu.Unlock()
		if live {
			t.Fatal("Apply started a live sender DURING the standalone emit " +
				"(clobber; tombstone did not block it) — #2033 race 3")
		}
		if lc := fl.liveCount(); lc > 1 {
			t.Fatalf(">1 live conn during the standalone emit (%d) — #2033 race 3", lc)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Release the standalone; releaseDrain finishes (removes the tombstone);
	// the deferred Apply then proceeds and starts a live sender.
	close(releaseStandalone)
	select {
	case <-relDone:
	case <-time.After(2 * time.Second):
		t.Fatal("releaseDrain did not complete")
	}
	select {
	case <-applyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("deferred Apply did not complete after the emit released")
	}

	total, conns := fl.goodbyeStats("lo")
	if conns != 1 || total != goodbyeCount {
		t.Fatalf("expected exactly one goodbye (1 conn, %d writes); got %d/%d",
			goodbyeCount, conns, total)
	}
	m.mu.Lock()
	_, live := m.senders["lo"]
	m.mu.Unlock()
	if !live {
		t.Fatal("deferred Apply did not start a live sender after the emit")
	}
	_ = m.Clear()
}

// TestRace2_TimeoutDoesNotEmitWhileOwnerCouldBeLive: if releaseDrain cannot
// join the sender within claimWaitTimeout (owner wedged), it must NOT read
// goodbyeEmitted (unordered) and must NOT emit a standalone — the owner may
// still be live. Drive releaseDrain directly with a wedged sender +
// goodbyeWanted and a shortened timeout; assert zero goodbyes.
//
// NON-TAUTOLOGY: against head 141eefb5 finishGraceful fell through after the
// timeout and read goodbyeEmitted anyway, then emitted a standalone → a goodbye
// would appear here → FAILS.
func TestRace2_TimeoutDoesNotEmitWhileOwnerCouldBeLive(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()

	// A wedged sender whose stopped never closes: gate its conn.Close so the
	// owner parks in finishShutdown before `defer close(stopped)` runs.
	iface := &net.Interface{Name: "lo", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("lo"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	fc := waitConn(t, fl.getConn, "lo")
	waitWrites(t, fc, 1)
	wedge := make(chan struct{})
	fc.setBeforeClose(func() { <-wedge }) // owner parks here forever

	// Hard-stop it and install a drainEntry with goodbyeWanted (as a racing
	// graceful Withdraw would have), then release with a SHORT timeout.
	m.mu.Lock()
	delete(m.senders, "lo")
	m.draining["lo"] = &drainEntry{sender: s, cfg: s.cfg, goodbyeWanted: true}
	s.signalStop(modeHard)
	ep := m.epoch
	m.mu.Unlock()

	orig := claimWaitTimeout
	claimWaitTimeout = 150 * time.Millisecond
	defer func() { claimWaitTimeout = orig }()

	done := make(chan struct{})
	go func() { m.releaseDrain("lo", s, ep, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("releaseDrain did not return after the join timeout")
	}

	// No standalone goodbye must have been emitted on the timeout path.
	total, conns := fl.goodbyeStats("lo")
	if conns != 0 || total != 0 {
		t.Fatalf("releaseDrain emitted a goodbye on the TIMEOUT path (owner could "+
			"be live) — got %d conns / %d writes; expected 0 (#2033 race 2)",
			conns, total)
	}
	// Tombstone is LEFT HELD after a timeout (the owner may still hold a live
	// conn — a future Apply must defer, never open a 2nd conn). A detached
	// reclaimer removes it only once the wedged owner finally exits.
	m.mu.Lock()
	_, stillDraining := m.draining["lo"]
	m.mu.Unlock()
	if !stillDraining {
		t.Fatal("releaseDrain removed the tombstone after a timeout; it must be " +
			"LEFT HELD (owner may still hold a live conn) — #2033 round-4")
	}

	// Now let the wedged owner exit; the reclaimer must remove the tombstone.
	close(wedge)
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		_, ok := m.draining["lo"]
		m.mu.Unlock()
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reclaimer did not remove the tombstone after the owner exited")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// --- #2033 round-4: changed-config restart shares releaseDrain's discipline ---

// TestRestartTimeoutNoGoodbyeNoReplacement (round-4 MAJOR 1+2): a changed-config
// Apply whose OLD sender WEDGES (never closes stopped) must, on the join
// timeout, NOT emit a standalone goodbye (even with a racing graceful Withdraw
// that flipped goodbyeWanted — the read would be unordered, owner may be live)
// AND must NOT start the replacement (the old conn may be live → would break
// ≤1-conn). The tombstone is LEFT HELD.
//
// NON-TAUTOLOGY: against head 5d7ef206 the inline restart read oldS.goodbyeEmitted
// after the timeout and emitted a standalone (MAJOR 1) — so a goodbye would
// appear here → FAILS.
func TestRestartTimeoutNoGoodbyeNoReplacement(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	old := waitConn(t, fl.getConn, "lo")
	waitWrites(t, old, 1)

	// WEDGE the old sender: its conn.Close blocks forever, so its `stopped`
	// never closes and the restart join will TIME OUT.
	wedge := make(chan struct{})
	old.setBeforeClose(func() { <-wedge })

	orig := claimWaitTimeout
	claimWaitTimeout = 150 * time.Millisecond
	defer func() { claimWaitTimeout = orig }()

	// Changed-config Apply (restart) runs concurrently; it will hard-stop the
	// old sender and block joining it (wedged) until the short timeout.
	applyDone := make(chan error, 1)
	go func() {
		applyDone <- m.Apply([]*config.RAInterfaceConfig{configChanged("lo")})
	}()

	// Race a graceful Withdraw in to flip goodbyeWanted on the restart entry.
	// Poll until the restart tombstone exists, then Withdraw.
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		_, draining := m.draining["lo"]
		m.mu.Unlock()
		if draining {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restart never installed the tombstone")
		}
		time.Sleep(2 * time.Millisecond)
	}
	_ = m.Withdraw() // flips goodbyeWanted on the (wedged) restart entry

	// Apply returns after the join timeout.
	select {
	case <-applyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("changed-config Apply did not return after the join timeout")
	}

	// No standalone goodbye on the timeout path (owner could be live).
	total, conns := fl.goodbyeStats("lo")
	if conns != 0 || total != 0 {
		// #8031: name WHICH conn emitted. The aggregate alone cannot separate
		// "the timeout path emitted" from "the reclaimer's legitimate #5094
		// goodbye was observed early", and those want different fixes.
		t.Fatalf("restart timeout emitted a goodbye (%d conns / %d writes); "+
			"the timeout path must NOT read goodbyeEmitted/emit — #2033 round-4 MAJOR 1"+
			"\n  per-conn attribution (#8031):%s",
			conns, total, fl.goodbyeAttribution("lo", old))
	}
	// No replacement started while the old conn may be live; ≤1 live conn.
	m.mu.Lock()
	_, live := m.senders["lo"]
	m.mu.Unlock()
	if live {
		t.Fatal("restart timeout started a replacement sender while the old conn " +
			"may be live — #2033 round-4 MAJOR 2 (≤1-conn)")
	}
	if lc := fl.liveCount(); lc > 1 {
		t.Fatalf(">1 live conn after restart timeout (%d) — #2033 round-4 MAJOR 2", lc)
	}
	// Tombstone is left held; reclaimed once the wedged owner exits.
	m.mu.Lock()
	_, stillDraining := m.draining["lo"]
	m.mu.Unlock()
	if !stillDraining {
		t.Fatal("restart timeout removed the tombstone; it must be LEFT HELD")
	}

	// #5094: the assertions above pin the DEGRADED window (owner still wedged).
	// Once the owner exits, the reclaimer must NOT drop the owed action: with a
	// racing graceful Withdraw the goodbye wins over the suppressed replacement,
	// so exactly one goodbye is emitted and no replacement is started. Let the
	// owner exit and wait for the reclaimer to settle (its final act is removing
	// the tombstone, after any synchronous goodbye) so the reclaimer's work
	// completes within this test rather than racing the harness teardown.
	close(wedge)
	waitDrainCleared(t, m, "lo")
	if _, conns := fl.goodbyeStats("lo"); conns != 1 {
		t.Fatalf("after reclaim: %d conns carried a goodbye, want exactly one "+
			"(the reclaimer must emit the owed goodbye exactly once — #5094)", conns)
	}
	m.mu.Lock()
	_, healedLive := m.senders["lo"]
	m.mu.Unlock()
	if healedLive {
		t.Fatal("reclaimer started a replacement despite a graceful withdraw; " +
			"the withdraw must win (#5094)")
	}
}

// TestRestartTimeoutNoReplacementWhenNoGoodbye (round-4 MAJOR 2): the same
// wedged-old-sender restart timeout, but with NO racing Withdraw (no goodbye
// wanted). startLocked must still NOT run while the old conn may be live — the
// replacement opens ONLY on the proven-closed arm. ≤1 live conn always.
//
// NON-TAUTOLOGY: against head 5d7ef206 the inline restart fell through to
// startLocked(cfg) after the timeout (MAJOR 2) → a replacement conn opened while
// the old one was still live → >1 live conn → FAILS.
func TestRestartTimeoutNoReplacementWhenNoGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	old := waitConn(t, fl.getConn, "lo")
	waitWrites(t, old, 1)

	wedge := make(chan struct{})
	old.setBeforeClose(func() { <-wedge })

	orig := claimWaitTimeout
	claimWaitTimeout = 150 * time.Millisecond
	defer func() { claimWaitTimeout = orig }()

	// Sample the live-conn count throughout to catch a transient 2-conn window.
	var peak int32
	stopSampling := make(chan struct{})
	sampleDone := make(chan struct{})
	go func() {
		defer close(sampleDone)
		for {
			select {
			case <-stopSampling:
				return
			default:
			}
			if lc := fl.liveCount(); lc > peak {
				peak = lc
			}
			time.Sleep(time.Millisecond)
		}
	}()

	err := m.Apply([]*config.RAInterfaceConfig{configChanged("lo")})
	_ = err // restart aborts on timeout; not necessarily an error

	close(stopSampling)
	<-sampleDone

	if peak > 1 {
		t.Fatalf("peak live conns = %d during a wedged restart timeout; the "+
			"replacement must open ONLY after the old conn is proven closed "+
			"(≤1-conn) — #2033 round-4 MAJOR 2", peak)
	}
	m.mu.Lock()
	_, live := m.senders["lo"]
	m.mu.Unlock()
	if live {
		t.Fatal("restart timeout started a replacement while the old conn may be live")
	}
	// No goodbye for a pure (no-withdraw) restart.
	total, conns := fl.goodbyeStats("lo")
	if conns != 0 || total != 0 {
		t.Fatalf("pure restart emitted a goodbye (%d conns / %d writes); expected 0", conns, total)
	}

	// #5094: the assertions above pin the DEGRADED window (≤1 conn while the old
	// owner is wedged). Once the owner exits, the reclaimer must START the
	// deferred replacement rather than dropping it — the interface must not be
	// left senderless. Wait for the replacement conn so the reclaimer's work
	// (and its openConn) completes within this test, then quiesce.
	close(wedge)
	newC := waitReplacementConn(t, fl, "lo", old)
	waitWrites(t, newC, 1)
	m.mu.Lock()
	_, healed := m.senders["lo"]
	m.mu.Unlock()
	if !healed {
		t.Fatal("reclaimer left the interface senderless after the wedged owner " +
			"exited — the deferred restart was dropped (#5094)")
	}
	_ = m.Clear()
}

// --- #2033 round-5: replacement decision is atomic under the act-lock ---

// installRestartEntry builds the state a changed-config restart reaches just
// before releaseDrain's final decision: an OLD sender, fully hard-stopped and
// dead (goodbyeEmitted=false, stopped closed), recorded in a drainEntry, plus
// the startEpoch the restart captured. Returns the old sender, its config, and
// the captured epoch. The caller drives releaseDrain(...) with an onProvenClose
// that starts the replacement, racing a Withdraw/Clear that supersedes it.
func installRestartEntry(t *testing.T, fl *fakeListen, m *Manager) (old *sender, cfg *config.RAInterfaceConfig, startEpoch uint64) {
	t.Helper()
	iface := &net.Interface{Name: "lo", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	old = newSender(testCfg("lo"), iface)
	if err := old.start(); err != nil {
		t.Fatalf("start old: %v", err)
	}
	fc := waitConn(t, fl.getConn, "lo")
	waitWrites(t, fc, 1)
	old.signalStop(modeHard)
	select {
	case <-old.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("old sender never stopped")
	}
	if old.goodbyeEmitted.Load() {
		t.Fatal("precondition: old hard stop should not have emitted a goodbye")
	}
	m.mu.Lock()
	m.draining["lo"] = &drainEntry{sender: old, cfg: old.cfg}
	startEpoch = m.epoch // the restart captured THIS epoch before unlocking
	m.mu.Unlock()
	return old, testCfg("lo"), startEpoch
}

// TestRound5_WithdrawDuringRestartDecisionNoReplacementGoodbyeEmitted: a
// graceful Withdraw that bumps the epoch AND flips goodbyeWanted BEFORE the
// restart's releaseDrain reaches its act-lock must make the restart emit the
// goodbye and NOT start the replacement (RA not re-armed). releaseDrain
// re-evaluates epoch + goodbyeWanted UNDER the act-lock with fresh state — no
// cached boolean — so the withdraw wins.
//
// NON-TAUTOLOGY: against the cached-boolean code (decision computed at the first
// lock, trusted across the unlock) the restart starts the replacement (RA
// re-armed after a newer withdraw) → a live sender exists → this test FAILS.
// (Mutation-verified with a gap-widening cached-boolean mutant.)
func TestRound5_WithdrawDuringRestartDecisionNoReplacementGoodbyeEmitted(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	old, cfg, startEpoch := installRestartEntry(t, fl, m)

	// onProvenClose runs UNDER the act-lock. The fix's contract is that it is
	// invoked ONLY when, AT THE ACT MOMENT, epoch==startEpoch AND !goodbyeWanted.
	// Capture the LIVE epoch + goodbyeWanted observed at call time; a violation
	// (called despite a supersession) is the cached-boolean bug.
	var startedDespiteSupersede bool
	startCalled := false
	onProvenClose := func() error {
		startCalled = true
		// We hold m.mu here. Fresh epoch must still be ours and no goodbye
		// wanted — otherwise a stale cached boolean started us after a newer op.
		if m.epoch != startEpoch || m.draining["lo"].goodbyeWanted {
			startedDespiteSupersede = true
		}
		return m.startLocked(cfg)
	}

	// Launch releaseDrain FIRST so it enters its decision; fire the superseding
	// Withdraw shortly after, so on a cached-boolean impl with a widened gap the
	// Withdraw lands in the decision→act window and the stale boolean re-arms RA.
	// On the FIXED code decision+act are atomic under one lock, so the Withdraw
	// lands strictly before or after — never mid-decision — and onProvenClose is
	// never called after a supersession.
	var wg sync.WaitGroup
	wg.Add(2)
	relErr := make(chan error, 1)
	go func() { defer wg.Done(); relErr <- m.releaseDrain("lo", old, startEpoch, onProvenClose) }()
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond) // try to land in the decision→act gap
		_ = m.Withdraw()
	}()
	wg.Wait()
	if err := <-relErr; err != nil {
		t.Fatalf("releaseDrain: %v", err)
	}

	// The precise round-5 invariant: onProvenClose (start the replacement) must
	// NEVER run after a supersession was already visible at the act moment. A
	// cached-boolean impl violates this — it calls onProvenClose with the stale
	// boolean while the live epoch has advanced / goodbyeWanted has flipped,
	// re-arming RA after a newer withdraw. The fixed code re-reads epoch +
	// goodbyeWanted UNDER the act-lock, so onProvenClose is reached only when the
	// decision is still valid. (Whether the withdraw lands before or after the
	// atomic decision is timing-dependent and both are correct; we assert ONLY
	// the never-start-after-supersede property, which holds on every interleave.)
	_ = startCalled
	if startedDespiteSupersede {
		t.Fatal("replacement started despite a newer Withdraw superseding the " +
			"restart at the act moment — stale cached decision across the unlock " +
			"— #2033 round-5")
	}
}

// TestRound5_ClearDuringRestartDecisionNoReplacement: same gap, but a Clear
// (epoch bump, NO goodbye wanted) supersedes the restart. The restart must NOT
// start the replacement (RA stays cleared) and emit NO goodbye.
//
// NON-TAUTOLOGY: against the cached-boolean code the restart starts the
// replacement (RA re-armed after a newer Clear) → FAILS.
// TestWithdrawOnceVsApplySingleOwner is the #2272 regression: WithdrawOnce must
// hold m.mu across its busy-check AND its tombstone install, so a concurrent
// Apply() / WithdrawOnce cannot start a competing sender between the two. We
// hammer Apply, WithdrawOnce, and Withdraw concurrently on ONE interface under
// -race and assert two invariants that the split-lock bug would break:
//
//  1. Single owner: the live NDP-conn count for the interface never exceeds 1.
//     Two senders (or a sender started during a WithdrawOnce goodbye) trips it.
//  2. No normal RA after a goodbye on any single conn: a sender that raced the
//     withdraw would emit a lifetime>0 RA after a lifetime-0 goodbye on the same
//     conn — the exact #2033 blackhole class the issue calls out.
//
// REVERT-PROOF: reverting WithdrawOnce to the pre-#2033 check-then-act shape
// (lock, check m.senders, UNLOCK, then start a sender + send the goodbye —
// dropping the lock between the check and the act) lets Apply start a live
// sender in the gap, so the peak live-conn count reaches 2 and/or a normal RA
// follows a goodbye on a conn, failing this test. Verified during development.
func TestWithdrawOnceVsApplySingleOwner(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	cfg := []*config.RAInterfaceConfig{testCfg("lo")}

	stop := make(chan struct{})
	var peak int32
	var peakMu sync.Mutex
	recordPeak := func() {
		lc := fl.liveCount()
		peakMu.Lock()
		if lc > peak {
			peak = lc
		}
		peakMu.Unlock()
	}

	var wg sync.WaitGroup
	worker := func(fn func()) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			fn()
			recordPeak()
		}
	}
	wg.Add(3)
	go worker(func() { _ = m.Apply(cfg) })
	go worker(func() { m.WithdrawOnce(cfg) })
	go worker(func() { _ = m.Withdraw() })

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Drain to a known state.
	_ = m.Clear()

	peakMu.Lock()
	p := peak
	peakMu.Unlock()
	if p > 1 {
		t.Fatalf("peak live conns = %d, want <=1 — WithdrawOnce raced a competing "+
			"sender onto the same interface (#2272 check-and-act race)", p)
	}
	if lc := fl.liveCount(); lc != 0 {
		t.Fatalf("leaked %d live conns after Clear", lc)
	}

	// Per-conn ordering: no normal RA may follow a goodbye on the SAME conn.
	// (A WithdrawOnce conn that somehow ran a sender, or a sender started during
	// the goodbye window, would show a lifetime>0 write after the lifetime-0 one.)
	fl.mu.Lock()
	conns := append([]*fakeConn(nil), fl.allConns["lo"]...)
	fl.mu.Unlock()
	for ci, c := range conns {
		writes := c.snapshot()
		firstGoodbye := -1
		for _, w := range writes {
			if w.lifetime == 0 {
				firstGoodbye = w.seq
				break
			}
		}
		if firstGoodbye < 0 {
			continue
		}
		for _, w := range writes {
			if w.lifetime > 0 && w.seq > firstGoodbye {
				t.Fatalf("conn %d: normal RA (lifetime=%v, seq=%d) emitted AFTER the "+
					"first goodbye (seq=%d) — single-owner-emit invariant broken (#2272/#2033)",
					ci, w.lifetime, w.seq, firstGoodbye)
			}
		}
	}
}

// TestWithdrawOnceHoldsTombstoneDuringGoodbye is the deterministic companion to
// the stress test above. It drives the PUBLIC WithdrawOnce path and proves that
// the claim-and-hold tombstone is held across the goodbye emit: while a
// WithdrawOnce goodbye is mid-write (gated), a concurrent Apply for the same
// interface must DEFER — it must not start a live sender and the live-conn count
// must stay <=1 for the whole emit window. After the goodbye completes the
// deferred Apply proceeds and starts the sender.
//
// This is the structural #2272 proof: even though the goodbye runs WITHOUT m.mu,
// the interface stays "busy" (tombstone present) so the check-and-act atomicity
// extends across the whole WithdrawOnce operation, not just the install instant.
func TestWithdrawOnceHoldsTombstoneDuringGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()

	// Gate the WithdrawOnce goodbye conn's first (lifetime-0) write so we can
	// hold the emit open. WithdrawOnce opens its conn via sendOneGoodbye and
	// writes only lifetime-0 RAs, so gate on lifetime==0.
	gateReached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fl.preHook("lo", func(lifetime time.Duration) {
		if lifetime == 0 {
			once.Do(func() { close(gateReached); <-release })
		}
	})

	woDone := make(chan struct{})
	go func() {
		m.WithdrawOnce([]*config.RAInterfaceConfig{testCfg("lo")})
		close(woDone)
	}()

	select {
	case <-gateReached:
	case <-time.After(2 * time.Second):
		t.Fatal("WithdrawOnce goodbye never reached its write gate")
	}

	// A concurrent Apply for "lo" must DEFER (the held tombstone makes the
	// interface busy) — no live sender, <=1 live conn — for the whole emit.
	applyDone := make(chan error, 1)
	go func() { applyDone <- m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}) }()
	for i := 0; i < 40; i++ {
		m.mu.Lock()
		_, live := m.senders["lo"]
		m.mu.Unlock()
		if live {
			t.Fatal("Apply started a live sender DURING the WithdrawOnce goodbye " +
				"(tombstone did not block it) — #2272 check-and-act race")
		}
		if lc := fl.liveCount(); lc > 1 {
			t.Fatalf(">1 live conn during the WithdrawOnce goodbye (%d) — #2272", lc)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Release the goodbye; WithdrawOnce finishes (removes the tombstone); the
	// deferred Apply then proceeds and starts a live sender.
	close(release)
	select {
	case <-woDone:
	case <-time.After(2 * time.Second):
		t.Fatal("WithdrawOnce did not complete after the goodbye released")
	}
	select {
	case <-applyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("deferred Apply did not complete after the emit released")
	}

	m.mu.Lock()
	_, live := m.senders["lo"]
	m.mu.Unlock()
	if !live {
		t.Fatal("deferred Apply did not start a live sender after the goodbye")
	}
	// Exactly one goodbye event (one conn carried the lifetime-0 writes).
	total, gconns := fl.goodbyeStats("lo")
	if gconns != 1 || total != goodbyeCount {
		t.Fatalf("expected exactly one goodbye (1 conn, %d writes); got %d/%d",
			goodbyeCount, gconns, total)
	}
	_ = m.Clear()
}

func TestRound5_ClearDuringRestartDecisionNoReplacement(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	fl := newFakeListen(t)
	m := New()
	old, cfg, startEpoch := installRestartEntry(t, fl, m)

	// onProvenClose runs under the act-lock; it must be invoked ONLY when epoch
	// is still startEpoch at the act moment. A Clear (epoch bump, no goodbye)
	// races concurrently; if a stale cached boolean starts the replacement after
	// the Clear advanced the epoch, that is the bug.
	var startedDespiteSupersede bool
	startCalled := false
	onProvenClose := func() error {
		startCalled = true
		if m.epoch != startEpoch {
			startedDespiteSupersede = true
		}
		return m.startLocked(cfg)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	relErr := make(chan error, 1)
	go func() { defer wg.Done(); relErr <- m.releaseDrain("lo", old, startEpoch, onProvenClose) }()
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond) // try to land in the decision→act gap
		_ = m.Clear()
	}()
	wg.Wait()
	if err := <-relErr; err != nil {
		t.Fatalf("releaseDrain: %v", err)
	}

	// Precise round-5 invariant: onProvenClose must NOT run after the Clear
	// advanced the epoch at the act moment (a stale cached boolean would re-arm
	// RA after a newer Clear). A Clear never wants a goodbye, so none is emitted.
	_ = startCalled
	_ = cfg
	if startedDespiteSupersede {
		t.Fatal("restart started a replacement after a newer Clear advanced the " +
			"epoch at the act moment (stale cached decision) — #2033 round-5")
	}
	total, conns := fl.goodbyeStats("lo")
	if conns != 0 || total != 0 {
		t.Fatalf("a Clear/restart race emitted a goodbye (%d conns / %d writes); "+
			"expected 0", conns, total)
	}
}

// installGatedListen wires listenFn + ensureLinkLocalFn so that a bind for the
// named "slow" interface BLOCKS until release is closed (simulating the
// link-local-settling bind retry that runs up to ~2s), while every other
// interface binds instantly. It returns release (close to unblock the slow
// bind) and a getConn accessor. It restores the originals on cleanup.
//
// This is the #2453 seam: with the fix the slow bind happens in the sender's
// OWN goroutine (no m.mu held), so a concurrent manager op on a DIFFERENT
// interface is unaffected. With the bug (bind under m.mu in startLocked) the
// slow bind stalls every other manager op.
func installGatedListen(t *testing.T, slow string) (release func(), liveCount func() int32) {
	t.Helper()
	origListen := listenFn
	origEnsure := ensureLinkLocalFn

	gate := make(chan struct{})
	var once sync.Once
	var live int32
	var liveMu sync.Mutex

	ensureLinkLocalFn = func(*net.Interface) error { return nil }
	listenFn = func(iface *net.Interface, _ ndp.Addr) (ndpConn, netip.Addr, error) {
		if iface.Name == slow {
			<-gate // block the slow interface's bind until released
		}
		fc := newFakeConn()
		fc.liveCounter = &live
		fc.liveMu = &liveMu
		liveMu.Lock()
		live++
		liveMu.Unlock()
		return fc, netip.MustParseAddr("fe80::1"), nil
	}

	release = func() { once.Do(func() { close(gate) }) }
	liveCount = func() int32 {
		liveMu.Lock()
		defer liveMu.Unlock()
		return live
	}

	t.Cleanup(func() {
		// Unblock any owner still parked in the gate, then wait for every conn
		// opened through this listenFn to be closed by its owner goroutine BEFORE
		// restoring the package globals. Restoring listenFn while a leaked owner
		// is still reading/calling it is the data race the race detector flags;
		// joining on liveCount==0 closes that window deterministically.
		release()
		for i := 0; i < 500; i++ {
			if liveCount() == 0 {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		listenFn = origListen
		ensureLinkLocalFn = origEnsure
	})
	return release, liveCount
}

// TestT2453_SlowBindDoesNotStallOtherManagerOps is the #2453 fail-on-revert
// concurrency proof: a sender whose bind is slow (stuck in the listen retry)
// MUST NOT hold the manager mutex m.mu, so concurrent manager operations that
// only need m.mu briefly complete promptly instead of waiting for the bind.
//
// The probes are operations that take m.mu and return WITHOUT joining the
// gated sender (so they isolate "is m.mu held across the bind?" from "does a
// same-interface withdraw legitimately wait for the owner to exit?"):
//   - WithdrawInterfaces(["ge-0-0-9"]) — a DIFFERENT interface (the motivating
//     VRRP-failover-on-another-RG case): finds no sender/tombstone, takes
//     m.mu, does nothing, returns. With the bug it blocks on m.mu.Lock()
//     behind startLocked's in-flight listen().
//   - Status() — takes m.mu, reads, returns.
//
// Fail-on-revert: restore the conn-open to run synchronously under m.mu in
// startLocked (the pre-#2453 behavior) and BOTH probes block on m.mu.Lock()
// until the gated bind releases, so the assertions below time out and the test
// FAILS.
func TestT2453_SlowBindDoesNotStallOtherManagerOps(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	release, liveCount := installGatedListen(t, "lo")

	m := New()

	// Apply on "lo" starts a sender whose bind is GATED (blocks in listen). With
	// the fix Apply itself returns promptly (the bind runs in the owner
	// goroutine, NOT under m.mu); run it in the background so the gated bind is
	// in flight while we contend the lock.
	applyDone := make(chan error, 1)
	go func() { applyDone <- m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}) }()

	// Give the gated bind a moment to be in flight (the owner goroutine is parked
	// in listenFn on <-gate).
	time.Sleep(50 * time.Millisecond)

	// Probe: concurrent manager ops on a DIFFERENT interface + a Status read.
	// They must NOT be serialized behind the in-flight bind on "lo". With the
	// bug they block on m.mu.Lock() until release.
	probeDone := make(chan struct{}, 1)
	start := time.Now()
	go func() {
		m.withdrawInterfacesForTest([]string{"ge-0-0-9"})
		_ = m.Status()
		probeDone <- struct{}{}
	}()

	select {
	case <-probeDone:
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("concurrent manager ops took %v while another interface's "+
				"bind was in flight — m.mu was held across the bind retry (#2453)", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("concurrent manager ops blocked >500ms behind an in-flight bind " +
			"on another interface — startLocked is holding m.mu across listen() (#2453)")
	}

	// Apply (startLocked) itself must also have returned promptly under the fix.
	select {
	case <-applyDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Apply blocked behind the in-flight bind — startLocked held " +
			"m.mu across listen() (#2453)")
	}

	// Release the gated bind and drain to a known state so the gated owner
	// goroutine exits before cleanup (cleanup also joins on liveCount==0).
	release()
	_ = m.Clear()
	for i := 0; i < 500; i++ {
		if liveCount() == 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestT2453_NormalStartStillBindsAndSends is the no-regression companion: with
// the conn-open moved into the owner goroutine, a normal start must still open
// the conn and emit its startup burst (proving the async open is wired and the
// owner reaches its send loop).
func TestT2453_NormalStartStillBindsAndSends(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	getConn, liveCount := installFakeListen(t)

	m := New()
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	fc := waitConn(t, getConn, "lo")
	// Startup burst is startupBurstCount normal (lifetime>0) RAs.
	waitWrites(t, fc, startupBurstCount)
	for _, w := range fc.snapshot() {
		if w.lifetime == 0 {
			t.Fatalf("normal start emitted a lifetime-0 (goodbye) RA in its burst")
		}
	}
	if lc := liveCount(); lc != 1 {
		t.Fatalf("expected exactly 1 live conn after a normal start, got %d", lc)
	}

	// Clean teardown leaves no live conns.
	if err := m.Withdraw(); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if lc := liveCount(); lc != 0 {
		t.Fatalf("leaked %d live conns after Withdraw", lc)
	}
}

// TestT2453_WithdrawDuringSlowBindEmitsGoodbye proves the conn==nil safety in
// finishShutdown: if a graceful Withdraw arrives while the bind is still
// retrying (so the owner never opens a conn), the manager's release-time
// backstop still emits exactly one standalone goodbye on a FRESH conn — the
// route is withdrawn, not silently dropped, and the owner never dereferences a
// nil conn (which would panic).
func TestT2453_WithdrawDuringSlowBindEmitsGoodbye(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}

	origListen := listenFn
	origEnsure := ensureLinkLocalFn
	t.Cleanup(func() { listenFn = origListen; ensureLinkLocalFn = origEnsure })

	var mu sync.Mutex
	allConns := map[string][]*fakeConn{}
	// The owner's bind never succeeds while gate is open; the standalone backstop
	// (sendOneGoodbye -> sender.listen) is allowed through once standalone=true.
	gate := make(chan struct{})
	var standalone atomic.Bool

	ensureLinkLocalFn = func(*net.Interface) error { return nil }
	listenFn = func(iface *net.Interface, _ ndp.Addr) (ndpConn, netip.Addr, error) {
		if !standalone.Load() {
			// Owner's bind: block until the test releases (then it returns an
			// error so the owner gives up without a conn).
			<-gate
			return nil, netip.Addr{}, errors.New("bind aborted")
		}
		fc := newFakeConn()
		mu.Lock()
		allConns[iface.Name] = append(allConns[iface.Name], fc)
		mu.Unlock()
		return fc, netip.MustParseAddr("fe80::1"), nil
	}

	m := New()
	applyDone := make(chan error, 1)
	go func() { applyDone <- m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}) }()
	time.Sleep(50 * time.Millisecond) // let the owner park in the gated bind

	// Graceful Withdraw while the bind is still in flight: flips goodbyeWanted,
	// signals stop (the owner's listen retry aborts via stopCh), then the release
	// path joins the dead owner (goodbyeEmitted=false, no conn) and emits a
	// standalone goodbye on a fresh conn.
	standalone.Store(true) // allow the backstop's fresh-conn bind to succeed
	close(gate)            // unblock the owner's bind so it gives up promptly

	if err := m.Withdraw(); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	<-applyDone

	mu.Lock()
	conns := append([]*fakeConn(nil), allConns["lo"]...)
	mu.Unlock()
	total, connsWithGoodbye := 0, 0
	for _, c := range conns {
		n := 0
		for _, w := range c.snapshot() {
			if w.lifetime == 0 {
				n++
			}
		}
		if n > 0 {
			connsWithGoodbye++
			total += n
		}
	}
	if connsWithGoodbye != 1 || total != goodbyeCount {
		t.Fatalf("expected exactly one standalone goodbye (1 conn, %d writes) for "+
			"a withdraw during a slow bind; got %d conns, %d writes",
			goodbyeCount, connsWithGoodbye, total)
	}
}

// installFailThenSucceedListen wires listenFn + ensureLinkLocalFn so that the
// FIRST open attempt for every interface FAILS (every bind retry returns an
// error, so sender.openConn gives up — the boot-time "link still doing DAD /
// link-local not yet present" case), and all subsequent opens (after fail is
// set false) succeed instantly. It returns a setter to flip to the succeed
// phase, a getConn accessor for the most-recent conn, and a liveCount probe.
//
// To keep the failing phase fast (the real listen() retries 10× with a 200ms
// interruptible sleep between attempts), the test shortens that wait by stopping
// the sender between Apply passes is NOT needed — instead we keep claimWaitTimeout
// untouched and rely on the owner reaching finishShutdown quickly: the bind
// returns its error immediately and the only delay is the inter-retry sleep,
// which the test tolerates via waitDead's generous poll budget.
func installFailThenSucceedListen(t *testing.T) (setSucceed func(), getConn func(string) *fakeConn, liveCount func() int32) {
	t.Helper()
	origListen := listenFn
	origEnsure := ensureLinkLocalFn

	var mu sync.Mutex
	var live int32
	var liveMu sync.Mutex
	var fail atomic.Bool
	fail.Store(true)
	conns := map[string]*fakeConn{}

	ensureLinkLocalFn = func(*net.Interface) error { return nil }
	listenFn = func(iface *net.Interface, _ ndp.Addr) (ndpConn, netip.Addr, error) {
		if fail.Load() {
			return nil, netip.Addr{}, errors.New("ra-test: bind failed (link not ready)")
		}
		fc := newFakeConn()
		fc.liveCounter = &live
		fc.liveMu = &liveMu
		liveMu.Lock()
		live++
		liveMu.Unlock()
		mu.Lock()
		conns[iface.Name] = fc
		mu.Unlock()
		return fc, netip.MustParseAddr("fe80::1"), nil
	}

	setSucceed = func() { fail.Store(false) }
	getConn = func(name string) *fakeConn {
		mu.Lock()
		defer mu.Unlock()
		return conns[name]
	}
	liveCount = func() int32 {
		liveMu.Lock()
		defer liveMu.Unlock()
		return live
	}

	t.Cleanup(func() {
		setSucceed()
		for i := 0; i < 500; i++ {
			if liveCount() == 0 {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		listenFn = origListen
		ensureLinkLocalFn = origEnsure
	})
	return setSucceed, getConn, liveCount
}

// senderDead reports whether the manager currently holds a sender for name whose
// initial conn open resolved without a live conn (dead). Used by the #2865 test
// to confirm the failed-open sender is in fact recorded as dead before the
// recovery Apply.
func (m *Manager) senderDead(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.senders[name]
	return ok && s.dead()
}

// TestT2865_DeadSenderRebuiltOnReconcile is the fail-on-revert proof for #2865:
// a sender whose initial openConn() FAILS (transient boot-time bind failure)
// stays in m.senders but never emits an RA. A subsequent Apply with the SAME
// (unchanged) config MUST rebuild it once the link is ready, so the interface
// eventually gets a live RA sender without any config change.
//
// Sequence:
//  1. listenFn fails every open → Apply("lo") records a sender that goes dead.
//  2. Flip listenFn to succeed (link now ready) — NO config change.
//  3. Apply("lo") with the IDENTICAL config → reconcile must detect the dead
//     sender, rebuild it, and the replacement opens a live conn that emits the
//     startup burst.
//
// Fail-on-revert: drop the `!existing.dead()` guard in Apply's reconcile (so a
// config-unchanged dead sender is skipped as "healthy"), and step 3 leaves the
// dead sender in place — no live conn is ever opened, the assertion that a live
// startup burst was emitted times out, and the test FAILS.
func TestT2865_DeadSenderRebuiltOnReconcile(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("lo interface unavailable")
	}
	setSucceed, getConn, liveCount := installFailThenSucceedListen(t)

	m := New()

	// Step 1: every open fails. Apply records a sender, whose owner gives up and
	// goes dead (run() -> openConn() false -> finishShutdown -> exit), but the
	// dead sender remains in m.senders.
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply (failing phase): %v", err)
	}

	// Wait for the owner to resolve its (failed) open and be recorded as dead.
	// The failing open retries 10× with a ~200ms inter-retry sleep (≈2s) before
	// openConn gives up, so allow a generous budget (~4s).
	deadObserved := false
	for i := 0; i < 2000; i++ {
		if m.senderDead("lo") {
			deadObserved = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !deadObserved {
		t.Fatal("sender never became dead after a failing open; cannot exercise #2865")
	}
	if lc := liveCount(); lc != 0 {
		t.Fatalf("expected 0 live conns while opens fail, got %d", lc)
	}

	// Step 2: link is now ready — opens will succeed. NO config change.
	setSucceed()

	// Step 3: re-Apply the IDENTICAL config. The reconcile must REBUILD the dead
	// sender (config is unchanged, so without the #2865 fix it would be skipped).
	if err := m.Apply([]*config.RAInterfaceConfig{testCfg("lo")}); err != nil {
		t.Fatalf("Apply (recovery phase): %v", err)
	}

	// A live conn must now exist and emit the startup burst — proving the dead
	// sender was rebuilt into a working one with no config change.
	fc := waitConn(t, getConn, "lo")
	waitWrites(t, fc, startupBurstCount)
	for _, w := range fc.snapshot() {
		if w.lifetime == 0 {
			t.Fatalf("rebuilt sender emitted a lifetime-0 (goodbye) RA in its burst")
		}
	}

	// The rebuilt sender must be live (not dead) and the sole conn.
	if m.senderDead("lo") {
		t.Fatal("sender is still dead after the recovery Apply — it was not rebuilt (#2865)")
	}
	if lc := liveCount(); lc != 1 {
		t.Fatalf("expected exactly 1 live conn after the rebuild, got %d", lc)
	}

	// Clean teardown leaves no live conns.
	if err := m.Withdraw(); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	for i := 0; i < 500; i++ {
		if liveCount() == 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if lc := liveCount(); lc != 0 {
		t.Fatalf("leaked %d live conns after Withdraw", lc)
	}
}
