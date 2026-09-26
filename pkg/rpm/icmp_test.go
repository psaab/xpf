package rpm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// fakeICMPConn is an in-memory net.PacketConn double for the ICMP
// prober seam. respond() inspects each sent echo and queues zero or
// more replies.
type fakeICMPConn struct {
	mu       sync.Mutex
	deadline time.Time
	replies  chan fakeReply
	respond  func(b []byte, dst net.Addr) []fakeReply
	sent     [][]byte
	sentAddr []net.Addr // destination passed to each WriteTo (#2494 zone check)
	opts     probeSockOpts
	network  string
	// failFast makes ReadFrom return an immediate timeout when no
	// reply is queued (simulates an instantly-unreachable target so
	// loss-threshold tests don't wait out real deadlines).
	failFast bool
}

type fakeReply struct {
	data []byte
	peer net.Addr
}

func (f *fakeICMPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	cp := append([]byte(nil), b...)
	f.mu.Lock()
	f.sent = append(f.sent, cp)
	f.sentAddr = append(f.sentAddr, addr)
	f.mu.Unlock()
	if f.respond != nil {
		for _, r := range f.respond(cp, addr) {
			f.replies <- r
		}
	}
	return len(b), nil
}

func (f *fakeICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	f.mu.Lock()
	deadline := f.deadline
	failFast := f.failFast
	f.mu.Unlock()
	if failFast {
		select {
		case r := <-f.replies:
			n := copy(b, r.data)
			return n, r.peer, nil
		default:
			return 0, nil, &net.OpError{Op: "read", Err: timeoutError{}}
		}
	}
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case r := <-f.replies:
		n := copy(b, r.data)
		return n, r.peer, nil
	case <-timeout:
		return 0, nil, &net.OpError{Op: "read", Err: timeoutError{}}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func (f *fakeICMPConn) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	return nil
}

func (f *fakeICMPConn) SetDeadline(t time.Time) error      { return f.SetReadDeadline(t) }
func (f *fakeICMPConn) SetWriteDeadline(t time.Time) error { return nil }
func (f *fakeICMPConn) Close() error                       { return nil }
func (f *fakeICMPConn) LocalAddr() net.Addr                { return &net.IPAddr{} }

// echoReply builds a matching (or mismatched) reply for a sent echo.
func echoReply(t *testing.T, sent []byte, v6 bool, mangleID bool, peer net.IP) fakeReply {
	t.Helper()
	proto := icmpProtocolIPv4
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	if v6 {
		proto = icmpProtocolIPv6
		replyType = ipv6.ICMPTypeEchoReply
	}
	msg, err := icmp.ParseMessage(proto, sent)
	if err != nil {
		t.Fatalf("parse sent echo: %v", err)
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("sent message is not an echo: %T", msg.Body)
	}
	id := echo.ID
	if mangleID {
		id ^= 0x5555
	}
	reply := icmp.Message{
		Type: replyType,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: echo.Seq, Data: echo.Data},
	}
	wire, err := reply.Marshal(nil)
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	return fakeReply{data: wire, peer: &net.IPAddr{IP: peer}}
}

func newFakeManager(respond func(b []byte, dst net.Addr) []fakeReply) (*Manager, *fakeICMPConn) {
	conn := &fakeICMPConn{replies: make(chan fakeReply, 8), respond: respond}
	m := New()
	m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
		conn.opts = opts
		conn.network = network
		return conn, nil
	}
	return m, conn
}

func TestProbeICMPEchoReplyPass(t *testing.T) {
	target := net.ParseIP("192.0.2.10")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	})
	test := &config.RPMTest{Name: "t", Target: "192.0.2.10"}
	rtt, err := m.probeICMP(context.Background(), test, probeSockOpts{})
	if err != nil {
		t.Fatalf("probeICMP: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("rtt = %v, want > 0", rtt)
	}
	if conn.network != "ip4:icmp" {
		t.Fatalf("network = %q, want ip4:icmp", conn.network)
	}
	// The probe actually put an echo request on the wire (the
	// pre-#1827 prober never did).
	if len(conn.sent) != 1 {
		t.Fatalf("sent %d packets, want 1", len(conn.sent))
	}
	msg, err := icmp.ParseMessage(icmpProtocolIPv4, conn.sent[0])
	if err != nil || msg.Type != ipv4.ICMPTypeEcho {
		t.Fatalf("sent packet is not an ICMP echo request: %v %v", msg, err)
	}
}

func TestProbeICMPv6EchoReplyPass(t *testing.T) {
	target := net.ParseIP("2001:db8::10")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, true, false, target)}
	})
	test := &config.RPMTest{Name: "t", Target: "2001:db8::10"}
	if _, err := m.probeICMP(context.Background(), test, probeSockOpts{}); err != nil {
		t.Fatalf("probeICMP v6: %v", err)
	}
	if conn.network != "ip6:ipv6-icmp" {
		t.Fatalf("network = %q, want ip6:ipv6-icmp", conn.network)
	}
}

func TestProbeICMPTimeoutFails(t *testing.T) {
	m, _ := newFakeManager(nil) // no replies at all
	test := &config.RPMTest{Name: "t", Target: "192.0.2.10"}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := m.probeICMP(ctx, test, probeSockOpts{})
	if err == nil {
		t.Fatal("probeICMP returned nil error on timeout, want failure")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want timeout", err)
	}
}

func TestProbeICMPIgnoresForeignReplies(t *testing.T) {
	target := net.ParseIP("192.0.2.10")
	other := net.ParseIP("192.0.2.99")
	m, _ := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{
			echoReply(t, b, false, true, target), // wrong id
			echoReply(t, b, false, false, other), // wrong peer
			echoReply(t, b, false, false, target),
		}
	})
	test := &config.RPMTest{Name: "t", Target: "192.0.2.10"}
	if _, err := m.probeICMP(context.Background(), test, probeSockOpts{}); err != nil {
		t.Fatalf("probeICMP should skip foreign replies and match the real one: %v", err)
	}
}

func TestProbeICMPSocketOptionsPropagate(t *testing.T) {
	target := net.ParseIP("192.0.2.10")
	m, conn := newFakeManager(func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	})
	test := &config.RPMTest{Name: "t", Target: "192.0.2.10"}
	opts := probeSockOpts{BindDevice: "ge-0-0-2.50", Mark: 0x1001}
	if _, err := m.probeICMP(context.Background(), test, opts); err != nil {
		t.Fatalf("probeICMP: %v", err)
	}
	if conn.opts != opts {
		t.Fatalf("socket opts = %+v, want %+v", conn.opts, opts)
	}
}

func TestProbeOptsMarkAndDeviceResolution(t *testing.T) {
	m := New()
	m.SetRethMap(map[string]string{"reth0": "ge-0/0/2"})
	cfg := &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"pinned": {Name: "pinned", Target: "1.1.1.1", NextHop: "172.16.50.1",
				DestinationInterface: "reth0.50"},
			"plain": {Name: "plain", Target: "8.8.8.8", RoutingInstance: "ISP-B"},
		}},
	}}
	m.Apply(context.Background(), cfg)
	defer m.StopAll()

	pinned := m.probeOpts(cfg.Probes["WAN"].Tests["pinned"], "WAN/pinned")
	if pinned.BindDevice != "ge-0-0-2.50" {
		t.Fatalf("pinned BindDevice = %q, want ge-0-0-2.50", pinned.BindDevice)
	}
	if pinned.Mark != uint32(config.ProbeFwmarkBase) {
		t.Fatalf("pinned Mark = %#x, want %#x", pinned.Mark, config.ProbeFwmarkBase)
	}

	plain := m.probeOpts(cfg.Probes["WAN"].Tests["plain"], "WAN/plain")
	if plain.BindDevice != "vrf-ISP-B" {
		t.Fatalf("plain BindDevice = %q, want vrf-ISP-B fallback", plain.BindDevice)
	}
	if plain.Mark != 0 {
		t.Fatalf("plain Mark = %#x, want 0", plain.Mark)
	}
}

func TestTransitionCallbackFires(t *testing.T) {
	m := New()
	var mu sync.Mutex
	var transitions []Transition
	m.SetTransitionCallback(func(tr Transition) {
		mu.Lock()
		transitions = append(transitions, tr)
		mu.Unlock()
	})

	key := "WAN/t"
	m.results[key] = &ProbeResult{ProbeName: "WAN", TestName: "t", LastStatus: "unknown"}

	test := &config.RPMTest{Name: "t", Target: "192.0.2.1", ThresholdSuccessive: 2}

	// Drive runSingleTest directly through the fake icmp seam.
	conn := &fakeICMPConn{replies: make(chan fakeReply, 8), failFast: true}
	m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
		return conn, nil
	}

	// Two consecutive failures (threshold 2) → one "fail" transition.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m.runSingleTest(ctx, "WAN", test, key, 2, time.Millisecond, 2)

	mu.Lock()
	got := append([]Transition(nil), transitions...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("transitions = %+v, want exactly one fail transition", got)
	}
	if got[0].Status != "fail" || got[0].ProbeName != "WAN" || got[0].TestName != "t" {
		t.Fatalf("transition = %+v", got[0])
	}
	if len(got[0].Results) == 0 {
		t.Fatal("transition carries no results snapshot")
	}
	if got[0].Generation != 1 {
		t.Fatalf("first transition generation = %d, want 1", got[0].Generation)
	}
	if got[0].Results[0].LastStatus != "fail" {
		t.Fatalf("first transition snapshot status = %q, want fail", got[0].Results[0].LastStatus)
	}

	// Now a success → one "pass" transition.
	target := net.ParseIP("192.0.2.1")
	conn.respond = func(b []byte, _ net.Addr) []fakeReply {
		return []fakeReply{echoReply(t, b, false, false, target)}
	}
	m.runSingleTest(ctx, "WAN", test, key, 1, time.Millisecond, 2)

	mu.Lock()
	got = append([]Transition(nil), transitions...)
	mu.Unlock()
	if len(got) != 2 || got[1].Status != "pass" {
		t.Fatalf("transitions = %+v, want fail then pass", got)
	}
	if got[1].Generation <= got[0].Generation {
		t.Fatalf("transition generations = %d, %d, want strictly increasing", got[0].Generation, got[1].Generation)
	}
	if len(got[1].Results) == 0 || got[1].Results[0].LastStatus != "pass" {
		t.Fatalf("second transition results = %+v, want pass snapshot", got[1].Results)
	}
}

// TestSetupErrorHoldsStateAndFiresNoTransition is the AGY PR #1843 F2
// regression test: a raw-socket open failure (capability/permission —
// an ENVIRONMENT error, not path health) must hold the test's current
// state completely. No SuccFail counting, no status change, no events,
// no Transition callback — so ip-monitoring can never inject/withdraw
// preferred routes off a capability regression. A real timeout on the
// same test still fails as today (contrast leg).
func TestSetupErrorHoldsStateAndFiresNoTransition(t *testing.T) {
	m := New()
	var mu sync.Mutex
	var transitions []Transition
	var events []Event
	m.SetTransitionCallback(func(tr Transition) {
		mu.Lock()
		transitions = append(transitions, tr)
		mu.Unlock()
	})
	m.SetEventCallback(func(ev Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	key := "WAN/t"
	m.results[key] = &ProbeResult{ProbeName: "WAN", TestName: "t", LastStatus: "pass"}
	test := &config.RPMTest{Name: "t", Target: "192.0.2.1", ThresholdSuccessive: 2}

	// Socket open fails (simulates CAP_NET_RAW dropped / EPERM).
	m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
		return nil, &net.OpError{Op: "listen", Err: timeoutError{}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Three full cycles, each over the threshold's worth of probes —
	// would be FAILED many times over if setup errors counted.
	for i := 0; i < 3; i++ {
		m.runSingleTest(ctx, "WAN", test, key, 3, time.Millisecond, 2)
	}

	m.mu.RLock()
	r := *m.results[key]
	m.mu.RUnlock()
	if r.LastStatus != "pass" {
		t.Fatalf("LastStatus = %q after setup errors, want held at pass", r.LastStatus)
	}
	if r.SuccFail != 0 {
		t.Fatalf("SuccFail = %d after setup errors, want 0 (no failure counting)", r.SuccFail)
	}
	if r.TotalSent != 0 {
		t.Fatalf("TotalSent = %d, want 0 (nothing reached the wire)", r.TotalSent)
	}
	mu.Lock()
	gotTransitions, gotEvents := len(transitions), len(events)
	mu.Unlock()
	if gotTransitions != 0 {
		t.Fatalf("transitions = %+v, want none for setup errors", transitions)
	}
	if gotEvents != 0 {
		t.Fatalf("events = %+v, want none for setup errors", events)
	}

	// Contrast: the socket opens but the echo genuinely times out —
	// the test FAILS as today and the transition fires.
	m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
		return &fakeICMPConn{replies: make(chan fakeReply, 1), failFast: true}, nil
	}
	m.runSingleTest(ctx, "WAN", test, key, 2, time.Millisecond, 2)

	m.mu.RLock()
	r = *m.results[key]
	m.mu.RUnlock()
	if r.LastStatus != "fail" {
		t.Fatalf("LastStatus = %q after real timeouts, want fail", r.LastStatus)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(transitions) != 1 || transitions[0].Status != "fail" {
		t.Fatalf("transitions = %+v, want one fail transition from the real timeout", transitions)
	}
}

// TestProbeICMPSetupErrorClassified pins the error classification:
// socket-open failures are ErrProbeSetup; timeout failures are not.
func TestProbeICMPSetupErrorClassified(t *testing.T) {
	m := New()
	m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
		return nil, &net.OpError{Op: "listen", Err: timeoutError{}}
	}
	test := &config.RPMTest{Name: "t", Target: "192.0.2.1"}
	_, err := m.probeICMP(context.Background(), test, probeSockOpts{})
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("socket-open failure not classified as ErrProbeSetup: %v", err)
	}

	m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
		return &fakeICMPConn{replies: make(chan fakeReply, 1), failFast: true}, nil
	}
	_, err = m.probeICMP(context.Background(), test, probeSockOpts{})
	if err == nil || errors.Is(err, ErrProbeSetup) {
		t.Fatalf("timeout must stay a genuine probe failure, got %v", err)
	}
}

// TestTCPAndHTTPSetupErrorsClassified (Codex PR #1843 HIGH-2): socket
// control/option failures on the tcp-ping and http-get dial path
// (SO_BINDTODEVICE to a nonexistent device — EPERM without
// CAP_NET_RAW, ENODEV with it; SO_MARK EPERM) classify as
// ErrProbeSetup so the probe loop holds state; a genuine connection
// refusal stays a path signal.
func TestTCPAndHTTPSetupErrorsClassified(t *testing.T) {
	// A listener we close immediately: dialing its port afterwards is
	// a genuine REFUSED — a real path/host signal.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	m := New()
	test := &config.RPMTest{Name: "t", Target: "127.0.0.1", DestPort: port}
	setupOpts := probeSockOpts{BindDevice: "xpf-nonexistent0"}

	// tcp-ping: bind-device failure → setup error.
	_, err = m.probeTCP(context.Background(), test, setupOpts)
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("tcp-ping bind-device failure not ErrProbeSetup: %v", err)
	}
	// tcp-ping: genuine refusal without socket options → path signal.
	_, err = m.probeTCP(context.Background(), test, probeSockOpts{})
	if err == nil || errors.Is(err, ErrProbeSetup) {
		t.Fatalf("tcp-ping refusal must stay a path signal, got %v", err)
	}

	// http-get: same classification through the transport/url.Error
	// wrapping.
	httpTest := &config.RPMTest{Name: "t", Target: fmt.Sprintf("http://127.0.0.1:%d/", port)}
	_, err = m.probeHTTP(context.Background(), httpTest, setupOpts)
	if !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("http-get bind-device failure not ErrProbeSetup: %v", err)
	}
	_, err = m.probeHTTP(context.Background(), httpTest, probeSockOpts{})
	if err == nil || errors.Is(err, ErrProbeSetup) {
		t.Fatalf("http-get refusal must stay a path signal, got %v", err)
	}
}
