package grpcapi

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// #16478 decisive regression: hold preface-only (pre-auth) connections past
// the fabric bound -> excess must be refused/closed immediately with a
// counted refusal, the held count must stay capped, and an authenticated
// peer must still connect during the flood.
//
// This drives the REAL path: NewServer (gate installed) ->
// fabricBoundListener -> buildFabricServer -> serveUntilDone over a real
// TCP listener, with the production limits shrunk through the same vars
// production reads (restored via cleanup). Holding connections are REAL
// HTTP/2 connections that completed the handshake (preface + SETTINGS via
// x/net/http2 Transport) and then send no RPC, so the interceptors never
// run — exactly the attack shape. The flood dials from 127.0.0.2
// (non-peer) while the authenticated peer is a real production dialPeer
// call (PSK credentials, GetStatus probe) from 127.0.0.1, which
// fabricPeerAddrFn names as the peer — so the reserve split is exercised
// end-to-end over real sockets, and pinned again with synthetic
// addresses by TestFabricGateReserveSplit16478.

// FAIL-ON-REVERT: with the gate unwrapped (fabricBoundListener passthrough)
// every holding conn is admitted by grpc.Server, FabricConnActive grows to
// the flood count, refusals stays 0, and the held-count assertions red.
// With KeepaliveParams removed, TestFabricIdleReaped16478 reds.

func fabricBoundTestServer16478(t *testing.T) *Server {
	t.Helper()
	s := NewServer("127.0.0.1:0", Config{
		Store:            newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		FabricPeerAddrFn: func() []string { return []string{"127.0.0.1"} },
	})
	s.fabricAuthKeyFn = func() []byte { return []byte(fabricTestKey) }
	return s
}

func shrinkFabricLimits16478(t *testing.T, total, reserve int) {
	t.Helper()
	origTotal, origReserve := fabricMaxConnsTotal, fabricPeerReserve
	fabricMaxConnsTotal, fabricPeerReserve = total, reserve
	t.Cleanup(func() { fabricMaxConnsTotal, fabricPeerReserve = origTotal, origReserve })
}

// holdPrefaceOnly16478 opens one TCP connection from srcIP (empty = OS
// default source) and completes the HTTP/2 client handshake (preface +
// SETTINGS), then holds it without any RPC. Distinct loopback sources
// (127.0.0.2 flood vs 127.0.0.1 peer) let one host present both the
// non-peer and peer classes to the gate.
func holdPrefaceOnly16478(t *testing.T, addr, srcIP string) (*http2.ClientConn, net.Conn) {
	t.Helper()
	d := net.Dialer{Timeout: 2 * time.Second}
	if srcIP != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(srcIP)}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(c)
	if err != nil {
		c.Close()
		t.Fatalf("http2 handshake %s: %v", addr, err)
	}
	return cc, c
}

func ccUsable16478(cc *http2.ClientConn) bool {
	if cc == nil || !cc.CanTakeNewRequest() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return cc.Ping(ctx) == nil
}

func TestFabricPreAuthFloodCappedAndPeerAdmitted16478(t *testing.T) {
	const total, reserve = 8, 2
	shrinkFabricLimits16478(t, total, reserve)
	s := fabricBoundTestServer16478(t)
	// Re-store the gate at shrunk limits with the production classifier.
	s.fabricConnGate.Store(newFabricConnGate(total, reserve, s.isFabricPeerRemote))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = s.serveUntilDone(ctx, s.buildFabricServer(), s.fabricBoundListener(lis))
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	addr := lis.Addr().String()

	// Flood from a NON-peer source (127.0.0.2): total+6 preface-only
	// connections. Only total-reserve may be admitted; the rest are
	// refused at Accept.
	const flood = total + 6
	held := make([]*http2.ClientConn, 0, flood)
	raws := make([]net.Conn, 0, flood)
	for range flood {
		cc, raw := holdPrefaceOnly16478(t, addr, "127.0.0.2")
		held = append(held, cc)
		raws = append(raws, raw)
	}
	defer func() {
		for _, r := range raws {
			r.Close()
		}
	}()

	usable := 0
	for _, cc := range held {
		if ccUsable16478(cc) {
			usable++
		}
	}
	if want := total - reserve; usable != want {
		t.Fatalf("usable non-peer preface-only conns = %d, want %d (total %d - reserve %d)", usable, want, total, reserve)
	}
	if got, want := s.FabricConnActive(), int64(total-reserve); got != want {
		t.Fatalf("FabricConnActive = %d, want %d (held count uncapped or reserve leaked to flood)", got, want)
	}
	if got, want := s.FabricConnRefusals(), uint64(flood-(total-reserve)); got != want {
		t.Fatalf("FabricConnRefusals = %d, want %d (one per excess conn)", got, want)
	}

	// Authenticated peer still connects DURING the flood, consuming the
	// reserve: real production dialPeer (PSK + GetStatus probe) from the
	// peer source 127.0.0.1. peerFabricGRPCPort is rebound to the test
	// listener's port.
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	oldPort := peerFabricGRPCPort
	peerFabricGRPCPort = port
	t.Cleanup(func() { peerFabricGRPCPort = oldPort })
	conn, err := s.dialPeer(context.Background())
	if err != nil {
		t.Fatalf("authenticated peer dialPeer during flood: %v (reserve denied peer)", err)
	}
	defer conn.Close()
	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer rcancel()
	if _, err := pb.NewBpfrxServiceClient(conn).GetStatus(rctx, &pb.GetStatusRequest{}); err != nil {
		t.Fatalf("authenticated peer GetStatus during flood: %v", err)
	}
	_ = conn.Close()

	// Drain the flood; slots must free exactly once per close.
	for _, r := range raws {
		r.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.FabricConnActive() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.FabricConnActive(); got != 0 {
		t.Fatalf("FabricConnActive = %d after flood drain, want 0 (slot leak)", got)
	}
}

func TestFabricGateReserveSplit16478(t *testing.T) {
	// Synthetic-address unit pin for the reserve: non-peer sources stop at
	// limit-reserve even while slots remain; peer sources may consume the
	// reserve; release frees exactly one slot (double Close safe).
	peerIP := "10.99.1.2"
	g := newFabricConnGate(8, 2, func(a net.Addr) bool {
		return a != nil && fabricPeerIP(a.String()) == fabricPeerIP(peerIP)
	})
	nonPeer := &net.TCPAddr{IP: net.ParseIP("10.99.9.9"), Port: 40000}
	peer := &net.TCPAddr{IP: net.ParseIP(peerIP), Port: 40001}

	admitted := 0
	for range 8 {
		if g.tryAcquire(nonPeer) {
			admitted++
		}
	}
	if admitted != 6 {
		t.Fatalf("non-peer admitted %d, want 6 (limit 8 - reserve 2)", admitted)
	}
	// Reserve still available to the peer.
	if !g.tryAcquire(peer) || !g.tryAcquire(peer) {
		t.Fatal("peer refused while reserve slots remained")
	}
	if g.tryAcquire(peer) {
		t.Fatal("peer admitted past total limit 8")
	}
	if got := g.activeCount(); got != 8 {
		t.Fatalf("active = %d, want 8", got)
	}
	// Release exactly once per conn even on double Close.
	c1, c2 := &fabricGatedConn{Conn: &fabricStubConn16478{remote: nonPeer}, gate: g, peer: false},
		&fabricGatedConn{Conn: &fabricStubConn16478{remote: peer}, gate: g, peer: true}
	_ = c1.Close()
	_ = c1.Close()
	if got := g.activeCount(); got != 7 {
		t.Fatalf("active after double Close = %d, want 7 (exactly-once release)", got)
	}
	_ = c2.Close()
	if got := g.activeCount(); got != 6 {
		t.Fatalf("active after peer Close = %d, want 6", got)
	}
}

type fabricStubConn16478 struct{ remote net.Addr }

func (c *fabricStubConn16478) Read([]byte) (int, error)         { return 0, errors.New("stub") }
func (c *fabricStubConn16478) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fabricStubConn16478) Close() error                     { return nil }
func (c *fabricStubConn16478) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fabricStubConn16478) RemoteAddr() net.Addr             { return c.remote }
func (c *fabricStubConn16478) SetDeadline(time.Time) error      { return nil }
func (c *fabricStubConn16478) SetReadDeadline(time.Time) error  { return nil }
func (c *fabricStubConn16478) SetWriteDeadline(time.Time) error { return nil }

func TestFabricBoundedListenerTemporaryRefusal16478(t *testing.T) {
	// Serve-loop contract: a refused Accept returns a TEMPORARY net.Error
	// (grpc.Server backs off, never exits) and the refused conn is closed
	// without claiming a slot.
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer inner.Close()
	g := newFabricConnGate(1, 0, nil)
	bl := &fabricBoundedListener{Listener: inner, gate: g}

	c1, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatalf("dial1: %v", err)
	}
	defer c1.Close()
	accepted, err := bl.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	defer accepted.Close()

	c2, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer c2.Close()
	if _, err := bl.Accept(); err == nil {
		t.Fatal("second Accept past limit returned nil error")
	} else {
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Temporary() {
			t.Fatalf("refusal error = %v, want temporary net.Error (grpc serve loop must retry, not exit)", err)
		}
	}
	if got := g.refusalsCount(); got != 1 {
		t.Fatalf("refusals = %d, want 1", got)
	}
	// Refused conn was closed server-side: client read gets EOF/closed.
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("refused conn still readable; excess was not closed immediately")
	}
}

func TestFabricConnBoundDefaults16478(t *testing.T) {
	// Pin the shipped values so a leaked test override cannot retune
	// production (mirrors TestRESTConnBoundDefault16081).
	if fabricMaxConnsTotal != 32 {
		t.Fatalf("fabricMaxConnsTotal = %d, want 32", fabricMaxConnsTotal)
	}
	if fabricPeerReserve != 4 {
		t.Fatalf("fabricPeerReserve = %d, want 4", fabricPeerReserve)
	}
	if fabricMaxConnectionIdle != 5*time.Minute {
		t.Fatalf("fabricMaxConnectionIdle = %v, want 5m", fabricMaxConnectionIdle)
	}
	if fabricMaxConnectionAge != time.Hour {
		t.Fatalf("fabricMaxConnectionAge = %v, want 1h", fabricMaxConnectionAge)
	}
	if fabricConnectionTimeout != 30*time.Second {
		t.Fatalf("fabricConnectionTimeout = %v, want 30s", fabricConnectionTimeout)
	}
}

func TestFabricIdleReaped16478(t *testing.T) {
	// MaxConnectionIdle complement: a preface-only connection with no RPC
	// is GOAWAY-drained by the production buildFabricServer once idle past
	// the (shrunk) bound, without any gate refusal. RED if KeepaliveParams
	// is removed from buildFabricServer.
	origIdle := fabricMaxConnectionIdle
	fabricMaxConnectionIdle = 300 * time.Millisecond
	t.Cleanup(func() { fabricMaxConnectionIdle = origIdle })

	s := fabricBoundTestServer16478(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = s.serveUntilDone(ctx, s.buildFabricServer(), s.fabricBoundListener(lis))
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })

	cc, raw := holdPrefaceOnly16478(t, lis.Addr().String(), "")
	defer raw.Close()
	if !ccUsable16478(cc) {
		t.Fatal("preface-only conn not usable immediately after handshake")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !cc.CanTakeNewRequest() {
			return // GOAWAY received: idle reaped.
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("idle preface-only conn still takes requests after MaxConnectionIdle; KeepaliveParams missing?")
}

func TestFabricPeerReserveClassifier16478(t *testing.T) {
	s := &Server{fabricPeerAddrFn: func() []string { return []string{"10.99.1.2", "2001:db8::2"} }}
	cases := []struct {
		remote string
		want   bool
	}{
		{"10.99.1.2:50051", true},
		{"10.99.1.2:1", true}, // ephemeral source port still peer
		{"[2001:db8::2]:50051", true},
		{"10.99.1.3:50051", false},
		{"10.99.9.9:50051", false},
		{"", false},
	}
	for _, tc := range cases {
		var a net.Addr
		if tc.remote != "" {
			ta, err := net.ResolveTCPAddr("tcp", tc.remote)
			if err != nil {
				t.Fatalf("ResolveTCPAddr %q: %v", tc.remote, err)
			}
			a = ta
		}
		if got := s.isFabricPeerRemote(a); got != tc.want {
			t.Errorf("isFabricPeerRemote(%q) = %v, want %v", tc.remote, got, tc.want)
		}
	}
	// No peer fn (standalone / bare server): nobody is peer, reserve
	// unreachable, general pool still applies — fail-closed.
	bare := &Server{}
	if bare.isFabricPeerRemote(&net.TCPAddr{IP: net.ParseIP("10.99.1.2"), Port: 1}) {
		t.Error("bare server classified a peer with no fabricPeerAddrFn")
	}
	// Real authenticated client (grpc) still works through the gate at
	// production limits: compile-time exercised by the flood test; here
	// assert the production client dial options are unchanged in shape by
	// a live insecure dial against the fabric server.
	s2 := fabricBoundTestServer16478(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = s2.serveUntilDone(ctx, s2.buildFabricServer(), s2.fabricBoundListener(lis))
		close(done)
	}()
	defer func() { cancel(); <-done }()
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(NewFabricAuthCreds(func() []byte { return []byte(fabricTestKey) })),
		grpc.WithUnaryInterceptor(FabricAuthUnaryClientInterceptor),
		grpc.WithStreamInterceptor(FabricAuthStreamClientInterceptor),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()
	cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer ccancel()
	if _, err := pb.NewBpfrxServiceClient(conn).GetStatus(cctx, &pb.GetStatusRequest{}); err != nil {
		t.Fatalf("authenticated GetStatus through gate: %v", err)
	}
}
