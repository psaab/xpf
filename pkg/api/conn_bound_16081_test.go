package api

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// #16081 (DOS-6) decisive regression: open concurrent REST connections past
// the new bound -> excess must be refused with a counted refusal while
// existing connections keep working.
//
// This drives the REAL path: NewServer -> Start -> wrapped listener ->
// http.Server, with the production gate shrunk through the same
// apiMaxConnsTotal var production reads (restored via cleanup). Holding
// connections are REAL TCP connections that have completed a /health
// request and stay open keep-alive, so the slots they hold are the slots
// the server actually granted — no fake listener, no direct gate poking
// for the main assertion.
//
// FAIL-ON-REVERT: with the bound removed (listeners unwrapped / gate never
// installed), every dial succeeds, refusals stays 0 and the excess read
// returns a 200 instead of a close — every load-bearing assertion reds.

func startBoundServer16081(t *testing.T, limit int) (*Server, string) {
	t.Helper()
	orig := apiMaxConnsTotal
	apiMaxConnsTotal = limit
	t.Cleanup(func() { apiMaxConnsTotal = orig })

	s := NewServer(Config{Addr: "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); s.Wait() })
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := s.EffectiveHTTPAddr()
	if addr == "" {
		t.Fatal("no effective HTTP address after Start")
	}
	return s, addr
}

// dialHealth16081 opens one TCP connection, issues GET /health and reads
// the full response, leaving the connection OPEN (keep-alive) so it keeps
// holding its gate slot. It returns the open conn.
func dialHealth16081(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := fmt.Fprintf(c, "GET /health HTTP/1.1\r\nHost: %s\r\n\r\n", addr); err != nil {
		t.Fatalf("write request: %v", err)
	}
	readHealth20016081(t, c)
	return c
}

// readHealth20016081 reads one HTTP response from c and requires 200.
func readHealth20016081(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, 4096)
	var got strings.Builder
	for !strings.Contains(got.String(), "\r\n\r\n") {
		n, err := c.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
		if err != nil {
			t.Fatalf("reading /health response: %v (got %q)", err, got.String())
		}
	}
	head := got.String()
	if !strings.HasPrefix(head, "HTTP/1.1 200") {
		t.Fatalf("/health status = %q, want 200", strings.SplitN(head, "\r\n", 2)[0])
	}
	// Drain the body so the connection is cleanly keep-alive reusable.
	if idx := strings.Index(head, "\r\n\r\n"); idx >= 0 {
		rest := head[idx+4:]
		var clen int
		for _, line := range strings.Split(head[:idx], "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				_, _ = fmt.Sscanf(strings.TrimSpace(line[len("content-length:"):]), "%d", &clen)
			}
		}
		need := clen - len(rest)
		for need > 0 {
			n, err := c.Read(buf)
			if n > 0 {
				need -= n
			}
			if err != nil {
				t.Fatalf("draining /health body: %v", err)
			}
		}
	}
}

func TestRESTConnBoundRefusesExcess16081(t *testing.T) {
	const limit = 4
	s, addr := startBoundServer16081(t, limit)

	// Fill the gate with live, working connections.
	held := make([]net.Conn, 0, limit)
	for range limit {
		held = append(held, dialHealth16081(t, addr))
	}
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	if got := s.RestConnActive(); got != limit {
		t.Fatalf("RestConnActive = %d, want %d after filling the gate", got, limit)
	}
	if got := s.RestConnRefusals(); got != 0 {
		t.Fatalf("RestConnRefusals = %d before excess, want 0", got)
	}

	// Excess connections: dialed at TCP level (the kernel completes the
	// handshake into the backlog) but refused by the gate at Accept — the
	// peer must observe a close, never a served response, and each refusal
	// must be counted.
	const excess = 3
	for i := range excess {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("excess dial %d: %v (refusal must be at accept, not dial)", i, err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprintf(c, "GET /health HTTP/1.1\r\nHost: %s\r\n\r\n", addr)
		buf := make([]byte, 256)
		n, rerr := c.Read(buf)
		if n > 0 {
			t.Fatalf("excess conn %d read %d bytes %q — it was SERVED past the bound", i, n, buf[:n])
		}
		if rerr == nil {
			t.Fatalf("excess conn %d: read returned no error and no data; want close", i)
		}
		_ = c.Close()
	}
	// Refusals are counted synchronously in Accept before the close the
	// peer observed, so the count is already final.
	if got := s.RestConnRefusals(); got != excess {
		t.Fatalf("RestConnRefusals = %d, want %d counted refusals", got, excess)
	}

	// Existing connections keep working: a fresh request on a held
	// keep-alive connection still answers 200.
	if _, err := fmt.Fprintf(held[0], "GET /health HTTP/1.1\r\nHost: %s\r\n\r\n", addr); err != nil {
		t.Fatalf("held conn write: %v", err)
	}
	readHealth20016081(t, held[0])

	// Freeing a slot admits the next connection (release path, not a
	// one-way ratchet).
	_ = held[limit-1].Close()
	held = held[:limit-1]
	deadline := time.Now().Add(5 * time.Second)
	for s.RestConnActive() != limit-1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.RestConnActive(); got != limit-1 {
		t.Fatalf("RestConnActive = %d after closing one held conn, want %d (slot not released)", got, limit-1)
	}
	c := dialHealth16081(t, addr)
	_ = c.Close()
	if got := s.RestConnRefusals(); got != excess {
		t.Fatalf("RestConnRefusals = %d after re-admission, want still %d", got, excess)
	}
}

// TestRESTConnBoundSharedAcrossPlanes16081 pins the per-Server (not
// per-leg) semantics: HTTP and HTTPS legs draw on ONE gate, so a flood on
// one plane cannot multiply the ceiling by the leg count.
func TestRESTConnBoundSharedAcrossPlanes16081(t *testing.T) {
	orig := apiMaxConnsTotal
	apiMaxConnsTotal = 2
	t.Cleanup(func() { apiMaxConnsTotal = orig })

	s := NewServer(Config{Addr: "127.0.0.1:0", TLS: true, HTTPSAddr: "127.0.0.1:0"})
	s.SetTLSCertDirForTest(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); s.Wait() })
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	httpAddr := s.EffectiveHTTPAddr()
	httpsAddr := s.EffectiveHTTPSAddr()
	if httpAddr == "" || httpsAddr == "" {
		t.Fatalf("effective addrs http=%q https=%q, want both", httpAddr, httpsAddr)
	}
	if s.gateFor() == nil {
		t.Fatal("NewServer installed no connection gate")
	}
	// Both planes draw on this one gate (verified behaviourally below:
	// filling it via HTTP refuses a fresh HTTPS connection).
	// refused.
	c1 := dialHealth16081(t, httpAddr)
	defer func() { _ = c1.Close() }()
	c2 := dialHealth16081(t, httpAddr)
	defer func() { _ = c2.Close() }()

	c, err := net.DialTimeout("tcp", httpsAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("https excess dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, rerr := c.Read(buf)
	if n > 0 || rerr == nil {
		t.Fatalf("HTTPS excess conn read n=%d err=%v — gate is per-leg, not per-Server", n, rerr)
	}
	if got := s.RestConnRefusals(); got != 1 {
		t.Fatalf("RestConnRefusals = %d, want 1 (HTTPS excess counted on the shared gate)", got)
	}
}

// TestRESTConnBoundDefault16081 pins the shipped limit so a leaked test
// override cannot silently retune production (mirrors
// TestLegDrainTimeoutDefault_6827).
func TestRESTConnBoundDefault16081(t *testing.T) {
	if apiMaxConnsTotal != 256 {
		t.Fatalf("apiMaxConnsTotal = %d, want shipped default 256", apiMaxConnsTotal)
	}
	s := NewServer(Config{Addr: "127.0.0.1:0"})
	g := s.gateFor()
	if g == nil {
		t.Fatal("NewServer must install a connection gate")
	}
	if g.limit != 256 {
		t.Fatalf("installed gate limit = %d, want 256", g.limit)
	}
	// Nil-safety: bare fixtures without a gate report zero, never panic.
	bare := &Server{}
	if bare.RestConnRefusals() != 0 || bare.RestConnActive() != 0 {
		t.Fatal("bare &Server{} must report zero refusals/active")
	}
}

// TestBoundedListenerTemporaryRefusal16081 unit-pins the serve-loop
// contract: a refused Accept returns a TEMPORARY net.Error (http.Server
// backs off, never exits) and the refused conn is closed without claiming
// a slot; release happens exactly once across double Close.
func TestBoundedListenerTemporaryRefusal16081(t *testing.T) {
	g := newAPIConnGate(1)
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = clientLn.Close() }()
	bl := &boundedListener{Listener: clientLn, gate: g}

	acceptAsync := func() <-chan net.Conn {
		ch := make(chan net.Conn, 1)
		go func() {
			c, aerr := bl.Accept()
			if aerr != nil {
				ch <- nil
				return
			}
			ch <- c
		}()
		return ch
	}

	// First conn admitted.
	d1, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial1: %v", err)
	}
	defer func() { _ = d1.Close() }()
	a1 := <-acceptAsync()
	if a1 == nil {
		t.Fatal("first Accept returned nil conn")
	}
	if got := g.activeCount(); got != 1 {
		t.Fatalf("active = %d after first admit, want 1", got)
	}

	// Second conn refused: Accept yields a temporary error, no conn.
	d2, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer func() { _ = d2.Close() }()
	type acceptRes struct {
		c   net.Conn
		err error
	}
	resCh := make(chan acceptRes, 1)
	go func() {
		c, aerr := bl.Accept()
		resCh <- acceptRes{c, aerr}
	}()
	res := <-resCh
	if res.c != nil {
		t.Fatalf("refused Accept returned conn %v, want nil", res.c)
	}
	var nerr net.Error
	if res.err == nil || !isTemporary16081(res.err, &nerr) {
		t.Fatalf("refused Accept err = %v, want temporary net.Error (serve loop must retry, not exit)", res.err)
	}
	if got := g.refusalsCount(); got != 1 {
		t.Fatalf("refusals = %d, want 1", got)
	}
	// Refused peer observes close.
	_ = d2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, rerr := d2.Read(make([]byte, 8)); rerr == nil {
		t.Fatal("refused peer read succeeded; want close")
	}

	// Double Close releases exactly once.
	if err := a1.Close(); err != nil {
		t.Fatalf("close admitted: %v", err)
	}
	_ = a1.Close()
	if got := g.activeCount(); got != 0 {
		t.Fatalf("active = %d after double close, want 0 (exactly-once release)", got)
	}
}

func isTemporary16081(err error, target *net.Error) bool {
	if err == nil {
		return false
	}
	ne, ok := err.(net.Error)
	if !ok {
		return false
	}
	*target = ne
	return ne.Temporary() //nolint:staticcheck // Temporary is the accept-loop contract http.Server checks.
}

// TestRESTConnRefusalsMetric16081 drives the real collector emitters: the
// refusal counter on the Server's gate must move the exported series, and
// both samples must be present at zero (the #3464 always-emit convention).
func TestRESTConnRefusalsMetric16081(t *testing.T) {
	collect := func(s *Server) map[string]float64 {
		t.Helper()
		c := newCollector(s)
		ch := make(chan prometheus.Metric, 8)
		c.emitRESTConnBound(ch)
		close(ch)
		out := map[string]float64{}
		for m := range ch {
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatalf("write metric: %v", err)
			}
			switch {
			case strings.Contains(m.Desc().String(), "xpf_rest_conn_refusals_total"):
				out["refusals"] = pb.GetCounter().GetValue()
			case strings.Contains(m.Desc().String(), "xpf_rest_conn_active"):
				out["active"] = pb.GetGauge().GetValue()
			}
		}
		return out
	}

	s := NewServer(Config{Addr: "127.0.0.1:0"})
	before := collect(s)
	if before["refusals"] != 0 {
		t.Fatalf("refusals at zero state = %v, want emitted 0", before["refusals"])
	}
	if _, ok := before["refusals"]; !ok {
		t.Fatal("xpf_rest_conn_refusals_total not emitted at zero")
	}
	if _, ok := before["active"]; !ok {
		t.Fatal("xpf_rest_conn_active not emitted at zero")
	}

	g := s.gateFor()
	if g == nil || !g.tryAcquire() {
		t.Fatal("gate missing or refuses its first slot")
	}
	defer g.release()
	g.noteRefusal(dummyAddr16081{})
	after := collect(s)
	if after["refusals"] != 1 {
		t.Fatalf("refusals after one gate refusal = %v, want 1", after["refusals"])
	}
	if after["active"] != 1 {
		t.Fatalf("active with one admitted conn = %v, want 1", after["active"])
	}

}

type dummyAddr16081 struct{}

func (dummyAddr16081) Network() string { return "tcp" }
func (dummyAddr16081) String() string  { return "192.0.2.1:12345" }
