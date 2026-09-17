package flowexport

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeConn records whether Close was called so the leak test can prove
// that connections opened before a mid-loop failure are torn down.
type fakeConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// withSeams swaps the resolve/dial seams for the duration of fn and
// restores them afterward via t.Cleanup. The context adapters preserve the
// legacy seam signatures used by the existing teardown tests while allowing
// the production path to enforce cancellation.
func withSeams(t *testing.T,
	resolve func(string, string) (*net.UDPAddr, error),
	dial func(string, *net.UDPAddr, *net.UDPAddr) (net.Conn, error),
	fn func()) {
	t.Helper()
	origResolve, origDial := resolveUDPAddr, dialUDP
	origResolveContext, origDialContext := resolveUDPAddrContext, dialUDPContext
	resolveUDPAddr = resolve
	dialUDP = dial
	resolveUDPAddrContext = func(ctx context.Context, network, address string) (*net.UDPAddr, error) {
		type result struct {
			addr *net.UDPAddr
			err  error
		}
		done := make(chan result, 1)
		go func() {
			addr, err := resolve(network, address)
			done <- result{addr: addr, err: err}
		}()
		select {
		case result := <-done:
			return result.addr, result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	dialUDPContext = func(ctx context.Context, network string, laddr *net.UDPAddr, address string) (net.Conn, error) {
		type resolveResult struct {
			addr *net.UDPAddr
			err  error
		}
		resolveDone := make(chan resolveResult, 1)
		go func() {
			addr, err := resolve(network, address)
			resolveDone <- resolveResult{addr: addr, err: err}
		}()
		var raddr *net.UDPAddr
		select {
		case result := <-resolveDone:
			if result.err != nil {
				return nil, result.err
			}
			raddr = result.addr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		type dialResult struct {
			conn net.Conn
			err  error
		}
		dialDone := make(chan dialResult, 1)
		go func() {
			conn, err := dial(network, laddr, raddr)
			dialDone <- dialResult{conn: conn, err: err}
		}()
		select {
		case result := <-dialDone:
			return result.conn, result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	t.Cleanup(func() {
		resolveUDPAddr, dialUDP = origResolve, origDial
		resolveUDPAddrContext, dialUDPContext = origResolveContext, origDialContext
	})
	fn()
}

// TestDialCollectors_SourceAddressResolveError proves the resolve error
// for a misconfigured SourceAddress is surfaced rather than silently
// dropped to a nil local bind.
//
// Against the pre-fix code (which ignored the SourceAddress resolve error
// and fell through to a successful DialUDP with laddr=nil) this test
// fails: dialCollectors returned a non-nil conns set and a nil error.
func TestDialCollectors_SourceAddressResolveError(t *testing.T) {
	sentinel := errors.New("bad source address")
	resolve := func(network, addr string) (*net.UDPAddr, error) {
		if strings.HasPrefix(addr, "192.0.2.250") {
			return nil, sentinel // simulate a misconfigured SourceAddress
		}
		return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 2055}, nil
	}
	dialed := false
	dial := func(network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dial should not be reached")
	}

	withSeams(t, resolve, dial, func() {
		conns, err := dialCollectors([]CollectorConfig{
			{Address: "192.0.2.10:2055", SourceAddress: "192.0.2.250"},
		})
		if err == nil {
			t.Fatal("expected error from bad SourceAddress resolve, got nil")
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected wrapped sentinel error, got %v", err)
		}
		if conns != nil {
			t.Fatalf("expected nil conns on resolve failure, got %v", conns)
		}
		if dialed {
			t.Fatal("dial must not be attempted when SourceAddress resolve fails")
		}
	})
}

// TestDialCollectors_NoLeakOnMidLoopResolveFailure proves a connection
// opened before a later raddr-resolve failure is closed before returning.
//
// Against the pre-fix code (which returned early on the raddr resolve
// error without closing already-opened conns) this test fails: the first
// fakeConn stays open and isClosed() reports false.
func TestDialCollectors_NoLeakOnMidLoopResolveFailure(t *testing.T) {
	first := &fakeConn{}
	resolveErr := errors.New("bad destination address")
	resolve := func(network, addr string) (*net.UDPAddr, error) {
		if strings.HasPrefix(addr, "192.0.2.99") {
			// Second collector's destination fails to resolve, mid-loop.
			return nil, resolveErr
		}
		return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 2055}, nil
	}
	dial := func(network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
		// First collector dials successfully and yields our recording fake.
		return first, nil
	}

	withSeams(t, resolve, dial, func() {
		conns, err := dialCollectors([]CollectorConfig{
			{Address: "192.0.2.10:2055", SourceAddress: "192.0.2.1"},
			{Address: "192.0.2.99:2055", SourceAddress: "192.0.2.1"},
		})
		if err == nil {
			t.Fatal("expected error from second collector resolve failure, got nil")
		}
		if !errors.Is(err, resolveErr) {
			t.Fatalf("expected wrapped resolve error, got %v", err)
		}
		if conns != nil {
			t.Fatalf("expected nil conns on failure, got %v", conns)
		}
		if !first.isClosed() {
			t.Fatal("connection opened before mid-loop failure was leaked (not closed)")
		}
	})
}

// TestDialCollectors_NoLeakOnDialFailure proves a successfully opened
// connection is closed when a later collector's dial fails. This path
// already closed conns before the fix; the test guards against
// regression while the surrounding code is refactored.
func TestDialCollectors_NoLeakOnDialFailure(t *testing.T) {
	first := &fakeConn{}
	dialErr := errors.New("dial refused")
	resolve := func(network, addr string) (*net.UDPAddr, error) {
		return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 2055}, nil
	}
	calls := 0
	dial := func(network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return nil, dialErr
	}

	withSeams(t, resolve, dial, func() {
		conns, err := dialCollectors([]CollectorConfig{
			{Address: "192.0.2.10:2055", SourceAddress: "192.0.2.1"},
			{Address: "192.0.2.11:2055", SourceAddress: "192.0.2.1"},
		})
		if err == nil {
			t.Fatal("expected dial error, got nil")
		}
		if !errors.Is(err, dialErr) {
			t.Fatalf("expected wrapped dial error, got %v", err)
		}
		if conns != nil {
			t.Fatalf("expected nil conns on failure, got %v", conns)
		}
		if !first.isClosed() {
			t.Fatal("connection opened before dial failure was leaked (not closed)")
		}
	})
}
