package api

import (
	"context"
	"net"
	"testing"
	"time"
)

// freeTCPPort reserves and immediately releases a localhost TCP port, returning
// its address. There is a small TOCTOU window between release and the caller
// re-binding, which is acceptable for a unit test.
func freeTCPPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return addr
}

// waitDialable blocks until addr accepts a TCP connection or the deadline
// elapses.
func waitDialable(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener %s never became reachable", addr)
}

// assertBindable asserts that addr can be bound (nothing is holding it),
// retrying briefly to absorb any close latency.
func assertBindable(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("port %s not released after shutdown (surviving listener leaked): %v", addr, lastErr)
}

// TestRunClosesSurvivingListenerOnBindFailure is the #5058 regression guard.
// The HTTPS listener is forced to fail its bind by pre-occupying its port; the
// sibling HTTP listener binds first and MUST be closed before Run returns, so
// no orphaned management socket is left behind.
//
// RED-on-revert: the pre-#5058 Run bound HTTP inside a goroutine and returned
// the HTTPS bind error without shutting the HTTP server down, leaving it
// serving forever. A dial to the HTTP address then succeeds and this test
// fails — proving the fix is required.
func TestRunClosesSurvivingListenerOnBindFailure(t *testing.T) {
	httpAddr := freeTCPPort(t)

	// Pre-occupy the HTTPS port so its bind fails deterministically with
	// "address already in use".
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind HTTPS blocker: %v", err)
	}
	defer blocker.Close()
	httpsAddr := blocker.Addr().String()

	srv := NewServer(Config{
		Addr:      httpAddr,
		HTTPSAddr: httpsAddr,
		TLS:       true,
	})
	if srv.httpsServer() == nil {
		t.Fatal("expected httpsServer to be configured (TLS + HTTPSAddr)")
	}

	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(context.Background()) }()

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run must return an error when the HTTPS listener cannot bind")
		}
		t.Logf("Run returned expected startup error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after a listener bind failure (blocked/leaked)")
	}

	// The surviving HTTP listener must be closed. On the buggy code a leaked
	// goroutine keeps serving httpAddr; poll long enough for it to come up so
	// a leak is caught deterministically.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", httpAddr, 100*time.Millisecond)
		if derr == nil {
			c.Close()
			t.Fatalf("HTTP listener %s still accepting connections after Run returned — surviving listener leaked (#5058)", httpAddr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Belt-and-suspenders: the HTTP port must be free to bind again.
	assertBindable(t, httpAddr)
}

// TestRunGracefulShutdownClosesBothListeners exercises the normal path: both
// listeners come up, and ctx cancellation shuts both down and joins their
// goroutines before Run returns nil — the ordering the fix must preserve.
func TestRunGracefulShutdownClosesBothListeners(t *testing.T) {
	httpAddr := freeTCPPort(t)
	httpsAddr := freeTCPPort(t)

	srv := NewServer(Config{
		Addr:      httpAddr,
		HTTPSAddr: httpsAddr,
		TLS:       true,
	})
	if srv.httpsServer() == nil {
		t.Fatal("expected httpsServer to be configured (TLS + HTTPSAddr)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()

	// Both listeners must come up.
	waitDialable(t, httpAddr)
	waitDialable(t, httpsAddr)

	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned error on graceful ctx-cancel shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancellation (serve goroutines not joined?)")
	}

	// Both sockets must be released: Shutdown closed them and both goroutines
	// were joined.
	assertBindable(t, httpAddr)
	assertBindable(t, httpsAddr)
}
