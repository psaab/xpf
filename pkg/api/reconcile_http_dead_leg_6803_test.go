package api

import (
	"net"
	"testing"
	"time"
)

// reconcile_http_dead_leg_6803_test.go — #6803.
//
// ReconcileHTTPS short-circuits a same-address call only when the leg is still
// SERVING:
//
//	case s.httpsLeg().serving() && s.httpsLeg().srv.Addr == addr: return nil
//
// ReconcileHTTP short-circuited on the address alone. An unexpected serve exit
// marks the leg dead and leaves it INSTALLED (it cannot be removed under lifeMu
// without deadlocking a shutdown that races the exit), so the address compare
// matched a corpse and the rebind returned nil having done nothing. The
// management API then stayed down until a daemon restart, whatever the caller
// did.
//
// The cells are PAIRED because this widens a trigger: over-widening it to fire
// on a healthy leg would tear the management socket down and rebuild it on every
// commit — an availability defect traded for an availability defect.

// killHTTPLeg6803 produces an UNEXPECTED serve exit the way production does:
// the listening socket goes away underneath a live Serve loop, which returns a
// non-ErrServerClosed error. It does not poke listenerLeg.dead directly, so the
// cell exercises the path the defect actually arrives on.
func killHTTPLeg6803(t *testing.T, s *Server, ln net.Listener) {
	t.Helper()
	_ = ln.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !s.HTTPServing() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the HTTP leg was still reported serving after its socket died")
}

// bootHTTPLeg6803 binds an HTTP leg at a real ephemeral loopback port and
// returns the server, the leg's listener, and its concrete address.
func bootHTTPLeg6803(t *testing.T) (*Server, net.Listener, string) {
	t.Helper()
	// retireTestServer's injected listen always binds 127.0.0.1:0, so the
	// address STRING carried on the leg (srv.Addr, which is what the short
	// circuit compares) is decoupled from the concrete port. That is what lets
	// this cell hold the address constant while the socket underneath changes —
	// the exact shape the defect needs.
	s := retireTestServer(t, nil)

	s.lifeMu.Lock()
	s.setHTTPSlot0(s.newAuthSlot())
	ln, err := s.listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.lifeMu.Unlock()
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	s.setHTTPServerTemplate(s.buildHTTPServer(addr, s.httpSlot0()))
	s.setHTTPLeg(s.serveLegLocked(s.httpLegPlan(), ln, false))
	s.lifeMu.Unlock()

	if !s.HTTPServing() {
		t.Fatal("the boot bind did not leave the HTTP leg serving; the case starts wrong")
	}
	return s, ln, addr
}

// TestReconcileHTTPRebindsADeadSameAddressLeg6803 is the cell the fix turns on.
//
// The SAME address is the whole point: it is the only shape where the address
// compare and the liveness question disagree. A fixture that changed the address
// could not see the defect, because the short circuit would not have fired
// either way.
//
// FAIL-ON-REVERT: restore the short circuit to
// `if s.httpLeg() != nil && s.httpLeg().srv.Addr == addr { return nil }` and the
// dead leg is never replaced.
func TestReconcileHTTPRebindsADeadSameAddressLeg6803(t *testing.T) {
	s, ln, addr := bootHTTPLeg6803(t)
	dead := s.httpLeg()
	killHTTPLeg6803(t, s, ln)

	if err := s.ReconcileHTTP(addr); err != nil {
		t.Fatalf("ReconcileHTTP to the same address: %v", err)
	}
	if s.httpLeg() == dead {
		t.Fatal("ReconcileHTTP short-circuited on a DEAD same-address leg, so the " +
			"management API stays down until a daemon restart — ReconcileHTTPS asks " +
			"serving() for exactly this reason (#6803)")
	}
	if !s.HTTPServing() {
		t.Fatal("ReconcileHTTP replaced the dead leg but the replacement is not serving")
	}
	if got := s.EffectiveHTTPAddr(); got == "" {
		t.Error("EffectiveHTTPAddr is still empty after a successful rebind, so " +
			"`show system services` keeps reporting the listener Failed")
	}
}

// TestReconcileHTTPLeavesALiveSameAddressLegAlone6803 is the over-reach half.
//
// Without it the fix is satisfied by dropping the short circuit entirely, which
// rebuilds the management socket on every reconcile — and reconcile runs on
// every commit and, since this issue, every 30s.
func TestReconcileHTTPLeavesALiveSameAddressLegAlone6803(t *testing.T) {
	s, _, addr := bootHTTPLeg6803(t)
	live := s.httpLeg()

	if err := s.ReconcileHTTP(addr); err != nil {
		t.Fatalf("ReconcileHTTP to the same address: %v", err)
	}
	if s.httpLeg() != live {
		t.Fatal("ReconcileHTTP REBOUND a healthy same-address leg; the liveness " +
			"question must widen the trigger for a dead leg only")
	}
	if !s.HTTPServing() {
		t.Fatal("the healthy leg stopped serving after a no-op reconcile")
	}
}

// TestHTTPServingMirrorsHTTPSServing6803 pins the accessor the two gates share.
//
// It is not a tautology: HTTPServing is what both api.ReconcileHTTP and the
// daemon's reconcileTo/re-assert gate ask, so an implementation that reported a
// dead leg as serving would re-open the whole issue at three call sites at once,
// with every behavioural cell above still green (they would simply never enter
// the rebind branch, and their "did it rebind" assertions would fail — but a
// version that reported a LIVE leg as dead passes those and bounces the socket
// forever, which is what this direction catches).
func TestHTTPServingMirrorsHTTPSServing6803(t *testing.T) {
	s, ln, _ := bootHTTPLeg6803(t)
	if !s.HTTPServing() {
		t.Fatal("HTTPServing reported a live leg as dead")
	}
	killHTTPLeg6803(t, s, ln)
	if s.HTTPServing() {
		t.Fatal("HTTPServing reported a dead leg as serving")
	}
	// A server with no HTTP leg at all reads not-serving, matching
	// HTTPSServing's nil-leg behaviour — serving() is defined on the nil leg.
	if (&Server{}).HTTPServing() {
		t.Error("a server with no HTTP leg reported one as serving")
	}
}
