package api

import (
	"context"
	"testing"
)

// TestReconcileLegsPositionalSwapDoesNotSelfCollide_14983 is the #14983
// (D36-03) positional self-collision regression: a pure address SWAP
// [A,B] -> [B,A] must converge. Pre-fix, reconcileLegsLocked bound leg 1's
// replacement B before retiring the current leg 1 (still serving B) and
// leg 0's replacement A before retiring the current leg 0 (still serving
// A); each bind raced its own still-held socket and failed EADDRINUSE /
// fake-EADDRINUSE, so every retry reproduced the same error and neither
// swap ever landed.
//
// FAIL-ON-REVERT: delete the addr -> live-leg adoption in
// reconcileLegsLocked and both binds fail against still-serving holders;
// this test goes RED.
func TestReconcileLegsPositionalSwapDoesNotSelfCollide_14983(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reqAddrs := []string{"127.0.0.1:0", "[::1]:0"}
	s := NewServer(Config{
		Addrs: reqAddrs,
	})
	s.SetTLSCertDirForTest(t.TempDir())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	defer func() { cancel(); s.Wait() }()

	bound := s.EffectiveHTTPAddrs()
	if len(bound) != 2 {
		t.Fatalf("EffectiveHTTPAddrs = %v, want 2 legs", bound)
	}
	v4, v6 := bound[0], bound[1]

	// Pure swap of the REQUESTED bind set: identical set, only the
	// order changed. The serving check compares the requested (srv)
	// addresses, so the swap must adopt both legs rather than re-bind.
	if err := s.ReconcileHTTPAddrs([]string{reqAddrs[1], reqAddrs[0]}); err != nil {
		t.Fatalf("positional swap ReconcileHTTPAddrs = %v; a pure swap must converge without EADDRINUSE self-collision (#14983)", err)
	}
	if got := s.EffectiveHTTPAddrs(); len(got) != 2 || got[0] != v6 || got[1] != v4 {
		t.Fatalf("after swap EffectiveHTTPAddrs = %v, want [%s %s]", got, v6, v4)
	}
	// Both swapped listeners actually answer.
	assertHTTP200(t, "http://"+v6+"/health")
	assertHTTP200(t, "http://"+v4+"/health")

	// Swap back; still no self-collision.
	if err := s.ReconcileHTTPAddrs([]string{reqAddrs[0], reqAddrs[1]}); err != nil {
		t.Fatalf("reverse swap ReconcileHTTPAddrs = %v", err)
	}
	if got := s.EffectiveHTTPAddrs(); len(got) != 2 || got[0] != v4 || got[1] != v6 {
		t.Fatalf("after reverse swap EffectiveHTTPAddrs = %v, want [%s %s]", got, v4, v6)
	}
}

// TestReconcileLegsDuplicatesRejected_14983 pins that a desired set naming
// the same address twice is rejected (no duplicate leg installed): the
// second occurrence must not bind a second socket at the same address nor
// retire the leg the first occurrence legitimately adopted.
func TestReconcileLegsDuplicatesRejected_14983(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := NewServer(Config{Addrs: []string{"127.0.0.1:0"}})
	s.SetTLSCertDirForTest(t.TempDir())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	defer func() { cancel(); s.Wait() }()
	a := s.EffectiveHTTPAddrs()[0]

	if err := s.ReconcileHTTPAddrs([]string{"127.0.0.1:0", "127.0.0.1:0"}); err == nil {
		t.Fatal("duplicate desired addresses must be rejected, not silently bound twice (#14983)")
	}
	if got := s.EffectiveHTTPAddrs(); len(got) != 1 || got[0] != a {
		t.Fatalf("after duplicate rejection EffectiveHTTPAddrs = %v, want [%s] retained", got, a)
	}
	if !s.HTTPServing() {
		t.Fatal("original leg must keep serving after duplicate rejection")
	}
}
