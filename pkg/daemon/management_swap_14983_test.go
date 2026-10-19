package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/api"
)

// cfgForMulti builds an api.Config with an explicit multi-address HTTP
// bind set (#14583 form), so the daemon-level tests below drive the same
// positional leg machinery as the dual-stack resolver.
func cfgForMulti(reg *fakeReg, addrs []string, auth *api.AuthConfig) api.Config {
	cfg := api.Config{Addrs: addrs, Auth: auth, ListenFunc: reg.listen}
	if len(addrs) > 0 {
		cfg.Addr = addrs[0]
	}
	return cfg
}

// TestMgmtSwapConvergesAndPublishesFullAuth_14983 is the daemon-level
// #14983 (D36-03) regression. It binds BOTH legs of the partial-rebind
// auth desync:
//
//  1. A positional swap [A,B] -> [B,A] of the HTTP bind set fails both
//     binds EADDRINUSE pre-fix (each new bind races its own still-serving
//     holder), so reconcileTo returns an error and, worse, leaves m.cur
//     pointing at the OLD positional set [A,B] even though the api
//     layer retained [A,B] too — the fingerprint and the live set agree
//     with each other but not with the desired [B,A] (retry debt that
//     can never converge, since every retry reproduces the collision).
//  2. While unsanctioned, a rotated credential publishes only the
//     intersection (here the empty set). Pre-fix the post-rebind gate
//     `m.cur.everyLiveLegNamedBy(next)` re-read the stale positional
//     m.cur and never fired, so the full rotation stayed withheld even
//     though every serving listener (A and B) was named by next — the
//     withheld grant was unrecoverable without swapping the config back.
//
// Post-fix the swap converges in the api layer (each desired address
// adopts the live leg already serving it), m.cur advances to [B,A], and
// the full rotated set publishes.
//
// FAIL-ON-REVERT: remove the addr->live-leg adoption in
// reconcileLegsLocked and both binds fail again; reconcileTo errors and
// LiveAuth stays the empty intersection.
func TestMgmtSwapConvergesAndPublishesFullAuth_14983(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a"}}
	if err := m.startTo(ctx, cfgForMulti(reg, []string{"10.0.0.1:8080", "10.0.0.2:8080"}, a)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if got := m.srv.EffectiveHTTPAddrs(); len(got) != 0 {
		// fakeLn.Addr() always reports 127.0.0.1; identity is tracked via reg.
		_ = got
	}
	if ln := reg.get("10.0.0.1:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("leg A not serving after start")
	}
	if ln := reg.get("10.0.0.2:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("leg B not serving after start")
	}

	// Swap the bind set AND rotate the credential in one commit.
	b := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-b"}}
	if err := m.reconcileTo(cfgForMulti(reg, []string{"10.0.0.2:8080", "10.0.0.1:8080"}, b)); err != nil {
		t.Fatalf("swap reconcile = %v; a pure positional swap must converge (#14983)", err)
	}

	// Fingerprint advanced to the swapped set.
	if len(m.cur.addrs) != 2 || m.cur.addrs[0] != "10.0.0.2:8080" || m.cur.addrs[1] != "10.0.0.1:8080" {
		t.Fatalf("m.cur.addrs = %v, want [10.0.0.2:8080 10.0.0.1:8080] after the swap", m.cur.addrs)
	}
	if m.cur.addr != "10.0.0.2:8080" {
		t.Fatalf("m.cur.addr = %q, want 10.0.0.2:8080", m.cur.addr)
	}

	// Full rotated credential published (the swap named every live leg).
	if snap := m.srv.LiveAuth(); snap == nil || snap.Users["webadmin"] != "secret-b" {
		t.Fatalf("LiveAuth = %+v, want rotated secret-b published once the swap converged; "+
			"withheld intersection must not survive a converged swap (#14983)", snap)
	}

	// Both original listeners still serving (adoption, no bounce).
	if ln := reg.get("10.0.0.1:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("leg A socket closed by a pure swap — adoption must keep the socket")
	}
	if ln := reg.get("10.0.0.2:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("leg B socket closed by a pure swap — adoption must keep the socket")
	}
}

// TestMgmtPartialRebindRetainsOffLoopbackDenyAll_14983 pins the nil-auth
// half of the partial-rebind desync: a two-leg HTTP set where one leg's
// replacement bind fails must keep the RETAINED off-loopback listener on
// deny-all, never nil (pass-through) — even though its sibling converged
// onto loopback.
//
// NOTE (adjudication during implementation): on current
// origin/master this case PASSES pre-fix — the whole-plane
// all-or-nothing m.cur advance keeps the retained address IN the
// fingerprint, so deny-all already publishes. It is retained as the
// fail-closed CONTROL that the #14983 live-sanction resync must not
// regress (a fingerprint-only resync that dropped the retained leg
// would publish nil here). The RED gate for #14983 is
// TestMgmtSwapConvergesAndPublishesFullAuth_14983 plus the api-level
// TestReconcileLegsPositionalSwapDoesNotSelfCollide_14983.
//
// FAIL-ON-REVERT: make publishNilDirectionLocked judge only a
// fingerprint that has dropped the retained leg.
func TestMgmtPartialRebindRetainsOffLoopbackDenyAll_14983(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret"}}
	if err := m.startTo(ctx, cfgForMulti(reg, []string{"10.0.0.1:8080", "10.0.0.2:8080"}, a)); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	// Remove all api-auth: the clamp wants both legs on loopback. Leg 0's
	// loopback bind succeeds; leg 1's loopback bind fails, so the
	// off-loopback leg 1 is RETAINED and still serving.
	reg.failAddr["127.0.0.2:8080"] = true
	next := cfgForMulti(reg, []string{"127.0.0.1:8080", "127.0.0.2:8080"}, nil)
	if err := m.reconcileTo(next); err == nil {
		t.Fatal("leg-1 rebind expected to fail, so the case never reached the partial state")
	}
	if ln := reg.get("10.0.0.2:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("retained off-loopback leg 1 (10.0.0.2:8080) not serving; the case proves nothing")
	}
	if ln := reg.get("127.0.0.1:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("converged loopback leg 0 (127.0.0.1:8080) not serving")
	}

	// The property: never nil while an off-loopback leg serves.
	if snap := m.srv.LiveAuth(); snap == nil {
		t.Fatal("nil auth published while the retained off-loopback leg 10.0.0.2:8080 is serving: " +
			"dynamicAuthMiddleware's nil snapshot is a pass-through, so the mutating REST API is " +
			"unauthenticated off-loopback (#14983 partial-rebind desync)")
	} else if _, ok := snap.Users["webadmin"]; ok {
		t.Fatalf("retained off-loopback leg still accepts the deleted credential: %+v", snap)
	} else if api.CredentialCount(snap) != 0 {
		t.Fatalf("LiveAuth = %+v, want deny-all (empty non-nil) while an off-loopback leg is retained", snap)
	}

	// Control: once leg 1's loopback bind converges, nil publishes.
	delete(reg.failAddr, "127.0.0.2:8080")
	if err := m.reconcileTo(next); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if snap := m.srv.LiveAuth(); snap != nil {
		t.Fatalf("post-convergence LiveAuth = %+v, want nil (both legs loopback)", snap)
	}
}

// TestMgmtPartialRebindDoesNotPublishGrantToRetained_14983 pins the
// grant half of the same desync: with one leg retained off its desired
// address, a rotated+granted credential must stay withheld (intersection
// only) until the retained leg converges. This is the CONTROL for the
// sanction logic — it must stay green both before and after the fix.
func TestMgmtPartialRebindDoesNotPublishGrantToRetained_14983(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a"}}
	if err := m.startTo(ctx, cfgForMulti(reg, []string{"10.0.0.1:8080", "10.0.0.2:8080"}, a)); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	reg.failAddr["10.0.0.3:8080"] = true
	b := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a", "ops": "secret-b"}}
	if err := m.reconcileTo(cfgForMulti(reg, []string{"10.0.0.3:8080", "10.0.0.2:8080"}, b)); err == nil {
		t.Fatal("leg-0 rebind expected to fail")
	}
	// "ops" was granted only for the converged endpoint; the retained leg
	// must not accept it. Intersection = {webadmin: secret-a} only.
	if snap := m.srv.LiveAuth(); snap == nil {
		t.Fatal("LiveAuth went nil during a failed partial rebind")
	} else if _, ok := snap.Users["ops"]; ok {
		t.Fatalf("retained listener gained granted credential ops before convergence: %+v", snap)
	} else if snap.Users["webadmin"] != "secret-a" {
		t.Fatalf("LiveAuth = %+v, want the intersection to keep webadmin", snap)
	}

	// Converge: full set publishes.
	delete(reg.failAddr, "10.0.0.3:8080")
	if err := m.reconcileTo(cfgForMulti(reg, []string{"10.0.0.3:8080", "10.0.0.2:8080"}, b)); err != nil {
		t.Fatalf("converging reconcile: %v", err)
	}
	if snap := m.srv.LiveAuth(); snap == nil || snap.Users["ops"] != "secret-b" {
		t.Fatalf("after convergence LiveAuth = %+v, want full set with ops", snap)
	}
}
