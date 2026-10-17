package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/sysservices"
)

// management_bootretry_5561_test.go is the fail-on-revert gate for the #5561
// round-14 MAJOR-5 property: the "retry debt" this package documents everywhere
// — "a bind failure retains the previous state and the NEXT COMMIT retries the
// bind" — must actually be true on the two BOOT paths, where there is nothing
// previous to retain and no retry worker to fall back on.
//
// It matters beyond reachability. Every argument in management.go for why an
// over-restrictive intermediate (a withheld grant, an empty intersection, a
// deny-all) is acceptable ends in "a later commit converges". That argument is
// only as good as the convergence, and on these two paths there was none: the
// state was permanent for the life of the process no matter what the operator
// committed.

// A boot HTTP bind failure must leave the reconciler able to RETRY. Before the
// fix, startTo returned before assigning m.srv, and reconcileTo's `m.srv == nil`
// short-circuit made every later reconcile a silent no-op: the management API
// stayed down until the daemon was restarted.
//
// FAIL-ON-REVERT: return from startTo before `m.srv = srv` on the error path and
// the retry below binds nothing.
func TestMgmtBootHTTPBindFailureIsRetriedByTheNextCommit_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Seed a CONVERGED fingerprint before the failing bind. Asserting
	// `curSet == false` on a fresh reconciler asserts the zero value and binds
	// nothing — deleting startTo's error-path `m.cur, m.curSet = mgmtEndpoint{},
	// false` leaves it green. Seeding makes the RESET observable, and the reset is
	// what the retry below depends on: a fingerprint left naming the endpoint that
	// FAILED makes `next.Addr != m.cur.addr` false on the next commit, so
	// ReconcileHTTP is never called and the management API stays down for the life
	// of the process. Daemon.Run only ever calls startTo once, on a fresh
	// reconciler, so this is a defensive reset being pinned rather than a state
	// production reaches — which is precisely why nothing pinned it before.
	m.cur = mgmtEndpoint{addr: "10.0.0.1:8080", tls: true, httpsAddr: "10.0.0.1:8443"}
	m.curSet = true

	reg.failAddr["10.0.0.1:8080"] = true
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err == nil {
		t.Fatal("the boot bind was expected to FAIL, so the case never reached the state it tests")
	}
	if m.curSet || !m.cur.isZero() {
		t.Fatalf("a boot bind failure left the fingerprint at (%+v, curSet=%v); NOTHING converged, "+
			"so it must be emptied or the next reconcile sees no leg as changed and retries "+
			"neither bind", m.cur, m.curSet)
	}
	// `show system services` reports the address it could not bind (#6401).
	if got := m.effectiveHTTPListener(); got.State != sysservices.StateFailed || got.Addr != "10.0.0.1:8080" {
		t.Fatalf("effective listener = %+v, want Failed at 10.0.0.1:8080", got)
	}

	// The next commit — the retry the whole file's fail-safe posture depends on.
	reg.failAddr["10.0.0.1:8080"] = false
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("the retry reconcile failed: %v", err)
	}
	if ln := reg.get("10.0.0.1:8080"); ln == nil || !ln.isOpen() {
		t.Fatal("the next commit did not bind the HTTP listener. A boot bind failure left " +
			"m.srv nil, so reconcileTo short-circuited on EVERY subsequent commit and the " +
			"management API was down for the life of the process — the documented " +
			"'the next commit retries via ReconcileHTTP' contract was never true here " +
			"(#5561 round 14, MAJOR 5)")
	}
	if m.cur.addr != "10.0.0.1:8080" || !m.curSet {
		t.Fatalf("fingerprint = (%q, curSet=%v) after the successful retry, want the converged bind",
			m.cur.addr, m.curSet)
	}
	if got := m.effectiveHTTPListener(); got.State != sysservices.StateListening {
		t.Fatalf("effective listener = %+v, want Listening after the retry paid off the debt", got)
	}
}

// A boot HTTPS bind failure is deliberately NON-fatal — api.Server.Start logs it
// and keeps the HTTP plane up. startTo then recorded the DESIRED HTTPS
// fingerprint as converged anyway, so reconcileTo's leg-changed test
// (`next.TLS != m.cur.tls || next.HTTPSAddr != m.cur.httpsAddr`) was false on
// every subsequent unchanged commit and ReconcileHTTPS was never called. The
// failure was permanent and silent: HTTPS management never came up, and nothing
// the operator committed would bring it up.
//
// FAIL-ON-REVERT: drop the `next.TLS && !srv.HTTPSServing()` clearing in startTo
// and the retry below binds nothing.
func TestMgmtBootHTTPSBindFailureIsRetriedByTheNextCommit_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg.failAddr["10.0.0.1:8443"] = true
	// HTTP binds; HTTPS does not. Start reports success (HTTPS is best-effort).
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("the HTTP leg was expected to come up: %v", err)
	}
	if ln := reg.get("10.0.0.1:8443"); ln != nil && ln.isOpen() {
		t.Fatal("the HTTPS bind was expected to FAIL, so the case never reached the state it tests")
	}
	if m.cur.tls || m.cur.httpsAddr != "" {
		t.Fatalf("the converged fingerprint records tls=%v https=%q, but NO HTTPS listener is "+
			"serving. Recording a desired fingerprint no leg implements makes the leg-changed "+
			"test below false forever, so ReconcileHTTPS is never called again (#5561 round 14, "+
			"MAJOR 5)", m.cur.tls, m.cur.httpsAddr)
	}

	// An UNCHANGED commit — the ordinary case, and the one that must retry.
	reg.failAddr["10.0.0.1:8443"] = false
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("the retry reconcile failed: %v", err)
	}
	if ln := reg.get("10.0.0.1:8443"); ln == nil || !ln.isOpen() {
		t.Fatal("an unchanged commit did not retry the HTTPS bind that failed at boot")
	}
	if !m.cur.tls || m.cur.httpsAddr != "10.0.0.1:8443" {
		t.Fatalf("HTTPS fingerprint = (tls=%v %q) after the successful retry, want the converged leg",
			m.cur.tls, m.cur.httpsAddr)
	}
}

// The retry debt is what makes an over-restrictive intermediate defensible, so
// pin the two together: an api-auth removal whose loopback bind fails leaves the
// off-loopback listener DENY-ALL (round 14, MAJOR 4), and the very next commit —
// once the bind succeeds — converges it to the committed nil. Without an exit,
// deny-all would be a permanent lockout rather than a fail-closed intermediate.
func TestMgmtDenyAllIntermediateConvergesOnTheNextCommit_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	auth := &api.AuthConfig{Users: map[string]string{"admin": "secret"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", auth)); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	reg.failAddr["127.0.0.1:8080"] = true
	if err := m.reconcileTo(cfgFor(reg, "127.0.0.1:8080", false, "", nil)); err == nil {
		t.Fatal("the loopback rebind was expected to FAIL")
	}
	snap := m.srv.LiveAuth()
	if snap == nil || api.CredentialCount(snap) != 0 {
		t.Fatalf("live snapshot = %+v, want the EMPTY (deny-all) intermediate", snap)
	}

	// The exit.
	delete(reg.failAddr, "127.0.0.1:8080")
	if err := m.reconcileTo(cfgFor(reg, "127.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if snap := m.srv.LiveAuth(); snap != nil {
		t.Fatalf("live snapshot = %+v after the loopback bind converged, want nil — every live "+
			"leg is now loopback, so the committed api-auth removal must actually take effect. "+
			"A deny-all with no exit is a lockout, not a fail-closed intermediate", snap)
	}
	if m.cur.addr != "127.0.0.1:8080" {
		t.Fatalf("live HTTP bind = %q, want the converged loopback address", m.cur.addr)
	}
}
