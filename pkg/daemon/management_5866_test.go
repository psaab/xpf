// #5866: the managementReconciler must, on a day-2 web-management change,
// atomically replace the live HTTP/HTTPS listener + authentication snapshot
// instead of leaving the boot-time server enforcing the old policy until a
// restart. These tests drive reconcileTo/startTo with a FAKE listener factory
// (no real ports) and cover: a bind/port change (new active, old closed),
// make-before-break coexistence, a TLS-material change (listener rebound,
// durable cert reloaded), a same-endpoint auth swap (no rebind), and a failed
// new-bind (old listener
// RETAINED, error surfaced — fail-closed to the previous working state).
//
// FAIL-ON-REVERT: revert reconcileTo to close-old-before-binding-new and the
// bind-failure test leaves nothing serving (RED); revert it to not swap and the
// bind/port + auth tests do not converge (RED).
package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/sysservices"
)

// fakeLn is an in-memory net.Listener: Accept blocks until Close, so an
// http.Server.Serve loop parks until Shutdown closes it (no real socket).
type fakeLn struct {
	addr   string
	closed chan struct{}
	once   sync.Once
}

func (f *fakeLn) Accept() (net.Conn, error) { <-f.closed; return nil, net.ErrClosed }
func (f *fakeLn) Close() error              { f.once.Do(func() { close(f.closed) }); return nil }
func (f *fakeLn) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (f *fakeLn) isOpen() bool {
	select {
	case <-f.closed:
		return false
	default:
		return true
	}
}

// fakeReg is the injected listener factory. It records, at each new listener's
// creation, whether every previously-created listener was still open — the
// make-before-break witness: a new endpoint must bind while the old is still
// serving.
type fakeReg struct {
	mu              sync.Mutex
	byAddr          map[string]*fakeLn
	failAddr        map[string]bool
	priorsOpenAtNew map[string]bool
}

func newFakeReg() *fakeReg {
	return &fakeReg{byAddr: map[string]*fakeLn{}, failAddr: map[string]bool{}, priorsOpenAtNew: map[string]bool{}}
}

func (r *fakeReg) listen(network, addr string) (net.Listener, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failAddr[addr] {
		return nil, fmt.Errorf("fake bind refused: %s", addr)
	}
	// #5866: model EADDRINUSE. Real net.Listen (Go sets SO_REUSEADDR, NOT
	// SO_REUSEPORT) rejects a second LISTEN on an addr that is still open. The
	// old whole-server rebuild re-bound the retained HTTP socket on a TLS enable
	// and would hit exactly this; the per-listener fix binds ONLY the changed
	// leg, so it never re-binds a still-open sibling. A closed addr may be
	// re-bound (enable -> disable -> re-enable on the same HTTPS port).
	if ln, ok := r.byAddr[addr]; ok && ln.isOpen() {
		return nil, fmt.Errorf("fake bind: listen tcp %s: bind: address already in use", addr)
	}
	priorsOpen := true
	for a, ln := range r.byAddr {
		if a != addr && !ln.isOpen() {
			priorsOpen = false
		}
	}
	r.priorsOpenAtNew[addr] = priorsOpen
	ln := &fakeLn{addr: addr, closed: make(chan struct{})}
	r.byAddr[addr] = ln
	return ln, nil
}

func (r *fakeReg) get(addr string) *fakeLn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byAddr[addr]
}

func cfgFor(reg *fakeReg, addr string, useTLS bool, httpsAddr string, auth *api.AuthConfig) api.Config {
	return api.Config{Addr: addr, TLS: useTLS, HTTPSAddr: httpsAddr, Auth: auth, ListenFunc: reg.listen}
}

func newTestMgmt(reg *fakeReg) *managementReconciler {
	// reconcileTo/startTo do not dereference d (only desired()/start() do), so a
	// bare Daemon is sufficient for these listener-lifecycle tests.
	return newManagementReconciler(&Daemon{}, api.Config{ListenFunc: reg.listen})
}

func waitClosed(t *testing.T, ln *fakeLn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !ln.isOpen() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("listener %s did not close within the drain window", ln.addr)
}

// Bar 1 + Bar 4: a bind/port change replaces the listener make-before-break —
// the new endpoint is active and the old is closed, and the new endpoint bound
// while the old was still serving (no unreachable window).
func TestMgmtReconcileBindChange_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	old := reg.get("10.0.0.1:8080")
	if old == nil || !old.isOpen() {
		t.Fatal("initial listener not active")
	}

	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", nil)); err != nil {
		t.Fatalf("bind-change reconcile: %v", err)
	}
	// New endpoint recorded + active.
	if m.cur.addr != "10.0.0.2:8080" {
		t.Fatalf("current endpoint = %q, want the new bind 10.0.0.2:8080", m.cur.addr)
	}
	newLn := reg.get("10.0.0.2:8080")
	if newLn == nil || !newLn.isOpen() {
		t.Fatal("new listener is not active after the bind change")
	}
	// Make-before-break: the new endpoint bound while the old was still open.
	if !reg.priorsOpenAtNew["10.0.0.2:8080"] {
		t.Fatal("new listener bound only AFTER the old closed — not make-before-break (#5866): " +
			"there was a window with no management listener")
	}
	// Old endpoint is retired.
	waitClosed(t, old)
}

// Bar 2: a TLS-material change make-before-break rebinds the HTTPS listener and
// serves the DURABLE self-signed cert (#5866 + #1916 D6). Enabling TLS and then
// moving the HTTPS bind rebinds the HTTPS leg (new socket bound while the old is
// still serving, then the old retired), but the on-disk self-signed pair is
// LOADED AS-IS on the rebind — re-minting would churn remote clients' TOFU pins
// (#5719 / PR #6378), so the served leaf bytes are IDENTICAL across the rebind.
//
// #6381: the OLD assertion required DIFFERENT leaf bytes ("a fresh cert per
// rebind"), the OPPOSITE of the shipping durable-cert contract. It passed only
// as a CI artifact — the production certGen writes /etc/xpf/tls, which is
// unwritable in CI, so LoadX509KeyPair found no pair and the persist write
// failed NON-FATALLY (generateSelfSignedCertAt LOGS the error but returns the
// fresh in-memory cert with a nil error, so HTTPS still installs), and every
// reconcile therefore re-minted a fresh in-memory cert whose leaf bytes
// differed. In production (writable /etc/xpf/tls) the second reconcile RELOADS
// the same pair -> identical bytes -> the old assertion would have FAILED. This
// test redirects certGen to a writable temp dir (SetTLSCertDirForTest) so the
// shipping durable-reload path is actually exercised, and asserts the intended
// invariant: the listener rebinds, but the durable cert is reloaded AS-IS.
func TestMgmtReconcileTLSChange_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start HTTP-only.
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	// Redirect HTTPS cert generation to a WRITABLE temp dir so the durable-reload
	// path (#1916 D6) genuinely persists — otherwise the write fails and every
	// reconcile re-mints a fresh in-memory cert, masking the real invariant
	// (#6381). Set before any TLS is enabled: startTo is HTTP-only, so certGen is
	// untouched until the first enable-TLS reconcile below.
	m.srv.SetTLSCertDirForTest(t.TempDir())
	if m.srv.HTTPSCertForTest() != nil {
		t.Fatal("HTTP-only server must not serve a TLS cert")
	}

	// Enable HTTPS -> the HTTPS leg binds and mints+persists the durable cert.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("enable-TLS reconcile: %v", err)
	}
	cert1 := m.srv.HTTPSCertForTest()
	if cert1 == nil {
		t.Fatal("HTTPS-enabled server must serve a TLS cert after the reconcile")
	}
	oldHTTPS := reg.get("10.0.0.1:8443")
	if oldHTTPS == nil || !oldHTTPS.isOpen() {
		t.Fatal("HTTPS listener not active after enabling TLS")
	}

	// Change the HTTPS bind -> make-before-break rebind of the HTTPS leg.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.2:8443", nil)); err != nil {
		t.Fatalf("https-rebind reconcile: %v", err)
	}
	cert2 := m.srv.HTTPSCertForTest()
	if cert2 == nil {
		t.Fatal("HTTPS cert missing after the https rebind")
	}

	// The listener WAS rebound: the new HTTPS socket is active, it bound while the
	// old was still open (make-before-break, no unreachable window), and the old
	// HTTPS socket is retired. This is the real #5866 TLS-material invariant.
	newHTTPS := reg.get("10.0.0.2:8443")
	if newHTTPS == nil || !newHTTPS.isOpen() {
		t.Fatal("HTTPS listener not rebound to the new address after the TLS-material change (#5866)")
	}
	if !reg.priorsOpenAtNew["10.0.0.2:8443"] {
		t.Fatal("new HTTPS bound only AFTER the old closed — not make-before-break (#5866): " +
			"there was a window with no HTTPS listener")
	}
	waitClosed(t, oldHTTPS)

	// The served cert is the DURABLE self-signed pair, LOADED AS-IS across the
	// rebind (#1916 D6): re-minting on a rebind would churn remote clients' TOFU
	// pins (#5719 / #6378), so the leaf bytes must be IDENTICAL. (The old test
	// wrongly required them to DIFFER — a CI-only artifact of an unwritable
	// /etc/xpf/tls, #6381.)
	if len(cert1.Certificate) == 0 || len(cert2.Certificate) == 0 {
		t.Fatal("served TLS cert has no leaf certificate")
	}
	if !bytesEqual(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Fatal("the durable self-signed cert must be RELOADED AS-IS on an HTTPS rebind, got different leaf " +
			"bytes — a rebind must not re-mint (that churns remote clients' TOFU pins, #1916 D6 / #6381)")
	}
}

// Bar 3: a same-endpoint auth change swaps the LIVE auth snapshot in place — no
// listener rebind (the server instance is unchanged), and the revoked credential
// is rejected on the next request.
func TestMgmtReconcileAuthSwapNoRebind_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	auth := &api.AuthConfig{Users: map[string]string{"admin": "secret"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", auth)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	srvBefore := m.srv
	ln := reg.get("10.0.0.1:8080")

	// Revoke admin on the SAME endpoint.
	revoked := &api.AuthConfig{Users: map[string]string{"other": "pw"}}
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", false, "", revoked)); err != nil {
		t.Fatalf("auth-swap reconcile: %v", err)
	}
	// No rebind: the SAME server instance and the SAME listener are retained.
	if m.srv != srvBefore {
		t.Fatal("a same-endpoint auth change must NOT rebind the listener (server instance changed)")
	}
	if !ln.isOpen() {
		t.Fatal("the listener was bounced on a same-endpoint auth change (#5866)")
	}
	// The live auth snapshot was swapped IN PLACE to the revoked set (admin gone,
	// other present). The api-level TestServerReplaceAuthLiveSwap_5866 proves such
	// a snapshot rejects the revoked credential on the next request.
	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("live auth snapshot is nil after the revoke reconcile")
	}
	if _, ok := snap.Users["admin"]; ok {
		t.Fatal("revoked credential 'admin' is STILL in the live auth snapshot — the swap did not " +
			"take effect (#5866)")
	}
	if _, ok := snap.Users["other"]; !ok {
		t.Fatal("the new credential 'other' is missing from the live auth snapshot")
	}
}

// Bar 5: a failed new-bind RETAINS the old listener (fail-closed to the previous
// working state, not mgmt-down) and surfaces the error. This is also the sharp
// make-before-break lever: a close-old-first implementation would leave nothing
// serving.
func TestMgmtReconcileBindFailureRetainsOld_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	old := reg.get("10.0.0.1:8080")
	srvBefore := m.srv

	reg.failAddr["10.0.0.2:8080"] = true
	err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", nil))
	if err == nil {
		t.Fatal("a failed listener replacement must surface an error")
	}
	// Old listener retained + still serving.
	if m.srv != srvBefore {
		t.Fatal("the live server was swapped despite the new bind failing (#5866)")
	}
	if m.cur.addr != "10.0.0.1:8080" {
		t.Fatalf("endpoint fingerprint = %q, want the retained 10.0.0.1:8080 (retry debt)", m.cur.addr)
	}
	if !old.isOpen() {
		t.Fatal("the OLD listener was closed on a failed replacement — management went DOWN " +
			"(fail-open); make-before-break must retain the previous working listener (#5866)")
	}
	// Give any (incorrect) async close a chance, then re-assert the old is up.
	time.Sleep(50 * time.Millisecond)
	if !old.isOpen() {
		t.Fatal("the OLD listener closed asynchronously after a failed replacement (#5866)")
	}
}

// #5866 per-leg independence: a TLS enable/disable/re-enable rebinds ONLY the
// HTTPS leg. The live HTTP listener is never re-bound (its socket stays the SAME
// fakeLn, still open) — under the old whole-server rebuild this re-bound the
// still-held HTTP socket and the strict fake rejects it with EADDRINUSE.
func TestMgmtReconcileHTTPSEnableDisableReEnable_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("initial HTTP-only start: %v", err)
	}
	httpLn := reg.get("10.0.0.1:8080")
	if httpLn == nil || !httpLn.isOpen() {
		t.Fatal("HTTP listener not active")
	}

	// Enable HTTPS -> only the HTTPS leg binds; HTTP is untouched.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("enable-TLS reconcile must succeed with the per-leg fix (no HTTP re-bind): %v", err)
	}
	if reg.get("10.0.0.1:8080") != httpLn || !httpLn.isOpen() {
		t.Fatal("the live HTTP listener was disturbed by a TLS enable (#5866): it must be the SAME open socket")
	}
	if hln := reg.get("10.0.0.1:8443"); hln == nil || !hln.isOpen() {
		t.Fatal("HTTPS listener not active after enable")
	}

	// Disable HTTPS -> HTTPS leg retires, HTTP untouched.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("disable-TLS reconcile: %v", err)
	}
	waitClosed(t, reg.get("10.0.0.1:8443"))
	if reg.get("10.0.0.1:8080") != httpLn || !httpLn.isOpen() {
		t.Fatal("HTTP listener disturbed by a TLS disable (#5866)")
	}

	// Re-enable HTTPS on the SAME addr (now free) -> binds a fresh HTTPS leg.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("re-enable-TLS reconcile: %v", err)
	}
	if hln := reg.get("10.0.0.1:8443"); hln == nil || !hln.isOpen() {
		t.Fatal("HTTPS listener not active after re-enable on the same port")
	}
	if reg.get("10.0.0.1:8080") != httpLn || !httpLn.isOpen() {
		t.Fatal("HTTP listener disturbed by a TLS re-enable (#5866)")
	}
}

// #5866: an HTTPS-bind-ONLY change (HTTP addr + TLS flag unchanged) make-before-
// break rebinds only the HTTPS leg; the HTTP listener is untouched.
func TestMgmtReconcileHTTPSBindOnlyChange_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("initial HTTP+HTTPS start: %v", err)
	}
	httpLn := reg.get("10.0.0.1:8080")
	oldHTTPS := reg.get("10.0.0.1:8443")

	// Move ONLY the HTTPS bind. HTTP stays on :8080.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.2:8443", nil)); err != nil {
		t.Fatalf("https-bind-only reconcile must succeed (HTTP untouched): %v", err)
	}
	if reg.get("10.0.0.1:8080") != httpLn || !httpLn.isOpen() {
		t.Fatal("the HTTP listener was re-bound by an HTTPS-only change (#5866)")
	}
	if newHTTPS := reg.get("10.0.0.2:8443"); newHTTPS == nil || !newHTTPS.isOpen() {
		t.Fatal("new HTTPS listener not active")
	}
	// Make-before-break: the new HTTPS bound while the old HTTPS was still open.
	if !reg.priorsOpenAtNew["10.0.0.2:8443"] {
		t.Fatal("new HTTPS bound only after the old closed — not make-before-break (#5866)")
	}
	waitClosed(t, oldHTTPS)
}

// #5866 symmetric case: an HTTP-addr change while HTTPS is present + UNCHANGED
// rebinds only the HTTP leg. The HTTPS listener is never re-bound (the old
// whole-server rebuild would re-bind the still-held HTTPS socket -> EADDRINUSE).
func TestMgmtReconcileHTTPChangeKeepsHTTPS_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("initial HTTP+HTTPS start: %v", err)
	}
	httpsLn := reg.get("10.0.0.1:8443")

	// Change ONLY the HTTP bind. HTTPS stays on :8443.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", true, "10.0.0.1:8443", nil)); err != nil {
		t.Fatalf("http-only reconcile must succeed without re-binding the unchanged HTTPS socket: %v", err)
	}
	if reg.get("10.0.0.1:8443") != httpsLn || !httpsLn.isOpen() {
		t.Fatal("the HTTPS listener was re-bound by an HTTP-only change (#5866 symmetric collision)")
	}
	if newHTTP := reg.get("10.0.0.2:8080"); newHTTP == nil || !newHTTP.isOpen() {
		t.Fatal("new HTTP listener not active")
	}
}

// #5866 revocation-honoring (the elevated Finding A): a SINGLE commit that BOTH
// revokes a credential AND changes the HTTPS endpoint to one that FAILS to bind
// must still reject the revoked credential on the next request — the revocation
// is published UP FRONT, regardless of the HTTPS rebind outcome — while the old
// HTTPS state is retained with retry debt.
//
// The GRANT half of the same commit does not land yet, and #5561 round 12 is why:
// the failed rebind leaves the old HTTPS listener serving an address this config
// asked to leave, and the credential set was committed for the address it asked
// to move to. So `other` is withheld until the HTTPS leg converges, which the
// control at the end drives. The two halves are deliberately split — a commit
// that revokes and grants at once must have its revocation honored immediately
// and its grant honored only where it was committed to apply.
//
// FAIL-ON-REVERT: without the up-front ReplaceAuth (publishing auth only after
// the legs converge), the failed HTTPS rebind leaves the revoked credential in
// the live snapshot -> the admin-absent assertion FAILS.
func TestMgmtReconcileRevokeHonoredDespiteHTTPSBindFailure_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	auth := &api.AuthConfig{Users: map[string]string{"admin": "secret"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", auth)); err != nil {
		t.Fatalf("initial HTTP+HTTPS start: %v", err)
	}
	oldHTTPS := reg.get("10.0.0.1:8443")

	// Bundled commit: revoke admin (new set has only "other") AND move the HTTPS
	// bind to an address that fails to bind.
	reg.failAddr["10.0.0.2:8443"] = true
	revoked := &api.AuthConfig{Users: map[string]string{"other": "pw"}}
	err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.2:8443", revoked))
	if err == nil {
		t.Fatal("a failed HTTPS rebind must surface an error (retry debt)")
	}

	// The revocation was honored despite the HTTPS bind failure: the live auth
	// snapshot no longer contains admin.
	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("live auth snapshot is nil after the revoke reconcile")
	}
	if _, ok := snap.Users["admin"]; ok {
		t.Fatal("revoked credential 'admin' is STILL live after a bundled revoke + failed HTTPS rebind " +
			"— a revoked credential must be rejected on the next request regardless of the rebind outcome (#5866)")
	}
	// ...and the grant half is WITHHELD while a leg is retained at an address
	// this commit asked to leave (#5561 round 12).
	if _, ok := snap.Users["other"]; ok {
		t.Fatal("the newly committed credential 'other' was published while the OLD HTTPS listener " +
			"at 10.0.0.1:8443 is still serving — that address is one this commit asked to move away " +
			"from, and it never accepted 'other' before, so publishing it there grants a credential " +
			"on a listener the committed config did not authorize (#5561 round 12)")
	}

	// The old HTTPS listener is retained (fail-closed) and its fingerprint is not
	// advanced (retry debt).
	if !oldHTTPS.isOpen() {
		t.Fatal("the old HTTPS listener was closed on a failed rebind (mgmt HTTPS went down)")
	}
	if m.cur.httpsAddr != "10.0.0.1:8443" {
		t.Fatalf("HTTPS fingerprint = %q, want the retained 10.0.0.1:8443 (retry debt)", m.cur.httpsAddr)
	}
	// The HTTP listener was never touched.
	if hln := reg.get("10.0.0.1:8080"); hln == nil || !hln.isOpen() {
		t.Fatal("the HTTP listener was disturbed by the HTTPS rebind")
	}

	// Control: the withholding is scoped to the FAILURE, not permanent. Let the
	// HTTPS rebind succeed and the full committed set lands — otherwise the
	// assertion above would be satisfied by an implementation that simply never
	// grants a new credential after any endpoint change.
	delete(reg.failAddr, "10.0.0.2:8443")
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.2:8443", revoked)); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if snap := m.srv.LiveAuth(); snap == nil || snap.Users["other"] != "pw" {
		t.Fatalf("post-convergence snapshot = %+v, want the full committed set — every live leg is "+
			"now at an address this config names, so the grant half must land", snap)
	}
}

// #5866 fail-open avoidance (the counterpart to the revocation-honoring case):
// removing ALL api-auth (next.Auth == nil, which clamps the HTTP bind to
// loopback) while the HTTP leg's OWN rebind to that loopback address FAILS must
// NOT drop the retained NON-loopback HTTP listener to no-auth. The nil is not
// published, because the gate reads the LIVE HTTP address (m.cur.addr, which the
// failed rebind left at the old non-loopback bind).
//
// What IS published there was inverted in #5561 round 14 (MAJOR 4), and this
// test's original expectation was the defect. It asserted that the retained
// listener keeps its PREVIOUS credential set — i.e. that `delete system services
// web-management api-auth` leaves the deleted secret authenticating full-power
// requests on a routable address, for as long as the loopback bind keeps
// failing. That is not a deferral; it is the round-7 fail-open in the one
// direction round 7 did not cover, and it is permanent rather than a window.
//
// The safe intermediate for "no credential is authorized here any more" is the
// DENY-ALL set: non-nil and empty, which dynamicAuthMiddleware rejects every
// non-exempt request against. It honours the revocation immediately (the
// operator's instruction) without publishing the nil (the fail-open), and it
// converges to nil on the retry that binds loopback. The sibling conjunct,
// covering a retained non-loopback HTTPS leg, is pinned by
// TestMgmtNilAuthNeverDropsARetainedOffLoopbackHTTPSLeg_5561.
func TestMgmtReconcileRemoveAuthDeniesAllWhenHTTPRebindFails_5866(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Live: non-loopback HTTP with auth (valid — auth present).
	auth := &api.AuthConfig{Users: map[string]string{"admin": "secret"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", auth)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	oldHTTP := reg.get("10.0.0.1:8080")

	// Commit removes ALL api-auth -> the bind clamps to loopback (127.0.0.1),
	// but that rebind FAILS. next.Auth == nil.
	reg.failAddr["127.0.0.1:8080"] = true
	err := m.reconcileTo(cfgFor(reg, "127.0.0.1:8080", false, "", nil))
	if err == nil {
		t.Fatal("a failed HTTP rebind must surface an error")
	}

	// The nil auth was NOT applied — that would be the fail-open. What IS applied
	// is deny-all: the removed credential stops working at once, and the retained
	// non-loopback listener answers nobody until the bind converges.
	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("api-auth was removed while the retained listener is still non-loopback — FAIL-OPEN (#5866): " +
			"a nil-on-loopback auth must not be applied to a retained non-loopback listener")
	}
	if pw, ok := snap.Users["admin"]; ok {
		t.Fatalf("the retained non-loopback listener still accepts admin=%q, a credential the "+
			"commit DELETED (#5561 round 14, MAJOR 4). The loopback bind that would have made "+
			"the removal safe failed, so this listener keeps serving a routable address — and "+
			"keeps honouring the deleted secret there until some later bind happens to succeed. "+
			"An api-auth removal is a revocation and must land immediately, like every other", pw)
	}
	if api.CredentialCount(snap) != 0 {
		t.Fatalf("the retained non-loopback listener enforces %+v, want the EMPTY (deny-all) set — "+
			"the committed policy authorizes no credential at all, and the only expressions of "+
			"that are nil (fail-open here) and deny-all", snap)
	}
	// Old non-loopback listener retained + open; fingerprint not advanced.
	if !oldHTTP.isOpen() {
		t.Fatal("the old HTTP listener was closed on a failed rebind (mgmt went down)")
	}
	if m.cur.addr != "10.0.0.1:8080" {
		t.Fatalf("HTTP fingerprint = %q, want the retained 10.0.0.1:8080 (retry debt)", m.cur.addr)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestMgmtReconcileRotationRevokesDespiteHTTPRebindFailure_5561 is the round-7
// MAJOR-2 guard.
//
// ReplaceAuth used to sit inside `if httpOK`, so when the HTTP leg's OWN rebind
// failed and the old listener was retained, a credential ROTATION was never
// published: the retained listener kept honouring the REVOKED secret, and not
// for a race window — indefinitely, until some later reconcile happened to
// succeed. The surrounding comment had the right argument for the wrong scope.
// It says a non-nil Auth only ADDS a requirement and so cannot fail open; that
// is true of the REVOCATION half against ANY live bind, including one retained
// by a failure, so gating that half on the rebind outcome bought nothing and
// cost revocation.
//
// Round 12 supplies the scope the round-7 comment was missing. A rotation is a
// revocation AND a grant, and only the first half is a tightening: `new-secret`
// was not accepted on this listener before, and the commit that introduced it
// asked to serve a DIFFERENT address. So the retained listener stops accepting
// `old-secret` at once and does not start accepting `new-secret` until the
// rebind converges — asserted here in both directions, since an implementation
// that published nothing would satisfy the revocation alone.
//
// The negative control for the OTHER axis is REMOVING all api-auth. That
// direction removes a requirement and can fail open, so what it WITHHOLDS on a
// failed HTTP rebind is the nil itself — not the revocation, which lands at once
// as the DENY-ALL set (#5561 round 14). It is covered by
// TestMgmtReconcileRemoveAuthDeniesAllWhenHTTPRebindFails_5866, which must stay
// green.
func TestMgmtReconcileRotationRevokesDespiteHTTPRebindFailure_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	old := &api.AuthConfig{Users: map[string]string{"admin": "old-secret"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", old)); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	// The operator rotates the credential AND the new bind fails.
	rotated := &api.AuthConfig{Users: map[string]string{"admin": "new-secret"}}
	reg.failAddr["10.0.0.2:8080"] = true
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", rotated)); err == nil {
		t.Fatal("a failed listener replacement must surface an error")
	}

	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("the live auth snapshot went nil on a failed rebind — that drops api-auth " +
			"entirely, which is the fail-open the deferral exists to prevent")
	}
	// The revocation half landed despite the failure (round 7).
	if got := snap.Users["admin"]; got == "old-secret" {
		t.Fatal("after a credential rotation whose HTTP rebind FAILED, the live snapshot still " +
			"authorizes old-secret — the revoked secret keeps working on the retained listener " +
			"until some later reconcile happens to succeed, which is a permanent fail-open " +
			"rather than a race window (#5561 round 7)")
	}
	// The grant half did not (round 12): 10.0.0.1:8080 is the address this commit
	// asked to leave, and it never accepted new-secret.
	if got := snap.Users["admin"]; got == "new-secret" {
		t.Fatal("the rotated secret was published to the listener at 10.0.0.1:8080, which this " +
			"commit asked to move away from and which never accepted it. A credential set is " +
			"committed together with the endpoint it is meant for; when that endpoint fails to " +
			"bind, the retained listener may lose credentials but must not gain them (#5561 " +
			"round 12)")
	}

	// Control: the withholding is scoped to the failure. Once the bind converges,
	// the rotated secret is live — so the assertion above is not satisfied by an
	// implementation that has simply stopped publishing rotations.
	delete(reg.failAddr, "10.0.0.2:8080")
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", rotated)); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if got := m.srv.LiveAuth(); got == nil || got.Users["admin"] != "new-secret" {
		t.Fatalf("post-convergence snapshot = %+v, want the rotated secret live on the endpoint "+
			"the operator committed", got)
	}
}

func TestMgmtHTTPAuthActivationDisablesClearLegBeforePublishing10826(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, cfgFor(reg, "127.0.0.1:8080", false, "", nil)); err != nil {
		t.Fatalf("initial HTTP start: %v", err)
	}
	oldHTTP := reg.get("127.0.0.1:8080")
	oldHandler := m.srv.HTTPHandlerForTest()
	if oldHTTP == nil || oldHandler == nil {
		t.Fatal("fixture has no serving HTTP leg to retire")
	}
	nextAuth := &api.AuthConfig{
		APIKeys:       map[string]bool{"new-api-key": true},
		APIKeyClasses: map[string]string{"new-api-key": "read-only"},
		APIKeyExpires: map[string]time.Time{"new-api-key": time.Now().Add(time.Hour)},
	}

	if err := m.reconcileTo(cfgFor(reg, "", false, "", nextAuth)); err != nil {
		t.Fatalf("enable auth and disable clear HTTP: %v", err)
	}
	waitClosed(t, oldHTTP)
	if m.srv.HTTPServing() || m.srv.EffectiveHTTPAddr() != "" {
		t.Fatalf("clear HTTP remains serving after auth activation: serving=%v addr=%q",
			m.srv.HTTPServing(), m.srv.EffectiveHTTPAddr())
	}
	if got := m.effectiveHTTPListener().State; got != sysservices.StateDisabled {
		t.Fatalf("effective HTTP state = %v, want Disabled", got)
	}
	if got := m.srv.LiveAuth(); got == nil || !got.APIKeys["new-api-key"] {
		t.Fatalf("the active snapshot did not publish the HTTPS/next-endpoint credential: %+v", got)
	}

	// The old handler is still reachable while its leg drains. Its slot must
	// remain pinned to deny-all rather than follow the new global snapshot.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set("X-API-Key", "new-api-key")
	rec := httptest.NewRecorder()
	oldHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("retiring clear-HTTP handler accepted the newly published credential: %d %s",
			rec.Code, rec.Body.String())
	}
}

func TestMgmtFailedRebindWithholdsCredentialPrivilegeUpgrade10826(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const key = "same-api-key"
	oldAuth := &api.AuthConfig{
		APIKeys:       map[string]bool{key: true},
		APIKeyClasses: map[string]string{key: "read-only"},
	}
	nextAuth := &api.AuthConfig{
		APIKeys:       map[string]bool{key: true},
		APIKeyClasses: map[string]string{key: "super-user"},
	}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", false, "", oldAuth)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	reg.failAddr["10.0.0.2:8080"] = true
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", nextAuth)); err == nil {
		t.Fatal("the failed bind was not surfaced")
	}
	if got := m.srv.LiveAuth(); got == nil || got.APIKeys[key] {
		t.Fatalf("a failed rebind retained the same secret with its upgraded super-user scope: %+v", got)
	}

	delete(reg.failAddr, "10.0.0.2:8080")
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:8080", false, "", nextAuth)); err != nil {
		t.Fatalf("converge rebind: %v", err)
	}
	if got := m.srv.LiveAuth(); got == nil || !got.APIKeys[key] || got.APIKeyClasses[key] != "super-user" {
		t.Fatalf("credential scope was not published after endpoint convergence: %+v", got)
	}
}
