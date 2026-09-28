package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/api"
)

// management_nilpublish_5561_test.go is the fail-on-revert gate for the PRE-REBIND
// call site of publishNilDirectionLocked (reconcileTo's `else` arm, #5561 round
// 16).
//
// Every other case in this package exercises the nil (remove-all-api-auth)
// direction on a rebind that FAILS, where the off-loopback listener is RETAINED
// and follows the server-wide snapshot — and on that path the pre-rebind call is
// redundant, because the post-rebind call publishes the same deny-all against the
// same unchanged m.cur. So the whole call site could be deleted with build, vet
// and both package suites staying green.
//
// The path where it is load-bearing is the one where the rebind SUCCEEDS, because
// there the old leg is RETIRED rather than retained, and a retired leg stops
// following the server-wide snapshot the instant it is retired:
//
//  1. A live HTTPS leg serves an off-loopback address under a committed credential.
//  2. The operator commits `delete system services web-management api-auth` and
//     removes the HTTPS interface. The default HTTPS bind resolves to loopback.
//  3. ReconcileHTTPS retires the old leg, and api.Server.trackRetiring PINS it to
//     whatever s.auth holds at that instant (listener.go, `leg.slot.pin`).
//  4. The post-rebind publish can no longer repair that pin: m.cur is loopback by
//     then so the nil the operator committed goes out, and authSlot.tighten
//     deliberately drops a nil next (server.go) — a nil REMOVES a requirement and
//     is licensed only by the loopback bind the commit converged.
// Without the pre-rebind publish the pin captured at step 3 is the DELETED
// credential, and it keeps authenticating on the routable address for the whole
// drain plus every keep-alive connection already accepted. The pre-rebind
// publish is what makes the pinned value deny-all instead.
//
// assertion is the consumer-visible one — whether the retired HTTPS listener's own
// handler admits the removed credential — reached by holding that leg's handler
// across the reconcile (api.Server.HTTPSHandlerForTest). Driving the handler is
// how pkg/daemon tests assert the policy the old leg enforces, and holding it
// before retirement avoids depending on a scheduling race against the drain.

// mgmtLegAdmits runs a Basic-auth request against a leg handler and reports
// whether it was admitted. A path outside the mux is used deliberately: an
// admitted request must not reach a real handler on a Server built without a
// dataplane, and 404-vs-401 is exactly the distinction being asserted.
func mgmtLegAdmits(t *testing.T, h http.Handler, user, pass string) bool {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/xpf-nilpublish-probe", nil)
	if user != "" || pass != "" {
		r.SetBasicAuth(user, pass)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code != http.StatusUnauthorized
}

// TestMgmtRemovedCredentialNeverSurvivesOnTheRetiredLeg_5561 drives the converging
// api-auth removal: the off-loopback listener is REPLACED, not retained.
//
// FAIL-ON-REVERT: delete reconcileTo's pre-rebind `else { m.publishNilDirectionLocked() }`
// arm. The retired leg is then pinned to the credential the commit DELETED, the
// post-rebind nil cannot tighten it away, and the probe below is admitted.
func TestMgmtRemovedCredentialNeverSurvivesOnTheRetiredLeg_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	served := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	live := m.desired(served)
	if !live.TLS || mgmtAddrIsLoopback(live.HTTPSAddr) {
		t.Fatalf("the served config resolves HTTPS to %q (TLS=%v), which is not an "+
			"off-loopback HTTPS listener — the case proves nothing", live.HTTPSAddr, live.TLS)
	}
	if err := m.startTo(ctx, live); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	// Hold the handler of the HTTPS leg the commit below RETIRES. After the
	// reconcile it is no longer reachable from the server's active leg.
	retired := m.srv.HTTPSHandlerForTest()
	if retired == nil {
		t.Fatal("no live HTTPS leg after start; the case has nothing to retire")
	}
	if !mgmtLegAdmits(t, retired, "webadmin", mgmtAuthTestSecret("secret-a")) {
		t.Fatal("the live off-loopback HTTPS listener rejects its own committed credential " +
			"before the case starts — the probe is not reaching the auth middleware and " +
			"every assertion below would pass vacuously")
	}

	// The commit: remove api-auth and its off-box HTTPS interface. The configured
	// HTTPS leg resolves to loopback and, unlike the failing-rebind cases, THAT
	// BIND SUCCEEDS — so the off-loopback leg is retired rather than retained.
	removed := mgmtAuthCommit(t, store, mgmtAuthConfigRemoveAuth())
	rm := m.desired(removed)
	if rm.Auth != nil {
		t.Fatalf("the api-auth removal fixture still resolves to a credential (%+v) — the case "+
			"never reaches the nil direction it is about", rm.Auth)
	}
	if !rm.TLS || !mgmtAddrIsLoopback(rm.HTTPSAddr) || rm.HTTPSAddr == live.HTTPSAddr {
		t.Fatalf("the api-auth removal resolves to HTTPS %q; the case needs a LOOPBACK address "+
			"DIFFERENT from the live %q, or no leg is retired and the post-rebind publish "+
			"never converges to nil", rm.HTTPSAddr, live.HTTPSAddr)
	}
	if err := m.reconcile(removed); err != nil {
		t.Fatalf("the loopback HTTPS rebind was expected to SUCCEED — that is the whole point of this "+
			"case, and the retained-listener path is already covered elsewhere: %v", err)
	}
	if m.cur.httpsAddr != rm.HTTPSAddr {
		t.Fatalf("live HTTPS bind = %q after the removal, want the converged %q",
			m.cur.httpsAddr, rm.HTTPSAddr)
	}

	// The property.
	if mgmtLegAdmits(t, retired, "webadmin", mgmtAuthTestSecret("secret-a")) {
		t.Fatalf("secret-a still authenticates on the RETIRED listener at %q. The operator "+
			"DELETED api-auth; the credential must stop working everywhere at once (#5561 "+
			"round 7), and a retired leg is not covered by the publish that follows the "+
			"rebind: it is pinned at retirement (api.trackRetiring) and a nil cannot tighten "+
			"it (api.authSlot.tighten drops a nil next by design). Retirement is asynchronous "+
			"— the socket keeps accepting until the serve goroutine reaches Shutdown, and "+
			"connections already accepted are served for the whole drain — so this is "+
			"a deleted credential live on a routable, MUTATING management API", live.HTTPSAddr)
	}
	// It is pinned to DENY-ALL, not to nil: an unauthenticated caller is refused
	// too. A nil pin would be dynamicAuthMiddleware's pass-through, which is the
	// same defect in its worst form.
	if mgmtLegAdmits(t, retired, "", "") {
		t.Fatalf("the retired off-loopback HTTPS listener at %q admits an UNAUTHENTICATED request. "+
			"The committed nil disables authentication outright and is licensed only by the "+
			"loopback address this commit BOUND — never on the one it retired",
			live.HTTPSAddr)
	}

	// Controls. The nil really did converge on the leg the commit named, so the
	// assertions above are a scoped suppression and not a blanket lockout — and
	// since the retired handler refuses the very request this one admits, the two
	// are necessarily different legs enforcing different policies.
	nowLive := m.srv.HTTPSHandlerForTest()
	if nowLive == nil {
		t.Fatal("the rebind installed no live HTTPS leg, so nothing was retired and the " +
			"case proved nothing")
	}
	if !mgmtLegAdmits(t, nowLive, "", "") {
		t.Fatalf("the LIVE loopback listener at %q still demands a credential after api-auth "+
			"was removed — the committed nil must land on the leg the commit bound", rm.HTTPSAddr)
	}
	if snap := m.srv.LiveAuth(); snap != nil {
		t.Fatalf("the server-wide snapshot is %+v after a converged api-auth removal, want nil "+
			"— if it is deny-all the retired leg's pin is untestable from here, because a "+
			"deny-all pin and a deny-all follow are indistinguishable", snap)
	}
	if ln := reg.get(rm.HTTPSAddr); ln == nil || !ln.isOpen() {
		t.Fatalf("the converged listener at %q is not serving", rm.HTTPSAddr)
	}
}
