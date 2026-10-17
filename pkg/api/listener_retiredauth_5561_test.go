package api

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// listener_retiredauth_5561_test.go is the fail-on-revert gate for the #5561
// round-14 MAJOR-2 property: a credential the committed config authorized for a
// NEW management address must never become valid on the address that same commit
// RETIRED.
//
// Retirement is asynchronous. stopLegLocked only closes a channel; the leg's
// serve goroutine wakes up later, and only then does Shutdown close the socket
// and drain. ReconcileHTTP/ReconcileHTTPS return as soon as that channel is
// closed, and the management reconciler then publishes the committed credential
// set. So there is a real interval — bounded by scheduling for new connections
// and by the 5s graceful drain for accepted ones — in which the retired listener
// is still answering requests. While every leg read one shared snapshot, the
// grant went out on that listener too.
//
// The fix is a per-leg snapshot pinned at retirement (authSlot), which can only
// tighten afterwards. These cases drive the leg handlers directly rather than
// over TCP: the property is which POLICY a leg enforces, and going through a
// real socket would make the assertion depend on winning a scheduling race
// against the drain, which is the opposite of a deterministic guard.

// legProbe runs a Basic-auth request against a leg's handler and reports whether
// it was admitted.
func legProbe(t *testing.T, leg *listenerLeg, user, pass string) bool {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/thing", nil)
	r.SetBasicAuth(user, pass)
	w := httptest.NewRecorder()
	leg.srv.Handler.ServeHTTP(w, r)
	return w.Code != http.StatusUnauthorized
}

// retireTestServer builds a Server whose legs serve a trivial 200 handler over
// the real per-leg auth middleware, with a listener factory that hands out
// closed-on-cleanup local sockets.
//
// #7667: /hold blocks until the returned release func is called. A leg cannot
// finish draining while a request is in flight — http.Server.Shutdown WAITS for
// active requests — so a test that needs the leg to still be RETIRING at a
// chosen moment can guarantee it instead of racing the drain.
func retireTestServer(t *testing.T, boot *AuthConfig) *Server {
	t.Helper()
	s, _ := retireTestServerWithHold(t, boot)
	return s
}

func retireTestServerWithHold(t *testing.T, boot *AuthConfig) (*Server, func()) {
	t.Helper()
	s, _, release := retireTestServerWithHoldEntered(t, boot)
	return s, release
}

// retireTestServerWithHoldEntered additionally returns a channel closed when a
// /hold request has ENTERED the handler (#6993).
//
// That is the moment http.Server.Shutdown starts waiting for, and it is the
// only edge that makes "the leg cannot finish draining" true rather than
// likely. The previous fixture wrote the request and slept 50ms; if the server
// had not accepted and entered the handler by then, Shutdown had nothing to
// wait for, the leg could drain at any later point, and the test failed on its
// round-7 revocation assertion with a message about a revocation that was never
// broken.
func retireTestServerWithHoldEntered(t *testing.T, boot *AuthConfig) (*Server, <-chan struct{}, func()) {
	t.Helper()
	s := &Server{}
	held := make(chan struct{})
	entered := make(chan struct{})
	var releaseOnce, enteredOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(held) }) }
	t.Cleanup(release)
	s.sharedBase = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			enteredOnce.Do(func() { close(entered) })
			<-held
		}
		w.WriteHeader(http.StatusOK)
	})
	s.auth.Store(boot)
	var mu sync.Mutex
	var lns []net.Listener
	s.listen = func(network, addr string) (net.Listener, error) {
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		mu.Lock()
		lns = append(lns, ln)
		mu.Unlock()
		return ln, nil
	}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, ln := range lns {
			_ = ln.Close()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.rootCtx = ctx
	return s, entered, release
}

// startHeldRequest7667 puts a request IN FLIGHT on ln and returns once the
// handler has certainly been entered. While it is in flight the leg's drain
// cannot complete, so the leg stays on the retiring list deterministically.
//
// This is the #7563 ordering applied to a fixture that was sampling an
// asynchronous observable: rather than hoping the drain has not finished, make
// it UNABLE to finish. The test then measures the property it names — that a
// leg which is still retiring honours a revocation — instead of measuring which
// goroutine the scheduler picked.
func startHeldRequest7667(t *testing.T, ln net.Listener, entered <-chan struct{}) {
	t.Helper()
	written := make(chan struct{})
	go func() {
		defer close(written)
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		req := "GET /hold HTTP/1.1\r\nHost: x\r\nAuthorization: Basic " +
			base64.StdEncoding.EncodeToString([]byte("admin:secret-a")) + "\r\n\r\n"
		_, _ = c.Write([]byte(req))
	}()
	<-written
	// #6993: wait for the handler to have ENTERED, not for a sleep to elapse.
	// Shutdown waits for requests it has already dispatched; a request that has
	// been WRITTEN but not yet dispatched is not one of them, so with a sleep
	// here the leg could still drain — and it drained AFTER the caller's
	// !drained precondition had already been sampled, which is why the failure
	// surfaced as a revocation defect instead of as the fixture losing a race.
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the held request never entered the handler, so http.Server.Shutdown has " +
			"nothing to wait for and the retired leg can finish draining at any point. The " +
			"case would then measure a leg the server has already reaped (#6993/#7667)")
	}
}

// retiredRevocationFailure6993 chooses WHICH failure the round-7 revocation
// assertion reports, from the one fact that separates the two meanings: whether
// the leg had finished draining by the time the probe ran.
//
// It is a function rather than an inline branch so the classification can be
// tested directly. The behaviour it encodes is only observable when a drain
// actually wins, which the held request exists to prevent — so an inline branch
// would be a correctness claim no cell could red.
//
// drained==true is NOT a revocation defect: pruneRetiredLocked drops a drained
// leg from the retiring list, so ReplaceAuth never tightens it and secret-a
// survives for a reason that has nothing to do with revocation. A leg the
// server has already reaped is deliberately no longer maintained — see the
// drainLeg commentary. Reporting that under the round-7 message is what made
// the #7667/#6993 flake read as a security defect, and it is the reason the
// obvious "fix" (relaxing the assertion) would have left a test that passes
// forever while guarding nothing.
func retiredRevocationFailure6993(drained bool) string {
	if drained {
		return "the retired leg finished draining between the precondition above and " +
			"ReplaceAuth, so it was pruned from the retiring list and never tightened. " +
			"This is the FIXTURE losing a race, not a revocation defect: a leg the server " +
			"has already reaped is deliberately no longer maintained (see the drainLeg " +
			"commentary). The held request exists to make this impossible — if this fires, " +
			"that hold stopped working (#6993/#7667)"
	}
	return "secret-a still authenticates on the retired listener — a retiring leg must " +
		"still honour a revocation immediately (#5561 round 7)"
}

// A commit that MOVES the management bind and ROTATES the credential must not
// make the new secret usable at the old address. The old leg is retired but is
// still serving while it drains, and the reconciler publishes the full committed
// set as soon as ReconcileHTTP returns.
//
// FAIL-ON-REVERT: drop the pin in stopLegLocked (let the retired leg keep
// following s.auth) and secret-b authenticates on the retired listener.
func TestRetiredLegNeverGainsARotatedCredential_5561(t *testing.T) {
	s, entered, _ := retireTestServerWithHoldEntered(t,
		&AuthConfig{Users: map[string]string{"admin": "secret-a"}})

	// Boot the first leg at some address, then rebind (which retires it).
	s.lifeMu.Lock()
	s.setHTTPSlot0(s.newAuthSlot())
	s.setHTTPServerTemplate(s.buildHTTPServer("10.0.0.1:8080", s.httpSlot0()))
	ln, err := s.listen("tcp", "10.0.0.1:8080")
	if err != nil {
		s.lifeMu.Unlock()
		t.Fatalf("listen: %v", err)
	}
	s.setHTTPLeg(s.serveLegLocked(s.httpLegPlan(), ln, false))
	retired := s.httpLeg()
	s.lifeMu.Unlock()

	if !legProbe(t, retired, "admin", "secret-a") {
		t.Fatal("the live listener rejects its own configured credential; the case starts wrong")
	}

	// #7667: hold a request IN FLIGHT so the retired leg cannot finish draining
	// before ReplaceAuth runs. Without this the fixture races the drain: a leg
	// that drains first is dropped by pruneRetiredLocked and ReplaceAuth never
	// tightens it, so secret-a survives and this test fails intermittently
	// under load — reporting "a revocation did not land" when nothing about
	// revocation was broken. Measured: forcing drained=true before ReplaceAuth
	// reproduces the exact failure, and leaving it false does not.
	startHeldRequest7667(t, ln, entered)

	if err := s.ReconcileHTTP("10.0.0.2:8080"); err != nil {
		t.Fatalf("ReconcileHTTP: %v", err)
	}
	live := s.httpLeg()
	if live == retired {
		t.Fatal("the rebind did not create a new leg, so nothing was retired")
	}

	// This is exactly what managementReconciler does once every live leg sits at
	// an address the committed config names.
	// The subject of this test is a leg that is STILL RETIRING. If the drain
	// finished anyway, say so by name — a leg the server has already reaped is
	// a different case (its policy is deliberately no longer maintained; see
	// the drainLeg commentary) and asserting revocation against it would be
	// asserting something the design does not promise.
	if retired.drained.Load() {
		t.Fatal("precondition: the retired leg already finished draining, so it is no " +
			"longer on the retiring list and ReplaceAuth will not tighten it. This " +
			"test is about a leg that is still RETIRING (#7667)")
	}

	s.ReplaceAuth(&AuthConfig{Users: map[string]string{"admin": "secret-b"}})

	if legProbe(t, retired, "admin", "secret-b") {
		t.Fatal("secret-b authenticates on the RETIRED listener at 10.0.0.1:8080. That " +
			"credential was committed for 10.0.0.2:8080; the same commit retired this " +
			"address, and retirement is asynchronous — the socket is still accepting and " +
			"the connections it already took are served for the whole drain. A grant must " +
			"never reach an address the commit moved away from (#5561 round 14, MAJOR 2)")
	}
	// The revocation half still lands there: round 7's property is not traded away.
	if legProbe(t, retired, "admin", "secret-a") {
		// #6993: classify BEFORE accusing the revocation path. The precondition
		// above samples `drained` at ONE instant, and the window that matters
		// runs from there to ReplaceAuth — a drain that completes inside it
		// leaves the leg off the retiring list, so ReplaceAuth never tightens it
		// and secret-a survives for a reason that has nothing to do with
		// revocation. That is the failure recorded in #7667, reported under this
		// message, and the reason it read as a security defect. The held request
		// is what makes the drain impossible; this re-read is what makes the
		// classification TOTAL if it ever becomes possible again.
		t.Fatal(retiredRevocationFailure6993(retired.drained.Load()))
	}
	// The live leg gets the whole committed set, as before.
	if !legProbe(t, live, "admin", "secret-b") {
		t.Fatal("the LIVE listener rejects the committed credential — the pin must not leak " +
			"onto the leg the commit actually named")
	}
}

// The same ordering in the direction that fails OPEN: a commit that removes all
// api-auth and converges to loopback publishes nil, and nil is
// dynamicAuthMiddleware's pass-through. The retired off-loopback leg must not
// see it — the #4047/#5127 clamp that licenses the nil was evaluated against the
// loopback address the commit BOUND, never against the one it retired.
//
// FAIL-ON-REVERT: let authSlot.tighten apply a nil `next` (or drop the pin) and
// the retired off-loopback listener answers an unauthenticated request.
func TestRetiredLegIsNeverDroppedToNoAuth_5561(t *testing.T) {
	s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "secret"}})

	s.lifeMu.Lock()
	s.setHTTPSlot0(s.newAuthSlot())
	s.setHTTPServerTemplate(s.buildHTTPServer("10.0.0.1:8080", s.httpSlot0()))
	ln, err := s.listen("tcp", "10.0.0.1:8080")
	if err != nil {
		s.lifeMu.Unlock()
		t.Fatalf("listen: %v", err)
	}
	s.setHTTPLeg(s.serveLegLocked(s.httpLegPlan(), ln, false))
	retired := s.httpLeg()
	s.lifeMu.Unlock()

	if err := s.ReconcileHTTP("127.0.0.1:8080"); err != nil {
		t.Fatalf("ReconcileHTTP: %v", err)
	}
	live := s.httpLeg()

	// The nil publishes once every LIVE leg is loopback — which is true here.
	s.ReplaceAuth(nil)

	r := httptest.NewRequest("GET", "/api/v1/config", nil)
	w := httptest.NewRecorder()
	retired.srv.Handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an UNAUTHENTICATED request to the retired off-loopback listener got %d. The "+
			"committed nil disables authentication entirely, and it is justified by the "+
			"loopback clamp on the address this commit BOUND — not on 10.0.0.1:8080, which "+
			"it retired and which is still serving while it drains (#5561 round 14, MAJOR 2)",
			w.Code)
	}
	// The live loopback leg does get the nil: the suppression is scoped to the
	// retired address, not a blanket refusal to ever remove api-auth.
	r = httptest.NewRequest("GET", "/api/v1/config", nil)
	w = httptest.NewRecorder()
	live.srv.Handler.ServeHTTP(w, r)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("the LIVE loopback listener still demands a credential after api-auth was " +
			"removed — the pin must not spread to the leg the commit named")
	}
}

// A live leg FOLLOWS the server-wide snapshot: the plain day-2 credential swap
// on an unchanged bind must still take effect on the very next request, with no
// rebind. This is the control that keeps the pin from being implemented as
// "every leg is pinned at creation", which would break #5866's whole premise.
func TestLiveLegFollowsTheServerSnapshot_5561(t *testing.T) {
	s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "secret-a"}})

	s.lifeMu.Lock()
	s.setHTTPSlot0(s.newAuthSlot())
	s.setHTTPServerTemplate(s.buildHTTPServer("10.0.0.1:8080", s.httpSlot0()))
	ln, err := s.listen("tcp", "10.0.0.1:8080")
	if err != nil {
		s.lifeMu.Unlock()
		t.Fatalf("listen: %v", err)
	}
	s.setHTTPLeg(s.serveLegLocked(s.httpLegPlan(), ln, false))
	live := s.httpLeg()
	s.lifeMu.Unlock()

	s.ReplaceAuth(&AuthConfig{Users: map[string]string{"admin": "secret-b"}})
	if legProbe(t, live, "admin", "secret-a") {
		t.Fatal("the revoked secret still authenticates on the LIVE listener — a day-2 " +
			"revocation must land on the next request without a rebind (#5866)")
	}
	if !legProbe(t, live, "admin", "secret-b") {
		t.Fatal("the newly committed secret does not authenticate on the LIVE listener")
	}
}
