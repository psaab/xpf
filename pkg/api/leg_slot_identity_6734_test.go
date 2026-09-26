package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// #6734: `pkg/api` substituted a fresh authSlot for a nil in TWO independent
// places — `listenerHandler` when building the handler, and `serveLegLocked`
// when registering the leg. A future call site passing nil to both would pin
// the leg to slot Y while every request on it was judged by slot X, so
// authSlot.pin / tighten would operate on an object nothing reads and a RETIRED
// listener would keep following the server-wide snapshot. That is the #5561
// round-14 defect the pin exists to prevent — a credential committed for the
// NEW address becoming valid on the address the same commit RETIRED.
//
// It was latent: all four production sites threaded one slot through both
// layers. legPlan makes it unrepresentable — the slot is allocated with the
// server and serveLegLocked no longer has a parameter to substitute for.
//
// THE ASSERTION IS BEHAVIOURAL, NOT POINTER IDENTITY, and that is deliberate.
// The issue suggests asserting "the leg's slot is the same pointer the handler
// reads". A pointer comparison is a proxy for the property and it can be
// satisfied while the property fails — a handler that closed over the right
// pointer but consulted s.auth directly would pass it. What the operator
// depends on is that PINNING THE LEG'S SLOT CHANGES WHAT REQUESTS ON THAT LEG
// ARE JUDGED BY. So the cells pin the leg's slot to one credential set, move
// the server-wide snapshot to a different one, and drive a real request through
// the leg's own handler.
//
// Divergence fails this in the only way that matters: the handler would read
// the unpinned slot X, which still follows s.auth, so the ROTATED credential
// would authenticate on the leg that was pinned away from it.

// legSlotDivergenceProbe pins leg's slot at the boot credential, rotates the
// server-wide snapshot to a different one, and reports what the leg accepts.
func legSlotDivergenceProbe(t *testing.T, s *Server, leg *listenerLeg) (acceptsPinned, acceptsRotated bool) {
	t.Helper()
	pinned := &AuthConfig{Users: map[string]string{"admin": "pinned-secret"}}
	rotated := &AuthConfig{Users: map[string]string{"admin": "rotated-secret"}}

	s.auth.Store(pinned)
	leg.slot.pin(pinned)
	// The server-wide snapshot moves on; a pinned leg must not follow it.
	s.auth.Store(rotated)

	return legProbe(t, leg, "admin", "pinned-secret"),
		legProbe(t, leg, "admin", "rotated-secret")
}

func assertLegHonoursItsOwnSlot(t *testing.T, s *Server, leg *listenerLeg, path string) {
	t.Helper()
	if leg == nil {
		t.Fatalf("%s: no leg was created; the cell asserts nothing", path)
	}
	if leg.slot == nil {
		t.Fatalf("%s: the leg has no slot at all", path)
	}
	acceptsPinned, acceptsRotated := legSlotDivergenceProbe(t, s, leg)
	if !acceptsPinned {
		t.Errorf("%s: the leg REJECTED the credential its own slot was pinned to. "+
			"The handler is not reading this leg's slot, so a pin cannot hold a "+
			"draining listener at the policy it was retired under (#6734/#5561).", path)
	}
	if acceptsRotated {
		t.Errorf("%s: the leg ACCEPTED a credential published AFTER its slot was "+
			"pinned. The handler is judging requests by a different slot than the "+
			"one pin/tighten operate on, so the retirement pin is a no-op and a "+
			"credential committed for the NEW address is valid on the address the "+
			"same commit RETIRED (#6734/#5561 round 14).", path)
	}
}

// TestLegSlotIsTheSlotTheHandlerReads6734 covers every production path that
// creates a leg. They are separate cells because each builds its plan
// differently — Start serves the servers NewServer built, while the reconcile
// paths plan fresh ones — and a divergence introduced in one would not show up
// in the others.
func TestLegSlotIsTheSlotTheHandlerReads6734(t *testing.T) {
	t.Run("Start_http", func(t *testing.T) {
		s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "boot"}})
		s.lifeMu.Lock()
		plan := s.planHTTPLeg("10.0.0.1:8080")
		s.httpSlot, s.httpServer = plan.slot, plan.srv
		ln, err := s.listen("tcp", "10.0.0.1:8080")
		if err != nil {
			s.lifeMu.Unlock()
			t.Fatalf("listen: %v", err)
		}
		// Exactly what Start does: serve the server built at construction,
		// re-pairing it with the slot written alongside it.
		s.httpLeg = s.serveLegLocked(s.httpLegPlan(), ln, false)
		leg := s.httpLeg
		s.lifeMu.Unlock()
		assertLegHonoursItsOwnSlot(t, s, leg, "Start (HTTP)")
	})

	t.Run("ReconcileHTTP", func(t *testing.T) {
		s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "boot"}})
		if err := s.ReconcileHTTP("10.0.0.2:8080"); err != nil {
			t.Fatalf("ReconcileHTTP: %v", err)
		}
		assertLegHonoursItsOwnSlot(t, s, s.httpLeg, "ReconcileHTTP")
	})

	// The shape that broke the first draft of this change: a caller that sets
	// s.httpsServer DIRECTLY, with no slot, and then calls Start. It is not
	// hypothetical — TestReconcileHTTPSReplacesADeadLeg_6827's fixture does it,
	// and the first version of httpsLegPlan assumed the pair always had a
	// single writer, so the leg got a nil slot and stopLegLocked nil-dereferenced
	// on the first pin. The plan adopts a missing slot and STORES IT BACK, which
	// is what keeps the field, the plan and the leg the same object.
	t.Run("Start_https_with_no_preallocated_slot", func(t *testing.T) {
		s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "boot"}})
		s.lifeMu.Lock()
		s.httpsServer = &http.Server{Addr: "10.0.0.4:8443"}
		s.httpsServer.Handler = s.listenerHandler("10.0.0.4:8443", s.httpsLegPlan().slot)
		if s.httpsSlot == nil {
			s.lifeMu.Unlock()
			t.Fatal("httpsLegPlan must adopt and STORE a slot when the field is nil; " +
				"without the store-back the leg and the field are different objects " +
				"and pin/tighten operate on one nothing reads (#6734)")
		}
		ln, err := s.listen("tcp", "10.0.0.4:8443")
		if err != nil {
			s.lifeMu.Unlock()
			t.Fatalf("listen: %v", err)
		}
		s.httpsLeg = s.serveLegLocked(s.httpsLegPlan(), ln, true)
		leg := s.httpsLeg
		s.lifeMu.Unlock()
		assertLegHonoursItsOwnSlot(t, s, leg, "Start (HTTPS, adopted slot)")
	})

	t.Run("ReconcileHTTPS", func(t *testing.T) {
		s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "boot"}})
		s.certGen = generateSelfSignedCertWithStatus
		if err := s.ReconcileHTTPS(true, "10.0.0.3:8443"); err != nil {
			t.Fatalf("ReconcileHTTPS: %v", err)
		}
		assertLegHonoursItsOwnSlot(t, s, s.httpsLeg, "ReconcileHTTPS")
	})
}

// TestServeLegCannotBeHandedAMismatchedSlot6734 is the structural half: the
// divergence is gone because there is no longer a second place that can
// allocate one.
//
// It asserts on BEHAVIOUR of the constructor rather than on a signature, so it
// is not satisfiable by a comment and does not break on a rename: a plan's leg
// and its handler must agree even when the server-wide snapshot disagrees with
// both. Reintroducing a slot parameter on serveLegLocked and substituting in it
// makes the leg's slot different from the handler's, and the probe reds.
func TestServeLegCannotBeHandedAMismatchedSlot6734(t *testing.T) {
	s := retireTestServer(t, &AuthConfig{Users: map[string]string{"admin": "boot"}})

	plan := s.planHTTPLeg("10.0.0.9:8080")
	if plan.slot == nil {
		t.Fatal("planHTTPLeg returned no slot; every leg must have one")
	}
	if plan.srv == nil || plan.srv.Handler == nil {
		t.Fatal("planHTTPLeg returned no server/handler")
	}

	s.lifeMu.Lock()
	ln, err := s.listen("tcp", "10.0.0.9:8080")
	if err != nil {
		s.lifeMu.Unlock()
		t.Fatalf("listen: %v", err)
	}
	leg := s.serveLegLocked(plan, ln, false)
	s.httpLeg = leg
	s.lifeMu.Unlock()

	if leg.slot != plan.slot {
		t.Fatal("serveLegLocked registered a slot other than the plan's — the leg " +
			"and its handler have diverged before a single request was served")
	}
	assertLegHonoursItsOwnSlot(t, s, leg, "planHTTPLeg -> serveLegLocked")

	// Positive control: a leg whose slot is NOT pinned must still follow the
	// server-wide snapshot, so the cells above are distinguishing "reads its own
	// slot" from "reads nothing at all".
	fresh := s.planHTTPLeg("10.0.0.10:8080")
	s.auth.Store(&AuthConfig{Users: map[string]string{"admin": "live-secret"}})
	r := httptest.NewRequest("GET", "/api/v1/thing", nil)
	r.SetBasicAuth("admin", "live-secret")
	w := httptest.NewRecorder()
	fresh.srv.Handler.ServeHTTP(w, r)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("an UNPINNED leg rejected the live server-wide credential; a slot " +
			"that follows nothing would make every assertion above vacuous")
	}
}
