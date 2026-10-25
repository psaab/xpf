package api

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// metrics_view_gate_16727_test.go pins #16727: /metrics on a
// credential-gated leg (non-loopback bind, or loopback with
// metrics-require-auth) authenticated the api-auth credential but made
// no login-class decision, so a credential whose class lacks view
// (built-in unauthorized) — refused every /api/v1 read — still received
// the exposition naming zones, policies, NAT pools and interfaces.
//
// Every case drives real HTTP over a real loopback listener through
// buildHTTPServer (the production chain: dynamicAuthMiddleware ->
// cross-site guard -> mutationAuthzGuard/readAuthz -> mux), with a
// fabricated remote peer so the api-auth credential is the identity
// that speaks. Both gated leg shapes are built explicitly: a slot whose
// bind classification requires auth (the non-loopback shape) and a
// loopback slot with MetricsRequireAuth set (the #16072 opt-in shape).
// The ungated loopback default must stay 200 with no credential.
//
// FAIL-ON-REVERT: dropping the /metrics PermView branch in readAuthz
// (or the bind classification on the slot) makes the unauthorized-class
// rows return 200 instead of 403.

func metrics16727Do(t *testing.T, base, path string, hdrs map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func metrics16727Auth(t *testing.T) (*AuthConfig, map[string]string, map[string]string) {
	t.Helper()
	unauthKey, err := config.HashAPIAuthSecret("0123456789abcdef-unauth-key-16727")
	if err != nil {
		t.Fatal(err)
	}
	viewKey, err := config.HashAPIAuthSecret("0123456789abcdef-view-key-16727")
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	auth := &AuthConfig{
		APIKeys:       map[string]bool{unauthKey: true, viewKey: true},
		APIKeyNames:   map[string]string{unauthKey: "no-view-key", viewKey: "view-key"},
		APIKeyClasses: map[string]string{unauthKey: "unauthorized", viewKey: "read-only"},
		APIKeyExpires: map[string]time.Time{unauthKey: expires, viewKey: expires},
	}
	return auth,
		map[string]string{"X-API-Key": "0123456789abcdef-unauth-key-16727"},
		map[string]string{"X-API-Key": "0123456789abcdef-view-key-16727"}
}

func TestMetricsRequiresViewOnCredentialGatedLegs16727(t *testing.T) {
	usePasswdFixture(t)
	auth, unauthHdr, viewHdr := metrics16727Auth(t)
	store := authzStore(t, authzTestConfig)

	// Control leg: the ungated loopback default must stay open, with
	// or without a credential (gate off carries no class decision).
	_, openBase := authzServer(t, Config{
		Addr:           "127.0.0.1:8080",
		Store:          store,
		Auth:           auth,
		PeerLookupFn:   remotePeer(),
		PeerLocalityFn: remoteLocality(),
	})
	if got := metrics16727Do(t, openBase, "/metrics", nil); got != http.StatusOK {
		t.Fatalf("ungated loopback /metrics without credential = %d, want 200 (control)", got)
	}
	if got := metrics16727Do(t, openBase, "/metrics", unauthHdr); got != http.StatusOK {
		t.Fatalf("ungated loopback /metrics with unauthorized-class key = %d, want 200 (gate off stays open)", got)
	}

	// Both gated shapes share one assertion set. Each shape builds its
	// own server so the non-loopback shape can install its slot before
	// the listener serves (authzServer's internal slot is unreachable
	// afterwards).
	shapes := []struct {
		name  string
		build func(t *testing.T) (*Server, string)
	}{
		{
			name: "non-loopback bind",
			build: func(t *testing.T) (*Server, string) {
				s := NewServer(Config{
					Addr:           "127.0.0.1:8080",
					Store:          store,
					Auth:           auth,
					PeerLookupFn:   remotePeer(),
					PeerLocalityFn: remoteLocality(),
				})
				slot := s.newAuthSlot()
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen: %v", err)
				}
				srv := s.buildHTTPServer(ln.Addr().String(), slot)
				// buildHTTPServer derives the classification from
				// the loopback socket address; restore the
				// non-loopback classification listenerHandler
				// would compute for a routable bind.
				slot.bindRequiresAuth = true
				go func() { _ = srv.Serve(ln) }()
				t.Cleanup(func() { _ = srv.Close(); waitForGateQuiescent(t) })
				return s, "http://" + ln.Addr().String()
			},
		},
		{
			name: "loopback with metrics-require-auth",
			build: func(t *testing.T) (*Server, string) {
				a := *auth
				a.MetricsRequireAuth = true
				s, base := authzServer(t, Config{
					Addr:           "127.0.0.1:8080",
					Store:          store,
					Auth:           &a,
					PeerLookupFn:   remotePeer(),
					PeerLocalityFn: remoteLocality(),
				})
				s.ReplaceMetricsRequireAuth(true)
				return s, base
			},
		},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			_, base := shape.build(t)

			if got := metrics16727Do(t, base, "/metrics", unauthHdr); got != http.StatusForbidden {
				t.Fatalf("%s: /metrics with unauthorized-class key = %d, want 403 — a class without view received the topology exposition", shape.name, got)
			}
			if got := metrics16727Do(t, base, "/metrics", viewHdr); got != http.StatusOK {
				t.Fatalf("%s: /metrics with read-only key = %d, want 200 (view control)", shape.name, got)
			}
			// This fixture's real listener is loopback, so the
			// bind gate does not 401 here; the class gate answers
			// 403 for an uncredentialed gated request. (On the
			// loopback-with-require-auth shape the auth middleware
			// 401s first, as #16072 pins.)
			if got := metrics16727Do(t, base, "/metrics", nil); got != http.StatusUnauthorized && got != http.StatusForbidden {
				t.Fatalf("%s: /metrics without credential = %d, want 401 or 403 (gated)", shape.name, got)
			}
			if got := metrics16727Do(t, base, "/health", nil); got != http.StatusOK {
				t.Fatalf("%s: /health without credential = %d, want 200 (unaffected)", shape.name, got)
			}
			// Control: the same unauthorized key is refused an /api/v1
			// read, so the /metrics denial is the class decision, not
			// a broken credential.
			if got := metrics16727Do(t, base, "/api/v1/config", unauthHdr); got != http.StatusForbidden {
				t.Fatalf("%s: /api/v1/config with unauthorized-class key = %d, want 403 (control)", shape.name, got)
			}
			if got := metrics16727Do(t, base, "/api/v1/config", viewHdr); got != http.StatusOK {
				t.Fatalf("%s: /api/v1/config with read-only key = %d, want 200 (control)", shape.name, got)
			}
		})
	}
}

// TestMetricsViewGateBasicUser16727 covers the Basic-user credential
// principal on a gated leg: an unauthorized-class user gets 403, a
// read-only user gets 200. Fails pre-fix with 200 for the first row.
func TestMetricsViewGateBasicUser16727(t *testing.T) {
	usePasswdFixture(t)
	expires := time.Now().Add(time.Hour)
	auth := &AuthConfig{
		Users:              map[string]string{"noview": "pw-noview", "viewer": "pw-viewer"},
		UserClasses:        map[string]string{"noview": "unauthorized", "viewer": "read-only"},
		UserExpires:        map[string]time.Time{"noview": expires, "viewer": expires},
		MetricsRequireAuth: true,
	}
	_, base := authzServer(t, Config{
		Addr:           "127.0.0.1:8080",
		Store:          authzStore(t, authzTestConfig),
		Auth:           auth,
		PeerLookupFn:   remotePeer(),
		PeerLocalityFn: remoteLocality(),
	})
	basic := func(user, pw string) map[string]string {
		return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pw))}
	}
	if got := metrics16727Do(t, base, "/metrics", basic("noview", "pw-noview")); got != http.StatusForbidden {
		t.Fatalf("/metrics with unauthorized-class Basic user = %d, want 403", got)
	}
	if got := metrics16727Do(t, base, "/metrics", basic("viewer", "pw-viewer")); got != http.StatusOK {
		t.Fatalf("/metrics with read-only Basic user = %d, want 200", got)
	}
}
