package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
)

// TestAuthMiddlewareCredentialExpiry16729 pins the runtime enforcement of
// api-auth `expires` between AuthConfig rebuilds (#16729, #10826).
//
// Before this test, the two `credentialExpiryActive` terms at the Basic check
// in checkAuthorizationIdentity and at the API-key check in
// matchAPIKeyIdentityWithExpiry were covered by no discriminating cell:
// deleting either term (MUT-B / MUT-K below) left the whole pkg/api suite
// green, because the only "expired credential" cell (authz_13241_test.go)
// installed a test-supplied resolver that reimplemented the expiry check
// itself. These cases drive the production paths end to end:
//
//   - Basic, X-API-Key and Bearer through the production auth handler (the real
//     throttledAuthCheck -> authCheckCredential -> checkAuthorizationIdentity /
//     matchAPIKeyIdentityWithExpiry chain), each with an unexpired control
//     that must still be admitted, so an over-broad rejection cannot pass.
//   - One principalFrom row that uses the DEFAULT resolver
//     (credentialPrincipalIdentityWithExpiry, ri.credentialResolver == nil),
//     so the off-box credential-principal path is covered against the
//     production expiry logic rather than a test twin.
//
// Mutation sensitivity (verified during implementation):
//   - MUT-B (dropping `!credentialExpiryActive(cfg.UserExpires[user])` from
//     checkAuthorizationIdentity) turns the "expired basic user" subtest red
//     (401 becomes 200) and the principalFrom row red (expired Basic principal
//     is minted).
//   - MUT-K (dropping `!credentialExpiryActive(cfg.APIKeyExpires[key])` from
//     matchAPIKeyIdentityWithExpiry) turns the "expired X-API-Key" and
//     "expired bearer" subtests red.
func TestAuthMiddlewareCredentialExpiry16729(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	// One AuthConfig carrying both an unexpired and an expired instance of
	// every credential kind, so each case can pair a rejection with the
	// control that proves the middleware itself is not blanket-denying.
	cfg := AuthConfig{
		Users: map[string]string{
			"admin":          "secret123",
			"expired-admin":  "secret123",
			"timeless-admin": "secret123",
		},
		UserClasses: map[string]string{
			"admin":          "super-user",
			"expired-admin":  "super-user",
			"timeless-admin": "super-user",
		},
		UserExpires: map[string]time.Time{
			"admin":         future,
			"expired-admin": past,
			// timeless-admin intentionally absent: zero expiry never expires.
		},
		APIKeys: map[string]bool{
			"live-key":    true,
			"expired-key": true,
			"ageless-key": true,
		},
		APIKeyNames: map[string]string{
			"live-key":    "live",
			"expired-key": "expired",
			"ageless-key": "ageless",
		},
		APIKeyClasses: map[string]string{
			"live-key":    "operator",
			"expired-key": "operator",
			"ageless-key": "operator",
		},
		APIKeyExpires: map[string]time.Time{
			"live-key":    future,
			"expired-key": past,
			// ageless-key intentionally absent.
		},
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name   string
		header map[string]string
		want   int
	}{
		{
			name:   "unexpired basic user admitted",
			header: map[string]string{"Authorization": basicAuth("admin", "secret123")},
			want:   http.StatusOK,
		},
		{
			name:   "expired basic user refused",
			header: map[string]string{"Authorization": basicAuth("expired-admin", "secret123")},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "basic user without expiry admitted",
			header: map[string]string{"Authorization": basicAuth("timeless-admin", "secret123")},
			want:   http.StatusOK,
		},
		{
			name:   "expired basic user with wrong password refused",
			header: map[string]string{"Authorization": basicAuth("expired-admin", "wrong")},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "unexpired X-API-Key admitted",
			header: map[string]string{"X-API-Key": "live-key"},
			want:   http.StatusOK,
		},
		{
			name:   "expired X-API-Key refused",
			header: map[string]string{"X-API-Key": "expired-key"},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "X-API-Key without expiry admitted",
			header: map[string]string{"X-API-Key": "ageless-key"},
			want:   http.StatusOK,
		},
		{
			name:   "unexpired bearer admitted",
			header: map[string]string{"Authorization": "Bearer live-key"},
			want:   http.StatusOK,
		},
		{
			name:   "expired bearer refused",
			header: map[string]string{"Authorization": "Bearer expired-key"},
			want:   http.StatusUnauthorized,
		},
		{
			name:   "bearer without expiry admitted",
			header: map[string]string{"Authorization": "Bearer ageless-key"},
			want:   http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh middleware per case: the auth-failure throttle is
			// stateful, and a shared instance would let earlier failures
			// lock out later (unrelated) cases.
			handler := productionAuthHandlerOnly(t, cfg, false, ok)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
			req.RemoteAddr = "198.51.100.10:12345"
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("got status %d, want %d", w.Code, tc.want)
			}
			if tc.want == http.StatusUnauthorized {
				if wa := w.Header().Get("WWW-Authenticate"); wa == "" {
					t.Error("expected WWW-Authenticate header on 401")
				}
			}
		})
	}
}

// TestPrincipalFromDefaultResolverRefusesExpiredCredential16729 covers the
// principalFrom credential row with the production default resolver
// (ri.credentialResolver == nil => credentialPrincipalIdentityWithExpiry).
// The #13241 memo test cannot detect a dropped expiry term because its
// injected resolver reimplements the check; this row cannot pass unless the
// production resolver itself refuses the expired credential.
func TestPrincipalFromDefaultResolverRefusesExpiredCredential16729(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	newServer := func(t *testing.T, cfg AuthConfig) *Server {
		t.Helper()
		s := &Server{peerLocalityFn: func(net.Addr, net.Addr) bool { return false }}
		s.auth.Store(&cfg)
		return s
	}
	// Off-box, unattributed peer: principalFrom must take the credential row.
	offBox := func() *requestIdentity {
		return &requestIdentity{
			pending: &pendingPeer{},
			id:      authz.PeerIdentity{Local: false, Detail: "off-box test peer"},
		}
	}

	t.Run("expired basic principal refused, unexpired admitted", func(t *testing.T) {
		cfg := AuthConfig{
			Users:       map[string]string{"admin": "secret123"},
			UserClasses: map[string]string{"admin": "super-user"},
			UserExpires: map[string]time.Time{"admin": future},
		}
		s := newServer(t, cfg)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/config/enter", nil)
		req.Header.Set("Authorization", basicAuth("admin", "secret123"))
		if p := s.principalFrom(req, nil, offBox()); p.Username != "admin" || p.Source != authz.SourceCredential {
			t.Fatalf("unexpired principal = %+v, want credential principal admin", p)
		}

		expired := cloneAuthConfig(cfg)
		expired.UserExpires["admin"] = past
		s.auth.Store(&expired)
		// Fresh requestIdentity: the memo from the live call above must not
		// leak into the expired-policy call.
		if p := s.principalFrom(req, nil, offBox()); p.Source != 0 || p.Username != "" {
			t.Fatalf("expired basic credential minted principal %+v, want unauthenticated", p)
		}
	})

	t.Run("expired API key principal refused, unexpired admitted", func(t *testing.T) {
		cfg := AuthConfig{
			APIKeys:       map[string]bool{"live-key": true},
			APIKeyNames:   map[string]string{"live-key": "deployment"},
			APIKeyClasses: map[string]string{"live-key": "operator"},
			APIKeyExpires: map[string]time.Time{"live-key": future},
		}
		s := newServer(t, cfg)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/config/enter", nil)
		req.Header.Set("X-API-Key", "live-key")
		if p := s.principalFrom(req, nil, offBox()); p.Username != "deployment" || p.Source != authz.SourceCredential {
			t.Fatalf("unexpired key principal = %+v, want credential principal deployment", p)
		}

		expired := cloneAuthConfig(cfg)
		// APIKeyExpires is keyed by the configured key value.
		expired.APIKeyExpires["live-key"] = past
		s.auth.Store(&expired)
		if p := s.principalFrom(req, nil, offBox()); p.Source != 0 || p.Username != "" {
			t.Fatalf("expired API key minted principal %+v, want unauthenticated", p)
		}
	})
}
