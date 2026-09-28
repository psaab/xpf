package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestConstantTimeAPIKeyMatch pins the functional contract of the constant-time
// API-key / Bearer-token comparison introduced for #4157: a configured key is
// accepted, anything else (including a same-prefix or wrong-length candidate)
// is rejected, and matching is independent of which key in the set matched.
func TestConstantTimeAPIKeyMatch(t *testing.T) {
	cfg := AuthConfig{
		APIKeys: map[string]bool{
			"tok-abc-123":  true,
			"tok-xyz-999":  true,
			"disabled-key": false, // a false-valued key must NOT authenticate
		},
	}

	tests := []struct {
		name      string
		presented string
		want      bool
	}{
		{"first configured key", "tok-abc-123", true},
		{"second configured key", "tok-xyz-999", true},
		{"empty token", "", false},
		{"unknown token", "not-a-key", false},
		{"shared prefix, wrong tail", "tok-abc-124", false},
		{"prefix of a valid key (wrong length)", "tok-abc-12", false},
		{"valid key plus trailing byte", "tok-abc-1234", false},
		{"false-valued key rejected", "disabled-key", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := constantTimeAPIKeyMatch(cfg, tt.presented); got != tt.want {
				t.Errorf("constantTimeAPIKeyMatch(%q) = %v, want %v", tt.presented, got, tt.want)
			}
		})
	}
}

// TestConstantTimeAPIKeyMatchEmptySet ensures an empty key set never
// authenticates — the OR of zero comparisons must be false.
func TestConstantTimeAPIKeyMatchEmptySet(t *testing.T) {
	cfg := AuthConfig{APIKeys: map[string]bool{}}
	if constantTimeAPIKeyMatch(cfg, "anything") {
		t.Fatal("empty key set authenticated a token")
	}
	if constantTimeAPIKeyMatch(cfg, "") {
		t.Fatal("empty key set authenticated an empty token")
	}
}

// TestBasicAuthUnknownUserRejected confirms the Basic-auth path still rejects
// an unknown username. The #4157 fix removed the early `return false` on
// !exists (which skipped the constant-time compare and leaked username
// existence via timing) and instead always runs ConstantTimeCompare against
// the looked-up value, then AND-s with existence — so an unknown user, a known
// user with the wrong password, and a known user whose password happens to
// equal the empty-string default must all be rejected.
func TestBasicAuthUnknownUserRejected(t *testing.T) {
	cfg := AuthConfig{
		Users: map[string]string{"admin": "secret123"},
	}

	cases := []struct {
		name string
		user string
		pass string
		want bool
	}{
		{"known user, correct password", "admin", "secret123", true},
		{"known user, wrong password", "admin", "nope", false},
		{"unknown user, valid password", "nobody", "secret123", false},
		{"unknown user, empty password", "nobody", "", false},
		{"known user, empty password", "admin", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := "Basic " + basicAuth64(tc.user, tc.pass)
			if got := checkAuthorization(hdr, cfg); got != tc.want {
				t.Errorf("checkAuthorization(%s:%s) = %v, want %v", tc.user, tc.pass, got, tc.want)
			}
		})
	}
}

func basicAuth64(user, pass string) string {
	// Mirror pkg/api/auth_test.go's basicAuth without the "Basic " prefix.
	return strings.TrimPrefix(basicAuth(user, pass), "Basic ")
}

// TestAuthMiddlewareConstantTimeIntegration re-exercises the middleware end to
// end after the #4157 change to confirm token acceptance/rejection through the
// real HTTP path (complements the unit-level helper tests).
func TestAuthMiddlewareConstantTimeIntegration(t *testing.T) {
	cfg := AuthConfig{
		Users:   map[string]string{"admin": "secret123"},
		APIKeys: map[string]bool{"tok-abc-123": true},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := authMiddleware(cfg, false, next)

	cases := []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"bearer valid", map[string]string{"Authorization": "Bearer tok-abc-123"}, http.StatusOK},
		{"bearer wrong-length", map[string]string{"Authorization": "Bearer tok-abc-12"}, http.StatusUnauthorized},
		{"x-api-key valid", map[string]string{"X-API-Key": "tok-abc-123"}, http.StatusOK},
		{"x-api-key shared-prefix", map[string]string{"X-API-Key": "tok-abc-124"}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/status", nil)
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}
