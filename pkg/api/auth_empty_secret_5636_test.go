package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// #5636 (codex-review-181 M28): defense-in-depth at the middleware layer. Even
// if a quoted-empty api-auth secret slips through a lenient config load and is
// wired into the runtime AuthConfig, the middleware must treat an EMPTY
// configured secret as "no valid credential" and reject the request. Before the
// fix, an empty stored password matched `username:` (empty password) via the
// constant-time compare and an empty stored api-key matched an empty
// Bearer/X-API-Key token — an authentication bypass on an off-loopback bind.

// RED-on-revert: a request presenting `admin:` (empty password) against a
// config whose stored password for admin is empty must be REJECTED (401). On
// revert of the auth.go `expected != ""` guard this goes RED — the empty stored
// password matches and the request authenticates (200).
func TestEmptyConfiguredBasicPasswordRejected(t *testing.T) {
	cfg := AuthConfig{
		Users:   map[string]string{"admin": ""},
		APIKeys: map[string]bool{},
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := productionAuthHandlerOnly(t, cfg, false, ok)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", basicAuth("admin", "")) // username:, empty password
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("empty configured Basic password must reject `admin:` (empty password); got status %d, want 401", rr.Code)
	}
}

// checkAuthorization is the unit under the middleware — assert it directly too
// so the RED-on-revert is unambiguous.
func TestCheckAuthorizationRejectsEmptyConfiguredSecret(t *testing.T) {
	cfg := AuthConfig{Users: map[string]string{"admin": ""}}
	if checkAuthorization(basicAuth("admin", ""), cfg) {
		t.Fatal("checkAuthorization authenticated `admin:` against an empty configured password (#5636 auth bypass)")
	}
	// A non-empty stored password still authenticates the matching request.
	cfg = AuthConfig{Users: map[string]string{"admin": "s3cret"}}
	if !checkAuthorization(basicAuth("admin", "s3cret"), cfg) {
		t.Fatal("checkAuthorization must still accept a correct non-empty password")
	}
	if checkAuthorization(basicAuth("admin", ""), cfg) {
		t.Fatal("checkAuthorization must reject an empty presented password against a non-empty stored password")
	}
}

// An empty configured api-key must never match — including the Bearer-empty
// vector (`Authorization: Bearer ` → empty token). On revert of the
// constantTimeAPIKeyMatch `key == ""` skip this goes RED.
func TestEmptyConfiguredAPIKeyRejected(t *testing.T) {
	cfg := AuthConfig{APIKeys: map[string]bool{"": true}}
	if constantTimeAPIKeyMatch(cfg, "") {
		t.Fatal("constantTimeAPIKeyMatch matched an empty presented token against an empty configured api-key (#5636)")
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := productionAuthHandlerOnly(t, cfg, false, ok)

	// Bearer with an empty token routes through constantTimeAPIKeyMatch.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("empty configured api-key must reject an empty Bearer token; got status %d, want 401", rr.Code)
	}

	// A non-empty configured api-key still authenticates the matching token.
	cfg = AuthConfig{APIKeys: map[string]bool{"tok-abc-123": true}}
	if !constantTimeAPIKeyMatch(cfg, "tok-abc-123") {
		t.Fatal("constantTimeAPIKeyMatch must still accept a correct non-empty api-key")
	}
}
