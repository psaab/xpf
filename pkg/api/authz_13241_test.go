package api

import (
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func cloneAuthConfig(a AuthConfig) AuthConfig {
	return AuthConfig{
		Users: maps.Clone(a.Users), UserClasses: maps.Clone(a.UserClasses),
		UserExpires: maps.Clone(a.UserExpires), APIKeys: maps.Clone(a.APIKeys),
		APIKeyNames: maps.Clone(a.APIKeyNames), APIKeyClasses: maps.Clone(a.APIKeyClasses),
		APIKeyExpires: maps.Clone(a.APIKeyExpires),
	}
}

func TestCredentialMemoReusesOnlySemanticallyCurrentPolicy13241(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/config/enter", nil)
	req.Header.Set("Authorization", "Basic YWRtaW46c2VjcmV0")
	cfg := AuthConfig{
		Users:       map[string]string{"admin": "secret"},
		UserClasses: map[string]string{"admin": "super-user"},
		UserExpires: map[string]time.Time{"admin": time.Now().Add(time.Hour)},
	}
	calls := 0
	ri := &requestIdentity{
		pending: &pendingPeer{},
		credentialResolver: func(a AuthConfig, _ *http.Request) (string, string, bool) {
			calls++
			if !credentialExpiryActive(a.UserExpires["admin"]) || a.Users["admin"] != "secret" {
				return "", "", false
			}
			return "admin", resolvedCredentialClass(a.UserClasses["admin"]), true
		},
	}
	s := &Server{peerLocalityFn: func(net.Addr, net.Addr) bool { return false }}
	s.auth.Store(&cfg)
	if p := s.principalFrom(req, nil, ri); p.Username != "admin" {
		t.Fatalf("principal = %+v, want admin", p)
	}
	// A deep-equal copy simulates reconcileTo's snapshot republish after an
	// unrelated commit: pointer identity changes, authorization semantics do not.
	copy := cloneAuthConfig(cfg)
	s.auth.Store(&copy)
	if p := s.principalFrom(req, nil, ri); p.Username != "admin" {
		t.Fatal("semantically unchanged policy was refused")
	}
	if calls != 1 {
		t.Fatalf("verifier called %d times for equivalent policy, want 1", calls)
	}
	// Even identical policy cannot outlive its time-based cap. Setting the
	// request-local cap into the past deterministically exercises that branch.
	ri.credMemo.expires = time.Now().Add(-time.Second)
	if p := s.principalFrom(req, nil, ri); p.Username != "admin" {
		t.Fatal("credential verification after memo expiry failed")
	}
	if calls != 2 {
		t.Fatalf("verifier called %d times after memo expiry, want 2", calls)
	}

	// A scope edit must invalidate the memo and run verification under the
	// new policy. The successful fake result confirms the changed policy was seen.
	changed := cloneAuthConfig(cfg)
	changed.UserClasses["admin"] = "read-only"
	s.auth.Store(&changed)
	if p := s.principalFrom(req, nil, ri); p.Username != "admin" {
		t.Fatal("credential under changed policy was refused")
	}
	if calls != 3 {
		t.Fatalf("verifier called %d times after semantic policy change, want 3", calls)
	}

	// An expired timestamp is part of policy equality and must be rechecked
	// against credential expiry before the request can continue.
	expired := cloneAuthConfig(changed)
	expired.UserExpires["admin"] = time.Now().Add(-time.Second)
	s.auth.Store(&expired)
	if p := s.principalFrom(req, nil, ri); p.Source != 0 {
		t.Fatal("expired credential was accepted")
	}
	if calls != 4 {
		t.Fatalf("verifier called %d times after expiry/policy change, want 4", calls)
	}
}
