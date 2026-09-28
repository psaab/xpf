package api

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestScopedAPIKeyServesHTTPSWhenClearHTTPIsDisabled10826(t *testing.T) {
	usePasswdFixture(t)
	certPath, keyPath, _ := writeManagementTLSFixture(
		t, t.TempDir(), "api-auth-https", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	const rawKey = "0123456789abcdef-api-auth-https"
	verifier, err := config.HashAPIAuthSecret(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	s := NewServer(Config{
		Addr:           "",
		TLS:            true,
		HTTPSAddr:      "127.0.0.1:0",
		TLSCertificate: certPath,
		TLSPrivateKey:  keyPath,
		Auth: &AuthConfig{
			APIKeys:       map[string]bool{verifier: true},
			APIKeyNames:   map[string]string{verifier: "view-automation"},
			APIKeyClasses: map[string]string{verifier: "read-only"},
			APIKeyExpires: map[string]time.Time{verifier: expires},
		},
		Store:          authzStore(t, authzTestConfig),
		PeerLookupFn:   remotePeer(),
		PeerLocalityFn: remoteLocality(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		s.Wait()
	})
	if s.HTTPServing() || s.EffectiveHTTPAddr() != "" {
		t.Fatalf("clear HTTP leg unexpectedly serves with api-auth enabled: serving=%v addr=%q",
			s.HTTPServing(), s.EffectiveHTTPAddr())
	}
	httpsAddr := s.EffectiveHTTPSAddr()
	if !s.HTTPSServing() || httpsAddr == "" {
		t.Fatalf("HTTPS leg is not serving: serving=%v addr=%q", s.HTTPSServing(), httpsAddr)
	}
	waitDialable(t, httpsAddr)

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	send := func(method, path, body string) int {
		t.Helper()
		req, err := http.NewRequest(method, "https://"+httpsAddr+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-API-Key", rawKey)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if got := send(http.MethodGet, "/api/v1/config", ""); got != http.StatusOK {
		t.Fatalf("valid view-scoped API key over HTTPS returned %d, want 200", got)
	}
	for _, path := range []string{"/api/v1/config/set", "/api/v1/system/action"} {
		if got := send(http.MethodPost, path, `{}`); got != http.StatusForbidden {
			t.Errorf("read-only API key over HTTPS returned %d for %s, want 403", got, path)
		}
	}
}
