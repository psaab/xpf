package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestIsLoopbackBindAddr covers the bind classification that decides whether
// /metrics is auth-gated (#4162).
func TestIsLoopbackBindAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.0.0.1", true},
		{"[::1]:8080", true},
		{"::1", true},
		{"192.168.1.5:8080", false},
		{"10.0.0.1:8080", false},
		{":8080", false},        // wildcard
		{"0.0.0.0:8080", false}, // all v4
		{"[::]:8080", false},    // all v6
		{"example.com:8080", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isLoopbackBindAddr(tc.addr); got != tc.want {
			t.Errorf("isLoopbackBindAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// TestMetricsAuthGateNonLoopback asserts the #4162 auth posture: on a
// non-loopback bind (metricsRequireAuth=true) /metrics demands credentials,
// while /health stays exempt; on loopback (false) /metrics stays open.
//
// FAIL-ON-REVERT: restoring the unconditional `path == "/metrics"` bypass makes
// the no-credential non-loopback case return 200 instead of 401.
func TestMetricsAuthGateNonLoopback(t *testing.T) {
	cfg := AuthConfig{
		Users:   map[string]string{"admin": "secret123"},
		APIKeys: map[string]bool{"tok-abc-123": true},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret123"))

	cases := []struct {
		name        string
		requireAuth bool
		path        string
		header      map[string]string
		want        int
	}{
		{"loopback metrics open", false, "/metrics", nil, http.StatusOK},
		{"non-loopback metrics no-key blocked", true, "/metrics", nil, http.StatusUnauthorized},
		{"non-loopback metrics with basic ok", true, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK},
		{"non-loopback metrics with api key ok", true, "/metrics", map[string]string{"X-API-Key": "tok-abc-123"}, http.StatusOK},
		{"non-loopback health still open", true, "/health", nil, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := authMiddleware(cfg, tc.requireAuth, next)
			req := httptest.NewRequest("GET", tc.path, nil)
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d", tc.name, w.Code, tc.want)
			}
		})
	}
}

// TestNewServerMetricsAuthIsOwnedByEachListener exercises the actual HTTP and
// HTTPS owner handlers constructed by NewServer. It intentionally covers both
// mixed-listener orientations so restoring one wrapper derived from cfg.Addr
// makes this test fail closed-to-open (or open-to-closed) immediately.
func TestNewServerMetricsAuthIsOwnedByEachListener(t *testing.T) {
	resetTLSSeams(t)
	// NewServer must install HTTPS after a persistence failure because the
	// generated in-memory certificate remains usable. Avoid test writes to the
	// production TLS location while preserving that production contract.
	tlsMkdirAllDurable = func(string, os.FileMode) error {
		return errors.New("injected TLS persistence failure")
	}

	auth := &AuthConfig{
		Users:   map[string]string{"admin": "secret123"},
		APIKeys: map[string]bool{"tok-abc-123": true},
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret123"))

	newServer := func(t *testing.T, cfg Config) *Server {
		t.Helper()
		s := NewServer(cfg)
		if s.httpServer() == nil || s.httpServer().Handler == nil {
			t.Fatal("NewServer did not install the HTTP owner handler")
		}
		if cfg.TLS && cfg.HTTPSAddr != "" && (s.httpsServer() == nil || s.httpsServer().Handler == nil) {
			t.Fatal("NewServer did not install the requested HTTPS owner handler")
		}
		return s
	}
	request := func(t *testing.T, handler http.Handler, path string, header map[string]string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		for key, value := range header {
			req.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != want {
			t.Fatalf("%s with headers %v: status = %d, want %d", path, header, recorder.Code, want)
		}
	}

	t.Run("HTTP loopback HTTPS wildcard", func(t *testing.T) {
		s := newServer(t, Config{
			Addr:      "127.0.0.1:8080",
			HTTPSAddr: "0.0.0.0:8443",
			TLS:       true,
			Auth:      auth,
		})
		request(t, s.httpServer().Handler, "/metrics", nil, http.StatusOK)
		request(t, s.httpsServer().Handler, "/metrics", nil, http.StatusUnauthorized)
		request(t, s.httpsServer().Handler, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK)
		request(t, s.httpsServer().Handler, "/metrics", map[string]string{"Authorization": "Bearer tok-abc-123"}, http.StatusOK)
		request(t, s.httpsServer().Handler, "/metrics", map[string]string{"X-API-Key": "tok-abc-123"}, http.StatusOK)
		request(t, s.httpsServer().Handler, "/health", nil, http.StatusOK)
		request(t, s.httpsServer().Handler, "/api/v1/status", nil, http.StatusUnauthorized)
	})

	t.Run("HTTP wildcard HTTPS loopback", func(t *testing.T) {
		s := newServer(t, Config{
			Addr:      "0.0.0.0:8080",
			HTTPSAddr: "127.0.0.1:8443",
			TLS:       true,
			Auth:      auth,
		})
		request(t, s.httpServer().Handler, "/metrics", nil, http.StatusUnauthorized)
		request(t, s.httpsServer().Handler, "/metrics", nil, http.StatusOK)
		request(t, s.httpServer().Handler, "/health", nil, http.StatusOK)
		request(t, s.httpServer().Handler, "/api/v1/status", nil, http.StatusUnauthorized)
	})

	t.Run("literal IPv4 and IPv6 loopback", func(t *testing.T) {
		v4 := newServer(t, Config{Addr: "127.0.0.2:8080", Auth: auth})
		request(t, v4.httpServer().Handler, "/metrics", nil, http.StatusOK)

		v6 := newServer(t, Config{
			Addr:      "192.0.2.10:8080",
			HTTPSAddr: "[::1]:8443",
			TLS:       true,
			Auth:      auth,
		})
		request(t, v6.httpsServer().Handler, "/metrics", nil, http.StatusOK)
	})

	t.Run("unprovable binds fail closed", func(t *testing.T) {
		for _, addr := range []string{
			":8080",
			"0.0.0.0:8080",
			"[::]:8080",
			"localhost:8080",
			"metrics.example.test:8080",
			"not-a-listen-address",
		} {
			s := newServer(t, Config{Addr: addr, Auth: auth})
			request(t, s.httpServer().Handler, "/metrics", nil, http.StatusUnauthorized)
		}
	})

	t.Run("auth-wrapped listener leaves health open", func(t *testing.T) {
		s := newServer(t, Config{Addr: "192.0.2.10:8080", Auth: auth})
		request(t, s.httpServer().Handler, "/metrics", nil, http.StatusUnauthorized)
		request(t, s.httpServer().Handler, "/health", nil, http.StatusOK)
		request(t, s.httpServer().Handler, "/api/v1/status", nil, http.StatusUnauthorized)
	})

	t.Run("nil auth leaves both listeners on the base mux", func(t *testing.T) {
		s := newServer(t, Config{
			Addr:      "192.0.2.10:8080",
			HTTPSAddr: "198.51.100.10:8443",
			TLS:       true,
		})
		request(t, s.httpServer().Handler, "/metrics", nil, http.StatusOK)
		request(t, s.httpsServer().Handler, "/metrics", nil, http.StatusOK)
		request(t, s.httpServer().Handler, "/not-a-route", nil, http.StatusNotFound)
		request(t, s.httpsServer().Handler, "/not-a-route", nil, http.StatusNotFound)
	})
}
