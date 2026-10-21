package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// metrics_loopback_gate_16072_test.go pins #16072: on a loopback bind,
// /metrics is open to any local UID by default (#4162), but with the opt-in
// `api-auth metrics-require-auth` gate an unauthorized local caller gets 401
// while a caller presenting a valid api-auth credential (the local scraper
// path) still scrapes. The gate rides inside AuthConfig, so it is published
// by ReplaceAuth / ReplaceMetricsRequireAuth exactly like a credential
// change, and a retired leg only ever tightens.
//
// FAIL-ON-REVERT: dropping the effectiveMetricsRequireAuth fold in
// authCheckCredential (or in throttledAuthCheckWithCheck) makes the
// no-credential loopback case return 200 instead of 401.

func metricsGateRequest(t *testing.T, handler http.Handler, path string, header map[string]string, want int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("GET %s headers=%v: status = %d, want %d", path, header, rec.Code, want)
	}
}

func TestLoopbackMetricsRequireAuthGate16072(t *testing.T) {
	gated := AuthConfig{
		Users:              map[string]string{"admin": "secret123"},
		APIKeys:            map[string]bool{"tok-abc-123": true},
		MetricsRequireAuth: true,
	}
	open := AuthConfig{
		Users:   map[string]string{"admin": "secret123"},
		APIKeys: map[string]bool{"tok-abc-123": true},
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret123"))

	// Loopback bind (metricsRequireAuth=false): the gate is the only thing
	// that can close /metrics.
	loopback := authMiddleware(gated, false, ok)
	metricsGateRequest(t, loopback, "/metrics", nil, http.StatusUnauthorized)
	metricsGateRequest(t, loopback, "/metrics", map[string]string{"Authorization": "Bearer wrong-token"}, http.StatusUnauthorized)
	metricsGateRequest(t, loopback, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK)
	metricsGateRequest(t, loopback, "/metrics", map[string]string{"Authorization": "Bearer tok-abc-123"}, http.StatusOK)
	metricsGateRequest(t, loopback, "/metrics", map[string]string{"X-API-Key": "tok-abc-123"}, http.StatusOK)
	// /health stays exempt even with the gate on.
	metricsGateRequest(t, loopback, "/health", nil, http.StatusOK)

	// Without the gate the loopback posture is unchanged (#4162).
	openHandler := authMiddleware(open, false, ok)
	metricsGateRequest(t, openHandler, "/metrics", nil, http.StatusOK)

	// Non-loopback already required credentials; the gate changes nothing.
	nonLoopback := authMiddleware(gated, true, ok)
	metricsGateRequest(t, nonLoopback, "/metrics", nil, http.StatusUnauthorized)
	metricsGateRequest(t, nonLoopback, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK)
}

func TestLoopbackMetricsGateDynamicSwap16072(t *testing.T) {
	resetTLSSeams(t)
	auth := &AuthConfig{
		Users:   map[string]string{"admin": "secret123"},
		APIKeys: map[string]bool{"tok-abc-123": true},
	}
	s := NewServer(Config{Addr: "127.0.0.1:8080", Auth: auth})
	handler := s.httpServer().Handler
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret123"))

	// Default: loopback /metrics is open.
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusOK)

	// Enabling the gate via the live swap closes it on the next request,
	// without a rebind; the credentialed scraper still works.
	s.ReplaceMetricsRequireAuth(true)
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusUnauthorized)
	metricsGateRequest(t, handler, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK)
	metricsGateRequest(t, handler, "/metrics", map[string]string{"X-API-Key": "tok-abc-123"}, http.StatusOK)
	metricsGateRequest(t, handler, "/health", nil, http.StatusOK)

	// A gate-only snapshot swap (same credentials, flag on) does the same.
	s.ReplaceMetricsRequireAuth(false)
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusOK)
	gated := *auth
	gated.MetricsRequireAuth = true
	s.ReplaceAuth(&gated)
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusUnauthorized)

	// Removing the gate reopens the loopback posture.
	s.ReplaceMetricsRequireAuth(false)
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusOK)

	// Cfg-level opt-in at construction: NewServer stamps it into the snapshot
	// without mutating the caller's AuthConfig.
	cfgAuth := &AuthConfig{Users: map[string]string{"admin": "secret123"}}
	s2 := NewServer(Config{Addr: "127.0.0.1:8080", Auth: cfgAuth, MetricsRequireAuth: true})
	if cfgAuth.MetricsRequireAuth {
		t.Fatal("NewServer mutated the caller's AuthConfig while stamping the metrics gate")
	}
	metricsGateRequest(t, s2.httpServer().Handler, "/metrics", nil, http.StatusUnauthorized)
	metricsGateRequest(t, s2.httpServer().Handler, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK)

	// Nil auth WITH the gate intent fails closed (fold witness): the gate
	// survives credential filtering that nils the snapshot, so /metrics
	// 401s while /health stays open. (An ungated nil snapshot still passes
	// through — see the s4 case below.)
	s3 := NewServer(Config{Addr: "127.0.0.1:8080", MetricsRequireAuth: true})
	metricsGateRequest(t, s3.httpServer().Handler, "/metrics", nil, http.StatusUnauthorized)
	metricsGateRequest(t, s3.httpServer().Handler, "/health", nil, http.StatusOK)

	s4 := NewServer(Config{Addr: "127.0.0.1:8080"})
	metricsGateRequest(t, s4.httpServer().Handler, "/metrics", nil, http.StatusOK)
}

// TestLoopbackMetricsGateSurvivesCredentialLoss16072 is the fold witness:
// a gate committed with a valid credential must not reopen when the
// credential snapshot is later lost (expiry/filtering publishes nil, or
// the gate is toggled with no snapshot at all). /metrics fails closed;
// /health stays exempt; other paths keep the nil pass-through.
//
// FAIL-ON-REVERT: reverting the Server.metricsGate independence (gate only
// inside AuthConfig, nil pass-through) makes the post-loss /metrics cases
// return 200.
func TestLoopbackMetricsGateSurvivesCredentialLoss16072(t *testing.T) {
	resetTLSSeams(t)
	auth := &AuthConfig{
		Users:              map[string]string{"admin": "secret123"},
		MetricsRequireAuth: true,
	}
	s := NewServer(Config{Addr: "127.0.0.1:8080", Auth: auth})
	handler := s.httpServer().Handler
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret123"))
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusUnauthorized)
	metricsGateRequest(t, handler, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK)

	// Credential loss: the snapshot goes nil (as resolveAPIBinds publishes
	// when every credential expired/was filtered). The gate must NOT reopen.
	s.ReplaceAuth(nil)
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusUnauthorized)
	metricsGateRequest(t, handler, "/metrics", map[string]string{"Authorization": basic}, http.StatusUnauthorized)
	metricsGateRequest(t, handler, "/health", nil, http.StatusOK)
	// Non-metrics paths keep the nil pass-through (loopback clamp posture):
	// a 404 from the mux, not a 401 from the gate.
	metricsGateRequest(t, handler, "/not-a-route", nil, http.StatusNotFound)

	// Credentials return (still gated): the scraper works again.
	s.ReplaceAuth(auth)
	metricsGateRequest(t, handler, "/metrics", map[string]string{"Authorization": basic}, http.StatusOK)
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusUnauthorized)

	// Gate toggled with no snapshot at all: still fails closed, and the
	// removal (published by the reconciler only when sanctioned) reopens.
	s.ReplaceAuth(nil)
	s.ReplaceMetricsRequireAuth(true)
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusUnauthorized)
	s.ReplaceMetricsRequireAuth(false)
	metricsGateRequest(t, handler, "/metrics", nil, http.StatusOK)
}

func TestMetricsGateRetainedIntersection16072(t *testing.T) {
	live := &AuthConfig{
		Users:              map[string]string{"admin": "secret123"},
		MetricsRequireAuth: true,
	}
	next := &AuthConfig{
		Users: map[string]string{"admin": "secret123"},
	}
	// The intersection preserves the gate from either side: a retained leg
	// never drops a gate the live or committed snapshot carries.
	if got := AuthForRetainedListener(live, next); !got.MetricsRequireAuth {
		t.Fatal("retained-listener intersection dropped the live metrics gate")
	}
	if got := AuthForRetainedListener(next, live); !got.MetricsRequireAuth {
		t.Fatal("retained-listener intersection dropped the committed metrics gate")
	}
	if got := AuthForRetainedListener(next, next); got.MetricsRequireAuth {
		t.Fatal("retained-listener intersection invented a metrics gate neither side carries")
	}
	if got := AuthForRetainedListener(nil, live); !got.MetricsRequireAuth {
		t.Fatal("universal-live intersection dropped the committed metrics gate")
	}
}
