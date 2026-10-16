package rpm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14178: probeHTTP validated only the configured target, then followed a
// redirect supplied by that endpoint to any other origin. The redirect
// target is endpoint-chosen, not operator-chosen, so it must stay on the
// configured origin: a cross-origin 2xx is not evidence the configured
// path is healthy.

// TestHTTPProbeCrossOriginRedirectIsRefused14178 is the decisive cell.
// A configured origin redirects to a second local origin returning 200.
// On pre-fix code the second origin receives the GET and probeHTTP
// reports pass; the fix must never dial it and must fail the probe.
func TestHTTPProbeCrossOriginRedirectIsRefused14178(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/health", http.StatusFound)
	}))
	defer source.Close()

	_, err := (&Manager{}).probeHTTP(context.Background(), &config.RPMTest{Target: source.URL}, probeSockOpts{})
	if err == nil {
		t.Fatal("probeHTTP followed a cross-origin redirect to a 200 and reported pass; want refusal")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("probeHTTP error = %v, want a redirect refusal", err)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("cross-origin redirect target received %d requests, want 0", got)
	}
}

// TestHTTPProbeRedirectSchemeChangeIsRefused14178 pins scheme
// strictness: http and https are different origins, so a Location that
// changes the scheme — a downgrade off TLS, or an upgrade the operator
// never configured — must not be followed. A plain-HTTP probe whose
// endpoint redirects to an https URL on the same host would otherwise
// run a TLS handshake the configured target never asked for (and, in
// this fixture, would fail TLS against a plain server — the refusal
// must come from the redirect policy, before any dial).
func TestHTTPProbeRedirectSchemeChangeIsRefused14178(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+"/health", http.StatusFound)
	}))
	defer source.Close()

	_, err := (&Manager{}).probeHTTP(context.Background(), &config.RPMTest{Target: source.URL}, probeSockOpts{})
	if err == nil {
		t.Fatal("probeHTTP followed a scheme-changing redirect and reported pass; want refusal")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("probeHTTP error = %v, want a redirect refusal", err)
	}
}

// TestHTTPProbeSameOriginRedirectStillPasses14178 is the legitimate
// control: a path move on the configured origin is still followed and
// its 2xx still counts as pass. Without this control a fix that simply
// refused every redirect would look green above.
func TestHTTPProbeSameOriginRedirectStillPasses14178(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/health", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if _, err := (&Manager{}).probeHTTP(context.Background(), &config.RPMTest{Target: server.URL + "/start"}, probeSockOpts{}); err != nil {
		t.Fatalf("same-origin redirect probe: %v, want pass", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("same-origin redirect endpoint received %d requests, want 2", got)
	}
}

// TestHTTPProbeRedirectToUnsupportedSchemeIsRefused14178 covers a
// Location whose scheme http-get can never probe. The http client
// already errors on such hops today; this pins that the fix keeps
// refusing them (as a probe failure, never a pass).
func TestHTTPProbeRedirectToUnsupportedSchemeIsRefused14178(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://127.0.0.1/health", http.StatusFound)
	}))
	defer source.Close()

	if _, err := (&Manager{}).probeHTTP(context.Background(), &config.RPMTest{Target: source.URL}, probeSockOpts{}); err == nil {
		t.Fatal("probeHTTP followed a redirect to an unsupported scheme and reported pass; want refusal")
	}
}
