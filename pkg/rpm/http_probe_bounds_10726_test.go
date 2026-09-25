package rpm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestHTTPProbeRedirectChainIsBounded10726 drives probeHTTP against a live
// redirecting endpoint. Removing the explicit CheckRedirect restores the
// standard-library 10-request chain and this request-count assertion goes RED.
func TestHTTPProbeRedirectChainIsBounded10726(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer server.Close()

	_, err := (&Manager{}).probeHTTP(context.Background(), &config.RPMTest{Target: server.URL}, probeSockOpts{})
	if err == nil || !strings.Contains(err.Error(), "redirect limit") {
		t.Fatalf("probeHTTP error = %v, want bounded redirect refusal", err)
	}
	if want := maxProbeRedirectHops + 1; requests != want {
		t.Fatalf("redirect endpoint received %d requests, want %d (initial request + at most %d redirects)",
			requests, want, maxProbeRedirectHops)
	}
}

// TestHTTPProbeBodyDrainStopsAtLimit10726 pins the response byte budget used by
// probeHTTP: a large response is a successful health check, but only the
// configured upper bound is consumed.
func TestHTTPProbeBodyDrainStopsAtLimit10726(t *testing.T) {
	const extra = 37
	body := strings.NewReader(strings.Repeat("x", maxProbeBodyBytes9049+extra))
	if err := drainProbeBody(body); err != nil {
		t.Fatalf("drainProbeBody: %v", err)
	}
	if got := body.Len(); got != extra {
		t.Fatalf("response bytes left unread = %d, want %d after %d-byte bound", got, extra, maxProbeBodyBytes9049)
	}
}
