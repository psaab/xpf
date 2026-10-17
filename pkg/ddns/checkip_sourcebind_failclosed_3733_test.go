package ddns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// checkip_sourcebind_failclosed_3733_test.go: FAIL-ON-REVERT coverage for #3733
// — the checkip probe is an address ORACLE, so a configured-but-unhonorable
// source binding must fail CLOSED (no probe, no address) rather than falling
// back to the kernel default route. Before #3733 the daemon logged a warning and
// STILL probed with the unbound default client, returning the wrong WAN's public
// IP (the class #2846 was meant to close). CheckIPBound centralizes the gate;
// these tests go RED if it degrades back to CheckIP's fall-open behavior.

// TestCheckIPBoundFailsClosedOnBindError proves that when a source was requested
// but could not be honored (bindErr != nil), CheckIPBound does NOT contact the
// checkip endpoint and returns ok=false — even though the (unbound) client WOULD
// have successfully fetched a public IP. Goes RED on revert: without the bindErr
// gate the server is hit and its address is returned/published (wrong WAN).
func TestCheckIPBoundFailsClosedOnBindError(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		// A real, non-reserved public address the validity gate accepts — this
		// is exactly the wrong-WAN IP that must NOT be published.
		_, _ = w.Write([]byte("93.184.216.34\n"))
	}))
	defer srv.Close()

	bindErr := errors.New("ddns: invalid source-address \"not-an-ip\": bad")
	a, ok, cerr := CheckIPBound(context.Background(), srv.Client(), srv.URL, true, nil, bindErr)
	// The fail-closed refusal must also be REPORTABLE, not just silent: the
	// daemon logs the reason once per (provider, error). A nil here would put
	// the bind failure back in the undiagnosable-forever bucket.
	if !errors.Is(cerr, bindErr) {
		t.Fatalf("CheckIPBound(bindErr) err = %v, want the bind error itself", cerr)
	}
	if ok {
		t.Fatalf("CheckIPBound with a bind error returned ok=true addr=%v; "+
			"the checkip oracle must fail closed, never publish an IP obtained "+
			"via the default route", a)
	}
	if a.IsValid() {
		t.Fatalf("CheckIPBound fail-closed must return the zero addr, got %v", a)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("CheckIPBound with a bind error contacted the checkip endpoint "+
			"%d time(s); it must not probe via the default route", n)
	}
}

// TestCheckIPBoundNoSourceUsesDefaultRoute proves the no-source-configured path
// is unchanged: bindErr == nil means the caller's client is the intended egress
// (unbound-by-config), so the probe proceeds and returns the public IP. Goes RED
// if the gate ever fails closed when no source was requested (would suppress
// publishing for every default-route deployment).
func TestCheckIPBoundNoSourceUsesDefaultRoute(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("93.184.216.34\n"))
	}))
	defer srv.Close()

	a, ok, cerr := CheckIPBound(context.Background(), srv.Client(), srv.URL, true, nil, nil)
	if !ok || a.String() != "93.184.216.34" || cerr != nil {
		t.Fatalf("CheckIPBound(no source, bindErr=nil) = %v ok=%v err=%v; want 93.184.216.34 true <nil>",
			a, ok, cerr)
	}
}

// TestCheckIPBoundAvailableSourceWorks proves the multi-WAN happy path #2846
// established: a configured source that resolves cleanly (bindErr == nil, and
// `client` is an ACTUAL source-bound client, not the unbound default) still
// probes and returns the public IP. The fail-closed gate keys ONLY on the bind
// error, so an honored source is never suppressed. Distinct from
// TestCheckIPBoundNoSourceUsesDefaultRoute (which threads the unbound default
// client): here the probe egresses through a real source-bound *http.Client.
func TestCheckIPBoundAvailableSourceWorks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("93.184.216.34\n"))
	}))
	defer srv.Close()

	// Build the REAL bound client: source-address 127.0.0.1 is the loopback the
	// httptest server listens on, so the source-bound socket connects to it
	// successfully (v4 source, v4 dial — no #2901 family mismatch). A valid
	// source-address resolves WITHOUT a bind error, so the caller passes
	// bindErr=nil and the probe must proceed through the bound client. Trust
	// the test server's certificate on the real production transport while
	// keeping its source-bound DialContext.
	client, err := newProviderHTTPClient(&config.DDNSProvider{Name: "p", SourceAddress: "127.0.0.1"})
	if err != nil {
		t.Fatalf("a valid source-address must resolve without error, got %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.DialContext == nil {
		t.Fatalf("expected a source-bound client with a DialContext, got %T (DialContext set=%v)",
			client.Transport, ok && tr.DialContext != nil)
	}
	tr.TLSClientConfig.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	a, ok2, cerr := CheckIPBound(context.Background(), client, srv.URL, true, nil, nil)
	if !ok2 || a.String() != "93.184.216.34" || cerr != nil {
		t.Fatalf("CheckIPBound(honored bound source) = %v ok=%v err=%v; want 93.184.216.34 true <nil>",
			a, ok2, cerr)
	}
}
