package ddns

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// surface_a_sourcebind_failclosed_4437_test.go: FAIL-ON-REVERT coverage for
// #4437 — a Surface A HTTP provider that configures a `source-address` which
// cannot be honored (a malformed source-address) must fail CLOSED (resolve to
// the no-op publisher, so the reconcile SKIPS the publish) rather than falling
// back to the UNBOUND default-route client and silently publishing from the
// wrong source. The bug lived ONLY on the cached-client path
// (resolveBackend / m.httpClients non-nil): httpClientCache.clientFor returns
// the unbound default client alongside the bind error, and resolveSurfaceABackend
// used to swallow that error and thread the unbound client into the backend. The
// nil-cache path already failed closed (newProviderHTTPClient surfaces the same
// error from inside the constructor); these tests pin the cached path to the
// same posture, mirroring the checkip observer's #3733 CheckIPBound gate.

// TestResolveSurfaceABackendFailsClosedOnCachedSourceBindError proves that a
// cached-client source-bind error degrades the provider to the no-op publisher
// (never a working HTTP backend built on the unbound default client). Goes RED
// on revert: without the fail-closed gate the unbound client is threaded in, the
// dyndns2 constructor succeeds, and resolveSurfaceABackend returns a live
// *dyndns2Backend that would publish from the default route.
func TestResolveSurfaceABackendFailsClosedOnCachedSourceBindError(t *testing.T) {
	cache := newHTTPClientCache()
	p := &config.DDNSProvider{
		Name:     "p",
		Backend:  "dyndns2",
		Server:   "https://dyn.example.net/nic/update",
		Username: "u",
		Password: config.NewSecret("pw"),
		// A configured-but-unhonorable source binding: clientFor resolves the
		// bindConfig, fails to parse the address, and returns (unbound client,
		// error). The publish must NOT egress via that unbound client.
		SourceAddress: "not-an-ip",
	}

	b, err := resolveSurfaceABackend(p, "host.example.net", 60, cache)
	if err != nil {
		// The degrade is a no-op backend + nil error (newSurfaceAHTTP logs the
		// error and returns nopUpdater), NOT a hard resolve error — the reconcile
		// treats the no-op backend as "skip this publish, re-attempt next cycle".
		t.Fatalf("resolveSurfaceABackend should degrade to the no-op publisher, "+
			"not hard-error: %v", err)
	}
	if !isNopUpdater(b) {
		t.Fatalf("a cached-client source-bind error must fail CLOSED to the no-op "+
			"publisher, got %T; a configured source-address that cannot be honored "+
			"must skip the publish, never egress from the unbound default route", b)
	}

	// The error path must NOT be cached (a corrected source-address on the next
	// commit rebuilds cleanly) — the cache holds no entry for the bad binding.
	if n := cache.size(); n != 0 {
		t.Fatalf("bind-error path must not cache a client, got %d entr(ies)", n)
	}
}

// TestResolveSurfaceABackendNoSourceUsesDefaultClient proves the fail-closed gate
// keys ONLY on the bind error: a provider with NO source-address (the default
// route is the intended egress) still resolves to a real, working HTTP backend
// through the cached default client. Goes RED if the gate ever over-fires and
// suppresses publishing for every default-route deployment.
func TestResolveSurfaceABackendNoSourceUsesDefaultClient(t *testing.T) {
	cache := newHTTPClientCache()
	p := &config.DDNSProvider{
		Name:     "p",
		Backend:  "dyndns2",
		Server:   "https://dyn.example.net/nic/update",
		Username: "u",
		Password: config.NewSecret("pw"),
		// No SourceAddress: bindConfig is the zero value, clientFor returns
		// (default client, nil error) — the operator never asked for a source.
	}

	b, err := resolveSurfaceABackend(p, "host.example.net", 60, cache)
	if err != nil {
		t.Fatalf("a no-source provider must resolve without error, got %v", err)
	}
	if isNopUpdater(b) {
		t.Fatalf("a provider with no source-address must resolve to a real backend " +
			"(the unbound default client is its intended egress), got the no-op publisher")
	}
	if _, ok := b.(*dyndns2Backend); !ok {
		t.Fatalf("expected a live *dyndns2Backend for the no-source happy path, got %T", b)
	}
}
