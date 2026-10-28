package ddns

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// surface_a_httpcache_reap_2956_test.go: FAIL-ON-REVERT coverage for #2956 — the
// Surface A per-binding HTTP client cache must REAP a superseded entry when a
// binding leaf changes, closing the old transport's idle-connection pool and
// dropping the map entry. Before #2956 a binding-leaf change keyed a fresh entry
// and the old one was simply never looked up again, accumulating for the daemon
// lifetime (the *http.Transport + idle pool retained). These tests go RED if the
// reap (close + evict) is removed or stops bounding the map under binding churn.

// TestHTTPClientCacheReapClosesSupersededTransport is the core unit-level
// fail-on-revert: after a binding change supersedes a cache entry, reap must call
// CloseIdleConnections on EXACTLY the superseded client and evict it, while
// leaving the still-live binding's client cached and open. The closeIdleConns
// seam records the call so the assertion fails if the close is dropped; the
// size() assertion fails if the eviction is dropped.
func TestHTTPClientCacheReapClosesSupersededTransport(t *testing.T) {
	c := newHTTPClientCache()

	var closed []*http.Client
	orig := closeIdleConns
	closeIdleConns = func(cl *http.Client) {
		closed = append(closed, cl)
		orig(cl) // still close for real
	}
	defer func() { closeIdleConns = orig }()

	pOld := &config.DDNSProvider{Name: "p", Backend: "generic", RFC2136Endpoint: config.RFC2136Endpoint{SourceAddress: "192.0.2.1"}}
	pNew := &config.DDNSProvider{Name: "p", Backend: "generic", RFC2136Endpoint: config.RFC2136Endpoint{SourceAddress: "192.0.2.2"}}

	clOld, err := c.clientFor(pOld)
	if err != nil {
		t.Fatalf("clientFor old: %v", err)
	}
	clNew, err := c.clientFor(pNew)
	if err != nil {
		t.Fatalf("clientFor new: %v", err)
	}
	if clOld == clNew {
		t.Fatal("distinct bindings must key distinct clients (precondition)")
	}
	if c.size() != 2 {
		t.Fatalf("want 2 cached clients before reap, got %d", c.size())
	}

	// The binding changed from .1 to .2: only the new key is still referenced.
	c.reap(map[string]struct{}{bindCacheKey(pNew): {}})

	if c.size() != 1 {
		t.Fatalf("reap must evict the superseded entry; want size 1, got %d", c.size())
	}
	// The still-live binding's client must survive AND remain cached (a re-lookup
	// returns the same pointer, not a freshly built one).
	clNew2, err := c.clientFor(pNew)
	if err != nil {
		t.Fatalf("clientFor new (2): %v", err)
	}
	if clNew2 != clNew {
		t.Fatal("reap must NOT evict the still-live binding's client")
	}
	// The superseded client's idle pool was closed exactly once.
	if len(closed) != 1 || closed[0] != clOld {
		t.Fatalf("reap must CloseIdleConnections on exactly the superseded client; closed=%v", closed)
	}
}

// TestHTTPClientCacheReapKeepsAllLiveBindings proves reap does not close a
// transport that is still the active one for a current binding: with every key
// in the live set, nothing is closed or evicted (only an actual key change is
// superseded).
func TestHTTPClientCacheReapKeepsAllLiveBindings(t *testing.T) {
	c := newHTTPClientCache()

	var closed int
	orig := closeIdleConns
	closeIdleConns = func(cl *http.Client) { closed++; orig(cl) }
	defer func() { closeIdleConns = orig }()

	pA := &config.DDNSProvider{Name: "a", Backend: "generic", RFC2136Endpoint: config.RFC2136Endpoint{SourceAddress: "192.0.2.10"}}
	pB := &config.DDNSProvider{Name: "b", Backend: "generic", RFC2136Endpoint: config.RFC2136Endpoint{SourceAddress: "192.0.2.11"}}
	if _, err := c.clientFor(pA); err != nil {
		t.Fatalf("clientFor a: %v", err)
	}
	if _, err := c.clientFor(pB); err != nil {
		t.Fatalf("clientFor b: %v", err)
	}

	c.reap(map[string]struct{}{
		bindCacheKey(pA): {},
		bindCacheKey(pB): {},
	})

	if c.size() != 2 {
		t.Fatalf("reap must keep every live binding; want 2, got %d", c.size())
	}
	if closed != 0 {
		t.Fatalf("reap must not close any still-live transport; closed=%d", closed)
	}
}

// TestSurfaceAReconcileReapsSupersededHTTPClients is the integration
// fail-on-revert: many successive commits that change a provider's source-address
// binding leaf must NOT grow the cache without bound. Each pass builds the
// backend (populating the cache for that binding) then runs a reconcile whose
// catalog references ONLY the current provider, so the prior binding's entry is
// superseded and reaped. Without the reap the map grows by one per pass.
func TestSurfaceAReconcileReapsSupersededHTTPClients(t *testing.T) {
	st, err := loadDDNSState(filepath.Join(t.TempDir(), "interface-ddns-state.json"))
	if err != nil {
		t.Fatalf("loadDDNSState: %v", err)
	}
	m := &SurfaceAManager{
		state:       st,
		runtime:     map[string]*surfaceAState{},
		httpClients: newHTTPClientCache(),
		now:         time.Now,
	}
	m.newBackend = m.resolveBackend

	ctx := context.Background()
	const N = 25
	for i := 0; i < N; i++ {
		src := fmt.Sprintf("192.0.2.%d", i+1)
		p := &config.DDNSProvider{
			Name:        "p",
			Backend:     "generic",
			URLTemplate: "https://example.test/u?ip=%i",
			RFC2136Endpoint: config.RFC2136Endpoint{
				SourceAddress: src,
			},
		}
		// Build the backend for this binding — populates the per-binding cache,
		// exactly as a reconcile pass's resolveBackend would.
		if _, err := m.resolveBackend(p, "h.example.test", 60); err != nil {
			t.Fatalf("resolveBackend pass %d: %v", i, err)
		}
		catalog := map[string]*config.DDNSProvider{"p": p}
		err := m.Reconcile(ctx, nil, func(context.Context, SurfaceAScope) (AddressObservation, bool) {
			return AddressObservation{}, false
		}, nil, catalog)
		if err != nil {
			t.Fatalf("Reconcile pass %d: %v", i, err)
		}
		if got := m.httpClients.size(); got > 2 {
			t.Fatalf("after pass %d the per-binding cache grew to %d — superseded "+
				"transports are not reaped (unbounded under binding churn, #2956)", i, got)
		}
	}
}
