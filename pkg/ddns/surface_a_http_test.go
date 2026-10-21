package ddns

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"github.com/psaab/xpf/pkg/config"
)

// surface_a_http_test.go: end-to-end engine-through-HTTP-backend tests (#2691
// P3). These drive the REAL SurfaceAManager (change-detection / forced-refresh /
// backoff / per-RG gate) through the REAL productionSurfaceABackend resolver and
// a REAL dyndns2 backend pointed at an httptest server — the full publish path,
// no fakeUpdater shortcut. This is the integration proof the plan requires: the
// engine drives the right HTTP calls, change-detection skips a no-change, and a
// backend error arms the engine backoff.

// httpScope builds a Surface A scope bound to a dyndns2 provider whose Server is
// the mock endpoint.
func httpScope(fqdn, serverURL string) SurfaceAScope {
	return SurfaceAScope{
		Key: ScopeKey{
			Family: FamilyV4, Interface: "ge-0-0-2", Unit: 50, RGOwner: 0,
			PolicyID: "dd2",
		},
		FQDN:   fqdn,
		TTL:    300,
		Source: AddressSourceInterface,
		Provider: &config.DDNSProvider{
			Name: "dd2", Backend: "dyndns2", Server: serverURL,
			Username: "u", Password: config.NewSecret("p"),
		},
	}
}

// newHTTPEngineManager builds a SurfaceAManager wired to the PRODUCTION backend
// factory (so the engine resolves a real dyndns2 backend per scope).
func newHTTPEngineManager(t *testing.T, now func() time.Time) *SurfaceAManager {
	t.Helper()
	st, _ := loadDDNSState(filepath.Join(t.TempDir(), "iface-ddns.json"))
	m := &SurfaceAManager{
		state:      st,
		runtime:    map[string]*surfaceAState{},
		newBackend: productionSurfaceABackend,
		now:        now,
	}
	m.seedFromStore()
	return m
}

type dyndns2Counter struct {
	mu     sync.Mutex
	calls  int
	lastIP string
	fail   bool
}

func (c *dyndns2Counter) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.calls++
		c.lastIP = r.URL.Query().Get("myip")
		fail := c.fail
		c.mu.Unlock()
		if fail {
			_, _ = w.Write([]byte("911\n"))
			return
		}
		_, _ = w.Write([]byte("good " + r.URL.Query().Get("myip") + "\n"))
	})
}

func TestEngineThroughDyndns2PublishAndSkip(t *testing.T) {
	cnt := &dyndns2Counter{}
	srv := httptest.NewServer(cnt.handler())
	defer srv.Close()
	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })
	sc := httpScope("wan.example.net", srv.URL)

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("publish: %v", err)
	}
	cnt.mu.Lock()
	calls, ip := cnt.calls, cnt.lastIP
	cnt.mu.Unlock()
	if calls != 1 || ip != "203.0.113.5" {
		t.Fatalf("expected one publish of 203.0.113.5, got calls=%d ip=%q", calls, ip)
	}
	// Second pass, unchanged, within forced-refresh: change-detection must SKIP
	// the wire call (no new HTTP request).
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("skip pass: %v", err)
	}
	cnt.mu.Lock()
	calls = cnt.calls
	cnt.mu.Unlock()
	if calls != 1 {
		t.Fatalf("unchanged address must not re-hit the provider; calls=%d", calls)
	}
	// Address change → a new wire publish.
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.9"), nil, nil); err != nil {
		t.Fatalf("change publish: %v", err)
	}
	cnt.mu.Lock()
	calls, ip = cnt.calls, cnt.lastIP
	cnt.mu.Unlock()
	if calls != 2 || ip != "203.0.113.9" {
		t.Fatalf("address change must republish; calls=%d ip=%q", calls, ip)
	}
}

func TestEngineThroughDyndns2BackoffOnError(t *testing.T) {
	cnt := &dyndns2Counter{fail: true}
	srv := httptest.NewServer(cnt.handler())
	defer srv.Close()
	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })
	sc := httpScope("wan.example.net", srv.URL)

	// First pass: the provider returns 911 → publish error → engine arms backoff.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil); err == nil {
		t.Fatal("expected a publish error from the 911 response")
	}
	cnt.mu.Lock()
	c1 := cnt.calls
	cnt.mu.Unlock()
	// Immediate retry inside the backoff window: the scope is skipped (no wire
	// call) — ban-avoidance.
	now = now.Add(time.Second)
	_ = m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil)
	cnt.mu.Lock()
	c2 := cnt.calls
	cnt.mu.Unlock()
	if c2 != c1 {
		t.Fatalf("scope in backoff must not hit the provider again; calls %d -> %d", c1, c2)
	}
	if st := m.Stats(); st.BackedOff < 1 {
		t.Fatalf("expected a backed-off skip, got %+v", st)
	}
}

// TestEngineSecretsNeverLogged asserts the credential-handling invariant
// (plan §8.1): a provider's password/token is never present in the catalog
// entry's String() (used by %v/slog) nor in any error the publish path returns.
func TestEngineSecretsNeverLogged(t *testing.T) {
	const secret = "SUPER-SECRET-TOKEN-9f3a"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a hard auth failure so the publish errors — the error must not
		// echo the password.
		_, _ = w.Write([]byte("badauth\n"))
	}))
	defer srv.Close()

	prov := &config.DDNSProvider{
		Name: "dd2", Backend: "dyndns2", Server: srv.URL,
		Username: "u", Password: config.NewSecret(secret),
		APIToken: config.NewSecret(secret), AWSSecretAccessKey: config.NewSecret(secret),
		TSIGSecret: config.NewSecret(secret),
	}
	// String()/slog formatting must redact every secret.
	if s := prov.String(); strings.Contains(s, secret) {
		t.Fatalf("DDNSProvider.String() leaked a secret: %q", s)
	}

	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })
	sc := httpScope("wan.example.net", srv.URL)
	sc.Provider = prov
	sc.Key.PolicyID = "dd2"

	err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, nil)
	if err == nil {
		t.Fatal("expected a badauth publish error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("publish error leaked the secret: %q", err.Error())
	}
}

// TestHTTPBackendErrorsNeverLeakSecret exercises the error path of every HTTP
// backend (generic %p-in-URL, cloudflare token, route53 secret key) and asserts
// no secret reaches the returned error. The generic backend is the highest-risk
// (the password is rendered into the query) so it is tested through a failing
// transport AND a malformed-URL render (#2691 P3 review MINOR).
func TestHTTPBackendErrorsNeverLeakSecret(t *testing.T) {
	const secret = "LEAK-CANARY-7c1d"

	t.Run("generic-transport-error", func(t *testing.T) {
		// A closed server makes the request a transport error whose *url.Error
		// embeds the full URL+query (the %p-expanded password).
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		closedURL := srv.URL
		srv.Close()
		b, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic",
			URLTemplate: closedURL + "/u?h=%h&i=%i&p=%p",
			Password:    config.NewSecret(secret),
		}, nil)
		if err != nil {
			t.Fatalf("newGenericBackend: %v", err)
		}
		err = b.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "93.184.216.34"))
		if err == nil {
			t.Fatal("expected a transport error against the closed server")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("generic transport error leaked the %%p password: %q", err.Error())
		}
	})

	t.Run("generic-malformed-url", func(t *testing.T) {
		// A control byte in the password makes the rendered URL unparseable,
		// hitting the build-request error path — which must not echo the secret.
		b, err := newGenericBackend(&config.DDNSProvider{
			Name: "g", Backend: "generic",
			URLTemplate: "https://x/u?p=%p",
			Password:    config.NewSecret("\x7f" + secret),
		}, nil)
		if err != nil {
			t.Fatalf("newGenericBackend: %v", err)
		}
		err = b.UpsertLease(context.Background(), hostRecord(t, "h.example.net", "93.184.216.34"))
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Fatalf("generic malformed-url error leaked the password: %q", err.Error())
		}
	})

	t.Run("cloudflare-auth-error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()
		b, err := newCloudflareBackend(&config.DDNSProvider{
			Name: "cf", Backend: "cloudflare", APIToken: config.NewSecret(secret),
			Zone: "example.net", Server: srv.URL,
		}, nil)
		if err != nil {
			t.Fatalf("newCloudflareBackend: %v", err)
		}
		err = b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "93.184.216.34"))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("cloudflare error must be non-nil and not leak the token: %v", err)
		}
	})

	t.Run("route53-error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><ErrorResponse><Error><Code>AccessDenied</Code><Message>x</Message></Error></ErrorResponse>`))
		}))
		defer srv.Close()
		b, err := newRoute53Backend(&config.DDNSProvider{
			Name: "r53", Backend: "route53",
			AWSAccessKeyID: "AKID", AWSSecretAccessKey: config.NewSecret(secret),
			AWSRegion: "us-east-1", HostedZoneID: "Z123", Server: srv.URL,
		}, nil)
		if err != nil {
			t.Fatalf("newRoute53Backend: %v", err)
		}
		err = b.UpsertLease(context.Background(), hostRecord(t, "wan.example.net", "93.184.216.34"))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("route53 error must be non-nil and not leak the secret key: %v", err)
		}
	})
}

// TestEngineNoBackendNoPhantomOwnership is the fail-on-revert proof for the
// #2691 P3 review MAJOR: an HTTP provider whose constructor errors on a missing
// credential degrades to the no-op backend, and a publish through it must NOT
// count an upsertOK, must NOT record (phantom) ownership, and must NOT advance
// the last-published cache (so it re-attempts every cycle once the credential is
// added). Reverting the isNopUpdater guard in publishLocked turns this RED.
func TestEngineNoBackendNoPhantomOwnership(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })

	// cloudflare with NO api-token / NO zone → newCloudflareBackend errors →
	// newSurfaceAHTTP degrades to nopUpdater{}.
	sc := SurfaceAScope{
		Key:      ScopeKey{Family: FamilyV4, Interface: "ge-0-0-2", Unit: 50, PolicyID: "cf"},
		FQDN:     "wan.example.net",
		TTL:      300,
		Source:   AddressSourceInterface,
		Provider: &config.DDNSProvider{Name: "cf", Backend: "cloudflare"}, // missing creds
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("93.184.216.34"), nil, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	st := m.Stats()
	if st.UpsertOK != 0 {
		t.Fatalf("a no-backend publish must NOT count an upsertOK; got %d", st.UpsertOK)
	}
	if st.SkippedNoBackend != 1 {
		t.Fatalf("expected one no-backend skip, got %+v", st)
	}
	if st.Scopes != 0 {
		t.Fatalf("a no-backend publish must NOT record (phantom) ownership; got %d owned records", st.Scopes)
	}
	// rt.lastAddr must NOT be set → a second pass re-attempts.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("93.184.216.34"), nil, nil); err != nil {
		t.Fatalf("Reconcile2: %v", err)
	}
	if st2 := m.Stats(); st2.SkippedNoBackend != 2 {
		t.Fatalf("a no-backend scope must re-attempt every cycle; got SkippedNoBackend=%d", st2.SkippedNoBackend)
	}
}

// TestStatusViewsSurfacesUnpublishedScopes is the #2843 fail-on-revert proof: a
// CONFIGURED scope that has never successfully published — because its provider
// resolved to the no-op backend (errSurfaceANoBackend) — MUST appear in
// StatusViews with the unpublished state and its no-backend reason, NOT be
// silently omitted. Reverting StatusViews to iterate the ownership records only
// (the pre-#2843 behavior) turns this RED: the no-backend scope has no ownership
// record, so it would not appear at all.
func TestStatusViewsSurfacesUnpublishedScopes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })

	// cloudflare with NO credentials → no-op backend → never publishes.
	noBackend := SurfaceAScope{
		Key:      ScopeKey{Family: FamilyV4, Interface: "ge-0-0-2", Unit: 50, PolicyID: "cf"},
		FQDN:     "broken.example.net",
		TTL:      300,
		Source:   AddressSourceInterface,
		Provider: &config.DDNSProvider{Name: "cf", Backend: "cloudflare"}, // missing creds
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{noBackend}, fixedObserver("93.184.216.34"), nil, nil); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The status MUST contain the configured-but-unpublished scope even though it
	// owns no record.
	views := m.StatusViews([]SurfaceAScope{noBackend})
	if len(views) != 1 {
		t.Fatalf("a configured scope with no ownership record must still appear; got %d views: %+v", len(views), views)
	}
	v := views[0]
	if v.FQDN != "broken.example.net" || v.Provider != "cf" || v.Interface != "ge-0-0-2" {
		t.Fatalf("unpublished status view identity mismatch: %+v", v)
	}
	if v.State != SurfaceAStateUnpublished {
		t.Fatalf("a no-backend scope must report state %q, got %q", SurfaceAStateUnpublished, v.State)
	}
	if v.Published != "" {
		t.Fatalf("a never-published scope must show no published address, got %q", v.Published)
	}
	if v.LastError == "" {
		t.Fatalf("an unpublished (no-backend) scope must carry a reason in LastError")
	}
}

// TestStatusViewsSurfacesPendingAndPublished proves the other configured-scope
// states: a scope still waiting on an address observation is `pending`, and a
// scope that successfully published is `published`. Mixed with a no-longer-
// configured owned record (withdraw-pending), it confirms StatusViews is the
// union of configured scopes + orphaned ownership, stably ordered.
func TestStatusViewsSurfacesPendingAndPublished(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	published := surfaceAScope("aaa.example.net", FamilyV4, 0)
	if err := m.Reconcile(context.Background(), []SurfaceAScope{published}, fixedObserver("203.0.113.5"), nil, nil); err != nil {
		t.Fatalf("Reconcile published: %v", err)
	}

	// A second, distinct configured scope whose address cannot be observed this
	// cycle (interface still coming up) → no ownership, no error → pending.
	pending := SurfaceAScope{
		Key:    ScopeKey{Family: FamilyV4, Interface: "ge-0-0-3", Unit: 0, PolicyID: "corp-2136"},
		FQDN:   "bbb.example.net",
		TTL:    300,
		Source: AddressSourceDHCP,
	}
	noObserve := func(context.Context, SurfaceAScope) (AddressObservation, bool) { return AddressObservation{}, false }
	if err := m.Reconcile(context.Background(), []SurfaceAScope{published, pending}, noObserve, nil, nil); err != nil {
		t.Fatalf("Reconcile pending: %v", err)
	}

	views := m.StatusViews([]SurfaceAScope{published, pending})
	byFQDN := map[string]SurfaceAStatusView{}
	for _, v := range views {
		byFQDN[v.FQDN] = v
	}
	if got := byFQDN["aaa.example.net"].State; got != SurfaceAStatePublished {
		t.Fatalf("published scope state = %q, want %q", got, SurfaceAStatePublished)
	}
	if got := byFQDN["bbb.example.net"].State; got != SurfaceAStatePending {
		t.Fatalf("never-observed scope state = %q, want %q", got, SurfaceAStatePending)
	}

	// Drop the published scope from config → its owned record is now orphaned.
	// StatusViews (called with only the pending scope configured) must surface the
	// orphan as withdraw-pending, not omit it.
	orphanViews := m.StatusViews([]SurfaceAScope{pending})
	var sawOrphan bool
	for _, v := range orphanViews {
		if v.FQDN == "aaa.example.net" {
			sawOrphan = true
			if v.State != SurfaceAStateWithdrawPending {
				t.Fatalf("orphaned ownership state = %q, want %q", v.State, SurfaceAStateWithdrawPending)
			}
		}
	}
	if !sawOrphan {
		t.Fatalf("an owned record for a no-longer-configured scope must appear as withdraw-pending; views=%+v", orphanViews)
	}
}
