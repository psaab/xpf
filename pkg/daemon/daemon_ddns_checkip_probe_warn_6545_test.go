package daemon

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
)

// daemon_ddns_checkip_probe_warn_6545_test.go: the checkip probe must not fail
// SILENTLY (#6545 review MINOR-3).
//
// ddns.CheckIP used to collapse every failure into a bare ok=false, and this
// observer mapped ok=false to an empty observation with no log line at all. A
// checkip-url that is malformed, unreachable, non-2xx, or (since #6545)
// redirects cross-host therefore became an indistinguishable, PERMANENT
// "transient observation failure": publishing stops forever and the operator
// gets zero diagnostic. That is the failure class #2773/#3737 were filed to
// eliminate, and it contradicts this package's own doctrine — pkg/ddns states at
// validateCheckIPURL that "a malformed URL is a configuration error, not a
// transient" — while the publish path surfaces the same causes by name.
//
// CheckIP/CheckIPBound now return the reason and this observer logs it once per
// (provider, error), mirroring checkIPSourceBindWarned.

// checkIPWarnMsg is the exact line the observer emits. Kept as a constant so the
// assertions below break loudly if the message is reworded rather than silently
// counting zero.
const checkIPWarnMsg = "ddns surface-a: checkip probe failed; no address observed " +
	"(publishing is suppressed until it succeeds)"

// newCheckIPObserverDaemon builds the minimal Daemon the Surface A observer
// needs: a real SurfaceAManager (CheckIPClient dereferences its client cache) and
// nothing else. No network, no state writes — NewSurfaceAManager only READS its
// durable store, and a missing store is the clean-empty case.
func newCheckIPObserverDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{}
	d.surfaceA.mgr = ddns.NewSurfaceAManager()
	return d
}

func checkIPScope(provider *config.DDNSProvider) ddns.SurfaceAScope {
	return ddns.SurfaceAScope{
		Key:      ddns.ScopeKey{Family: ddns.FamilyV4, Interface: "ge-0/0/0", Unit: 0},
		FQDN:     "wan.example.net",
		Source:   ddns.AddressSourceCheckIP,
		Provider: provider,
	}
}

// captureWarnings installs a recording slog handler for the duration of the test
// and returns it.
func captureWarnings(t *testing.T) *recordingSlogHandler {
	t.Helper()
	rec := &recordingSlogHandler{level: slog.LevelWarn}
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return rec
}

// TestCheckIPProbeFailureIsWarnedOnce is the fail-on-revert gate for the daemon
// half: a failing checkip probe must produce EXACTLY ONE operator-visible
// warning, no matter how many reconcile passes hit it.
//
// The driver is a malformed checkip-url (ftp://), which ddns.CheckIP rejects
// before any transport is touched — hermetic, and a genuine permanent
// configuration error of the same class as a cross-host-redirecting endpoint.
//
// RED on revert in TWO directions, both by assertion:
//   - drop the warn (or drop the error return that feeds it) and the count is 0
//     ("logged 0 times ... a permanently misconfigured checkip-url is invisible")
//   - drop the LoadOrStore dedup and the count is 3 (one line per poll tick,
//     which is why the existing sibling warnings are deduped at all)
func TestCheckIPProbeFailureIsWarnedOnce(t *testing.T) {
	rec := captureWarnings(t)
	d := newCheckIPObserverDaemon(t)
	obs := d.surfaceAObserver(&config.Config{})
	scope := checkIPScope(&config.DDNSProvider{
		Name:       "badprov",
		Backend:    "duckdns",
		CheckIPURL: "ftp://checkip.example/",
	})

	const passes = 3
	for i := 0; i < passes; i++ {
		if _, ok := obs(context.Background(), scope); ok {
			t.Fatalf("pass %d: a malformed checkip-url must not yield an observation", i)
		}
	}

	switch n := rec.count(checkIPWarnMsg); n {
	case 1: // exactly right
	case 0:
		t.Fatalf("a failing checkip probe logged 0 times over %d passes: a permanently "+
			"misconfigured checkip-url is invisible to the operator — publishing stops "+
			"with no stated reason, forever (#2773/#3737 class)", passes)
	default:
		t.Fatalf("a failing checkip probe logged %d times over %d passes; the "+
			"once-per-(provider,error) dedup is gone and the observer will flood "+
			"the journal every poll tick", n, passes)
	}
}

// TestCheckIPProbeWarnReArmsOnDifferentError proves the dedup key includes the
// ERROR, not just the provider: a provider whose failure CHANGES (e.g. the
// operator fixes the URL scheme and the endpoint then refuses the redirect) must
// surface the new reason rather than staying muted behind the first one.
func TestCheckIPProbeWarnReArmsOnDifferentError(t *testing.T) {
	rec := captureWarnings(t)
	d := newCheckIPObserverDaemon(t)
	obs := d.surfaceAObserver(&config.Config{})

	p := &config.DDNSProvider{Name: "prov", Backend: "duckdns", CheckIPURL: "ftp://checkip.example/"}
	if _, ok := obs(context.Background(), checkIPScope(p)); ok {
		t.Fatal("malformed checkip-url must not yield an observation")
	}
	// Same provider name, a DIFFERENT failure reason (host-less https: the
	// scheme is now valid, the missing host is the distinct refusal).
	p2 := &config.DDNSProvider{Name: "prov", Backend: "duckdns", CheckIPURL: "https://"}
	if _, ok := obs(context.Background(), checkIPScope(p2)); ok {
		t.Fatal("host-less checkip-url must not yield an observation")
	}

	if n := rec.count(checkIPWarnMsg); n != 2 {
		t.Fatalf("two DIFFERENT checkip failures for one provider logged %d time(s), want 2; "+
			"a changed failure reason must re-arm the warning, not stay muted behind the first", n)
	}
}

// #14372 (fixture F-DR3-H5-3): a Surface A scope over a plaintext http
// checkip-url publishes NOTHING. The plaintext server answers an attacker
// public IP; on the buggy tree the observer would return it and Surface A
// would publish it as the firewall's FQDN. With the runtime https backstop
// the probe fails closed (transient miss, never a withdraw) and the server
// is never contacted.
func TestCheckIPPlaintextPublishesNothing(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("93.184.216.34\n"))
	}))
	defer srv.Close()

	rec := captureWarnings(t)
	d := newCheckIPObserverDaemon(t)
	obs := d.surfaceAObserver(&config.Config{})
	scope := checkIPScope(&config.DDNSProvider{
		Name: "httpprov", Backend: "duckdns", CheckIPURL: srv.URL,
	})
	if _, ok := obs(context.Background(), scope); ok {
		t.Fatal("a plaintext http checkip scope yielded an observation; a spoofed " +
			"response would control the published DNS record (#14372)")
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("plaintext checkip endpoint contacted %d time(s); the probe must refuse before any fetch", n)
	}
	if n := rec.count(checkIPWarnMsg); n != 1 {
		t.Fatalf("plaintext checkip failure warned %d time(s), want 1 (the refusal must be operator-visible)", n)
	}
}

// TestCheckIPNoAddressDoesNotWarn is the over-reach guard. An endpoint that
// ANSWERS but carries no address of the requested family is the ordinary
// dual-stack miss (a v4-only checkip service probed for AAAA) — it happens on
// every pass for every v6-less deployment and must stay SILENT. Warning on it
// would trade one silent failure for a permanent stream of false alarms.
func TestCheckIPNoAddressDoesNotWarn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A valid 200 with a v4 address and no v6 one.
		_, _ = w.Write([]byte("93.184.216.34\n"))
	}))
	defer srv.Close()

	rec := captureWarnings(t)
	d := newCheckIPObserverDaemon(t)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	d.surfaceA.mgr.SetCheckIPRootCAsForTesting(pool)
	obs := d.surfaceAObserver(&config.Config{})
	scope := checkIPScope(&config.DDNSProvider{
		Name: "goodprov", Backend: "duckdns", CheckIPURL: srv.URL,
	})
	// Probe the V6 family against a v4-only body: a legitimate miss.
	scope.Key.Family = ddns.FamilyV6

	if _, ok := obs(context.Background(), scope); ok {
		t.Fatal("a v4-only checkip body must not yield a v6 observation")
	}
	if n := rec.count(checkIPWarnMsg); n != 0 {
		t.Fatalf("an ordinary no-address-of-this-family miss warned %d time(s); it is the "+
			"normal dual-stack case and must stay silent, or every v6-less deployment "+
			"logs a false alarm", n)
	}

	// Same endpoint, the family it CAN answer: still no warning, and a real
	// observation — proof the harness reaches the server at all, so the zero
	// above is not a vacuous pass.
	scope.Key.Family = ddns.FamilyV4
	obsv, ok := obs(context.Background(), scope)
	if !ok || obsv.Addr.String() != "93.184.216.34" {
		t.Fatalf("v4 probe = %v ok=%v, want 93.184.216.34 true (the harness must actually "+
			"reach the checkip endpoint)", obsv.Addr, ok)
	}
	if n := rec.count(checkIPWarnMsg); n != 0 {
		t.Fatalf("a SUCCESSFUL checkip probe warned %d time(s)", n)
	}
}
