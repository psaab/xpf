package ddns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// backend_dualstack_withdraw_3738_test.go: fail-on-revert proofs for the
// dual-stack same-name withdraw fix (#3738, codex-157 H10/M06). For a dual-stack
// scope (an A and an AAAA at the SAME name through the SAME provider), withdrawing
// ONE family must PRESERVE the sibling. Two backends have only a HOST-granular
// withdraw verb — DuckDNS clear=true (the spec: "ignore all ip's and clear both
// your records") and dyndns2 offline=YES (hostname-level) — so firing that verb
// to drop one family blackholes the sibling. The fix threads a
// LeaseDNSRecord.SiblingFamilyOwned flag (set by the engine from an ownership-store
// scan) that makes those two backends SKIP the destructive verb when a sibling is
// still live. These tests go RED if the guard is reverted (a clear/offline is
// issued while the sibling is owned) or the engine stops setting the flag.

// countingHandler records the DuckDNS-shape requests it sees so a test can assert
// which family params / clears reached the wire.
type dnsReqLog struct {
	mu       sync.Mutex
	ipSet    int // requests carrying ip=
	ipv6Set  int // requests carrying ipv6=
	clears   int // requests carrying clear=true
	offlines int // requests carrying offline=YES
}

func (l *dnsReqLog) handler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		l.mu.Lock()
		if q.Get("ip") != "" {
			l.ipSet++
		}
		if q.Get("ipv6") != "" {
			l.ipv6Set++
		}
		if q.Get("clear") == "true" {
			l.clears++
		}
		if q.Get("offline") == "YES" {
			l.offlines++
		}
		l.mu.Unlock()
		_, _ = w.Write([]byte(body))
	})
}

func (l *dnsReqLog) snapshot() (ip, ipv6, clears, offlines int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ipSet, l.ipv6Set, l.clears, l.offlines
}

// TestDuckDNSWithdrawSiblingProtected is the backend-level proof: DeleteLease with
// SiblingFamilyOwned=true issues NO clear (preserving the live sibling); with the
// flag false it issues clear=true (single-family / full-teardown — the pre-#3738
// behaviour). RED if the guard is removed (a clear fires with the flag set).
func TestDuckDNSWithdrawSiblingProtected(t *testing.T) {
	log := &dnsReqLog{}
	srv := httptest.NewServer(log.handler("OK"))
	defer srv.Close()

	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name: "duck", Backend: "duckdns", Server: srv.URL,
		APIToken: config.NewSecret("tok-abc"),
	}, nil)
	if err != nil {
		t.Fatalf("newDuckDNSBackend: %v", err)
	}

	// Sibling still live → the host-wide clear MUST be suppressed (no wire op).
	rec := hostRecord(t, "home.duckdns.org", "2001:db8::1")
	rec.SiblingFamilyOwned = true
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("DeleteLease (sibling live) should be a no-op success, got %v", err)
	}
	if _, _, clears, _ := log.snapshot(); clears != 0 {
		t.Fatalf("sibling-protected withdraw must issue NO clear=true; saw %d clears", clears)
	}

	// No sibling → the real clear is issued.
	rec2 := hostRecord(t, "home.duckdns.org", "2001:db8::1")
	rec2.SiblingFamilyOwned = false
	if err := b.DeleteLease(context.Background(), rec2); err != nil {
		t.Fatalf("DeleteLease (single family) clear: %v", err)
	}
	if _, _, clears, _ := log.snapshot(); clears != 1 {
		t.Fatalf("single-family withdraw must issue exactly one clear=true; saw %d clears", clears)
	}
}

// TestDyndns2WithdrawSiblingProtected is the backend-level proof for dyndns2: the
// hostname-level offline=YES is suppressed while a sibling is live, and issued for
// a single-family / full teardown. RED if the guard is removed.
func TestDyndns2WithdrawSiblingProtected(t *testing.T) {
	log := &dnsReqLog{}
	srv := httptest.NewServer(log.handler("good 203.0.113.5\n"))
	defer srv.Close()

	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "dd2", Backend: "dyndns2", Server: srv.URL,
		Username: "u", Password: config.NewSecret("p"),
	}, nil)
	if err != nil {
		t.Fatalf("newDyndns2Backend: %v", err)
	}

	rec := hostRecord(t, "wan.example.net", "2001:db8::1")
	rec.SiblingFamilyOwned = true
	if err := b.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("DeleteLease (sibling live) should be a no-op success, got %v", err)
	}
	if _, _, _, offlines := log.snapshot(); offlines != 0 {
		t.Fatalf("sibling-protected withdraw must issue NO offline=YES; saw %d offlines", offlines)
	}

	rec2 := hostRecord(t, "wan.example.net", "203.0.113.5")
	rec2.SiblingFamilyOwned = false
	if err := b.DeleteLease(context.Background(), rec2); err != nil {
		t.Fatalf("DeleteLease (single family) offline: %v", err)
	}
	if _, _, _, offlines := log.snapshot(); offlines != 1 {
		t.Fatalf("single-family withdraw must issue exactly one offline=YES; saw %d offlines", offlines)
	}
}

// dualStackObserver returns a v4 address for a v4 scope and a v6 address for a v6
// scope, or an INVALID address for whichever family is named in `lost` (an
// address-loss withdraw).
func dualStackObserver(v4, v6 string, lost Family) AddressObserver {
	a4 := netip.MustParseAddr(v4)
	a6 := netip.MustParseAddr(v6)
	return func(_ context.Context, sc SurfaceAScope) (AddressObservation, bool) {
		if sc.Key.Family == lost {
			return AddressObservation{}, true // valid observation, no address → withdraw
		}
		if sc.Key.Family == FamilyV6 {
			return AddressObservation{Addr: a6, Source: AddressSourceInterface}, true
		}
		return AddressObservation{Addr: a4, Source: AddressSourceInterface}, true
	}
}

func duckScope(fqdn string, family Family, serverURL string) SurfaceAScope {
	return SurfaceAScope{
		Key: ScopeKey{
			Family: family, Interface: "ge-0-0-2", Unit: 50, RGOwner: 0,
			PolicyID: "duck",
		},
		FQDN:   fqdn,
		TTL:    300,
		Source: AddressSourceInterface,
		Provider: &config.DDNSProvider{
			Name: "duck", Backend: "duckdns", Server: serverURL,
			APIToken: config.NewSecret("tok-abc"),
		},
	}
}

// TestSurfaceADuckDNSDualStackWithdrawPreservesSibling drives the FULL engine
// through a real DuckDNS backend (httptest): publish an A + an AAAA at the same
// duckdns name, lose the v6 address, and assert NO clear=true reached the wire
// (the live A is preserved) — then a full teardown of the surviving A DOES issue
// clear=true. RED on revert (the v6 loss would clear=true and blackhole the A).
func TestSurfaceADuckDNSDualStackWithdrawPreservesSibling(t *testing.T) {
	log := &dnsReqLog{}
	srv := httptest.NewServer(log.handler("OK"))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0)
	m := newHTTPEngineManager(t, func() time.Time { return now })

	scV4 := duckScope("home.duckdns.org", FamilyV4, srv.URL)
	scV6 := duckScope("home.duckdns.org", FamilyV6, srv.URL)
	both := []SurfaceAScope{scV4, scV6}

	// Publish both families.
	pubObs := dualStackObserver("203.0.113.7", "2001:db8::1", 0)
	if err := m.Reconcile(context.Background(), both, pubObs, nil, nil); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if ip, ipv6, clears, _ := log.snapshot(); ip != 1 || ipv6 != 1 || clears != 0 {
		t.Fatalf("publish should set A + AAAA and no clear; ip=%d ipv6=%d clears=%d", ip, ipv6, clears)
	}

	// Lose the v6 address while v4 stays live. The v6 withdraw must NOT clear
	// (the sibling A is still owned) — the fix preserves the A.
	now = now.Add(time.Minute)
	lostV6 := dualStackObserver("203.0.113.7", "2001:db8::1", FamilyV6)
	if err := m.Reconcile(context.Background(), both, lostV6, nil, nil); err != nil {
		t.Fatalf("v6-loss reconcile: %v", err)
	}
	if _, _, clears, _ := log.snapshot(); clears != 0 {
		t.Fatalf("dual-stack v6 loss must NOT clear (would blackhole the live A); saw %d clears", clears)
	}
	// v4 ownership survives, v6 ownership was dropped.
	if _, ok := m.state.get(scV4.effectiveKey(), surfaceAIdentity, ""); !ok {
		t.Fatalf("the still-live v4 record must remain owned after a v6 withdraw")
	}
	if _, ok := m.state.get(scV6.effectiveKey(), surfaceAIdentity, ""); ok {
		t.Fatalf("the withdrawn v6 record's ownership must be dropped")
	}

	// Full teardown of the surviving v4 (binding removed): with no sibling left,
	// the real clear=true fires and cleans the name.
	now = now.Add(time.Minute)
	catalog := map[string]*config.DDNSProvider{"duck": scV4.Provider}
	if err := m.Reconcile(context.Background(), nil, pubObs, nil, catalog); err != nil {
		t.Fatalf("full teardown reconcile: %v", err)
	}
	if _, _, clears, _ := log.snapshot(); clears != 1 {
		t.Fatalf("last-family teardown must issue exactly one clear=true; saw %d clears", clears)
	}
	if _, ok := m.state.get(scV4.effectiveKey(), surfaceAIdentity, ""); ok {
		t.Fatalf("v4 ownership must be dropped after the full teardown clear")
	}
}

// TestSurfaceAEngineSetsSiblingFlag proves the ENGINE sets SiblingFamilyOwned
// correctly (independent of the backend): a dual-stack withdraw flags the sibling;
// a single-family withdraw and a full-teardown last-family withdraw do NOT. This
// is what makes the DuckDNS/dyndns2 guard fire. RED if withdrawOwnedLocked stops
// scanning for a sibling.
func TestSurfaceAEngineSetsSiblingFlag(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	scV4 := surfaceAScope("home.example.net", FamilyV4, 0)
	scV6 := surfaceAScope("home.example.net", FamilyV6, 0)
	obs := dualStackObserver("203.0.113.7", "2001:db8::1", 0)

	// Publish both families.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scV4, scV6}, obs, nil, nil); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Withdraw ONLY the v6 binding (v4 still configured + owned) → the recorded
	// delete must carry SiblingFamilyOwned=true.
	now = now.Add(time.Minute)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136"}}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scV4}, obs, nil, catalog); err != nil {
		t.Fatalf("v6 teardown: %v", err)
	}
	del := lastDelete(t, fu)
	if del.ForwardType != "AAAA" {
		t.Fatalf("expected the AAAA to be withdrawn, got %q", del.ForwardType)
	}
	if !del.SiblingFamilyOwned {
		t.Fatalf("a dual-stack same-name withdraw must set SiblingFamilyOwned (the v4 sibling is still owned)")
	}

	// Full teardown of the surviving v4 → no sibling left → flag false.
	now = now.Add(time.Minute)
	if err := m.Reconcile(context.Background(), nil, obs, nil, catalog); err != nil {
		t.Fatalf("full teardown: %v", err)
	}
	del = lastDelete(t, fu)
	if del.ForwardType != "A" {
		t.Fatalf("expected the A to be withdrawn last, got %q", del.ForwardType)
	}
	if del.SiblingFamilyOwned {
		t.Fatalf("the last-family withdraw must NOT set SiblingFamilyOwned (no sibling remains)")
	}
}

// TestSurfaceASingleFamilyWithdrawNoSiblingFlag proves a NON-dual-stack scope's
// withdraw never flags a sibling (so its clear/offline still fires normally).
func TestSurfaceASingleFamilyWithdrawNoSiblingFlag(t *testing.T) {
	fu := newFakeUpdater()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceATestManager(t, fu, func() time.Time { return now })

	scV4 := surfaceAScope("solo.example.net", FamilyV4, 0)
	obs := fixedObserver("203.0.113.7")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scV4}, obs, nil, nil); err != nil {
		t.Fatalf("publish: %v", err)
	}
	now = now.Add(time.Minute)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136"}}
	if err := m.Reconcile(context.Background(), nil, obs, nil, catalog); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	del := lastDelete(t, fu)
	if del.SiblingFamilyOwned {
		t.Fatalf("a single-family scope withdraw must NOT set SiblingFamilyOwned")
	}
}

// lastDelete returns the most recently recorded DeleteLease record.
func lastDelete(t *testing.T, fu *fakeUpdater) LeaseDNSRecord {
	t.Helper()
	fu.mu.Lock()
	defer fu.mu.Unlock()
	if len(fu.deletes) == 0 {
		t.Fatalf("no DeleteLease was recorded")
	}
	return fu.deletes[len(fu.deletes)-1]
}
