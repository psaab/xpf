package ddns

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// #2691 P2 Surface A tests THROUGH THE REAL rfc2136 backend against the stateful
// in-process fake DNS server (the same harness backend_rfc2136_test.go uses).
//
// These exist because the fakeUpdater-based engine tests CANNOT catch the two
// production-path bugs the P2 review found: (MAJOR-1) a self-owned record could
// never be updated because the no-DHCID replace-owned path refuses a pre-
// existing name, and (MAJOR-2) withdraw never reached the wire because the
// withdraw helper ignored the newBackend factory. fakeUpdater appends on any
// UpsertLease and does not model RFC 2136 prerequisites OR the production
// newBackend wiring, so it passed while production did the wrong thing. The
// tests below drive the REAL rfc2136 backend (self-owned mode) and assert the
// actual ZONE STATE + the actual wire DELETE, with PRODUCTION wiring (newBackend
// set, m.backend nil).

// newSurfaceAManagerRealBackend builds a Surface A manager wired EXACTLY like
// production: the newBackend factory resolves the live rfc2136 self-owned
// backend (pointed at srv), and the static m.backend is left NIL. This is the
// wiring that exposes MAJOR-2 (a nil m.backend made the old backendForOwned
// always no-op the withdraw).
func newSurfaceAManagerRealBackend(t *testing.T, srv *fakeDNSServer) *SurfaceAManager {
	t.Helper()
	dir := t.TempDir()
	st, _ := loadDDNSState(filepath.Join(dir, "iface-ddns.json"))
	m := &SurfaceAManager{
		state:   st,
		runtime: map[string]*surfaceAState{},
		now:     func() time.Time { return time.Unix(1_700_000_000, 0) },
		// PRODUCTION WIRING: only newBackend is set; backend stays nil.
		newBackend: func(p *config.DDNSProvider, fqdn string, ttl int) (DNSUpdater, error) {
			c := &config.DHCPDynamicDNSConfig{RFC2136Endpoint: config.RFC2136Endpoint{UpdateServer: srv.addrUDP}}
			pol := ddnsPolicy{conflictPolicy: "replace-owned", backend: "rfc2136"}
			u, err := newRFC2136Updater(pol, c.RFC2136Endpoint, nil, nil, nil)
			if err != nil {
				return nil, err
			}
			u.selfOwned = true
			if cl, ok := u.client.(*dns.Client); ok {
				cl.Timeout = 3 * time.Second
			}
			return u, nil
		},
	}
	return m
}

func realScope(fqdn string) SurfaceAScope {
	return SurfaceAScope{
		Key:    ScopeKey{Family: FamilyV4, Interface: "ge-0-0-2", Unit: 50, PolicyID: "corp-2136"},
		FQDN:   fqdn,
		TTL:    300,
		Source: AddressSourceInterface,
		// Provider non-nil so backendFor's newBackend factory is exercised.
		Provider: &config.DDNSProvider{Name: "corp-2136", Backend: "rfc2136"},
	}
}

func aRR(fqdn, addr string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(fqdn), Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   net.ParseIP(addr),
	}
}

// MAJOR-1: an address change must update the zone (B replaces A), and a
// same-address forced-refresh of an existing name must SUCCEED (not be refused).
func TestSurfaceARealBackendReplacesOnAddressChange(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := newSurfaceAManagerRealBackend(t, srv)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136", Backend: "rfc2136"}}
	sc := realScope("wan.example.net")

	// Publish A.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if !srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("after first publish the zone must hold A=203.0.113.5")
	}

	// Change to B — through the REAL backend this is the path MAJOR-1 broke
	// (NameNotUsed would refuse the pre-existing name). The zone must now hold B
	// and NOT A (atomic in-place replace, no blackhole).
	m.now = func() time.Time { return time.Unix(1_700_000_060, 0) }
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.9"), nil, catalog); err != nil {
		t.Fatalf("change to B: %v (MAJOR-1: self-owned replace must succeed on a pre-existing name)", err)
	}
	if !srv.zoneHas(aRR("wan.example.net", "203.0.113.9")) {
		t.Fatal("after address change the zone must hold the NEW address B=203.0.113.9")
	}
	if srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("after address change the OLD address A=203.0.113.5 must be gone (in-place replace)")
	}
	if st := m.Stats(); st.UpsertFail != 0 {
		t.Fatalf("no publish should have failed; got UpsertFail=%d", st.UpsertFail)
	}
}

// #3739 (M08): a co-resident FOREIGN A at the self-owned name must SURVIVE both
// the first publish and a later renumber. The old sendAddSelfOwned did a
// delete-RRset (CLASS=ANY) of the whole A set before inserting, destroying any
// foreign value; the value-specific replace now removes ONLY xpf's own prior
// rdata (exact-RR delete) so the foreign record is never collateral. Reverting
// sendAddSelfOwned to RemoveRRset makes the first zoneHas(foreign) assertion RED
// (the foreign A is wiped on the first publish).
func TestSurfaceARealBackendPreservesForeignRecord(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := newSurfaceAManagerRealBackend(t, srv)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136", Backend: "rfc2136"}}
	sc := realScope("wan.example.net")

	// A human/other appliance already published a FOREIGN A at the shared name.
	const foreign = "198.51.100.20"
	srv.seedRR(aRR("wan.example.net", foreign))

	// First publish (no prior xpf value ⇒ Insert-only, additive): xpf's A must
	// coexist with the foreign one — neither is destroyed.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if !srv.zoneHas(aRR("wan.example.net", foreign)) {
		t.Fatal("M08: a co-resident FOREIGN A must survive xpf's first publish (Insert-only, not delete-RRset)")
	}
	if !srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("xpf's own A must be published alongside the foreign record")
	}

	// Renumber xpf's own value: Remove(old-xpf)+Insert(new-xpf) in one atomic
	// UPDATE. The foreign A survives; the OLD xpf value is gone; the NEW is live.
	m.now = func() time.Time { return time.Unix(1_700_000_060, 0) }
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.9"), nil, catalog); err != nil {
		t.Fatalf("renumber: %v", err)
	}
	if !srv.zoneHas(aRR("wan.example.net", foreign)) {
		t.Fatal("M08: the foreign A must survive an xpf renumber (exact-RR delete of only xpf's prior value)")
	}
	if !srv.zoneHas(aRR("wan.example.net", "203.0.113.9")) {
		t.Fatal("renumber must publish the NEW xpf value")
	}
	if srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("renumber must remove xpf's OWN prior value (203.0.113.5)")
	}
	if st := m.Stats(); st.UpsertFail != 0 {
		t.Fatalf("no publish should have failed; got UpsertFail=%d", st.UpsertFail)
	}
}

// MAJOR-1: a same-address forced-refresh of an existing name must succeed.
func TestSurfaceARealBackendForcedRefreshSucceeds(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := newSurfaceAManagerRealBackend(t, srv)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136", Backend: "rfc2136"}}
	sc := realScope("wan.example.net")
	sc.ForcedRefresh = time.Hour

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Past the forced-refresh floor, SAME address — the wire re-assert must
	// SUCCEED against the now-existing name (MAJOR-1: no NameNotUsed refusal).
	m.now = func() time.Time { return time.Unix(1_700_000_000+7200, 0) }
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("forced-refresh of an existing name must succeed, got: %v", err)
	}
	if !srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("after forced-refresh the zone must still hold A=203.0.113.5")
	}
	if st := m.Stats(); st.UpsertFail != 0 || st.UpsertOK < 2 {
		t.Fatalf("forced-refresh must be a successful re-publish; stats=%+v", st)
	}
}

// MAJOR-2: address-loss withdraw must send a real DNS DELETE (production wiring:
// newBackend set, m.backend nil — the wiring that made the old backendForOwned
// no-op the delete and orphan the RR).
func TestSurfaceARealBackendWithdrawOnAddressLoss(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := newSurfaceAManagerRealBackend(t, srv)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136", Backend: "rfc2136"}}
	sc := realScope("wan.example.net")

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("zone must hold the record before withdraw")
	}
	// Address definitively lost.
	lost := func(context.Context, SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{Source: AddressSourceInterface}, true
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, lost, nil, catalog); err != nil {
		t.Fatalf("withdraw on address loss: %v", err)
	}
	if srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("MAJOR-2: address-loss withdraw must REMOVE the RR from the zone (real DNS DELETE)")
	}
	if st := m.Stats(); st.DeleteOK != 1 || st.DeleteFail != 0 || st.Scopes != 0 {
		t.Fatalf("withdraw must record one real delete + drop ownership; stats=%+v", st)
	}
}

// MAJOR-2: config-removal withdraw (the binding is gone, so there is no live
// SurfaceAScope) must REBUILD the backend from the provider catalog and send a
// real DNS DELETE.
func TestSurfaceARealBackendWithdrawOnConfigRemoval(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := newSurfaceAManagerRealBackend(t, srv)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136", Backend: "rfc2136"}}
	sc := realScope("wan.example.net")

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("zone must hold the record before removal")
	}
	// Binding removed (empty scope list) but the provider catalog is still
	// committed — Pass 2 must rebuild the backend by scope.PolicyID and DELETE.
	if err := m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("withdraw on config removal: %v", err)
	}
	if srv.zoneHas(aRR("wan.example.net", "203.0.113.5")) {
		t.Fatal("MAJOR-2: config-removal withdraw must REMOVE the RR (rebuild backend from the catalog)")
	}
	if st := m.Stats(); st.DeleteOK != 1 || st.DeleteFail != 0 || st.Scopes != 0 {
		t.Fatalf("config-removal withdraw must record one real delete; stats=%+v", st)
	}
}

// MINOR M1 + #3735: if the provider was removed from the catalog too
// (rename/removal), the withdraw cannot reach the old endpoint. It must still NOT
// claim success (no DeleteOK) and NOT drop ownership (keep the RR cleanable), but
// pre-#3735 it churned a recurring reconcile error every sweep. #3735 recognizes
// this as a TERMINAL orphan: a single loud operator alarm fires (Stats.Orphaned +
// a SurfaceAStateOrphaned status row) and the wire delete is not re-attempted —
// the record stays owned and operator-visible for MANUAL cleanup (auto-withdrawal
// is deferred: the old creds are redacted config.Secret and the old endpoint is
// usually decommissioned).
func TestSurfaceARealBackendWithdrawNoProviderKeepsOwnership(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := newSurfaceAManagerRealBackend(t, srv)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136", Backend: "rfc2136"}}
	sc := realScope("wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Binding AND provider both gone: empty scopes + empty catalog.
	if err := m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil, map[string]*config.DDNSProvider{}); err != nil {
		t.Fatalf("provider-gone withdraw must not churn a reconcile error (terminal orphan alarm): %v", err)
	}
	st := m.Stats()
	if st.DeleteOK != 0 || st.Scopes != 1 {
		t.Fatalf("an unresolvable withdraw must not claim success nor drop ownership; stats=%+v", st)
	}
	if st.Orphaned != 1 {
		t.Fatalf("#3735: a provider-gone withdraw must raise exactly one orphan alarm; stats=%+v", st)
	}
	views := m.StatusViews(nil)
	if len(views) != 1 || views[0].State != SurfaceAStateOrphaned || views[0].FQDN != "wan.example.net" {
		t.Fatalf("#3735: a provider-gone orphan must surface a SurfaceAStateOrphaned status row; got %+v", views)
	}
}

// MINOR M1 (publish side): a publish that the backend REFUSES must not increment
// the success counter. A self-owned in-place replace does not refuse a name, so
// drive a refusal via a non-self-owned third-party-conflict path is not the
// Surface A contract — instead assert the happy-path counter honesty: a
// successful publish increments UpsertOK exactly once and UpsertFail zero.
func TestSurfaceARealBackendPublishCounterHonesty(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m := newSurfaceAManagerRealBackend(t, srv)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136", Backend: "rfc2136"}}
	sc := realScope("wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil, catalog); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if st := m.Stats(); st.UpsertOK != 1 || st.UpsertFail != 0 {
		t.Fatalf("a successful publish must be UpsertOK=1 UpsertFail=0; stats=%+v", st)
	}
}

// Per-RG gate through the real backend: the RG1 master publishes (zone holds the
// record); a non-master neither publishes NOR withdraws an already-owned record
// (stop-writing-never-withdraw) — the RR stays in the zone.
func TestSurfaceARealBackendPerRGGate(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	catalog := map[string]*config.DDNSProvider{"corp-2136": {Name: "corp-2136", Backend: "rfc2136"}}

	scRG1 := realScope("vip.example.net")
	scRG1.Key.RGOwner = 1
	obs := fixedObserver("198.51.100.7")

	// MASTER node publishes.
	mMaster := newSurfaceAManagerRealBackend(t, srv)
	gateMaster := func(s ScopeKey) bool { return s.RGOwner == 1 }
	if err := mMaster.Reconcile(context.Background(), []SurfaceAScope{scRG1}, obs, gateMaster, catalog); err != nil {
		t.Fatalf("master publish: %v", err)
	}
	if !srv.zoneHas(aRR("vip.example.net", "198.51.100.7")) {
		t.Fatal("RG1 master must publish the record")
	}

	// Non-master node that already owns the record: gate closed → no publish, no
	// withdraw. The record must remain in the zone (the master refreshes it).
	mBackup := newSurfaceAManagerRealBackend(t, srv)
	if err := mBackup.Reconcile(context.Background(), []SurfaceAScope{scRG1}, obs, func(ScopeKey) bool { return true }, catalog); err != nil {
		t.Fatalf("backup seed: %v", err)
	}
	if err := mBackup.Reconcile(context.Background(), []SurfaceAScope{scRG1}, obs, func(ScopeKey) bool { return false }, catalog); err != nil {
		t.Fatalf("backup gated pass: %v", err)
	}
	if !srv.zoneHas(aRR("vip.example.net", "198.51.100.7")) {
		t.Fatal("a gated-out non-master must NOT withdraw the record (stop-writing-never-withdraw)")
	}
	if st := mBackup.Stats(); st.DeleteOK != 0 {
		t.Fatalf("a gated-out scope must not delete; stats=%+v", st)
	}
}
