package ddns

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// #1387 inc-2 manager-level integration tests: the Manager driving the
// LIVE rfc2136 backend (resolved per-Reconcile) against the in-process
// miekg/dns server, plus the reconcile-pass / skip counters and the
// enabled→disabled withdraw-once behaviour.

// fakeLeaseSource is the test LeaseParser double (#2691 P1a): the engine now
// reads leases through the injected LeaseParser seam instead of parsing the
// Kea memfile itself (the Kea-memfile parser stays in pkg/dhcpserver, and its
// CSV-specific behavior is covered verbatim by the parser tests there). The
// integration tests below inject the EXACT Leases the real Kea parser would
// have produced from the memfile rows they previously wrote — so every
// manager+backend assertion is preserved unchanged.
type fakeLeaseSource struct {
	v4 []Lease
	v6 []Lease
}

func (s *fakeLeaseSource) parser() LeaseParser {
	return func(_ string, family int, _ time.Time) ([]Lease, error) {
		if family == 6 {
			return s.v6, nil
		}
		return s.v4, nil
	}
}

// laptopMacLease is the Lease the real Kea parser yields for the recurring
// memfile row `10.0.1.5,aa,,...,1,laptop,0` (hwaddr aa, no client-id ⇒
// identity "mac:aa").
func laptopMacLease() []Lease {
	return []Lease{{Family: 4, Address: "10.0.1.5", Identity: "mac:aa", SubnetID: "1", HostName: "laptop"}}
}

// laptopCIDLease is the Lease for `10.0.1.5,aa:bb,01:02:03,...,1,laptop,0`
// (client-id present ⇒ identity "cid:01:02:03", client-id preferred over hwaddr).
func laptopCIDLease() []Lease {
	return []Lease{{Family: 4, Address: "10.0.1.5", Identity: "cid:01:02:03", SubnetID: "1", HostName: "laptop"}}
}

// laptopNoIdentityLease is the Lease for `10.0.1.5,,,...,1,laptop,0`
// (no hwaddr, no client-id ⇒ empty identity, keyed on address).
func laptopNoIdentityLease() []Lease {
	return []Lease{{Family: 4, Address: "10.0.1.5", Identity: "", SubnetID: "1", HostName: "laptop"}}
}

// freshCIDLease is the Lease for `10.0.1.9,aa:bb,07:08:09,...,1,fresh,0`.
func freshCIDLease() []Lease {
	return []Lease{{Family: 4, Address: "10.0.1.9", Identity: "cid:07:08:09", SubnetID: "1", HostName: "fresh"}}
}

// prodManagerTo builds a production-shaped manager (resolve-per-Reconcile)
// whose factory points the live backend at the fake server. The returned
// fakeLeaseSource is the lease input; tests mutate its v4/v6 slices to model
// lease arrival/departure (the seam that replaced writing a Kea memfile).
func prodManagerTo(t *testing.T, srv *fakeDNSServer) (*Manager, *fakeLeaseSource) {
	t.Helper()
	dir := t.TempDir()
	src := &fakeLeaseSource{}
	m := newManagerForTesting(
		src.parser(),
		nopUpdater{},
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		c.UpdateServer = srv.addrUDP
		return newRFC2136Updater(pol, c.RFC2136Endpoint, nil,
			func() { m.skippedPTRNotAuth.Add(1) },
			func() { m.skippedConflict.Add(1) })
	}
	return m, src
}

func ddnsCfg(server string) *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
			Backend:    "rfc2136",
			RFC2136Endpoint: config.RFC2136Endpoint{
				UpdateServer: server,
			},
		},
	}
}

func TestManagerReconcileLiveBackendPublishesAndExpires(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	// Cycle 1: one active v4 lease → forward + reverse published; owned.
	src.v4 = laptopMacLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	st := m.Stats()
	if st.UpsertOK == 0 {
		t.Errorf("UpsertOK = 0, want >0 (live backend should publish)")
	}
	if st.OwnedRecords != 1 {
		t.Errorf("OwnedRecords = %d, want 1", st.OwnedRecords)
	}
	if st.ReconcileOK != 1 {
		t.Errorf("ReconcileOK = %d, want 1", st.ReconcileOK)
	}
	// The server saw a forward A add + a reverse PTR add.
	var sawA, sawPTR bool
	for _, up := range srv.recorded() {
		for _, rr := range up.adds {
			switch rr.(type) {
			case *dns.A:
				sawA = true
			case *dns.PTR:
				sawPTR = true
			}
		}
	}
	if !sawA || !sawPTR {
		t.Errorf("server did not see both A and PTR adds (A=%v PTR=%v)", sawA, sawPTR)
	}

	// Cycle 2: lease gone (empty CSV) → the owned record is deleted.
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	st = m.Stats()
	if st.DeleteOK == 0 {
		t.Errorf("DeleteOK = 0, want >0 (expired lease should delete)")
	}
	if st.OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d, want 0 after expiry", st.OwnedRecords)
	}
}

func TestManagerReconcileSteadyStateNoChurn(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	src.v4 = laptopMacLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	after1 := m.Stats().UpsertOK
	// Two more cycles with the SAME lease: recordsEqual short-circuit means
	// the stable lease is NOT re-upserted (plan risk R5).
	for i := 0; i < 2; i++ {
		if err := m.Reconcile(context.Background(), cfg); err != nil {
			t.Fatalf("reconcile %d: %v", i+2, err)
		}
	}
	if got := m.Stats().UpsertOK; got != after1 {
		t.Errorf("UpsertOK churned across steady-state cycles: %d -> %d (want flat)", after1, got)
	}
}

func TestManagerEnabledThenDisabledWithdrawsOnce(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m, src := prodManagerTo(t, srv)
	enabled := ddnsCfg(srv.addrUDP)
	src.v4 = laptopMacLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), enabled); err != nil {
		t.Fatalf("enable reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("expected 1 owned record after enable")
	}

	// Disable via DynamicDNS != nil with Enabled=false (NOT a nil stanza):
	// the backend config (Backend + UpdateServer) is retained, so the
	// resolve-per-Reconcile factory still builds the LIVE backend (a disabled
	// policy that keeps backend "rfc2136" + an update-server resolves the
	// rfc2136 updater, not the nop). withdrawAllLocked then deletes the owned
	// record THROUGH that live backend before the !pol.enabled branch returns.
	// (Whole-stanza removal — DynamicDNS=nil — resolves the nop and is covered
	// by the stanza-removal withdraw test.)
	disabled := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled: false,
		Domain:  "example.com",
		Backend: "rfc2136",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: srv.addrUDP,
		},
	}}
	if err := m.Reconcile(context.Background(), disabled); err != nil {
		t.Fatalf("disable reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d after disable, want 0 (withdraw)", m.Stats().OwnedRecords)
	}
	delsAfterDisable := m.Stats().DeleteOK
	// A second disabled reconcile is a no-op (store empty) — withdraw once.
	if err := m.Reconcile(context.Background(), disabled); err != nil {
		t.Fatalf("second disable reconcile: %v", err)
	}
	if got := m.Stats().DeleteOK; got != delsAfterDisable {
		t.Errorf("second disabled reconcile re-deleted: %d -> %d (want once)", delsAfterDisable, got)
	}
}

// TestManagerStanzaRemovalWithdrawsThroughLiveBackend covers the
// whole-stanza removal path (DynamicDNS == nil), distinct from the
// Enabled=false path above. When the operator deletes the entire DynamicDNS
// stanza, policyFromConfig(nil) yields backend "" so the resolve-per-Reconcile
// factory resolves a nopUpdater (no update-server/TSIG left to build the live
// backend). The manager must NOT swap the live updater (which published the
// records) for the nop before withdrawing — otherwise withdrawAllLocked runs
// through the nop, dropping ownership entries while sending NO real DNS delete,
// orphaning the published records. This test wires a recording fakeUpdater as
// the live backend, publishes a record, then removes the stanza and asserts
// the fake RECEIVES the delete (record actually withdrawn) and ownership is
// cleared. It FAILS pre-fix (the nop swallows the delete: 0 deletes recorded).
func TestManagerStanzaRemovalWithdrawsThroughLiveBackend(t *testing.T) {
	dir := t.TempDir()
	fake := newFakeUpdater()
	src := &fakeLeaseSource{}
	m := newManagerForTesting(
		src.parser(),
		fake,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	// Factory mirrors NewProductionManager: a usable rfc2136 policy yields
	// the (recording) live backend; anything else (incl. stanza removal where
	// backend resolves to "") yields the nopUpdater.
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		return fake, nil
	}

	src.v4 = laptopMacLease()
	src.v6 = nil

	// Enable + publish via the live (fake) backend.
	enabled := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", TTLSeconds: 300,
		Backend: "rfc2136",
		RFC2136Endpoint: config.RFC2136Endpoint{
			UpdateServer: "192.0.2.53",
		},
	}}
	if err := m.Reconcile(context.Background(), enabled); err != nil {
		t.Fatalf("enable reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("expected 1 owned record after enable, got %d", m.Stats().OwnedRecords)
	}
	if len(fake.upserts) == 0 {
		t.Fatalf("live backend recorded no upsert on enable")
	}

	// Remove the ENTIRE stanza (DynamicDNS == nil). The factory now resolves
	// the nop, but the live updater must still withdraw the owned record.
	removed := &config.DHCPServerConfig{DynamicDNS: nil}
	if err := m.Reconcile(context.Background(), removed); err != nil {
		t.Fatalf("stanza-removal reconcile: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Errorf("OwnedRecords = %d after stanza removal, want 0 (withdrawn)", got)
	}
	if len(fake.deletes) == 0 {
		t.Fatal("stanza removal did not send a real DNS delete through the live backend " +
			"(records orphaned) — the nop swallowed the withdraw")
	}
}

func TestManagerReconcileFailCountsAndDoesNotWedge(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	// Make the FORWARD zone always SERVFAIL so the upsert errors.
	srv.setRcode("example.com.", dns.RcodeServerFailure)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	src.v4 = laptopMacLease()
	src.v6 = nil
	err := m.Reconcile(context.Background(), cfg)
	if err == nil {
		t.Fatal("a forward-zone SERVFAIL must surface a reconcile error")
	}
	st := m.Stats()
	if st.UpsertFail == 0 {
		t.Errorf("UpsertFail = 0, want >0")
	}
	if st.ReconcileFail != 1 {
		t.Errorf("ReconcileFail = %d, want 1", st.ReconcileFail)
	}
	// Nothing was recorded as owned (upsert failed before recording).
	if st.OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d, want 0 (failed upsert records no ownership)", st.OwnedRecords)
	}
	// The loop is not wedged: a subsequent successful cycle publishes.
	srv.clearRcode("example.com.")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Errorf("recovery did not publish: OwnedRecords = %d", m.Stats().OwnedRecords)
	}
}

func TestManagerPTRNotAuthCountedNotFailed(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeNotAuth)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	src.v4 = laptopMacLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile: a reverse NOTAUTH must not fail the pass: %v", err)
	}
	st := m.Stats()
	if st.SkippedPTRNotAuth != 1 {
		t.Errorf("SkippedPTRNotAuth = %d, want 1", st.SkippedPTRNotAuth)
	}
	// Forward A still owned + reconcile OK.
	if st.OwnedRecords != 1 {
		t.Errorf("OwnedRecords = %d, want 1 (forward published)", st.OwnedRecords)
	}
	if st.ReconcileOK != 1 {
		t.Errorf("ReconcileOK = %d, want 1", st.ReconcileOK)
	}
}

// ownedFQDNs returns the FQDNs the manager currently records as owned.
func ownedFQDNs(m *Manager) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for _, r := range m.state.records {
		out = append(out, r.FQDN)
	}
	return out
}

// TestManagerReplaceOwnedRefusedAddRecordsNoOwnership_NoIdentity is the #2648
// MAJOR-1 regression at the MANAGER level (the layer the original tests never
// exercised). A third party owns the forward name; the lease has NO client
// identity (empty client_id AND hwaddr), so the delete path has no DHCID-match
// guard. Cycle 1 must REFUSE the add and record NO ownership; cycle 2 (lease
// gone) must issue NO delete and leave the third party's A intact.
//
// fail-on-revert: restoring upsertLocked's unconditional state.put on the
// refusal path re-records phantom ownership, and cycle 2 then deletes the
// third party's A → this test goes red (BOUNDARY BREACH).
func TestManagerReplaceOwnedRefusedAddRecordsNoOwnership_NoIdentity(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	// Third party already published laptop.example.com A 10.0.1.5 (no DHCID).
	thirdParty := &dns.A{
		Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.1.5"),
	}
	srv.seedRR(thirdParty)

	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	// Cycle 1: an active v4 lease for the SAME name+address, NO identity
	// (empty client_id AND hwaddr).
	src.v4 = laptopNoIdentityLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("#2648: refused add recorded phantom ownership; OwnedRecords=%d want 0 (owned=%v)",
			got, ownedFQDNs(m))
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("third-party A vanished after a refused add")
	}

	// Cycle 2: lease gone — no owned state, so NO delete must be issued and the
	// third party's A must survive.
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("#2648 BOUNDARY BREACH (end-to-end, no-identity): manager deleted a third-party A it did not create")
	}
	if m.Stats().DeleteOK != 0 {
		t.Errorf("a delete was issued for a name xpf never owned; DeleteOK=%d want 0", m.Stats().DeleteOK)
	}
}

// TestManagerReplaceOwnedRefusedAddRecordsNoOwnership_Identity is the
// identity-bearing arm of the #2648 MAJOR-1 regression: a third party owns the
// name (no DHCID / a foreign DHCID), and the lease HAS a client identity. The
// add must still be refused with NO ownership recorded (phantom-state
// pollution), and the third party's record must survive both cycles.
func TestManagerReplaceOwnedRefusedAddRecordsNoOwnership_Identity(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	thirdParty := &dns.A{
		Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.1.5"),
	}
	srv.seedRR(thirdParty)

	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	// Active v4 lease WITH an identity (client_id set).
	src.v4 = laptopCIDLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("#2648: refused identity add recorded phantom ownership; OwnedRecords=%d want 0 (owned=%v)",
			got, ownedFQDNs(m))
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("third-party A vanished after a refused identity add")
	}

	// Cycle 2: lease gone — third party survives, no delete issued.
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("#2648 BOUNDARY BREACH (end-to-end, identity): manager deleted a third-party A it did not create")
	}
}

// TestManagerReplaceOwnedFreshNameFullLifecycle proves the manager path still
// works for the happy case: a fresh name is claimed (ownership recorded), and
// the lease's expiry deletes exactly that owned record via the DHCID-guarded
// delete.
func TestManagerReplaceOwnedFreshNameFullLifecycle(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	src.v4 = freshCIDLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("fresh name not owned; OwnedRecords=%d want 1", m.Stats().OwnedRecords)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "fresh.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.9")}
	if !srv.zoneHas(a) {
		t.Fatalf("fresh A not published")
	}

	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("owned record not cleared after expiry; OwnedRecords=%d", m.Stats().OwnedRecords)
	}
	if srv.zoneHas(a) {
		t.Errorf("owned A not deleted after expiry")
	}
}

// ddnsCfgSkipExisting is ddnsCfg with the skip-existing conflict policy.
func ddnsCfgSkipExisting(server string) *config.DHCPServerConfig {
	cfg := ddnsCfg(server)
	cfg.DynamicDNS.ConflictPolicy = "skip-existing"
	return cfg
}

// TestManagerSkipExistingConflictRecordsNoOwnership is the #2660 boundary
// regression at the MANAGER level (the #2648/#2659 lesson: test through
// reconcileOnceLocked, the layer that surfaces the breach, not the updater in
// isolation). Under skip-existing, a third party already owns the forward name.
// Cycle 1 must REFUSE the add and record NO ownership; cycle 2 (lease gone)
// must issue NO delete and leave the third party's A intact. skip-existing
// never writes a DHCID, so a phantom-owned record's later release would take
// sendRemoveForward's plain exact-RR delete branch and wipe the third party's
// RR — the exact breach #2660 closes.
//
// fail-on-revert: changing the skip-existing YX path back to `return nil`
// re-records phantom ownership (cycle 1 OwnedRecords=1), and cycle 2 then
// deletes the third party's A → this test goes red.
func TestManagerSkipExistingConflictRecordsNoOwnership(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	// Third party already published laptop.example.com A 10.0.1.5 (no DHCID).
	thirdParty := &dns.A{
		Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.1.5"),
	}
	srv.seedRR(thirdParty)

	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfgSkipExisting(srv.addrUDP)

	// Cycle 1: an active v4 lease for the SAME name+address.
	src.v4 = laptopCIDLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("#2660: skip-existing refused add recorded phantom ownership; OwnedRecords=%d want 0 (owned=%v)",
			got, ownedFQDNs(m))
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("third-party A vanished after a refused skip-existing add")
	}
	if got := m.Stats().SkippedConflict; got != 1 {
		t.Errorf("SkippedConflict = %d, want 1", got)
	}

	// Cycle 2: lease gone — no owned state, so NO delete must be issued and the
	// third party's A must survive.
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("#2660 BOUNDARY BREACH (end-to-end): manager deleted a third-party A it did not create under skip-existing")
	}
	if got := m.Stats().DeleteOK; got != 0 {
		t.Errorf("a delete was issued for a name xpf never owned; DeleteOK=%d want 0", got)
	}
}

// TestManagerSkipExistingFreshNameFullLifecycle proves the manager path still
// works for the happy case under skip-existing: a fresh (unused) name is
// claimed (ownership recorded → the RRsetNotUsed prereq passes), and the
// lease's expiry deletes exactly that owned record.
func TestManagerSkipExistingFreshNameFullLifecycle(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfgSkipExisting(srv.addrUDP)

	src.v4 = freshCIDLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("fresh skip-existing name not owned; OwnedRecords=%d want 1", m.Stats().OwnedRecords)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "fresh.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.9")}
	if !srv.zoneHas(a) {
		t.Fatalf("fresh A not published")
	}

	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("owned record not cleared after expiry; OwnedRecords=%d", m.Stats().OwnedRecords)
	}
	if srv.zoneHas(a) {
		t.Errorf("owned A not deleted after expiry")
	}
}

// TestManagerForwardPublishedPTRFailsRecordsOwnership is the #2661 regression
// at the MANAGER level (the layer reconcileOnceLocked drives). The forward A
// add succeeds but the reverse PTR add returns a NON-skippable error (SERVFAIL).
// Pre-#2661 the manager recorded NO ownership while the forward was already
// live in DNS → the forward was ORPHANED (live but untracked, never cleanable).
// Post-fix the manager records ownership of the live forward with PTRPending so
// it is tracked + cleanable, and a later release deletes it.
//
// fail-on-revert: restoring UpsertLease to return a plain error (no pending
// sentinel) / upsertLocked to record no ownership on that error re-creates the
// orphan: cycle 1 OwnedRecords=0 while the A is live, and cycle 2 issues no
// delete → the A survives in the zone with no owner → this test goes red.
func TestManagerForwardPublishedPTRFailsRecordsOwnership(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	// The reverse zone always SERVFAILs (a non-skippable, transient error —
	// NOT NOTAUTH/REFUSED, which is the permanent counted-skip case).
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeServerFailure)

	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	// Cycle 1: an active v4 lease. Forward A publishes; reverse PTR SERVFAILs.
	src.v4 = laptopCIDLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1 must not fail the pass on a PTR-only failure: %v", err)
	}
	// The forward A is LIVE in the zone...
	liveA := &dns.A{Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}
	if !srv.zoneHas(liveA) {
		t.Fatalf("forward A was not published")
	}
	// ...and it MUST be owned (tracked + cleanable), not orphaned.
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("#2661: forward published but NOT owned (orphaned); OwnedRecords=%d want 1 (owned=%v)",
			got, ownedFQDNs(m))
	}
	if got := m.Stats().PTRDeferred; got != 1 {
		t.Errorf("PTRDeferred = %d, want 1 (the PTR failure must be counted)", got)
	}
	// The owned record must be marked PTR-pending so the PTR is retried.
	if !ownedPTRPending(m, "laptop.example.com") {
		t.Errorf("owned record not marked PTRPending; the PTR will never be retried")
	}

	// Cycle 2: PTR zone recovers. The forward re-add is an idempotent no-op and
	// the still-missing PTR publishes; the record settles (PTRPending cleared).
	srv.clearRcode("1.0.10.in-addr.arpa.")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2 (PTR retry): %v", err)
	}
	livePTR := &dns.PTR{
		Hdr: dns.RR_Header{Name: reversePTRName(netip.MustParseAddr("10.0.1.5")) + ".", Rrtype: dns.TypePTR},
		Ptr: "laptop.example.com.",
	}
	if !srv.zoneHas(livePTR) {
		t.Errorf("reverse PTR was not published on the retry cycle")
	}
	if ownedPTRPending(m, "laptop.example.com") {
		t.Errorf("PTRPending not cleared after a successful PTR retry")
	}

	// Cycle 3: lease gone — the (now fully-owned) forward is deleted, never
	// orphaned. This is the no-orphan proof: a release withdraws the forward.
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 3 (release): %v", err)
	}
	if srv.zoneHas(liveA) {
		t.Fatalf("#2661: the forward A was NOT withdrawn on release — it was orphaned")
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d after release, want 0", m.Stats().OwnedRecords)
	}
}

// TestManagerPTRPendingReleaseWithoutRetryStillCleansForward proves the forward
// is cleanable even if the PTR NEVER recovers: a record stuck PTR-pending is
// still owned, so when the lease expires the release withdraws the forward
// (#2661 — the forward is tracked + cleanable regardless of the PTR outcome).
func TestManagerPTRPendingReleaseWithoutRetryStillCleansForward(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeServerFailure)

	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	src.v4 = laptopCIDLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	liveA := &dns.A{Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}
	if !srv.zoneHas(liveA) || m.Stats().OwnedRecords != 1 {
		t.Fatalf("forward not owned after PTR failure")
	}

	// Lease gone while still PTR-pending (PTR zone still broken): the forward
	// must still be withdrawn (it is OWNED — that is the whole point of #2661).
	// DeleteLease deletes the forward FIRST, then the PTR; the PTR delete to the
	// still-broken zone surfaces an error so the reconcile pass reports it and
	// keeps the ownership entry for a later retry, but the forward A is GONE
	// from the zone — never orphaned. (Re-deleting an already-gone forward on a
	// later cycle is an idempotent NXRRSET no-op.)
	src.v4 = nil
	_ = m.Reconcile(context.Background(), cfg) // PTR-delete error is expected/non-fatal here
	if srv.zoneHas(liveA) {
		t.Fatalf("#2661: a PTR-pending forward was NOT cleaned on release — orphaned")
	}
	// The forward is withdrawn from DNS; ownership lingers only because the PTR
	// delete to the broken zone could not complete. Once the PTR zone recovers
	// the entry clears. Prove no orphan + eventual cleanup: recover the zone.
	srv.clearRcode("1.0.10.in-addr.arpa.")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 3 (cleanup after PTR zone recovery): %v", err)
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d after PTR-zone recovery, want 0", m.Stats().OwnedRecords)
	}
}

// TestManagerPTRNotAuthOwnedNotPending guards the no-regression case: a NOTAUTH
// reverse zone (permanently not ours) is a counted SKIP — the forward is owned
// but NOT marked PTR-pending (there is nothing to retry), so steady state does
// not churn re-attempting an UPDATE the server will always refuse.
func TestManagerPTRNotAuthOwnedNotPending(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeNotAuth)

	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	src.v4 = laptopCIDLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("forward not owned after a NOTAUTH PTR skip")
	}
	if m.Stats().SkippedPTRNotAuth != 1 {
		t.Errorf("SkippedPTRNotAuth = %d, want 1", m.Stats().SkippedPTRNotAuth)
	}
	if m.Stats().PTRDeferred != 0 {
		t.Errorf("PTRDeferred = %d, want 0 (NOTAUTH is a permanent skip, not a retry)", m.Stats().PTRDeferred)
	}
	if ownedPTRPending(m, "laptop.example.com") {
		t.Errorf("NOTAUTH-skip record must NOT be PTRPending (nothing to retry)")
	}
	// Steady state: a second cycle does not re-upsert (no churn) — the record
	// is settled, not pending.
	after := m.Stats().UpsertOK
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if got := m.Stats().UpsertOK; got != after {
		t.Errorf("NOTAUTH-skip record churned a re-upsert: %d -> %d (want flat)", after, got)
	}
}

// ownedPTRPending reports whether the owned record for fqdn is PTR-pending.
func ownedPTRPending(m *Manager, fqdn string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.state.records {
		if r.FQDN == fqdn {
			return r.PTRPending
		}
	}
	return false
}

// TestManagerForwardPublishedPTRConflictRecordsOwnership is the #2676
// regression at the MANAGER level (the layer reconcileOnceLocked drives — the
// #2648/#2659/#2661 lesson: an updater-in-isolation test misses the orphan;
// only the reconcile layer surfaces it). Under skip-existing the FORWARD A add
// SUCCEEDS (its name is unused) but the REVERSE PTR add hits a conflict
// refusal because the reverse RRset is already owned by another party.
//
// Pre-#2676 ordering bug: UpsertLease wrapped the PTR-side
// errDDNSConflictRefused into a chain carrying BOTH errDDNSConflictRefused AND
// errDDNSPTRPending; upsertLocked checked errDDNSConflictRefused FIRST →
// removed the pre-written intent → recorded NO ownership while the forward A
// was already LIVE → ORPHANED forward (live in the zone, untracked, never
// cleanable). Post-fix: a PTR-side conflict-refusal is a PERMANENT counted skip
// (like NOTAUTH) that returns nil; the forward is OWNED, owned-not-pending, and
// a later release withdraws it.
//
// fail-on-revert: restoring UpsertLease to wrap the PTR-conflict as
// `%w: %w`, err(=errDDNSConflictRefused), errDDNSPTRPending AND restoring
// upsertLocked to check errDDNSConflictRefused before errDDNSPTRPending
// re-creates the orphan — cycle 1 OwnedRecords=0 while the A is live, and the
// release issues no delete, so the A survives untracked → this test goes red.
func TestManagerForwardPublishedPTRConflictRecordsOwnership(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	// A THIRD PARTY already owns the reverse PTR RRset for 10.0.1.5 — the
	// forward name (laptop.example.com) is unused, so the forward A add will
	// SUCCEED; only the reverse PTR add collides.
	addr := netip.MustParseAddr("10.0.1.5")
	thirdPartyPTR := &dns.PTR{
		Hdr: dns.RR_Header{Name: reversePTRName(addr) + ".", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300},
		Ptr: "someone-else.example.net.",
	}
	srv.seedRR(thirdPartyPTR)

	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfgSkipExisting(srv.addrUDP)

	// Cycle 1: an active v4 lease. Forward A publishes; reverse PTR is refused.
	src.v4 = laptopCIDLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 1 must not fail the pass on a PTR-only conflict: %v", err)
	}
	// The forward A is LIVE in the zone...
	liveA := &dns.A{Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}
	if !srv.zoneHas(liveA) {
		t.Fatalf("forward A was not published")
	}
	// ...and it MUST be OWNED (tracked + cleanable), not orphaned.
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("#2676: forward published but NOT owned (orphaned); OwnedRecords=%d want 1 (owned=%v)",
			got, ownedFQDNs(m))
	}
	// The third party's PTR must survive — xpf never adopts/overwrites it.
	if !srv.zoneHas(thirdPartyPTR) {
		t.Fatalf("#2676: third-party reverse PTR vanished after a refused PTR add")
	}
	// A PTR-side conflict-refusal is a PERMANENT skip, NOT a pending retry:
	// the owned record must NOT be PTR-pending (nothing to retry — the reverse
	// is permanently another party's).
	if ownedPTRPending(m, "laptop.example.com") {
		t.Errorf("#2676: a PTR-conflict record must NOT be PTRPending (the reverse is permanently not ours)")
	}
	if got := m.Stats().PTRDeferred; got != 0 {
		t.Errorf("PTRDeferred = %d, want 0 (a PTR conflict is a permanent skip, not a transient retry)", got)
	}
	if got := m.Stats().SkippedConflict; got != 1 {
		t.Errorf("SkippedConflict = %d, want 1 (the PTR conflict must be counted)", got)
	}

	// Steady state: a second cycle does not churn — the record is settled
	// (owned-not-pending), so no re-upsert beyond the idempotent forward re-add.
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}

	// Cycle 3: lease gone — the (owned) forward A is DELETED, never orphaned.
	// This is the no-orphan proof: a release withdraws the forward xpf created
	// while leaving the third party's PTR intact.
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile 3 (release): %v", err)
	}
	if srv.zoneHas(liveA) {
		t.Fatalf("#2676: the forward A was NOT withdrawn on release — it was orphaned")
	}
	if m.Stats().OwnedRecords != 0 {
		t.Errorf("OwnedRecords = %d after release, want 0", m.Stats().OwnedRecords)
	}
	if !srv.zoneHas(thirdPartyPTR) {
		t.Errorf("#2676: the third party's reverse PTR must survive the release (xpf never owned it)")
	}
}

func TestOwnedRecordViews(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	src.v4 = laptopMacLease()
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	views := m.OwnedRecordViews()
	if len(views) != 1 {
		t.Fatalf("OwnedRecordViews len = %d, want 1", len(views))
	}
	v := views[0]
	if v.FQDN != "laptop.example.com" || v.ForwardType != "A" || v.Address != "10.0.1.5" {
		t.Errorf("unexpected view: %+v", v)
	}
	if v.PTRName == "" {
		t.Errorf("view missing PTR name")
	}
}
