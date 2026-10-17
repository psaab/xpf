package ddns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #3735 fail-on-revert proofs: a provider IDENTITY change (rename to a different
// endpoint / in-place server-zone edit / removed binding after an edit) must not
// silently mishandle the record the OLD provider published. The durable
// ownedRecord now carries a NON-SECRET backend fingerprint, the #2903 adoption
// guard is provider-AWARE, and an un-withdrawable old record is KEPT + alarmed
// (never silently adopted, overwritten, or deleted at the wrong endpoint). These
// drive the manager through the PRODUCTION wiring (newBackend set, m.backend nil)
// with a per-endpoint fake so a delete at the WRONG endpoint is observable.

// endpointRegistry hands out a distinct fakeUpdater per backend endpoint
// (keyed by the provider's UpdateServer), so a test can assert exactly which
// endpoint received an upsert or a delete — the crux of the H03 false-success
// check (a withdraw must not land at the mutated NEW endpoint).
type endpointRegistry struct {
	mu sync.Mutex
	by map[string]*fakeUpdater
}

func newEndpointRegistry() *endpointRegistry { return &endpointRegistry{by: map[string]*fakeUpdater{}} }

func (r *endpointRegistry) get(ep string) *fakeUpdater {
	r.mu.Lock()
	defer r.mu.Unlock()
	u := r.by[ep]
	if u == nil {
		u = newFakeUpdater()
		r.by[ep] = u
	}
	return u
}

// newSurfaceAProviderChangeManager builds a manager with PRODUCTION wiring: only
// newBackend is set (m.backend stays nil), and it resolves a per-endpoint fake
// keyed on the provider's UpdateServer. So a publish/withdraw actually routes to
// the endpoint the provider names — the same resolution production does.
func newSurfaceAProviderChangeManager(t *testing.T, reg *endpointRegistry, now func() time.Time) *SurfaceAManager {
	t.Helper()
	dir := t.TempDir()
	st, err := loadDDNSState(filepath.Join(dir, "iface-ddns.json"))
	if err != nil {
		t.Fatalf("loadDDNSState: %v", err)
	}
	return &SurfaceAManager{
		state:   st,
		runtime: map[string]*surfaceAState{},
		orphans: map[string]surfaceAOrphan{},
		now:     now,
		newBackend: func(p *config.DDNSProvider, _ string, _ int) (DNSUpdater, error) {
			return reg.get(p.UpdateServer), nil
		},
	}
}

// providerScope builds a Surface A scope bound to a provider whose backend
// endpoint (UpdateServer) is `server` and whose provider name (PolicyID) is
// `policyID`. The same *DDNSProvider must also be placed in the reconcile catalog
// so the fingerprint matches on both the publish and withdraw sides.
func providerScope(policyID, server, fqdn string) (SurfaceAScope, *config.DDNSProvider) {
	prov := &config.DDNSProvider{Name: policyID, Backend: "rfc2136", UpdateServer: server}
	sc := SurfaceAScope{
		Key: ScopeKey{
			Family:    FamilyV4,
			Interface: "ge-0-0-2",
			Unit:      50,
			PolicyID:  policyID,
			FQDN:      fqdn,
		},
		FQDN:     fqdn,
		TTL:      300,
		Source:   AddressSourceInterface,
		Provider: prov,
	}
	return sc, prov
}

func orphanRow(views []SurfaceAStatusView) *SurfaceAStatusView {
	for i := range views {
		if views[i].State == SurfaceAStateOrphaned {
			return &views[i]
		}
	}
	return nil
}

// H01 — a provider RENAME to a DIFFERENT endpoint (prov-a -> prov-b, same
// FQDN+addr) must NOT be silently adopted by the provider-blind #2903 guard.
// Before #3735 liveRR keyed only on {FQDN, AddrText}, so the prov-b republish
// made the old prov-a record's {FQDN, addr} "live" and the guard dropped prov-a
// ownership WITHOUT a wire delete — orphaning the record at provider A with no
// trace. Now the old record is KEPT and a loud orphan alarm fires.
//
// FAIL-ON-REVERT: revert the provider-aware liveByPolicy/liveByFP guard (back to
// {FQDN, AddrText}) and prov-a is adopted again — Orphaned drops to 0 and Scopes
// drops to 1, so the assertions below go RED.
func TestSurfaceAProviderRenameDifferentEndpointOrphans(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	scA, provA := providerScope("prov-a", "ns-a.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scA}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov-a": provA}); err != nil {
		t.Fatalf("publish via prov-a: %v", err)
	}
	if got := len(reg.get("ns-a.example.net:53").upserts); got != 1 {
		t.Fatalf("prov-a endpoint must have the initial publish; upserts=%d", got)
	}

	// Operator renames the provider stanza: prov-a is GONE, prov-b (a DIFFERENT
	// endpoint) now owns the same FQDN+address.
	scB, provB := providerScope("prov-b", "ns-b.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scB}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov-b": provB}); err != nil {
		t.Fatalf("republish via prov-b: %v", err)
	}

	// No exact-RR delete anywhere: the old endpoint is un-withdrawable (prov-a
	// gone), and the new endpoint's live RR must not be deleted.
	if got := len(reg.get("ns-a.example.net:53").deletes); got != 0 {
		t.Fatalf("no delete may reach the departed prov-a endpoint; deletes=%d", got)
	}
	if got := len(reg.get("ns-b.example.net:53").deletes); got != 0 {
		t.Fatalf("the live RR at prov-b must not be exact-RR deleted; deletes=%d", got)
	}
	st := m.Stats()
	if st.Orphaned != 1 {
		t.Fatalf("a provider rename to a different endpoint must raise exactly one orphan alarm; stats=%+v", st)
	}
	if st.Scopes != 2 {
		t.Fatalf("the old prov-a ownership must be KEPT (orphaned) alongside the new prov-b record; scopes=%d", st.Scopes)
	}
	views := m.StatusViews([]SurfaceAScope{scB})
	row := orphanRow(views)
	if row == nil || row.FQDN != "wan.example.net" || row.Provider != "prov-a" {
		t.Fatalf("an orphaned status row naming the OLD provider must be surfaced; views=%+v", views)
	}
	if !strings.Contains(row.LastError, "manual cleanup required") {
		t.Fatalf("the orphan row must carry the manual-cleanup reason; got %q", row.LastError)
	}
}

// A provider rename to the SAME endpoint (prov-a -> prov-b, identical
// server/zone) is a pure name change with NO real orphan: the fingerprint axis
// adopts it in place (no wire delete, no false alarm). This guards the liveByFP
// adoption axis specifically.
//
// FAIL-ON-REVERT: remove the fingerprint adoption axis (liveByFP) and this
// same-endpoint rename is no longer adopted — it becomes a spurious orphan
// (Orphaned==1), so the Orphaned==0 assertion goes RED.
func TestSurfaceAProviderRenameSameEndpointAdoptsNoAlarm(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	scA, provA := providerScope("prov-a", "ns-shared.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scA}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov-a": provA}); err != nil {
		t.Fatalf("publish via prov-a: %v", err)
	}
	// Rename only the provider NAME; the endpoint is identical.
	scB, provB := providerScope("prov-b", "ns-shared.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scB}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov-b": provB}); err != nil {
		t.Fatalf("republish via prov-b: %v", err)
	}
	if got := len(reg.get("ns-shared.example.net:53").deletes); got != 0 {
		t.Fatalf("a same-endpoint rename must adopt in place, not delete the live RR; deletes=%d", got)
	}
	st := m.Stats()
	if st.Orphaned != 0 {
		t.Fatalf("a same-endpoint rename is not an orphan (no false alarm); stats=%+v", st)
	}
	if st.Scopes != 1 {
		t.Fatalf("the stale prov-a ownership must be adopted/dropped, leaving one record; scopes=%d", st.Scopes)
	}
}

// H02 — an IN-PLACE provider mutation (same provider NAME, different endpoint)
// keeps the scope key, so the scope is never a Pass-2 withdraw candidate; the
// republish overwrites ownership with the NEW endpoint and orphans the record at
// the OLD endpoint. publishLocked now detects the fingerprint change and alarms
// while still publishing the new record.
//
// FAIL-ON-REVERT: remove the publishLocked fingerprint compare and the mutation
// is silent — Orphaned stays 0, so the assertion goes RED.
func TestSurfaceAProviderInPlaceMutationOrphansOldEndpoint(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	scOld, provOld := providerScope("prov", "ns-a.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scOld}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provOld}); err != nil {
		t.Fatalf("initial publish: %v", err)
	}

	// Edit the provider's server in place (same PolicyID); force a republish so
	// the unchanged address still re-asserts the wire record.
	scNew, provNew := providerScope("prov", "ns-b.example.net:53", "wan.example.net")
	m.ForceRefresh()
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scNew}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provNew}); err != nil {
		t.Fatalf("republish after in-place mutation: %v", err)
	}

	if got := len(reg.get("ns-b.example.net:53").upserts); got != 1 {
		t.Fatalf("the new endpoint must receive the re-asserted record; upserts=%d", got)
	}
	if got := len(reg.get("ns-a.example.net:53").deletes); got != 0 {
		t.Fatalf("the old endpoint's record must NOT be auto-withdrawn (deferred); deletes=%d", got)
	}
	st := m.Stats()
	if st.Orphaned != 1 {
		t.Fatalf("an in-place provider mutation must raise exactly one orphan alarm; stats=%+v", st)
	}
	views := m.StatusViews([]SurfaceAScope{scNew})
	if orphanRow(views) == nil {
		t.Fatalf("the in-place mutation orphan must be operator-visible; views=%+v", views)
	}
	// The healthy published row for the new endpoint is still present.
	var published bool
	for _, v := range views {
		if v.State == SurfaceAStatePublished {
			published = true
		}
	}
	if !published {
		t.Fatalf("the new-endpoint record must still be published; views=%+v", views)
	}
}

// H03 — a removed-binding withdraw AFTER an in-place provider edit must NOT be
// issued at the mutated NEW endpoint (a delete the new server accepts as a
// no-op success, false-success-dropping ownership while the OLD record stays
// live). classifyOwnedBackend now compares fingerprints and treats a mismatch as
// un-withdrawable: KEEP ownership + alarm, no wrong-endpoint delete.
//
// FAIL-ON-REVERT: drop the fingerprint mismatch check (rebuild from the current
// catalog like the old backendForOwned) and the withdraw lands at ns-b — the
// ns-b delete count becomes 1, ownership is dropped (Scopes==0), and Orphaned
// stays 0, so every assertion below goes RED.
func TestSurfaceARemovedBindingWithdrawWrongEndpointOrphans(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	scOld, provOld := providerScope("prov", "ns-a.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scOld}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provOld}); err != nil {
		t.Fatalf("initial publish: %v", err)
	}

	// The binding is removed AND the provider was edited in place to a new
	// endpoint. The catalog still has "prov", but it now points at ns-b.
	provNew := &config.DDNSProvider{Name: "prov", Backend: "rfc2136", UpdateServer: "ns-b.example.net:53"}
	if err := m.Reconcile(context.Background(), nil, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provNew}); err != nil {
		t.Fatalf("removed-binding reconcile must not churn an error (terminal orphan): %v", err)
	}

	if got := len(reg.get("ns-b.example.net:53").deletes); got != 0 {
		t.Fatalf("H03: a withdraw must NOT be issued at the mutated new endpoint; ns-b deletes=%d", got)
	}
	st := m.Stats()
	if st.DeleteOK != 0 {
		t.Fatalf("H03: no delete may be counted as success; stats=%+v", st)
	}
	if st.Scopes != 1 {
		t.Fatalf("H03: ownership must be KEPT (no false-success drop); scopes=%d", st.Scopes)
	}
	if st.Orphaned != 1 {
		t.Fatalf("H03: a wrong-endpoint withdraw must raise exactly one orphan alarm; stats=%+v", st)
	}
}

// The legitimate #2903 on-disk migration (FQDN-less prefix -> FQDN-bearing
// prefix, SAME provider) must STILL adopt in place with a real provider carrying
// a fingerprint — proving the provider-aware guard does not regress the migration
// path via the PolicyID axis when a fingerprint is present on the new record.
func TestSurfaceAFQDNMigrationStillAdoptsWithFingerprint(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	sc, prov := providerScope("prov", "ns.example.net:53", "wan.example.net")

	// Seed a pre-#2903 ownership record: SAME provider + name + address, but keyed
	// under the FQDN-LESS scope prefix and with NO stored fingerprint (older store).
	legacyKey := sc.Key
	legacyKey.FQDN = ""
	m.state.put(ownedRecord{
		Family:      4,
		Identity:    surfaceAIdentity,
		Address:     "",
		FQDN:        "wan.example.net",
		ForwardType: "A",
		TTL:         300,
		AddrText:    "203.0.113.5",
	}.withScope(legacyKey))
	if err := m.state.save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": prov}); err != nil {
		t.Fatalf("post-upgrade reconcile: %v", err)
	}
	if got := len(reg.get("ns.example.net:53").deletes); got != 0 {
		t.Fatalf("the #2903 migration must not delete the live RR; deletes=%d", got)
	}
	st := m.Stats()
	if st.Orphaned != 0 {
		t.Fatalf("the same-provider migration must not false-alarm; stats=%+v", st)
	}
	if st.Scopes != 1 {
		t.Fatalf("after migration exactly one record must remain owned; scopes=%d", st.Scopes)
	}
}

// backendFingerprint is a STABLE, NON-SECRET endpoint fingerprint (#3735): it
// changes with any endpoint-identity field and is INVARIANT to every credential
// (the #2053 no-secret-on-disk property) and to non-endpoint transport fields.
func TestBackendFingerprintStableAndSecretFree(t *testing.T) {
	if backendFingerprint(nil) != "" {
		t.Fatalf("nil provider must fingerprint to the empty string")
	}
	base := &config.DDNSProvider{
		Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53",
	}
	if backendFingerprint(base) != backendFingerprint(&config.DDNSProvider{
		Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53",
	}) {
		t.Fatalf("identical endpoint identity must fingerprint identically")
	}

	// An explicit `backend rfc2136` and the implicit default share a fingerprint.
	if backendFingerprint(&config.DDNSProvider{Name: "p", UpdateServer: "ns.example.net:53"}) !=
		backendFingerprint(&config.DDNSProvider{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53"}) {
		t.Fatalf("empty backend must normalize to rfc2136 in the fingerprint")
	}

	// Every endpoint-identity field must move the fingerprint.
	endpointChanges := []*config.DDNSProvider{
		{Name: "p", Backend: "dyndns2", UpdateServer: "ns.example.net:53"},  // backend type
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns2.example.net:53"}, // server
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", Zone: "z"},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", HostedZoneID: "Z"},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", AWSRegion: "us-east-1"},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", Server: "http://ep"},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", URLTemplate: "http://ep/%h"},
	}
	baseFP := backendFingerprint(base)
	for i, p := range endpointChanges {
		if backendFingerprint(p) == baseFP {
			t.Fatalf("endpoint change #%d must alter the fingerprint", i)
		}
	}

	// Every CREDENTIAL / non-endpoint transport field must NOT move it (the #2053
	// no-secret contract: the fingerprint must be persistable without disclosing a
	// secret and without depending on one).
	secretVariants := []*config.DDNSProvider{
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", TSIGSecret: config.Secret("hunter2")},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", Password: config.Secret("hunter2")},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", APIToken: config.Secret("tok")},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", AWSSecretAccessKey: config.Secret("sk")},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", Username: "u"},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", TSIGKeyName: "k"},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", AWSAccessKeyID: "AKIA"},
		{Name: "p", Backend: "rfc2136", UpdateServer: "ns.example.net:53", SourceAddress: "203.0.113.9"},
		{Name: "different-name", Backend: "rfc2136", UpdateServer: "ns.example.net:53"},
	}
	for i, p := range secretVariants {
		if backendFingerprint(p) != baseFP {
			t.Fatalf("credential/non-endpoint field #%d must NOT alter the fingerprint", i)
		}
	}
}

// The fingerprint is persisted on the owned record but NO secret is: the state
// file must contain the fingerprint and must NOT contain the provider's TSIG
// secret (the #2053 posture is unchanged by #3735).
func TestSurfaceAFingerprintPersistedNoSecretOnDisk(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "iface-ddns.json")
	st, err := loadDDNSState(statePath)
	if err != nil {
		t.Fatalf("loadDDNSState: %v", err)
	}
	m := &SurfaceAManager{
		state:   st,
		runtime: map[string]*surfaceAState{},
		orphans: map[string]surfaceAOrphan{},
		now:     func() time.Time { return now },
		newBackend: func(p *config.DDNSProvider, _ string, _ int) (DNSUpdater, error) {
			return reg.get(p.UpdateServer), nil
		},
	}
	prov := &config.DDNSProvider{
		Name: "prov", Backend: "rfc2136", UpdateServer: "ns.example.net:53",
		TSIGKeyName: "k", TSIGAlgorithm: "hmac-sha256", TSIGSecret: config.Secret("SUPERSECRETKEY=="),
	}
	sc := SurfaceAScope{
		Key:      ScopeKey{Family: FamilyV4, Interface: "ge-0-0-2", Unit: 50, PolicyID: "prov", FQDN: "wan.example.net"},
		FQDN:     "wan.example.net",
		TTL:      300,
		Source:   AddressSourceInterface,
		Provider: prov,
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{sc}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": prov}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	owned, ok := m.state.get(sc.effectiveKey(), surfaceAIdentity, "")
	if !ok || owned.BackendFingerprint == "" || owned.BackendFingerprint != backendFingerprint(prov) {
		t.Fatalf("the owned record must store the provider fingerprint; got %q", owned.BackendFingerprint)
	}

	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, owned.BackendFingerprint) {
		t.Fatalf("the state file must persist the fingerprint")
	}
	if strings.Contains(body, "SUPERSECRETKEY==") {
		t.Fatalf("#2053: the TSIG secret must NOT be written to the ownership state file")
	}
}

// lostObserver returns a definitive address loss (ok=true, invalid Addr) for every
// scope — the Pass-1 address-loss trigger. fixedObserver requires a parseable
// address, so the Pass-1 fixtures define their own loss observer (DR18-H2).
func lostObserver() AddressObserver {
	return func(context.Context, SurfaceAScope) (AddressObservation, bool) {
		return AddressObservation{}, true
	}
}

// DR18-H2 / #14438 — a Pass-1 address-loss withdraw AFTER an in-place provider
// endpoint edit must NOT be issued at the mutated NEW endpoint. The scope is
// still configured, so it never reaches Pass 2's classifyOwnedBackend guard;
// without a Pass-1 fingerprint check it called backendFor(sc) (the CURRENT
// provider) and withdrew at ns-b, false-success-dropping ownership while the
// OLD record stayed live with no orphan alarm.
//
// FAIL-ON-REVERT: remove the Pass-1 fingerprint guard in reconcileScopeLocked
// and the withdraw lands at ns-b — ns-b deletes becomes 1, ownership is dropped
// (Scopes==0), and Orphaned stays 0, so every assertion below goes RED.
func TestSurfaceAPass1AddressLossWithdrawWrongEndpointOrphans(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	scOld, provOld := providerScope("prov", "ns-a.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scOld}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provOld}); err != nil {
		t.Fatalf("initial publish: %v", err)
	}
	if got := len(reg.get("ns-a.example.net:53").upserts); got != 1 {
		t.Fatalf("initial publish must land at ns-a; upserts=%d", got)
	}

	// Same provider NAME edited in place to ns-b; address lost (Pass 1, binding
	// still configured).
	scNew, _ := providerScope("prov", "ns-b.example.net:53", "wan.example.net")
	provNew := &config.DDNSProvider{Name: "prov", Backend: "rfc2136", UpdateServer: "ns-b.example.net:53"}
	scNew.Provider = provNew
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scNew}, lostObserver(), nil,
		map[string]*config.DDNSProvider{"prov": provNew}); err != nil {
		t.Fatalf("address-loss reconcile must not churn an error (terminal orphan): %v", err)
	}

	if got := len(reg.get("ns-b.example.net:53").deletes); got != 0 {
		t.Fatalf("DR18-H2: a Pass-1 address-loss withdraw must NOT be issued at the mutated new endpoint; ns-b deletes=%d", got)
	}
	if got := len(reg.get("ns-a.example.net:53").deletes); got != 0 {
		t.Fatalf("DR18-H2: no delete may be issued at the old endpoint either (deferred); ns-a deletes=%d", got)
	}
	st := m.Stats()
	if st.DeleteOK != 0 {
		t.Fatalf("DR18-H2: no delete may be counted as success; stats=%+v", st)
	}
	if st.Scopes != 1 {
		t.Fatalf("DR18-H2: ownership must be KEPT (no false-success drop); scopes=%d", st.Scopes)
	}
	if st.Orphaned != 1 {
		t.Fatalf("DR18-H2: a wrong-endpoint Pass-1 withdraw must raise exactly one orphan alarm; stats=%+v", st)
	}
	views := m.StatusViews([]SurfaceAScope{scNew})
	if orphanRow(views) == nil {
		t.Fatalf("DR18-H2: the Pass-1 orphan must be operator-visible; views=%+v", views)
	}
	// Idempotent: a second loss pass must not re-alarm or attempt a delete.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scNew}, lostObserver(), nil,
		map[string]*config.DDNSProvider{"prov": provNew}); err != nil {
		t.Fatalf("second address-loss reconcile: %v", err)
	}
	if st := m.Stats(); st.Orphaned != 1 || st.Scopes != 1 {
		t.Fatalf("DR18-H2: orphan alarm must be idempotent; stats=%+v", st)
	}
	if got := len(reg.get("ns-b.example.net:53").deletes); got != 0 {
		t.Fatalf("DR18-H2: second pass must not delete at ns-b; deletes=%d", got)
	}
}

// DR18-H2 control — a normal Pass-1 address-loss withdraw (endpoint UNCHANGED)
// still deletes at the original endpoint and drops ownership with no alarm.
func TestSurfaceAPass1AddressLossWithdrawSameEndpointDeletes(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	scOld, provOld := providerScope("prov", "ns-a.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scOld}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provOld}); err != nil {
		t.Fatalf("initial publish: %v", err)
	}
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scOld}, lostObserver(), nil,
		map[string]*config.DDNSProvider{"prov": provOld}); err != nil {
		t.Fatalf("address-loss reconcile: %v", err)
	}
	if got := len(reg.get("ns-a.example.net:53").deletes); got != 1 {
		t.Fatalf("control: same-endpoint address-loss withdraw must delete at ns-a; deletes=%d", got)
	}
	st := m.Stats()
	if st.Scopes != 0 {
		t.Fatalf("control: ownership must be dropped after a successful withdraw; scopes=%d", st.Scopes)
	}
	if st.Orphaned != 0 {
		t.Fatalf("control: same-endpoint withdraw must not alarm; stats=%+v", st)
	}
	if st.DeleteOK != 1 {
		t.Fatalf("control: exactly one delete must succeed; stats=%+v", st)
	}
}
