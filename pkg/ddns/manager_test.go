package ddns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #1387 DHCP DDNS reconciler unit tests (increment 1). Everything is
// driven through fakeUpdater — no network, no DNS, no lab. These prove
// the never-delete-non-owned boundary, the move/reassign/expire
// transitions, the state-aware lease parser, hostname normalization,
// PTR byte-order, retry-no-wedge, and withdraw-on-disable.

// fakeUpdater records every upsert/delete and can be made to fail.
type fakeUpdater struct {
	mu        sync.Mutex
	upserts   []LeaseDNSRecord
	deletes   []LeaseDNSRecord
	failUpd   map[string]bool // FQDN -> fail upsert
	failDel   map[string]bool // FQDN -> fail delete
	failEvery bool            // fail all ops (retry-no-wedge probe)
	// failedCalls counts UpsertLease/DeleteLease calls that RETURNED an error
	// (the #2691 P2 Surface A backoff test asserts the backend is not re-hit
	// while a scope is in its error-backoff window).
	failedCalls int
}

func newFakeUpdater() *fakeUpdater {
	return &fakeUpdater{failUpd: map[string]bool{}, failDel: map[string]bool{}}
}

func (f *fakeUpdater) UpsertLease(_ context.Context, rec LeaseDNSRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failEvery || f.failUpd[rec.FQDN] {
		f.failedCalls++
		return fmt.Errorf("fake: upsert %s failed", rec.FQDN)
	}
	f.upserts = append(f.upserts, rec)
	return nil
}

func (f *fakeUpdater) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failEvery || f.failDel[rec.FQDN] {
		f.failedCalls++
		return fmt.Errorf("fake: delete %s failed", rec.FQDN)
	}
	f.deletes = append(f.deletes, rec)
	return nil
}

func (f *fakeUpdater) upsertNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.upserts {
		out = append(out, r.FQDN+"="+r.Addr.String())
	}
	sort.Strings(out)
	return out
}

func (f *fakeUpdater) deleteNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.deletes {
		out = append(out, r.FQDN+"="+r.Addr.String())
	}
	sort.Strings(out)
	return out
}

func testDDNS(t *testing.T, up DNSUpdater) *Manager {
	t.Helper()
	dir := t.TempDir()
	return newManagerForTesting(
		nil, // spine tests drive reconcileOnceLocked with synthetic Leases
		up,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
}

func enabledPolicy() ddnsPolicy {
	return policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled:    true,
		Domain:     "example.com",
		TTLSeconds: 300,
	})
}

func leaseV4(addr, ident, host string) Lease {
	return Lease{Family: 4, Address: addr, Identity: ident, HostName: host, SubnetID: "1"}
}

func runReconcile(t *testing.T, m *Manager, pol ddnsPolicy, leases []Lease) error {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	// #2691 P1b: reconcileOnceLocked now takes a per-family env (the same policy
	// is applied to both families here) + the disabled map. The updater is the
	// manager's single test updater for both families; nil gate/resolver ⇒ all
	// scopes writable (the standalone / zero-scope path these tests assert on).
	env := &reconcileEnv{
		pol:     [2]ddnsPolicy{pol, pol},
		updater: [2]DNSUpdater{m.updater, m.updater},
	}
	return m.reconcileOnceLocked(context.Background(), env, leases, nil, nil)
}

// writeCSV writes a file (used by the state-store tests to seed an on-disk
// state JSON). Moved from ddns_test.go; the Kea-CSV-specific uses stayed with
// the parser tests in pkg/dhcpserver.
func writeCSV(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---- hostname normalization ----

func TestDeriveFQDN(t *testing.T) {
	cases := []struct {
		name                         string
		host, clientFQDN, id, domain string
		source                       string
		want                         string
		wantErr                      bool
	}{
		{"plain host + domain", "laptop", "", "mac:aa", "example.com", "client-hostname", "laptop.example.com", false},
		{"uppercase sanitized", "LapTop", "", "mac:aa", "example.com", "client-hostname", "laptop.example.com", false},
		{"dotted claim relabeled to single label (#14996)", "host.sub.example.com", "", "mac:aa", "example.com", "client-hostname", "host.example.com", false},
		{"illegal chars stripped", "my_host!*", "", "mac:aa", "example.com", "client-hostname", "myhost.example.com", false},
		{"no name no domain errors", "", "", "mac:aa", "example.com", "client-hostname", "", true},
		{"fqdn source prefers client fqdn (relabeled into zone)", "ignored", "real.example.org", "mac:aa", "example.com", "fqdn", "real.example.com", false},
		{"fqdn multi-label relabeled (#14996)", "ignored", "real.dept.example.com", "mac:aa", "example.com", "fqdn", "real.example.com", false},
		{"mac-fallback synthesizes", "", "", "mac:aabbccddeeff", "example.com", "mac-fallback", "dhcp-macaabbccddeeff.example.com", false},
		{"bare label no domain", "host", "", "mac:aa", "", "client-hostname", "host", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveFQDN(tc.host, tc.clientFQDN, tc.id, tc.domain, tc.source)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("deriveFQDN = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDeriveFQDNEnforcesZoneContainment proves a client can never publish a
// name OUTSIDE the configured domain (the #1387 MAJOR-1 escape boundary).
// Every escape vector — a dotted name in a foreign TLD, a trailing dot, a
// double-dot, a deeper foreign subtree — must yield a name contained in the
// configured zone. Non-tautological: against the pre-fix finalizeFQDN (which
// returned sanitizeFQDN(name) for any dotted name) every one of these cases
// publishes outside example.com and the containment assertion fails.
func TestDeriveFQDNEnforcesZoneContainment(t *testing.T) {
	const domain = "corp.example.com"
	// Each input is a client-controlled name that tries to escape the zone.
	escapeInputs := []struct {
		name   string
		offer  string // the client-controlled name fed to the active source
		want   string // expected published FQDN (must be within domain)
		source string
	}{
		{"foreign tld", "host.attacker.tld", "host.corp.example.com", "client-hostname"},
		{"sibling public domain", "evil.example.net", "evil.corp.example.com", "client-hostname"},
		{"trailing dot foreign", "evil.example.net.", "evil.corp.example.com", "client-hostname"},
		{"double dot", "a..evil.net", "a.corp.example.com", "client-hostname"},
		{"deep foreign subtree", "a.b.c.attacker.tld", "a.corp.example.com", "client-hostname"},
		{"fqdn source foreign", "evil.attacker.tld", "evil.corp.example.com", "fqdn"},
	}
	for _, tc := range escapeInputs {
		t.Run(tc.name, func(t *testing.T) {
			// Route the client-controlled name through whichever source is
			// active: the client-FQDN option for source=fqdn, the host-name
			// option otherwise.
			host, clientFQDN := tc.offer, ""
			if tc.source == "fqdn" {
				host, clientFQDN = "ignored", tc.offer
			}
			got, err := deriveFQDN(host, clientFQDN, "mac:aa", domain, tc.source)
			if err != nil {
				t.Fatalf("deriveFQDN error: %v", err)
			}
			// The cardinal assertion: the result is contained in the zone.
			if got != domain && !strings.HasSuffix(got, "."+domain) {
				t.Fatalf("name %q ESCAPED zone %q (derived from %q)", got, domain, tc.offer)
			}
			if tc.want != "" && got != tc.want {
				t.Fatalf("deriveFQDN = %q, want %q", got, tc.want)
			}
		})
	}

	// A within-zone MULTI-label name is no longer preserved verbatim
	// (#14996, D40-02): it is relabeled to its first label under the zone.
	got, err := deriveFQDN("host.dept.corp.example.com", "", "mac:aa", domain, "client-hostname")
	if err != nil {
		t.Fatal(err)
	}
	if got != "host.corp.example.com" {
		t.Fatalf("multi-label within-zone name not relabeled to single label: %q", got)
	}
	// A within-zone SINGLE-label name is preserved verbatim.
	got, err = deriveFQDN("host.corp.example.com", "", "mac:aa", domain, "client-hostname")
	if err != nil {
		t.Fatal(err)
	}
	if got != "host.corp.example.com" {
		t.Fatalf("single-label within-zone name relabeled: %q", got)
	}
}

func TestSanitizeLabelTrimsAndCaps(t *testing.T) {
	if got := sanitizeLabel("-foo-"); got != "foo" {
		t.Fatalf("trim dashes: got %q", got)
	}
	long := ""
	for i := 0; i < 80; i++ {
		long += "a"
	}
	if got := sanitizeLabel(long); len(got) != maxDNSLabel {
		t.Fatalf("cap: got len %d want %d", len(got), maxDNSLabel)
	}
	if got := sanitizeLabel("___"); got != "" {
		t.Fatalf("all-illegal: got %q", got)
	}
}

// ---- PTR byte-order ----

func TestReversePTRName(t *testing.T) {
	v4 := reversePTRName(netip.MustParseAddr("192.0.2.5"))
	if v4 != "5.2.0.192.in-addr.arpa" {
		t.Fatalf("v4 PTR = %q", v4)
	}
	// 2001:db8::1 -> 32 reversed nibbles + ip6.arpa
	v6 := reversePTRName(netip.MustParseAddr("2001:db8::1"))
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if v6 != want {
		t.Fatalf("v6 PTR =\n %q\nwant\n %q", v6, want)
	}
}

func TestBuildLeaseRecordFamilyAndTTLDefault(t *testing.T) {
	rec, err := buildLeaseRecord("h.example.com", "10.0.0.5", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ForwardType != "A" || rec.TTL != defaultDDNSTTL {
		t.Fatalf("v4 record wrong: %+v", rec)
	}
	rec6, err := buildLeaseRecord("h.example.com", "2001:db8::5", 120)
	if err != nil {
		t.Fatal(err)
	}
	if rec6.ForwardType != "AAAA" || rec6.TTL != 120 {
		t.Fatalf("v6 record wrong: %+v", rec6)
	}
	if _, err := buildLeaseRecord("h", "not-an-ip", 60); err == nil {
		t.Fatal("expected error for invalid address")
	}
}

// ---- reconciler transitions ----

func TestReconcileAddsActiveLeases(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{
		leaseV4("10.0.0.10", "mac:aa", "host-a"),
		leaseV4("10.0.0.11", "mac:bb", "host-b"),
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := up.upsertNames()
	want := []string{"host-a.example.com=10.0.0.10", "host-b.example.com=10.0.0.11"}
	if !equalStr(got, want) {
		t.Fatalf("upserts = %v want %v", got, want)
	}
	// Idempotent: a second reconcile with the same leases adds nothing.
	up.upserts = nil
	if err := runReconcile(t, m, pol, []Lease{
		leaseV4("10.0.0.10", "mac:aa", "host-a"),
		leaseV4("10.0.0.11", "mac:bb", "host-b"),
	}); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if n := len(up.upserts); n != 0 {
		t.Fatalf("idempotent reconcile re-upserted %d records", n)
	}
}

// runReconcileForce drives one reconcile pass with the operator force-now latch
// engaged (env.force = true, #5710), the in-engine analogue of `request system
// dynamic-dns update` reaching the DHCP Surface-B path. It is otherwise
// identical to runReconcile (nil gate/resolver ⇒ all scopes writable).
func runReconcileForce(t *testing.T, m *Manager, pol ddnsPolicy, leases []Lease) error {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	env := &reconcileEnv{
		pol:     [2]ddnsPolicy{pol, pol},
		updater: [2]DNSUpdater{m.updater, m.updater},
		force:   true,
	}
	return m.reconcileOnceLocked(context.Background(), env, leases, nil, nil)
}

// TestReconcileForceRepublishesUnchangedRecord is the #5710 (M37) fail-on-revert
// guard: an operator `request system dynamic-dns update` must FORCE the wire
// upsert of a DHCP DDNS record even when its content is unchanged, so a drifted
// or manually-deleted authoritative RR can be repaired. The routine reconcile
// path deliberately SKIPS an unchanged record (change-detection efficiency); the
// forced pass must NOT. Neutralizing the force path (dropping the `!env.force`
// guard on the Pass-1 unchanged-skip) makes the forced pass skip too and this
// test goes RED (0 re-upserts).
func TestReconcileForceRepublishesUnchangedRecord(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	lease := []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}

	// Initial publish.
	if err := runReconcile(t, m, pol, lease); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if got := up.upsertNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("initial upserts = %v", got)
	}

	// Routine reconcile with unchanged content: the efficiency short-circuit
	// skips the wire upsert. This is the behaviour the forced path contrasts
	// against — assert it stays a no-op so the test proves force is what makes
	// the difference (not some unrelated re-publish).
	up.upserts = nil
	if err := runReconcile(t, m, pol, lease); err != nil {
		t.Fatalf("reconcile 2 (unchanged, no force): %v", err)
	}
	if n := len(up.upserts); n != 0 {
		t.Fatalf("routine reconcile re-upserted unchanged record %d time(s); want 0", n)
	}

	// Forced reconcile with the SAME unchanged content: must re-assert the RR
	// onto the wire despite the unchanged-content short-circuit.
	up.upserts = nil
	if err := runReconcileForce(t, m, pol, lease); err != nil {
		t.Fatalf("reconcile 3 (unchanged, forced): %v", err)
	}
	if got := up.upsertNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("forced reconcile upserts = %v; want the unchanged record re-published", got)
	}
}

// TestForceRefreshLatchArmsNextPass proves the ForceRefresh() latch is one-shot
// and consumed via the full ReconcileScoped entry point (the daemon's arming
// path), not only the reconcileOnceLocked seam: after ForceRefresh() a single
// reconcile re-upserts the unchanged record, and the pass AFTER it (latch
// cleared) reverts to the skip-unchanged behaviour.
func TestForceRefreshLatchArmsNextPass(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", TTLSeconds: 300,
		},
	}
	// Seed a lease the parser will return. testDDNS wires a nil parser, so drive
	// the desired set directly through reconcileOnceLocked for the initial
	// publish, then exercise the ForceRefresh()+ReconcileScoped arming path
	// (which reads leases via the parser — nil parser ⇒ empty). To keep the
	// record OWNED across the empty-lease passes we assert on the latch, not on
	// re-publish here; the wire-upsert force semantics are covered by
	// TestReconcileForceRepublishesUnchangedRecord above.
	if err := runReconcile(t, m, enabledPolicy(), []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatalf("seed reconcile: %v", err)
	}
	// Arm the latch; the internal flag must be set and then cleared by the next
	// ReconcileScoped pass.
	m.ForceRefresh()
	m.mu.Lock()
	armed := m.forceNext
	m.mu.Unlock()
	if !armed {
		t.Fatal("ForceRefresh did not arm forceNext")
	}
	if err := m.ReconcileScoped(context.Background(), cfg, ReconcileOptions{}); err != nil {
		t.Fatalf("forced ReconcileScoped: %v", err)
	}
	m.mu.Lock()
	stillArmed := m.forceNext
	m.mu.Unlock()
	if stillArmed {
		t.Fatal("forceNext latch not consumed by the reconcile pass (should be one-shot)")
	}
}

func TestReconcileExpireDeletesOwnedRecord(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Lease gone -> record deleted.
	if err := runReconcile(t, m, pol, nil); err != nil {
		t.Fatal(err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("deletes = %v", got)
	}
	if n := len(m.state.records); n != 0 {
		t.Fatalf("owned state not cleared after delete: %d", n)
	}
}

func TestReconcileClientMovesAddress(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Same client (mac:aa), new address.
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.20", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("old address not deleted on move: deletes=%v", got)
	}
	// New address added.
	found := false
	for _, r := range up.upserts {
		if r.Addr.String() == "10.0.0.20" {
			found = true
		}
	}
	if !found {
		t.Fatalf("new address not added on move: upserts=%v", up.upsertNames())
	}
}

func TestReconcileAddressReassignedToNewClient(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	// Client A holds 10.0.0.10.
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Same address now leased to client B with a different name. Old
	// owner must be cleaned before the new owner is added.
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:bb", "host-b")}); err != nil {
		t.Fatal(err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("old owner not cleaned on reassign: deletes=%v", got)
	}
	gotUp := false
	for _, r := range up.upserts {
		if r.FQDN == "host-b.example.com" && r.Addr.String() == "10.0.0.10" {
			gotUp = true
		}
	}
	if !gotUp {
		t.Fatalf("new owner not added on reassign: upserts=%v", up.upsertNames())
	}
}

func TestReconcileDeleteFailureBlocksReplacementUpsert(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}

	up.upserts = nil
	up.deletes = nil
	up.failDel["host-a.example.com"] = true
	err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:bb", "host-b")})
	if err == nil {
		t.Fatal("expected delete failure")
	}
	if n := len(up.upserts); n != 0 {
		t.Fatalf("replacement upserted despite failed cleanup: %v", up.upsertNames())
	}
	if n := len(up.deletes); n != 0 {
		t.Fatalf("unexpected successful delete despite injected failure: %v", up.deleteNames())
	}
	if m.deleteFail.Load() != 1 {
		t.Fatalf("deleteFail = %d, want 1", m.deleteFail.Load())
	}
	if _, ok := m.state.get(ScopeKey{}, "mac:aa", "10.0.0.10"); !ok {
		t.Fatal("old ownership entry dropped after failed delete")
	}

	delete(up.failDel, "host-a.example.com")
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:bb", "host-b")}); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("retry cleanup delete calls = %v", got)
	}
	if m.deleteOK.Load() != 1 {
		t.Fatalf("deleteOK = %d, want 1", m.deleteOK.Load())
	}
	if got := up.upsertNames(); !equalStr(got, []string{"host-b.example.com=10.0.0.10"}) {
		t.Fatalf("replacement upserts = %v", got)
	}
	if _, ok := m.state.get(ScopeKey{}, "mac:aa", "10.0.0.10"); ok {
		t.Fatal("old ownership entry still present after successful retry")
	}
}

// TestReconcileNeverDeletesNonOwned proves the cardinal-sin boundary: a
// record that was never recorded as owned is never deleted, even when a
// lease for that address/name disappears between reconciles. We seed the
// store via reconcile, then DELETE the store entry out from under the
// manager (simulating a record the firewall does not own) and confirm a
// subsequent expire issues NO delete for it.
func TestReconcileNeverDeletesNonOwned(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	// Forget ownership (as if this record belongs to someone else).
	m.mu.Lock()
	m.state.records = map[string]ownedRecord{}
	m.mu.Unlock()
	up.deletes = nil
	// Lease disappears: with no owned entry, nothing must be deleted.
	if err := runReconcile(t, m, pol, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(up.deletes); n != 0 {
		t.Fatalf("deleted %d non-owned records (cardinal sin)", n)
	}
}

// TestReconcileRetryDoesNotWedge proves a permanently-failing updater does
// not wedge the loop: reconcile returns the error but completes, and a
// later reconcile after the updater recovers makes progress.
func TestReconcileRetryDoesNotWedge(t *testing.T) {
	up := newFakeUpdater()
	up.failEvery = true
	m := testDDNS(t, up)
	pol := enabledPolicy()
	lease := []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}

	for i := 0; i < 3; i++ {
		err := runReconcile(t, m, pol, lease)
		if err == nil {
			t.Fatalf("iter %d: expected error from failing updater", i)
		}
	}
	if m.upsertFail.Load() < 3 {
		t.Fatalf("upsertFail = %d, want >= 3", m.upsertFail.Load())
	}
	// Nothing got recorded as owned (no successful upsert).
	if n := len(m.state.records); n != 0 {
		t.Fatalf("owned state populated despite all upserts failing: %d", n)
	}
	// Updater recovers: now the record is published.
	up.failEvery = false
	if err := runReconcile(t, m, pol, lease); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if n := len(m.state.records); n != 1 {
		t.Fatalf("owned state not populated after recovery: %d", n)
	}
}

// TestReconcileSkipsUnnamedLease: a lease with no host-name and the
// default source is skipped (counted), not published with junk.
func TestReconcileSkipsUnnamedLease(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "")}); err != nil {
		t.Fatal(err)
	}
	if n := len(up.upserts); n != 0 {
		t.Fatalf("published %d records for an unnamed lease", n)
	}
	if m.skippedNoName.Load() != 1 {
		t.Fatalf("skippedNoName = %d, want 1", m.skippedNoName.Load())
	}
}

// TestWithdrawOnDisable: when the feature is turned off, owned records are
// withdrawn from DNS.
func TestWithdrawOnDisable(t *testing.T) {
	up := newFakeUpdater()
	m := testDDNS(t, up)
	pol := enabledPolicy()
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatal(err)
	}
	up.deletes = nil
	// Disabled policy -> withdraw all.
	m.mu.Lock()
	err := m.withdrawAllLocked(context.Background())
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := up.deleteNames(); !equalStr(got, []string{"host-a.example.com=10.0.0.10"}) {
		t.Fatalf("withdraw deletes = %v", got)
	}
	if n := len(m.state.records); n != 0 {
		t.Fatalf("owned state not cleared on withdraw: %d", n)
	}
}

// TestNilUpdaterIsNopNotPanic proves the #1387 MAJOR-2 boundary: increment 1
// defers the live backend, so a manager built with a nil DNSUpdater must run
// as a logged no-op, NOT panic on the first publish or on a withdraw. Against
// the pre-fix code (m.updater.UpsertLease called unguarded on a nil
// interface) the enabled reconcile panics with a nil-pointer dereference, so
// this test is non-tautological.
func TestNilUpdaterIsNopNotPanic(t *testing.T) {
	// Construction with nil must not panic and must substitute a no-op
	// backend (the production constructor path).
	prod := NewManager(nil, nil, "node0")
	if prod.updater == nil {
		t.Fatal("NewManager(nil, nil, ...) left a nil updater")
	}
	if !isNopUpdater(prod.updater) {
		t.Fatalf("NewManager(nil, nil, ...) did not install a nopUpdater: %T", prod.updater)
	}

	// Enabled reconcile + withdraw on a manager with no live backend: both
	// must complete without panicking. Use the testing constructor so the
	// state/lease paths are temp dirs.
	m := testDDNS(t, nil) // nil -> nopUpdater
	if !isNopUpdater(m.updater) {
		t.Fatalf("nil updater not converted to nopUpdater: %T", m.updater)
	}
	pol := enabledPolicy()

	// Publish path: an active lease must be processed (logged-skipped), with
	// NO ownership recorded for a record that never reached a real backend.
	if err := runReconcile(t, m, pol, []Lease{leaseV4("10.0.0.10", "mac:aa", "host-a")}); err != nil {
		t.Fatalf("reconcile with no backend errored: %v", err)
	}
	if n := len(m.state.records); n != 0 {
		t.Fatalf("no-backend reconcile recorded %d phantom ownership entries", n)
	}
	if m.skippedNoBackend.Load() == 0 {
		t.Fatal("no-backend upsert was not counted as skipped")
	}
	if m.upsertOK.Load() != 0 {
		t.Fatalf("no-backend upsert counted as upsertOK = %d", m.upsertOK.Load())
	}

	// Withdraw path: disabling DDNS while owned state exists must be a safe
	// no-op on the wire, but it must NOT drop ownership through the no-op
	// backend (#2699). A record reaching the store was published by a real
	// backend (the nop upsert path records no ownership), so forgetting it
	// while the live RR persists would orphan it. The withdraw-all keeps the
	// entry so a later reconcile with a real backend can clean it.
	m.mu.Lock()
	m.state.put(ownedRecord{
		Family: 4, Identity: "mac:bb", Address: "10.0.0.20",
		FQDN: "host-b.example.com", ForwardType: "A",
		PTRName: "20.0.0.10.in-addr.arpa", TTL: 300,
	})
	err := m.withdrawAllLocked(context.Background())
	m.mu.Unlock()
	if err != nil {
		// withdrawAllLocked swallows errDDNSNoBackendToWithdraw (it is the
		// legitimate disabled-with-no-backend case), so no error is surfaced.
		t.Fatalf("withdraw with no backend errored: %v", err)
	}
	if _, ok := m.state.get(ScopeKey{}, "mac:bb", "10.0.0.20"); !ok {
		t.Fatal("#2699 regression: no-backend withdraw DROPPED ownership; " +
			"the live RR is now orphaned (unrecoverable)")
	}
	if m.deleteFail.Load() == 0 {
		t.Fatal("#2699: no-backend withdraw should count a deleteFail (delete owed but no backend)")
	}
}

// TestReconcileParseErrorSuppressesFamilyDeletes proves the #1387 MAJOR-4
// fail-safe: when a family's lease CSV cannot be parsed, that family's lease
// set is unreliable, so the reconciler must NOT delete its owned records (a
// transient malformed CSV would otherwise mass-delete every valid record of
// that family). The v6 family, whose CSV is fine, is unaffected. Against the
// pre-fix Reconcile (which logged the parse error then reconciled with the
// nil/partial set) the owned v4 record looks expired and is deleted, so this
// test fails pre-fix.
// TestReconcileParseErrorSuppressesFamilyDeletes exercises the engine's
// untrusted-family fail-safe: when a family's LeaseParser returns an error,
// that family's destructive diff is suppressed (no deletes) and the error is
// surfaced, while a healthy family reconciles normally. #2691 P1a moved the
// engine to pkg/ddns and replaced the internal Kea-memfile parse with the
// LeaseParser seam, so this test injects a parser that errors for family 4 and
// succeeds for family 6 — the SAME engine behavior the dhcpserver-resident
// version asserted via the real Kea parser (whose CSV-specific parse-error
// detection stays covered verbatim by the parser tests in pkg/dhcpserver).
func TestReconcileParseErrorSuppressesFamilyDeletes(t *testing.T) {
	up := newFakeUpdater()
	dir := t.TempDir()

	v4OK := []Lease{{Family: 4, Address: "10.0.0.10", Identity: "mac:aa", HostName: "host-a", SubnetID: "1"}}
	v6OK := []Lease{{Family: 6, Address: "2001:db8::5", Identity: "duid:00:01/7", HostName: "host-6", SubnetID: "1"}}

	// v4Broken flips on for cycle 2: the v4 parser then returns an error
	// (unreadable source) so the engine must mark family 4 untrusted.
	v4Broken := false
	parser := func(_ string, family int, _ time.Time) ([]Lease, error) {
		switch family {
		case 4:
			if v4Broken {
				return nil, fmt.Errorf("fake: v4 lease source unreadable")
			}
			return v4OK, nil
		default:
			return v6OK, nil
		}
	}

	m := newManagerForTesting(
		parser,
		up,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)

	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
		},
	}

	// Cycle 1: a valid v4 lease and a valid v6 lease -> both published+owned.
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("cycle 1 reconcile: %v", err)
	}
	if n := len(m.state.records); n != 2 {
		t.Fatalf("cycle 1 owned records = %d, want 2", n)
	}

	// Cycle 2: the v4 parser errors (unreadable source); the v6 parser is
	// still healthy. The v4 owned record must be PRESERVED (no delete); the
	// reconcile must surface the parse error.
	up.deletes = nil
	v4Broken = true
	err := m.Reconcile(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected the v4 parse error to be surfaced")
	}
	// No v4 deletes at all this cycle.
	for _, d := range up.deletes {
		if d.Addr.Is4() {
			t.Fatalf("v4 record deleted despite unreadable lease source: %s", d.FQDN)
		}
	}
	// The v4 owned record is still in the store.
	if _, ok := m.state.get(ScopeKey{}, "mac:aa", "10.0.0.10"); !ok {
		t.Fatal("v4 owned record dropped after a v4 parse error (mass-delete bug)")
	}
	// The healthy v6 owned record is also still present (active this cycle).
	if _, ok := m.state.get(ScopeKey{}, "duid:00:01/7", "2001:db8::5"); !ok {
		t.Fatal("healthy v6 owned record lost while v4 was untrusted")
	}
}

// ---- state store persistence ----

func TestStateStorePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	s, err := loadDDNSState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	s.put(ownedRecord{Family: 4, Identity: "mac:aa", Address: "10.0.0.10", FQDN: "h.example.com", ForwardType: "A", PTRName: "10.0.0.10.in-addr.arpa", TTL: 300})
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	s2, err := loadDDNSState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := s2.get(ScopeKey{}, "mac:aa", "10.0.0.10"); !ok || r.FQDN != "h.example.com" {
		t.Fatalf("reload lost record: %+v ok=%v", r, ok)
	}
}

func TestStateStoreCorruptReturnsEmptyStoreClassifiedError(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	writeCSV(t, statePath, "{ this is not json")
	s, err := loadDDNSState(statePath)
	if err == nil {
		t.Fatal("expected an error for corrupt state")
	}
	// #2650: the error must be CLASSIFIED corrupt so the manager can fail closed.
	if !errors.Is(err, errDDNSStateCorrupt) {
		t.Fatalf("corrupt store error must wrap errDDNSStateCorrupt, got %v", err)
	}
	if s == nil || len(s.records) != 0 {
		t.Fatalf("corrupt store must return an empty store, got %+v", s)
	}
}

// TestStateStoreUnsupportedVersionClassifiedError proves a state file with an
// unknown (future) non-zero Version returns an EMPTY store plus a CLASSIFIED
// unsupported-version error (#2650) — never silently decoding records that may
// carry a different tuple shape into wrong-tuple deletes, and never silently
// trusting the empty store. No panic. Against the pre-#2691 loader (which never
// checked Version) the records load and would be trusted, so this fails pre-fix.
func TestStateStoreUnsupportedVersionClassifiedError(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	// A syntactically-valid state file from a FUTURE format version, with a
	// record. The current loader must NOT trust it.
	writeCSV(t, statePath, `{"version":99,"records":[{"family":4,"identity":"mac:aa","address":"10.0.0.10","fqdn":"h.example.com","forward_type":"A","ptr_name":"10.0.0.10.in-addr.arpa","ttl":300}]}`)
	s, err := loadDDNSState(statePath)
	if err == nil {
		t.Fatal("expected an error for an unsupported state version")
	}
	if !errors.Is(err, errDDNSStateUnsupportedVersion) {
		t.Fatalf("unsupported-version error must wrap errDDNSStateUnsupportedVersion, got %v", err)
	}
	if s == nil {
		t.Fatal("loadDDNSState returned nil store on unsupported version (must be empty store)")
	}
	if len(s.records) != 0 {
		t.Fatalf("unsupported version must return an empty store (no wrong-tuple records), got %d records", len(s.records))
	}

	// A version-0 (pre-versioning / zero-value) file is tolerated and its
	// records load — the field was absent or defaulted, not a future format.
	v0path := filepath.Join(dir, "state-v0.json")
	writeCSV(t, v0path, `{"records":[{"family":4,"identity":"mac:bb","address":"10.0.0.20","fqdn":"h2.example.com","forward_type":"A","ptr_name":"20.0.0.10.in-addr.arpa","ttl":300}]}`)
	s0, err := loadDDNSState(v0path)
	if err != nil {
		t.Fatalf("version-0 store must load, got error: %v", err)
	}
	if _, ok := s0.get(ScopeKey{}, "mac:bb", "10.0.0.20"); !ok {
		t.Fatal("version-0 store should load its records")
	}
}

// TestCorruptStateFailsClosedRefusingAllOps is the #2650 fail-on-revert test:
// a corrupt ownership state file must put the manager into the DEGRADED
// (fail-closed) state — it refuses to publish AND to withdraw any record, never
// silently resetting to an empty store and reconciling-from-empty (which would
// leak previously-owned records and could overwrite a peer-owned name). It also
// proves the bad file is quarantined (preserved, not overwritten) and the alarm
// is surfaced in Stats. Reverting loadStateOrDegrade to the old fail-open path
// (treat the empty store as trusted, no degraded flag) makes this test RED: the
// reconcile would publish the lease and the assertions on no-ops + degraded fail.
func TestCorruptStateFailsClosedRefusingAllOps(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	// A corrupt store left behind by a crash / disk fault.
	writeCSV(t, statePath, "{ this is not valid json at all")

	src := &fakeLeaseSource{v4: laptopMacLease()}
	up := newFakeUpdater()
	m := newManagerForTesting(
		src.parser(),
		up,
		statePath,
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)

	// Degraded must be set at construction, and surfaced in Stats.
	if !m.degraded {
		t.Fatal("manager must be DEGRADED after loading a corrupt state file")
	}
	if st := m.Stats(); !st.Degraded || st.DegradedReason == "" {
		t.Fatalf("Stats must report Degraded with a reason, got %+v", st)
	}

	// The corrupt file must be quarantined aside (preserved for inspection),
	// not left in place to be overwritten by a later save.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("corrupt state file must be quarantined (renamed away); stat err=%v", err)
	}
	matches, _ := filepath.Glob(statePath + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("expected exactly one quarantined copy, found %v", matches)
	}

	// A reconcile with an ENABLED config + a live lease must FAIL CLOSED: no
	// publish, no withdraw, an error returned, and the state file NOT recreated.
	cfg := &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled:    true,
			Domain:     "example.com",
			TTLSeconds: 300,
		},
	}
	err := m.Reconcile(context.Background(), cfg)
	if err == nil {
		t.Fatal("reconcile must return an error while degraded (fail closed)")
	}
	if names := up.upsertNames(); len(names) != 0 {
		t.Fatalf("degraded manager must NOT publish any record, got upserts %v", names)
	}
	if names := up.deleteNames(); len(names) != 0 {
		t.Fatalf("degraded manager must NOT withdraw any record, got deletes %v", names)
	}
	// The reconcile must NOT have written a fresh (empty) state file — that
	// would erase the only signal that ownership was lost.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("degraded manager must not recreate the ownership state file")
	}
	// The pass is counted as a failure so an operator watching ReconcileFail /
	// the degraded gauge sees the suspension.
	if st := m.Stats(); st.ReconcileFail == 0 {
		t.Fatal("a degraded reconcile must count as a reconcile failure")
	}
}

// TestUnsupportedVersionStateFailsClosed proves the unknown-future-version path
// also fails closed + quarantines (the sibling of the corrupt path, #2650).
func TestUnsupportedVersionStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	writeCSV(t, statePath, `{"version":99,"records":[{"family":4,"identity":"mac:aa","address":"10.0.0.10","fqdn":"h.example.com","forward_type":"A","ptr_name":"10.0.0.10.in-addr.arpa","ttl":300}]}`)

	up := newFakeUpdater()
	m := newManagerForTesting(
		(&fakeLeaseSource{}).parser(),
		up,
		statePath,
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	if !m.degraded {
		t.Fatal("unsupported-version state must put the manager into the degraded state")
	}
	// No record from the future-version file leaked into the in-memory store.
	if len(m.state.records) != 0 {
		t.Fatalf("unsupported-version records must not load, got %d", len(m.state.records))
	}
	matches, _ := filepath.Glob(statePath + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("unsupported-version file must be quarantined, found %v", matches)
	}
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
