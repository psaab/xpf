package ddns

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// spine_fixes_test.go — fail-on-revert regressions for the DDNS spine bugs
// re-verified against current master after the #2691 P0-P3 redesign:
//
//   - #2699: deleteOwnedLocked must NOT drop ownership through the no-op
//     backend after a restart / backend removal (orphaning the live RR).
//   - #2700: a partial dual-stack teardown must KEEP the shared RFC 4701
//     DHCID so the surviving family's record stays protected and its later
//     delete still satisfies the DHCID-match prerequisite.
//   - #2708: PTRPending must be exposed per owned record (view + current
//     gauge), not just the cumulative PTRDeferred lifetime counter.
//
// The teardown tests drive the REAL rfc2136 backend against the in-process
// stateful fake DNS server (the #2691 P2 lesson: a fakeUpdater that bypasses
// the ownership/wire logic cannot prove an orphan/hijack bug). Reverting any
// of the three fixes makes the matching test fail.

// dualStackLease pairs a v4 + a v6 lease under the SAME host-name with
// PRODUCTION-SHAPED identities (#14602): the v4 lease carries the
// `cid:` identity identity4 produces and the v6 lease the `duid:`
// identity identity6 produces. The two families of one dual-stack host
// therefore digest to DIFFERENT RFC 4701 DHCIDs — there is no single
// shared DHCID across families in production. (The pre-#14602 fixture
// passed one identical string for both families, a shape identity6
// cannot produce; it tested a condition that never occurs.) Each
// family publishes its OWN DHCID, and the manager store is the
// cross-family ownership proof.
func dualStackLease() (v4, v6 []Lease) {
	v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: "cid:01:02:03", SubnetID: "1", HostName: "laptop"}}
	v6 = []Lease{{Family: 6, Address: "2001:db8::5", Identity: "duid:00:01:00:01:22:33:44:55:66:77/16777216", SubnetID: "1", HostName: "laptop"}}
	return v4, v6
}

// dhcidForName builds the DHCID RR the backend would publish for (identity,
// fqdn) so a test can assert its presence/absence in the stateful zone.
func dhcidForName(t *testing.T, identity, fqdn string) *dns.DHCID {
	t.Helper()
	d, ok := dhcidRR(identity, fqdn, 300)
	if !ok {
		t.Fatalf("dhcidRR(%q,%q) returned ok=false", identity, fqdn)
	}
	return d
}

// TestPartialDualStackTeardownKeepsSharedDHCID is the #2700 fail-on-revert
// regression, rewritten with production-shaped identities (#14602). A
// dual-stack client publishes an A and an AAAA under one FQDN; each
// family digests its OWN identity string (`cid:` v4, `duid:` v6) so
// the name carries TWO per-family DHCIDs, not one shared one.
// Releasing only the v4 lease must delete the A and the v4 DHCID but
// KEEP the v6 DHCID (so the surviving AAAA stays ownership-protected);
// releasing the v6 lease afterwards must then delete the AAAA AND its
// now-unshared DHCID, leaving no orphan.
//
// Note: the original #2700 wording ("one shared DHCID")
// described the identical-identity fixture, a shape identity6 cannot
// produce. The #14602 regression test
// (TestDualStackProductionIdentitiesBothPublishReplaceOwned) is the
// publish-side proof with production shapes; this test is the
// teardown-side proof with the same shapes.
func TestPartialDualStackTeardownKeepsSharedDHCID(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	// Independent v4 + v6 blocks (#2663) so both families publish under
	// replace-owned with a DHCID; reuse the same cfg for both.
	cfg.DynamicDNSv6 = cfg.DynamicDNS

	const v4Identity = "cid:01:02:03"
	const v6Identity = "duid:00:01:00:01:22:33:44:55:66:77/16777216"
	const fqdn = "laptop.example.com"
	v4, v6 := dualStackLease()

	// Cycle 1: both families active → A, AAAA, and BOTH per-family
	// DHCIDs published.
	src.v4, src.v6 = v4, v6
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("publish reconcile: %v", err)
	}
	dhcid4 := dhcidForName(t, v4Identity, fqdn)
	dhcid6 := dhcidForName(t, v6Identity, fqdn)
	if !srv.zoneHas(dhcid4) {
		t.Fatal("setup: v4 DHCID was not published")
	}
	if !srv.zoneHas(dhcid6) {
		t.Fatal("setup: v6 DHCID was not published")
	}
	if m.Stats().OwnedRecords != 2 {
		t.Fatalf("want 2 owned records (A+AAAA), got %d", m.Stats().OwnedRecords)
	}

	// Cycle 2: v4 lease released, v6 still active. The A and the v4
	// DHCID are withdrawn but the v6 DHCID MUST survive (the AAAA
	// still needs it for its own delete prerequisite).
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("partial-teardown reconcile: %v", err)
	}
	if !srv.zoneHas(dhcid6) {
		t.Fatal("#2700/#14602 regression: v6 DHCID was deleted on partial dual-stack " +
			"teardown — the surviving AAAA is now unprotected and will leak")
	}
	if srv.zoneHas(dhcid4) {
		t.Fatal("v4 DHCID orphaned after the v4 family released")
	}
	// The A must be gone; the AAAA must remain.
	if hasA := zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeA); hasA {
		t.Fatal("v4 A record was not withdrawn on lease release")
	}
	if hasAAAA := zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeAAAA); !hasAAAA {
		t.Fatal("surviving v6 AAAA was wrongly removed on the v4 teardown")
	}

	// Cycle 3: v6 lease released too → the AAAA must be deleted, AND
	// its (now-unshared) DHCID removed with it, leaving no orphan.
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("final-teardown reconcile: %v", err)
	}
	if zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeAAAA) {
		t.Fatal("#2700: surviving AAAA leaked — its delete failed the DHCID-match prereq")
	}
	if srv.zoneHas(dhcid6) {
		t.Fatal("#2700: v6 DHCID orphaned after the last family released")
	}
	if m.Stats().OwnedRecords != 0 {
		t.Fatalf("want 0 owned records after full teardown, got %d", m.Stats().OwnedRecords)
	}
}

// zoneHasType reports whether the stateful zone holds any RR of rrtype at name.
func zoneHasType(s *fakeDNSServer, name string, rrtype uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.zone[dns.CanonicalName(name)]
	for _, rr := range set {
		if rr.Header().Rrtype == rrtype {
			return true
		}
	}
	return false
}

// TestRestartNoBackendKeepsOwnershipNotOrphan is the #2699 fail-on-revert
// regression at the RECONCILE layer. A real backend publishes a record (so
// ownership is persisted to the store). A FRESH manager is then constructed
// from that persisted store (a daemon restart) with a config that resolves to
// the no-op backend (DDNS disabled / update-server removed). Reconcile must
// KEEP the ownership entry (the live RR stays cleanable), NOT drop it.
//
// Pre-fix (deleteOwnedLocked dropped ownership on isNopUpdater): the restart
// reconcile no-ops the delete but deletes ownership, orphaning the live RR.
func TestRestartNoBackendKeepsOwnershipNotOrphan(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	lease4 := filepath.Join(dir, "leases4.csv")
	lease6 := filepath.Join(dir, "leases6.csv")
	clock := func() time.Time { return time.Unix(1_700_000_000, 0) }

	// --- Process 1: publish via a live backend, persisting ownership. ---
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	src1 := &fakeLeaseSource{}
	m1 := newManagerForTesting(src1.parser(), nopUpdater{}, statePath, lease4, lease6, "node0", clock)
	m1.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		c.UpdateServer = srv.addrUDP
		return newRFC2136Updater(pol, c, nil,
			func() { m1.skippedPTRNotAuth.Add(1) },
			func() { m1.skippedConflict.Add(1) })
	}
	src1.v4 = laptopCIDLease()
	if err := m1.Reconcile(context.Background(), ddnsCfg(srv.addrUDP)); err != nil {
		t.Fatalf("process-1 publish reconcile: %v", err)
	}
	if m1.Stats().OwnedRecords != 1 {
		t.Fatalf("process-1: want 1 owned record, got %d", m1.Stats().OwnedRecords)
	}

	// --- Process 2: fresh manager loads the persisted store; the config now
	// resolves to the no-op backend (DDNS disabled). ---
	src2 := &fakeLeaseSource{} // no leases this process (lease gone too)
	m2 := newManagerForTesting(src2.parser(), nopUpdater{}, statePath, lease4, lease6, "node0", clock)
	if m2.Stats().OwnedRecords != 1 {
		t.Fatalf("process-2: persisted store should load 1 owned record, got %d", m2.Stats().OwnedRecords)
	}
	m2.newUpdater = func(_ ddnsPolicy, _ *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		// No backend resolvable after restart (config removed / no update-server).
		return nopUpdater{}, nil
	}

	// DDNS disabled → withdraw path runs through the resolved no-op backend.
	disabled := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{Enabled: false}}
	if err := m2.Reconcile(context.Background(), disabled); err != nil {
		t.Fatalf("process-2 disabled reconcile errored: %v", err)
	}
	if got := m2.Stats().OwnedRecords; got != 1 {
		t.Fatalf("#2699 regression: restart-with-no-backend DROPPED ownership "+
			"(OwnedRecords=%d, want 1); the live RR is orphaned and unrecoverable", got)
	}
	if m2.Stats().DeleteFail == 0 {
		t.Fatal("#2699: no-backend withdraw should count a deleteFail (delete owed, no backend)")
	}
	// And the RR is still live on the wire (never withdrawn through the nop).
	if !srv.zoneHas(dhcidForName(t, "cid:01:02:03", "laptop.example.com")) {
		t.Fatal("setup: published DHCID missing from zone")
	}

	// --- Process 3: a live backend re-appears → the kept ownership is now
	// withdrawn for real (proves "kept for retry" actually converges). ---
	src3 := &fakeLeaseSource{}
	m3 := newManagerForTesting(src3.parser(), nopUpdater{}, statePath, lease4, lease6, "node0", clock)
	m3.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		c.UpdateServer = srv.addrUDP
		return newRFC2136Updater(pol, c, nil,
			func() { m3.skippedPTRNotAuth.Add(1) },
			func() { m3.skippedConflict.Add(1) })
	}
	// Live backend present but DDNS now disabled (turn-off) → withdraw-all
	// through the live backend resolved for the family.
	disabledLive := &config.DHCPServerConfig{DynamicDNS: &config.DHCPDynamicDNSConfig{
		Enabled: false, Backend: "rfc2136", UpdateServer: srv.addrUDP,
	}}
	if err := m3.Reconcile(context.Background(), disabledLive); err != nil {
		t.Fatalf("process-3 withdraw reconcile: %v", err)
	}
	if got := m3.Stats().OwnedRecords; got != 0 {
		t.Fatalf("process-3: live backend re-appeared but ownership not withdrawn (OwnedRecords=%d)", got)
	}
	if zoneHasType(srv, dns.Fqdn("laptop.example.com"), dns.TypeA) {
		t.Fatal("process-3: the live RR was not actually withdrawn from the zone")
	}
}

// TestPTRPendingExposedPerRecord is the #2708 fail-on-revert regression. A
// reverse PTR add that fails with a non-skippable (SERVFAIL) error leaves the
// forward owned with PTRPending=true. That condition must be visible per record
// (OwnedRecordViews) and as a CURRENT gauge (Stats.PTRPendingNow), distinct
// from the cumulative PTRDeferred. A later successful reconcile clears it.
//
// Pre-fix: OwnedRecordView omitted PTRPending and Stats had no current gauge —
// a half-published record was indistinguishable from a settled one.
func TestPTRPendingExposedPerRecord(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	// Reverse zone SERVFAILs → the PTR add fails with a non-skippable error,
	// so the forward is owned with PTRPending set.
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeServerFailure)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	src.v4 = laptopMacLease()

	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("reconcile (forward ok, PTR deferred): %v", err)
	}

	// The owned-record view must EXPOSE the pending flag (#2708).
	views := m.OwnedRecordViews()
	if len(views) != 1 {
		t.Fatalf("want 1 owned record view, got %d", len(views))
	}
	if !views[0].PTRPending {
		t.Fatal("#2708 regression: OwnedRecordView does not expose PTRPending " +
			"(a half-published record is invisible to operators)")
	}

	// The CURRENT gauge must read 1, distinct from the lifetime counter.
	st := m.Stats()
	if st.PTRPendingNow != 1 {
		t.Fatalf("#2708 regression: PTRPendingNow = %d, want 1 (current pending gauge)", st.PTRPendingNow)
	}
	if st.PTRDeferred == 0 {
		t.Fatal("PTRDeferred (lifetime) should also be >0")
	}

	// Recovery: reverse zone heals → the next reconcile publishes the PTR and
	// clears the pending flag. PTRPendingNow falls back to 0; PTRDeferred (a
	// lifetime counter) stays put — that distinction is the #2708 point.
	srv.clearRcode("1.0.10.in-addr.arpa.")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	views = m.OwnedRecordViews()
	if len(views) == 1 && views[0].PTRPending {
		t.Fatal("#2708: PTRPending not cleared after the PTR finally published")
	}
	if got := m.Stats().PTRPendingNow; got != 0 {
		t.Fatalf("#2708: PTRPendingNow = %d after recovery, want 0", got)
	}
}
