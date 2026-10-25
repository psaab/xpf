package ddns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// legacy_dhcid_16591_test.go — #16591 fail-on-revert regressions:
// pre-#14995 names carry the legacy per-identity DHCID (raw clientID,
// including the IAID-bearing v6 form). The current device digest can
// never match it, so before the fix a renumber / forced refresh was
// refused forever (stale A kept resolving, ownership dropped by the
// manager) and the guarded delete was a counted skip (stale A +
// legacy DHCID orphaned). After the fix Attempt B and the guarded
// delete also accept the legacy digest of the SAME identity, and a
// legacy-matched add replaces the legacy DHCID with the device
// DHCID in the same UPDATE. A foreign (different-identity) DHCID —
// current or legacy-shaped — is still refused.

const legacyHost = "legacy.example.com"

// seedLegacyName seeds the wire as a pre-#14995 build left it: the
// forward RR plus the LEGACY DHCID for identity at fqdn.
func seedLegacyName(t *testing.T, srv *fakeDNSServer, identity, fqdn, addr string) (fwd dns.RR, legacy *dns.DHCID) {
	t.Helper()
	legacy, ok := legacyDHCIDRR(identity, fqdn, 300)
	if !ok {
		t.Fatalf("legacyDHCIDRR(%q) not ok", identity)
	}
	a := net.ParseIP(addr)
	if a.To4() != nil {
		fwd = &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(fqdn), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: a}
	} else {
		fwd = &dns.AAAA{Hdr: dns.RR_Header{Name: dns.Fqdn(fqdn), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: a}
	}
	srv.seedRR(fwd)
	srv.seedRR(legacy)
	return fwd, legacy
}

func deviceDHCID(t *testing.T, identity, fqdn string) *dns.DHCID {
	t.Helper()
	d, ok := dhcidRR(identity, fqdn, 300)
	if !ok {
		t.Fatalf("dhcidRR(%q) not ok", identity)
	}
	return d
}

// TestLegacyDHCIDRenumberMigrates16591 is the backend renumber cell
// for cid:, mac: and duid: (IAID-bearing) identities: a legacy name
// whose address changes must publish the new address, drop the old,
// and converge onto the device DHCID with no conflict counted.
func TestLegacyDHCIDRenumberMigrates16591(t *testing.T) {
	cases := []struct {
		name     string
		identity string
		oldAddr  string
		newAddr  string
		v6       bool
	}{
		{"cid", "cid:0102", "10.0.1.5", "10.0.1.6", false},
		{"mac", "mac:aa:bb:cc:dd:ee:ff", "10.0.1.5", "10.0.1.6", false},
		{"duid-iaid", "duid:00:03:00:01:aa:bb:cc:dd:ee:ff/16777216", "2001:db8::5", "2001:db8::6", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeDNSServer(t, nil)
			srv.setStateful(true)
			var ptr, conf int
			u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
				Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
			}, &ptr, &conf)
			oldFwd, legacy := seedLegacyName(t, srv, tc.identity, legacyHost, tc.oldAddr)
			recFn := recV4ID
			if tc.v6 {
				recFn = func(fqdn, addr, id string, ttl int) LeaseDNSRecord {
					r := recV6(fqdn, addr, ttl)
					r.ClientID = id
					return r
				}
			}
			if err := u.UpsertLease(context.Background(), recFn(legacyHost, tc.newAddr, tc.identity, 300)); err != nil {
				t.Fatalf("renumber upsert over legacy DHCID: %v", err)
			}
			if conf != 0 {
				t.Errorf("legacy renumber counted as conflict: %d", conf)
			}
			var newFwd dns.RR
			if tc.v6 {
				newFwd = &dns.AAAA{Hdr: dns.RR_Header{Name: legacyHost + ".", Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP(tc.newAddr)}
			} else {
				newFwd = &dns.A{Hdr: dns.RR_Header{Name: legacyHost + ".", Rrtype: dns.TypeA}, A: net.ParseIP(tc.newAddr)}
			}
			if !srv.zoneHas(newFwd) {
				t.Errorf("new address %s not published", tc.newAddr)
			}
			// The migration UPDATE inserts the new RR; the old RR
			// is removed by the manager's Pass-1 delete in the
			// real flow — at the backend a refresh add leaves the
			// old RR until that delete, which must now succeed
			// (proven by the delete cells). Here assert DHCID
			// convergence: device present, legacy gone.
			_ = oldFwd
			if !srv.zoneHas(deviceDHCID(t, tc.identity, legacyHost)) {
				t.Errorf("device DHCID not published after legacy migration")
			}
			if srv.zoneHas(legacy) {
				t.Errorf("legacy DHCID still present after migration (want replaced in same UPDATE)")
			}
			// Forced refresh (same address) must also succeed.
			if err := u.UpsertLease(context.Background(), recFn(legacyHost, tc.newAddr, tc.identity, 300)); err != nil {
				t.Fatalf("forced refresh after migration: %v", err)
			}
		})
	}
}

// TestLegacyDHCIDForcedRefreshAndDelete16591 covers refresh at the
// same address and the guarded delete of a never-refreshed legacy
// name: both must succeed and leave nothing behind.
func TestLegacyDHCIDForcedRefreshAndDelete16591(t *testing.T) {
	for _, identity := range []string{"cid:0102", "mac:aa:bb:cc:dd:ee:ff", "duid:00:03:00:01:aa:bb:cc:dd:ee:ff/16777216"} {
		srv := newFakeDNSServer(t, nil)
		srv.setStateful(true)
		var ptr, conf int
		u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
		}, &ptr, &conf)
		isV6 := len(identity) > 5 && identity[:5] == "duid:"
		addr := "10.0.1.5"
		if isV6 {
			addr = "2001:db8::5"
		}
		fwd, legacy := seedLegacyName(t, srv, identity, legacyHost, addr)
		recFn := recV4ID
		if isV6 {
			recFn = func(fqdn, a, id string, ttl int) LeaseDNSRecord {
				r := recV6(fqdn, a, ttl)
				r.ClientID = id
				return r
			}
		}
		// Forced refresh: same tuple, legacy DHCID on the wire.
		if err := u.UpsertLease(context.Background(), recFn(legacyHost, addr, identity, 300)); err != nil {
			t.Fatalf("[%s] forced refresh over legacy DHCID: %v", identity, err)
		}
		if srv.zoneHas(legacy) {
			t.Fatalf("[%s] legacy DHCID survived refresh migration", identity)
		}
		if !srv.zoneHas(deviceDHCID(t, identity, legacyHost)) {
			t.Fatalf("[%s] device DHCID missing after refresh", identity)
		}
		// Delete after migration (device prerequisite).
		if err := u.DeleteLease(context.Background(), recFn(legacyHost, addr, identity, 300)); err != nil {
			t.Fatalf("[%s] delete after migration: %v", identity, err)
		}
		if srv.zoneHas(fwd) || srv.zoneHas(deviceDHCID(t, identity, legacyHost)) {
			t.Fatalf("[%s] records leaked after post-migration delete", identity)
		}

		// Fresh legacy name, delete WITHOUT any refresh: the
		// guarded delete must match the legacy prerequisite.
		srv2 := newFakeDNSServer(t, nil)
		srv2.setStateful(true)
		var ptr2, conf2 int
		u2 := testUpdater(t, srv2, &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
		}, &ptr2, &conf2)
		fwd2, legacy2 := seedLegacyName(t, srv2, identity, legacyHost, addr)
		if err := u2.DeleteLease(context.Background(), recFn(legacyHost, addr, identity, 300)); err != nil {
			t.Fatalf("[%s] legacy delete: %v", identity, err)
		}
		if conf2 != 0 {
			t.Fatalf("[%s] legacy delete counted as conflict skip: %d", identity, conf2)
		}
		if srv2.zoneHas(fwd2) {
			t.Fatalf("[%s] legacy A/AAAA leaked after delete", identity)
		}
		if srv2.zoneHas(legacy2) {
			t.Fatalf("[%s] legacy DHCID orphaned after delete", identity)
		}
	}
}

// TestLegacyDHCIDForeignStillRefused16591 is the negative control: a
// DHCID of a DIFFERENT identity — device-shaped or legacy-shaped —
// must still refuse the add, count the conflict, stay untouched by
// a delete, and record no ownership.
func TestLegacyDHCIDForeignStillRefused16591(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)

	foreign := "cid:FOREIGN"
	fwd, foreignLegacy := seedLegacyName(t, srv, foreign, legacyHost, "10.0.1.50")
	_ = foreignLegacy
	// Also seed the foreign DEVICE dhcid shape would be distinct;
	// the wire carries only the legacy one here.
	mine := "cid:MINE16591"
	if err := u.UpsertLease(context.Background(), recV4ID(legacyHost, "10.0.1.51", mine, 300)); !errors.Is(err, errDDNSConflictRefused) {
		t.Fatalf("add over foreign legacy DHCID must refuse; got %v", err)
	}
	if conf == 0 {
		t.Errorf("foreign legacy collision must be counted")
	}
	if !srv.zoneHas(fwd) {
		t.Errorf("foreign record touched by refused add")
	}
	if srv.zoneHas(deviceDHCID(t, mine, legacyHost)) {
		t.Errorf("refused add wrote our DHCID (adoption)")
	}
	confBefore := conf
	if err := u.DeleteLease(context.Background(), recV4ID(legacyHost, "10.0.1.51", mine, 300)); err != nil {
		t.Fatalf("delete over foreign name must be counted skip, not error: %v", err)
	}
	if conf <= confBefore {
		t.Errorf("foreign delete must count the skip")
	}
	if !srv.zoneHas(fwd) || !srv.zoneHas(foreignLegacy) {
		t.Fatalf("foreign records deleted by our delete")
	}
}

// TestLegacyDHCIDCurrentDigestControl16591: a name already on the
// device digest behaves exactly as before (refresh succeeds, no
// legacy RR ever appears).
func TestLegacyDHCIDCurrentDigestControl16591(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)
	identity := "cid:0102"
	a := &dns.A{Hdr: dns.RR_Header{Name: legacyHost + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.1.9")}
	srv.seedRR(a)
	srv.seedRR(deviceDHCID(t, identity, legacyHost))
	if err := u.UpsertLease(context.Background(), recV4ID(legacyHost, "10.0.1.9", identity, 300)); err != nil {
		t.Fatalf("current-digest refresh: %v", err)
	}
	if conf != 0 {
		t.Errorf("current-digest refresh counted conflict: %d", conf)
	}
	if legacy, ok := legacyDHCIDRR(identity, legacyHost, 300); ok && srv.zoneHas(legacy) {
		t.Errorf("legacy DHCID appeared on a current-digest name")
	}
}

// TestManagerLegacyRenumber16591 is the acceptance probe: a legacy
// wire name whose lease renumbers must end old=false new=true
// ownedAfter=1, then tear down cleanly (no orphan DHCID). Pre-fix
// Pass 1's delete was a counted skip yet dropped ownership, and
// Pass 2's add was refused and deleted the intent — old stayed
// true, new stayed false, owned fell to 0.
func TestManagerLegacyRenumber16591(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	const identity = "cid:01000000000001" // Ethernet client-id -> mac pairing
	const fqdn = "legacyhost.example.com"
	fwd, legacy := seedLegacyName(t, srv, identity, fqdn, "10.0.0.10")
	_ = fwd
	// Ownership as the pre-upgrade build recorded it.
	m.mu.Lock()
	m.state.put(ownedRecord{FQDN: fqdn, Address: "10.0.0.10", ForwardType: "A", TTL: 300, Family: 4, Identity: identity, ClientID: identity})
	if err := m.state.save(); err != nil {
		m.mu.Unlock()
		t.Fatalf("seed state: %v", err)
	}
	m.mu.Unlock()

	src.v4 = []Lease{{Family: 4, Address: "10.0.0.11", Identity: identity, SubnetID: "1", HostName: "legacyhost"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("renumber reconcile: %v", err)
	}
	oldA := &dns.A{Hdr: dns.RR_Header{Name: fqdn + ".", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.0.10")}
	newA := &dns.A{Hdr: dns.RR_Header{Name: fqdn + ".", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.0.11")}
	old, new_ := srv.zoneHas(oldA), srv.zoneHas(newA)
	ownedAfter := m.Stats().OwnedRecords
	if old || !new_ || ownedAfter != 1 {
		t.Fatalf("manager probe: old=%v new=%v ownedAfter=%d, want old=false new=true ownedAfter=1", old, new_, ownedAfter)
	}
	if srv.zoneHas(legacy) {
		t.Fatalf("legacy DHCID survived renumber migration")
	}
	if !srv.zoneHas(deviceDHCID(t, identity, fqdn)) {
		t.Fatalf("device DHCID missing after renumber")
	}
	// Teardown: lease gone removes A + device DHCID, no orphan.
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("teardown reconcile: %v", err)
	}
	if srv.zoneHas(newA) || zoneHasType(srv, fqdn+".", dns.TypeDHCID) {
		t.Fatalf("records orphaned after teardown")
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("OwnedRecords=%d after teardown, want 0", got)
	}
}

// TestLegacyDHCIDKeepSiblingDelete16591: a same-identity dual-record
// name where Pass 1 keeps the DHCID for the survivor — the delete
// must match the legacy prerequisite yet retain the legacy DHCID;
// the last delete then removes it (plus any device DHCID).
func TestLegacyDHCIDKeepSiblingDelete16591(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)
	identity := "cid:0102"
	fwd, legacy := seedLegacyName(t, srv, identity, legacyHost, "10.0.1.5")
	// keepDHCID=true via DeleteLease is manager-driven; drive the
	// backend directly with KeepForwardDHCID set.
	rec := recV4ID(legacyHost, "10.0.1.5", identity, 300)
	rec.KeepForwardDHCID = true
	if err := u.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("keep-DHCID legacy delete: %v", err)
	}
	if srv.zoneHas(fwd) {
		t.Fatalf("forward leaked on keep-DHCID delete")
	}
	if !srv.zoneHas(legacy) {
		t.Fatalf("legacy DHCID removed despite keepDHCID (survivor unprotected)")
	}
	// Last delete removes everything.
	rec.KeepForwardDHCID = false
	// Re-seed the forward so the exact-RR delete has a target again.
	srv.seedRR(fwd)
	if err := u.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("last legacy delete: %v", err)
	}
	if srv.zoneHas(fwd) || srv.zoneHas(legacy) {
		t.Fatalf("records leaked after last legacy delete")
	}
}

// TestLegacySiblingProven16591: the second family's publish at a
// name whose sibling still carries only its LEGACY DHCID must be
// admitted by the legacy sibling proof — under replace-owned AND
// skip-existing — must retain the legacy RR (the sibling's only
// proof until it migrates), and must add the device DHCID. A
// foreign sibling claim (different device, legacy-shaped DHCID of
// another identity) must still be refused.
func TestLegacySiblingProven16591(t *testing.T) {
	// Paired device: v4 Ethernet client-id + v6 DUID-LL same MAC.
	v4ID := "cid:01aabbccddeeff"
	v6ID := "duid:00:03:00:01:aa:bb:cc:dd:ee:ff/16777216"
	for _, policy := range []string{"replace-owned", "skip-existing"} {
		srv := newFakeDNSServer(t, nil)
		srv.setStateful(true)
		var ptr, conf int
		u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", ConflictPolicy: policy,
		}, &ptr, &conf)
		// Sibling (v4) published pre-#14995: A + legacy DHCID.
		_, legacySib := seedLegacyName(t, srv, v4ID, legacyHost, "10.0.1.5")
		// v6 claimant, same device, sibling threaded.
		rec := recV6(legacyHost, "2001:db8::5", 300)
		rec.ClientID = v6ID
		rec.SiblingFamilyOwned = true
		rec.SiblingClientID = v4ID
		if err := u.UpsertLease(context.Background(), rec); err != nil {
			t.Fatalf("[%s] sibling publish over legacy sibling DHCID: %v", policy, err)
		}
		aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: legacyHost + ".", Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP("2001:db8::5")}
		if !srv.zoneHas(aaaa) {
			t.Fatalf("[%s] sibling AAAA not published", policy)
		}
		if !srv.zoneHas(legacySib) {
			t.Fatalf("[%s] legacy sibling DHCID removed (sibling stranded)", policy)
		}
		if policy == "replace-owned" && !srv.zoneHas(deviceDHCID(t, v6ID, legacyHost)) {
			t.Fatalf("[%s] device DHCID not added by sibling publish", policy)
		}
	}
	// Foreign sibling: wire carries a DIFFERENT device's legacy
	// DHCID; the claimant's threaded sibling identity is that
	// foreign identity but the claimant is a different device —
	// sameDeviceClient fails, so no proof is even attempted and
	// Attempts A/B refuse.
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)
	seedLegacyName(t, srv, v4ID, legacyHost, "10.0.1.5")
	rec := recV6(legacyHost, "2001:db8::99", 300)
	rec.ClientID = "duid:00:03:00:01:11:22:33:44:55:66/16777216"
	rec.SiblingFamilyOwned = true
	rec.SiblingClientID = v4ID
	if err := u.UpsertLease(context.Background(), rec); !errors.Is(err, errDDNSConflictRefused) {
		t.Fatalf("foreign sibling over legacy DHCID must refuse; got %v", err)
	}
}
