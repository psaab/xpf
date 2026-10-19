package ddns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// cross_family_client_bind_15072_test.go — #15072 (A40-01) residual
// regression: the cross-family sibling proof must be bound to the
// CLIENT, not only to the FQDN.
//
// #14995 (merged after the #15072 research base) demoted the store
// scan to a candidate source and required a wire DHCID proof, but
// crossTypeSiblingOwned still returned ANY opposite-family row at
// the same scope+endpoint regardless of client identity, so
// upsertLocked stamped SiblingFamilyOwned/SiblingClientID even for
// a foreign claimant, and the strict-fail policy had no foreign-
// sibling cell at all. Fix direction (issue): "Bind the sibling
// proof to the client (e.g. equal hwaddr/DUID-LL from Kea, or an
// operator reservation link); otherwise keep the name-level guard.
// Acceptance: an unrelated-DUID v6 lease at an xpf-owned v4 name is
// refused under all three policies while the #14602 dual-stack test
// still publishes both."
//
// These cells drive the REAL manager + rfc2136 backend against the
// stateful fake. RED on current origin/master for the manager-level
// binding cells (crossTypeSiblingOwned returns the foreign row and
// the recording updater observes SiblingFamilyOwned=true for it)
// and for any policy cell where a foreign record were published;
// GREEN after crossTypeSiblingOwned filters by sameDeviceClient.
// The #14602 control (TestDualStackProductionIdentitiesBothPublish-
// ReplaceOwned, genuinely paired Ethernet cid + DUID-LL) must stay
// green — it is run alongside these cells.

// seedVictim15072 publishes the victim family's record through the
// production manager path under the given conflict policy.
func seedVictim15072(t *testing.T, srv *fakeDNSServer, policy string, v6Victim bool) (*Manager, *fakeLeaseSource) {
	t.Helper()
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	if policy != "" {
		cfg.DynamicDNS.ConflictPolicy = policy
	}
	cfg.DynamicDNSv6 = cfg.DynamicDNS
	if v6Victim {
		src.v6 = []Lease{{Family: 6, Address: "2001:db8::5", Identity: victimV6Identity, SubnetID: "1", HostName: "laptop"}}
	} else {
		src.v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: victimV4Identity, SubnetID: "1", HostName: "laptop"}}
	}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("victim seed reconcile (%s): %v", policy, err)
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("setup (%s): OwnedRecords=%d, want 1", policy, got)
	}
	return m, src
}

// TestCrossFamilySiblingBindsClientIdentity15072 is the direct
// manager-level binding proof: a same-device opposite-family row IS
// a sibling candidate, a foreign-device row at the same FQDN/scope/
// endpoint is NOT. RED pre-fix (foreign row returned).
func TestCrossFamilySiblingBindsClientIdentity15072(t *testing.T) {
	m, _ := prodManagerTo(t, newFakeDNSServer(t, nil))
	// Victim v4 row owned for the paired device.
	victim := ownedRecord{
		Family:   4,
		Identity: victimV4Identity,
		Address:  "10.0.1.5",
		FQDN:     crossFamilyFQDN,
		ClientID: victimV4Identity,
	}
	m.state.put(victim)

	// Same-device v6 claimant (DUID-LL embedding the victim's MAC
	// 00:00:00:00:00:01 from cid:01000000000001) pairs.
	paired := ownedRecord{
		Family:   6,
		Identity: victimV6Identity,
		Address:  "2001:db8::5",
		FQDN:     crossFamilyFQDN,
		ClientID: victimV6Identity,
	}
	if sib := m.crossTypeSiblingOwned(paired); sib == nil {
		t.Fatal("#15072: same-device opposite-family row must be a sibling candidate")
	} else if sib.ClientID != victimV4Identity {
		t.Fatalf("#15072: sibling ClientID=%q, want victim %q", sib.ClientID, victimV4Identity)
	}

	// Foreign v6 claimant: unrelated DUID at the same name.
	foreign := ownedRecord{
		Family:   6,
		Identity: foreignV6Identity,
		Address:  "2001:db8::99",
		FQDN:     crossFamilyFQDN,
		ClientID: foreignV6Identity,
	}
	if sib := m.crossTypeSiblingOwned(foreign); sib != nil {
		t.Fatalf("#15072: unrelated-DUID row returned as sibling (ClientID=%q); sibling proof must bind to the client", sib.ClientID)
	}

	// Foreign v4 claimant mirrored against a v6 victim.
	m2, _ := prodManagerTo(t, newFakeDNSServer(t, nil))
	m2.state.put(ownedRecord{
		Family:   6,
		Identity: victimV6Identity,
		Address:  "2001:db8::5",
		FQDN:     crossFamilyFQDN,
		ClientID: victimV6Identity,
	})
	foreignV4 := ownedRecord{
		Family:   4,
		Identity: foreignV4Identity,
		Address:  "10.0.1.99",
		FQDN:     crossFamilyFQDN,
		ClientID: foreignV4Identity,
	}
	if sib := m2.crossTypeSiblingOwned(foreignV4); sib != nil {
		t.Fatalf("#15072: unrelated v4 client-id row returned as sibling (ClientID=%q)", sib.ClientID)
	}
	// Empty identities never pair (fail closed).
	noID := ownedRecord{Family: 4, Address: "10.0.1.7", FQDN: crossFamilyFQDN}
	if sib := m2.crossTypeSiblingOwned(noID); sib != nil {
		t.Fatal("#15072: empty-identity claimant must not be a sibling")
	}
}

// TestCrossFamilyForeignRefusedAllPolicies15072 is the acceptance
// cell from the issue: an unrelated-DUID v6 lease at an xpf-owned
// v4 name (and the mirror) is refused under ALL THREE policies,
// with no foreign RR, no foreign DHCID, no phantom ownership, and
// the victim untouched. strict-fail surfaces the collision as a
// reconcile error rather than the conflict sentinel — either way
// nothing is published or owned.
func TestCrossFamilyForeignRefusedAllPolicies15072(t *testing.T) {
	for _, policy := range []string{"replace-owned", "skip-existing", "strict-fail"} {
		t.Run(policy+"/foreign-AAAA-at-v4-name", func(t *testing.T) {
			srv := newFakeDNSServer(t, nil)
			srv.setStateful(true)
			m, src := seedVictim15072(t, srv, policy, false)
			cfg := ddnsCfg(srv.addrUDP)
			cfg.DynamicDNS.ConflictPolicy = policy
			cfg.DynamicDNSv6 = cfg.DynamicDNS
			src.v6 = []Lease{{Family: 6, Address: "2001:db8::99", Identity: foreignV6Identity, SubnetID: "2", HostName: "laptop"}}
			_ = m.Reconcile(context.Background(), cfg)
			if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
				t.Fatalf("#15072/%s: foreign AAAA published at victim v4 name", policy)
			}
			if srv.zoneHas(dhcidForName(t, foreignV6Identity, crossFamilyFQDN)) {
				t.Fatalf("#15072/%s: foreign DHCID at victim name", policy)
			}
			if m.OwnedForTesting(foreignV6Identity, "2001:db8::99") {
				t.Fatalf("#15072/%s: foreign client recorded phantom ownership", policy)
			}
			if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
				t.Fatalf("#15072/%s: victim A vanished", policy)
			}
			if got := m.Stats().OwnedRecords; got != 1 {
				t.Fatalf("#15072/%s: OwnedRecords=%d, want 1 (victim only)", policy, got)
			}
		})
		t.Run(policy+"/foreign-A-at-v6-name", func(t *testing.T) {
			srv := newFakeDNSServer(t, nil)
			srv.setStateful(true)
			m, src := seedVictim15072(t, srv, policy, true)
			cfg := ddnsCfg(srv.addrUDP)
			cfg.DynamicDNS.ConflictPolicy = policy
			cfg.DynamicDNSv6 = cfg.DynamicDNS
			src.v4 = []Lease{{Family: 4, Address: "10.0.1.99", Identity: foreignV4Identity, SubnetID: "2", HostName: "laptop"}}
			_ = m.Reconcile(context.Background(), cfg)
			if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
				t.Fatalf("#15072/%s: foreign A published at victim v6 name", policy)
			}
			if srv.zoneHas(dhcidForName(t, foreignV4Identity, crossFamilyFQDN)) {
				t.Fatalf("#15072/%s: foreign DHCID at victim name", policy)
			}
			if m.OwnedForTesting(foreignV4Identity, "10.0.1.99") {
				t.Fatalf("#15072/%s: foreign client recorded phantom ownership", policy)
			}
			if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
				t.Fatalf("#15072/%s: victim AAAA vanished", policy)
			}
			if got := m.Stats().OwnedRecords; got != 1 {
				t.Fatalf("#15072/%s: OwnedRecords=%d, want 1 (victim only)", policy, got)
			}
		})
	}
}

// TestCrossFamilySameDevicePublishesAllPolicies15072 is the
// legitimate control adjacent to the mechanism: the SAME device
// (Ethernet client-id v4 + DUID-LL v6 embedding the same MAC)
// publishes both families under every policy — the client binding
// must not re-break #14602 dual-stack.
func TestCrossFamilySameDevicePublishesAllPolicies15072(t *testing.T) {
	for _, policy := range []string{"replace-owned", "skip-existing", "strict-fail"} {
		t.Run(policy, func(t *testing.T) {
			srv := newFakeDNSServer(t, nil)
			srv.setStateful(true)
			m, src := prodManagerTo(t, srv)
			cfg := ddnsCfg(srv.addrUDP)
			cfg.DynamicDNS.ConflictPolicy = policy
			cfg.DynamicDNSv6 = cfg.DynamicDNS
			src.v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: victimV4Identity, SubnetID: "1", HostName: "laptop"}}
			src.v6 = []Lease{{Family: 6, Address: "2001:db8::5", Identity: victimV6Identity, SubnetID: "1", HostName: "laptop"}}
			if err := m.Reconcile(context.Background(), cfg); err != nil {
				t.Fatalf("#15072/%s: dual-stack reconcile: %v", policy, err)
			}
			if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
				t.Fatalf("#15072/%s: same-device A missing", policy)
			}
			if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
				t.Fatalf("#15072/%s: same-device AAAA missing (client binding broke dual-stack)", policy)
			}
			if got := m.Stats().OwnedRecords; got != 2 {
				t.Fatalf("#15072/%s: OwnedRecords=%d, want 2", policy, got)
			}
		})
	}
}
