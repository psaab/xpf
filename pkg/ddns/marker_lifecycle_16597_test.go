package ddns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// marker_lifecycle_16597_test.go — #16597 (R3-A40-06) fail-on-revert
// regression: the device DHCID marker published under
// skip-existing/strict-fail to prove a same-device sibling must have
// an owner and a delete path.
//
// Pre-fix, the marker published by the first family's successful
// add was tracked only in the updater's per-cycle lifetime
// (siblingMarkerRR) and never withdrawn: after both leases expired
// the A/AAAA were removed by plain exact-RR deletes but the lone
// DHCID remained, permanently burning the name — a returning device
// coming back single-family (or any other client) then hit the
// name-level NameNotUsed guard against xpf's own leftover and was
// refused as a third-party conflict.
//
// These tests drive the REAL manager + rfc2136 backend against the
// stateful fake. RED pre-fix (marker survives full teardown, the
// single-family re-claim is refused with a counted conflict).
// GREEN after the last family's delete withdraws the marker
// value-specifically (markerSharedWithSibling=false) while a
// surviving sibling keeps it (markerSharedWithSibling=true). The
// #15072 same-device control (both families publish under every
// policy) and the #14995/#15072 foreign-hijack cells must stay green.

// TestDualStackSkipExistingMarkerWithdrawn16597 is the acceptance
// cell: a same-device dual-stack publish under skip-existing writes
// the device marker; full teardown must leave NO RR at the name,
// and a later single-family re-claim by the SAME device must not be
// refused.
func TestDualStackSkipExistingMarkerWithdrawn16597(t *testing.T) {
	for _, policy := range []string{"skip-existing", "strict-fail"} {
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
				if policy == "strict-fail" {
					// strict-fail surfaces any conflict as an error; a
					// clean dual-stack publish should not error, but
					// tolerate a first-pass error only if both RRs landed.
					if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) ||
						!zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
						t.Fatalf("#16597/%s: dual-stack reconcile: %v", policy, err)
					}
				} else {
					t.Fatalf("#16597/%s: dual-stack reconcile: %v", policy, err)
				}
			}
			if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
				t.Fatalf("#16597/%s: same-device A missing after publish", policy)
			}
			if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
				t.Fatalf("#16597/%s: same-device AAAA missing after publish", policy)
			}
			marker := dhcidForName(t, victimV4Identity, crossFamilyFQDN)
			if !srv.zoneHas(marker) {
				t.Fatalf("#16597/%s: setup: device proof marker not published", policy)
			}
			if got := m.Stats().OwnedRecords; got != 2 {
				t.Fatalf("#16597/%s: OwnedRecords=%d, want 2", policy, got)
			}

			// Partial teardown: v4 gone, v6 survives — marker MUST stay.
			src.v4 = nil
			_ = m.Reconcile(context.Background(), cfg)
			if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
				t.Fatalf("#16597/%s: A not withdrawn on partial teardown", policy)
			}
			if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
				t.Fatalf("#16597/%s: surviving AAAA removed on partial teardown", policy)
			}
			if !srv.zoneHas(marker) {
				t.Fatalf("#16597/%s: marker removed while sibling AAAA still owned", policy)
			}

			// Full teardown: last family gone — NO RR may remain.
			src.v6 = nil
			_ = m.Reconcile(context.Background(), cfg)
			if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
				t.Fatalf("#16597/%s: AAAA leaked after full teardown", policy)
			}
			if srv.zoneHas(marker) {
				t.Fatalf("#16597/%s: device marker orphaned after full teardown — name burned", policy)
			}
			if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeDHCID) {
				t.Fatalf("#16597/%s: DHCID remains at name after full teardown", policy)
			}
			if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) ||
				zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
				t.Fatalf("#16597/%s: forward RR remains after full teardown", policy)
			}
			if got := m.Stats().OwnedRecords; got != 0 {
				t.Fatalf("#16597/%s: OwnedRecords=%d after teardown, want 0", policy, got)
			}

			// Re-claim: the same device returns single-family (v4 only).
			// Pre-fix the orphaned marker makes NameNotUsed fail and the
			// claim is refused as a third-party conflict.
			confBefore := m.Stats().SkippedConflict
			src.v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: victimV4Identity, SubnetID: "1", HostName: "laptop"}}
			src.v6 = nil
			_ = m.Reconcile(context.Background(), cfg)
			if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
				t.Fatalf("#16597/%s: single-family re-claim refused — name still burned by orphan marker", policy)
			}
			if got := m.Stats().SkippedConflict; got != confBefore {
				t.Fatalf("#16597/%s: re-claim counted as conflict (%d -> %d); orphan marker blamed a third party", policy, confBefore, got)
			}
			if !m.OwnedForTesting(victimV4Identity, "10.0.1.5") {
				t.Fatalf("#16597/%s: re-claimed record not owned", policy)
			}
		})
	}
}

// TestDualStackSkipExistingMarkerSingleFamily16597 covers the case
// where only ONE family ever publishes but a same-pass paired sibling
// existed at publish time (so the marker was written), then that
// single family is withdrawn: the marker must be removed with it.
func TestDualStackSkipExistingMarkerSingleFamily16597(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfgSkipExisting(srv.addrUDP)
	cfg.DynamicDNSv6 = cfg.DynamicDNS

	// Both families desired in the same pass — the first add publishes
	// the marker so the sibling can prove itself.
	src.v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: victimV4Identity, SubnetID: "1", HostName: "laptop"}}
	src.v6 = []Lease{{Family: 6, Address: "2001:db8::5", Identity: victimV6Identity, SubnetID: "1", HostName: "laptop"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("#16597: dual-stack reconcile: %v", err)
	}
	marker := dhcidForName(t, victimV4Identity, crossFamilyFQDN)
	if !srv.zoneHas(marker) {
		t.Fatal("#16597: setup: marker not published")
	}

	// Withdraw only v6, then v4: the marker survives the first, dies
	// with the last.
	src.v6 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("#16597: partial reconcile: %v", err)
	}
	if !srv.zoneHas(marker) {
		t.Fatal("#16597: marker removed while v4 sibling still owned")
	}
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("#16597: final reconcile: %v", err)
	}
	if srv.zoneHas(marker) {
		t.Fatal("#16597: marker orphaned after last family withdrawn")
	}
	if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeDHCID) {
		t.Fatal("#16597: DHCID remains after full teardown")
	}
}

// TestMarkerGhostDeleteHarmless16597 proves a last-family delete
// under skip-existing for a record that never had a sibling (no
// marker was ever published) does not disturb a foreign DHCID that
// shares the name — the value-specific ghost delete is a no-op.
func TestMarkerGhostDeleteHarmless16597(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)

	var ptr, conf int
	ghostCfg := ddnsCfgSkipExisting(srv.addrUDP)
	u := testUpdater(t, srv, ghostCfg.DynamicDNS, &ptr, &conf)

	// A foreign DHCID is seeded AFTER our publish (a pre-existing
	// foreign DHCID would refuse the skip-existing add at the
	// name-level guard). The value-specific marker delete must then
	// remove only the exact device DHCID — absent here, since no
	// sibling ever proved and no marker was published — and leave
	// the foreign DHCID alone.
	rec := recV4ID("solo.example.com", "10.0.1.5", victimV4Identity, 300)
	// No paired/sibling identity: siblingCandidate is false, so no
	// marker is published on add.
	if err := u.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("#16597: single-family upsert: %v", err)
	}
	if srv.zoneHas(dhcidForName(t, victimV4Identity, "solo.example.com")) {
		t.Fatal("#16597: single-family add must not publish a marker without a sibling candidate")
	}
	srv.seedRR(dhcidForName(t, foreignV4Identity, "solo.example.com"))
	if err := u.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("#16597: single-family delete: %v", err)
	}
	if !srv.zoneHas(dhcidForName(t, foreignV4Identity, "solo.example.com")) {
		t.Fatal("#16597: ghost marker delete removed a foreign DHCID")
	}
	if zoneHasType(srv, dns.Fqdn("solo.example.com"), dns.TypeA) {
		t.Fatal("#16597: A not withdrawn")
	}
}
