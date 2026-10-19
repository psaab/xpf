package ddns

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// cross_family_hijack_14995_test.go — #14995 (D40-01) fail-on-revert
// regression: an unauthenticated cross-family DDNS sibling claim must
// not hijack a name or poison the RFC 2136 DHCID prerequisites.
//
// Mechanism (pre-fix): crossTypeSiblingOwned matches on canonical FQDN
// + opposite family ONLY — not on client identity, subnet, scope, or
// authority. A bare DHCP REQUEST is the only input (Kea lease rows are
// unauthenticated): a foreign client that merely REQUESTS the same
// hostname as a victim, from the opposite address family, becomes a
// "sibling" in the manager store. upsertLocked then stamps
// SiblingFamilyOwned=true and the RFC 2136 backend downgrades the
// foreign claim from the name-level NameNotUsed / DHCID-match guards
// to a per-type RRsetNotUsed guard:
//
//   - replace-owned sibling branch inserts the foreign A/AAAA plus a
//     FOREIGN DHCID at the victim's name (in violation of RFC 4701
//     §3.5 / RFC 4703, which cap DHCID at ONE RR per owner name), and
//   - skip-existing/strict-fail downgrades NameNotUsed to RRsetNotUsed.
//
// Real deletes (sendRemoveForward) never carry the sibling signal, so
// the sibling branch is an add-only bypass with no delete-side proof:
// the foreign client's phantom ownership lets a later release aim the
// DHCID prerequisite at the victim's name.
//
// These tests drive the REAL rfc2136 backend against the in-process
// stateful fake (RFC-faithful NameNotUsed/RRsetNotUsed/DHCID prereqs).
// They go RED on the pre-fix code (foreign AAAA + foreign DHCID
// published, phantom ownership recorded) and GREEN after the fix
// (foreign claim refused with errDDNSConflictRefused, no ownership,
// victim's A + DHCID untouched). The legitimate production dual-stack
// control (cid: v4 / duid: v6, same hostname, both publish, per-family
// DHCIDs, clean teardown) is TestDualStackProductionIdentitiesBothPublishReplaceOwned
// (#14602) and must stay green.

const (
	victimV4Identity  = "cid:01000000000001"
	victimV6Identity  = "duid:00:03:00:01:00:00:00:00:00:01/16777216"
	foreignV6Identity = "duid:00:03:00:01:de:ad:be:ef:00:11/42"
	foreignV4Identity = "cid:01deadbeef0011"
	crossFamilyFQDN   = "laptop.example.com"
)

// seedVictimV4 publishes the victim's A + its per-family DHCID through
// the production manager path and returns the manager + lease source.
func seedVictimV4(t *testing.T, srv *fakeDNSServer, policy string) (*Manager, *fakeLeaseSource) {
	t.Helper()
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	if policy != "" {
		cfg.DynamicDNS.ConflictPolicy = policy
	}
	cfg.DynamicDNSv6 = cfg.DynamicDNS
	src.v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: victimV4Identity, SubnetID: "1", HostName: "laptop"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("victim seed reconcile: %v", err)
	}
	if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
		t.Fatal("setup: victim A missing")
	}
	// Only assert the DHCID under replace-owned (skip-existing never
	// writes one).
	if policy == "" || policy == "replace-owned" {
		if !srv.zoneHas(dhcidForName(t, victimV4Identity, crossFamilyFQDN)) {
			t.Fatal("setup: victim DHCID missing")
		}
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("setup: OwnedRecords=%d, want 1 (victim A only)", got)
	}
	return m, src
}

// TestCrossFamilyForeignAAAAHijackRefused14995 is the decisive
// replace-owned cell: a foreign v6 client (different DUID, different
// subnet) REQUESTING the victim's hostname must be refused. Pre-fix it
// publishes its AAAA plus a second, foreign DHCID at the victim's name
// and records phantom ownership.
func TestCrossFamilyForeignAAAAHijackRefused14995(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := seedVictimV4(t, srv, "")

	cfg := ddnsCfg(srv.addrUDP)
	cfg.DynamicDNSv6 = cfg.DynamicDNS

	// Foreign v6 client claims the same hostname. Victim's v4 lease is
	// still live — this is exactly the sibling-bypass precondition.
	src.v6 = []Lease{{Family: 6, Address: "2001:db8::99", Identity: foreignV6Identity, SubnetID: "2", HostName: "laptop"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("foreign-claim reconcile: %v", err)
	}

	if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
		t.Fatal("#14995: foreign AAAA published at victim's name via cross-family sibling bypass")
	}
	if srv.zoneHas(dhcidForName(t, foreignV6Identity, crossFamilyFQDN)) {
		t.Fatal("#14995: foreign DHCID poisoned victim's name (RFC 4701 allows one DHCID RR per name)")
	}
	if m.OwnedForTesting(foreignV6Identity, "2001:db8::99") {
		t.Fatal("#14995: foreign client recorded phantom ownership for victim's name")
	}
	// Victim untouched.
	if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
		t.Fatal("victim A vanished during foreign claim")
	}
	if !srv.zoneHas(dhcidForName(t, victimV4Identity, crossFamilyFQDN)) {
		t.Fatal("victim DHCID vanished during foreign claim")
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("OwnedRecords=%d after foreign claim, want 1 (victim only)", got)
	}
	if got := m.Stats().SkippedConflict; got == 0 {
		t.Fatal("foreign claim was not counted as a conflict refusal")
	}

	// The foreign claim must stay refused on retry (no first-cycle fluke).
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("foreign-claim retry reconcile: %v", err)
	}
	if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
		t.Fatal("#14995: foreign AAAA published on retry")
	}
	if m.OwnedForTesting(foreignV6Identity, "2001:db8::99") {
		t.Fatal("#14995: foreign client recorded phantom ownership on retry")
	}
}

// TestCrossFamilyForeignAHijackRefused14995 is the mirrored cell: the
// victim owns the AAAA and a foreign v4 client REQUESTS the hostname.
func TestCrossFamilyForeignAHijackRefused14995(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	cfg.DynamicDNSv6 = cfg.DynamicDNS

	// Victim v6 first.
	src.v6 = []Lease{{Family: 6, Address: "2001:db8::5", Identity: victimV6Identity, SubnetID: "1", HostName: "laptop"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("victim seed reconcile: %v", err)
	}
	if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
		t.Fatal("setup: victim AAAA missing")
	}

	// Foreign v4 client claims the same hostname.
	src.v4 = []Lease{{Family: 4, Address: "10.0.1.99", Identity: foreignV4Identity, SubnetID: "2", HostName: "laptop"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("foreign-claim reconcile: %v", err)
	}
	if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
		t.Fatal("#14995: foreign A published at victim's name via cross-family sibling bypass")
	}
	if srv.zoneHas(dhcidForName(t, foreignV4Identity, crossFamilyFQDN)) {
		t.Fatal("#14995: foreign DHCID poisoned victim's name")
	}
	if m.OwnedForTesting(foreignV4Identity, "10.0.1.99") {
		t.Fatal("#14995: foreign client recorded phantom ownership for victim's name")
	}
	if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
		t.Fatal("victim AAAA vanished during foreign claim")
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("OwnedRecords=%d after foreign claim, want 1 (victim only)", got)
	}
}

// TestCrossFamilySkipExistingForeignAAAARefused14995 proves the
// skip-existing downgrade is closed: with SiblingFamilyOwned no longer
// stamped for a foreign identity, the name-level NameNotUsed guard
// refuses the foreign AAAA. (Pre-fix sendAdd downgraded to
// RRsetNotUsed and admitted it.)
func TestCrossFamilySkipExistingForeignAAAARefused14995(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := seedVictimV4(t, srv, "skip-existing")

	cfg := ddnsCfgSkipExisting(srv.addrUDP)
	// Victim still live; foreign v6 claims the name.
	src.v6 = []Lease{{Family: 6, Address: "2001:db8::99", Identity: foreignV6Identity, SubnetID: "2", HostName: "laptop"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("foreign-claim reconcile: %v", err)
	}
	if zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeAAAA) {
		t.Fatal("#14995: foreign AAAA published under skip-existing via sibling downgrade")
	}
	if m.OwnedForTesting(foreignV6Identity, "2001:db8::99") {
		t.Fatal("#14995: foreign client recorded phantom ownership under skip-existing")
	}
	if !zoneHasType(srv, dns.Fqdn(crossFamilyFQDN), dns.TypeA) {
		t.Fatal("victim A vanished during foreign claim")
	}
	if got := m.Stats().OwnedRecords; got != 1 {
		t.Fatalf("OwnedRecords=%d after foreign claim, want 1 (victim only)", got)
	}
}
