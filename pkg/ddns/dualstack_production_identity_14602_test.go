package ddns

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// dualstack_production_identity_14602_test.go — #14602 fail-on-revert
// regression: under the default replace-owned policy a dual-stack DHCP
// client whose v4 lease identity is production-shaped (`cid:`/`mac:`)
// and whose v6 lease identity is production-shaped (`duid:<duid>/<iaid>`)
// must publish BOTH its A and its AAAA under one FQDN.
//
// Pre-fix, the two identities digest to two different RFC 4701 DHCIDs.
// Whichever family publishes first owns the name under its own DHCID; the
// sibling family's Attempt B (DHCID-matches-ours) can never match the
// sibling's DHCID, so it is refused with errDDNSConflictRefused on every
// cycle (owned=1, SkippedConflict rises, err=nil) and half the host's
// forward DNS never appears — silently.
//
// The sibling record is published in Pass 2 of the FIRST reconcile (map
// iteration order decides which family wins), so both add paths must
// recognise an already-manager-owned sibling; the fix's ownership proof
// is the manager store, not a shared digest.

const (
	prodV4Identity = "cid:01:02:03"
	prodV6Identity = "duid:00:01:00:01:22:33:44:55:66:77/16777216"
	otherV4Ident   = "cid:aa:bb:cc"
)

func prodDualStackLeases() (v4, v6 []Lease) {
	v4 = []Lease{{Family: 4, Address: "10.0.1.5", Identity: prodV4Identity, SubnetID: "1", HostName: "laptop"}}
	v6 = []Lease{{Family: 6, Address: "2001:db8::5", Identity: prodV6Identity, SubnetID: "1", HostName: "laptop"}}
	return v4, v6
}

func TestDualStackProductionIdentitiesBothPublishReplaceOwned(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)
	cfg.DynamicDNSv6 = cfg.DynamicDNS

	const fqdn = "laptop.example.com"
	v4, v6 := prodDualStackLeases()

	// Two cycles: the bug is stable across cycles (not a first-cycle
	// transient), so assert after both.
	for cycle := 1; cycle <= 2; cycle++ {
		src.v4, src.v6 = v4, v6
		if err := m.Reconcile(context.Background(), cfg); err != nil {
			t.Fatalf("cycle %d reconcile: %v", cycle, err)
		}
		if !zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeA) {
			t.Fatalf("cycle %d: A missing — v4 family lost the DHCID race (#14602)", cycle)
		}
		if !zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeAAAA) {
			t.Fatalf("cycle %d: AAAA missing — v6 family lost the DHCID race (#14602)", cycle)
		}
		if got := m.Stats().OwnedRecords; got != 2 {
			t.Fatalf("cycle %d: OwnedRecords=%d, want 2 (A+AAAA both manager-owned)", cycle, got)
		}
		if got := m.Stats().SkippedConflict; got != 0 {
			t.Fatalf("cycle %d: SkippedConflict=%d, want 0 (sibling must not be refused as a foreign conflict)", cycle, got)
		}
	}

	// A different client claiming the same hostname while the
	// legitimate A is still live must still be refused: its A RRset
	// already exists (the legitimate client's), so the per-type guard
	// refuses it and no ownership is recorded for the foreign tuple.
	// (A foreign claim at a name xpf never published is refused by the
	// name-level guards — covered by the #2648/#2660 tests.)
	src.v4 = append(append([]Lease{}, v4...),
		Lease{Family: 4, Address: "10.0.1.99", Identity: otherV4Ident, SubnetID: "1", HostName: "laptop"})
	src.v6 = v6
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("foreign-claim reconcile: %v", err)
	}
	if srv.zoneHas(&dns.A{Hdr: dns.RR_Header{Name: fqdn + ".", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.99")}) {
		t.Fatal("foreign client's A was published at the contested name (#14602 guard weakened)")
	}
	if m.OwnedForTesting(otherV4Ident, "10.0.1.99") {
		t.Fatal("foreign client recorded phantom ownership for the contested name")
	}
	// The legitimate records must survive the foreign attempt.
	if !zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeA) || !zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeAAAA) {
		t.Fatal("legitimate A/AAAA vanished during foreign-claim cycle")
	}
	if got := m.Stats().OwnedRecords; got != 2 {
		t.Fatalf("OwnedRecords=%d after foreign claim, want 2", got)
	}

	// Full teardown: releasing both families removes both forwards and
	// leaves no orphaned DHCID at the name.
	src.v4, src.v6 = nil, nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("teardown reconcile: %v", err)
	}
	if zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeA) {
		t.Fatal("A leaked after full teardown")
	}
	if zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeAAAA) {
		t.Fatal("AAAA leaked after full teardown")
	}
	if zoneHasType(srv, dns.Fqdn(fqdn), dns.TypeDHCID) {
		t.Fatal("DHCID orphaned after full teardown")
	}
	if got := m.Stats().OwnedRecords; got != 0 {
		t.Fatalf("OwnedRecords=%d after teardown, want 0", got)
	}
}
