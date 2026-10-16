package ddns

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// TestIPChangeWithCoexistingTXTKeepsDHCID_14189 is the #14189 regression.
//
// A client at 10.0.0.10 publishes A + DHCID at client1.example.com; an
// unrelated TXT RRset also lives at that name. The lease moves to
// 10.0.0.11 (same identity/FQDN). Pass 1 deletes the old A; Pass 2 must
// publish the new A. Before the fix Pass 1 also removed the DHCID
// (dhcidSharedWithOther scanned only m.state.records, not the desired
// set), so Pass 2's sendAddOwned Attempt A failed YXDOMAIN (TXT exists)
// and Attempt B failed NXRRSET (DHCID gone) -> errDDNSConflictRefused on
// every reconcile, forever.
func TestIPChangeWithCoexistingTXTKeepsDHCID_14189(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	m, src := prodManagerTo(t, srv)
	cfg := ddnsCfg(srv.addrUDP)

	const identity = "cid:14189-move"
	const fqdn = "client1.example.com"

	// Cycle 1: publish 10.0.0.10.
	src.v4 = []Lease{{Family: 4, Address: "10.0.0.10", Identity: identity, SubnetID: "1", HostName: "client1"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("publish reconcile: %v", err)
	}
	dhcid := dhcidForName(t, identity, fqdn)
	if !srv.zoneHas(dhcid) {
		t.Fatal("setup: DHCID was not published")
	}
	oldA := &dns.A{Hdr: dns.RR_Header{Name: fqdn + ".", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.0.10")}
	if !srv.zoneHas(oldA) {
		t.Fatal("setup: old A was not published")
	}

	// Co-resident foreign TXT at same name (pre-existing other RRset).
	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: fqdn + ".", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"hello"},
	}
	srv.seedRR(txt)

	// Cycle 2: IP change to 10.0.0.11, same identity/hostname.
	src.v4 = []Lease{{Family: 4, Address: "10.0.0.11", Identity: identity, SubnetID: "1", HostName: "client1"}}
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("IP-change reconcile: %v", err)
	}

	newA := &dns.A{Hdr: dns.RR_Header{Name: fqdn + ".", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.0.11")}

	if !srv.zoneHas(newA) {
		t.Fatal("#14189 regression: new A 10.0.0.11 not published after IP change (permanent conflict refusal)")
	}
	if srv.zoneHas(oldA) {
		t.Fatal("old A 10.0.0.10 still present after IP change")
	}
	if !srv.zoneHas(dhcid) {
		t.Fatal("DHCID lost after IP change")
	}
	if !srv.zoneHas(txt) {
		t.Fatal("co-resident TXT clobbered")
	}
	if m.Stats().OwnedRecords != 1 {
		t.Fatalf("want 1 owned record after move, got %d", m.Stats().OwnedRecords)
	}

	// Cycle 3: repeat with unchanged lease — must stay settled.
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("repeat reconcile: %v", err)
	}
	if !srv.zoneHas(newA) || !srv.zoneHas(dhcid) {
		t.Fatal("record/DHCID not stable on repeat reconcile")
	}

	// Cycle 4: lease gone — A and DHCID removed, TXT untouched.
	src.v4 = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("teardown reconcile: %v", err)
	}
	if srv.zoneHas(newA) {
		t.Fatal("A not withdrawn after lease release")
	}
	if srv.zoneHas(dhcid) {
		t.Fatal("DHCID orphaned after last record released")
	}
	if !srv.zoneHas(txt) {
		t.Fatal("co-resident TXT clobbered on teardown")
	}
	if m.Stats().OwnedRecords != 0 {
		t.Fatalf("want 0 owned records after teardown, got %d", m.Stats().OwnedRecords)
	}
}
