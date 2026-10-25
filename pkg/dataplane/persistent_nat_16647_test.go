package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16647: persistentNATKey dropped Protocol and RoutingScope, so TCP/UDP on
// one socket and overlapping-address tenants merged into one row.

func binding16647(protocol uint8, scope uint32) *PersistentNATBinding {
	return &PersistentNATBinding{
		SrcIP:        netip.MustParseAddr("10.0.0.1"),
		SrcPort:      40000,
		NatIP:        netip.MustParseAddr("203.0.113.1"),
		NatPort:      50000,
		PoolName:     "p1",
		LastSeen:     time.Now(),
		Timeout:      time.Hour,
		Permit:       config.PersistentNATPermitTargetHostPort,
		Protocol:     protocol,
		RoutingScope: scope,
		PermittedRemotes: []PersistentNATRemote{
			{IP: netip.MustParseAddr("8.8.8.8"), Port: 53},
		},
	}
}

func TestPersistentNATTableKeepsProtocolAndScopeDistinct16647(t *testing.T) {
	tbl := NewPersistentNATTable()
	tbl.Save(binding16647(6, 0))
	tbl.Save(binding16647(17, 0))
	tbl.Save(binding16647(6, 7))
	if got := tbl.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3 distinct leases (tcp, udp, tcp@scope7)", got)
	}
	src := netip.MustParseAddr("10.0.0.1")
	if b := tbl.LookupScoped(src, 40000, "p1", 17, 0); b == nil || b.Protocol != 17 {
		t.Fatalf("UDP lookup = %+v", b)
	}
	if b := tbl.LookupScoped(src, 40000, "p1", 6, 7); b == nil || b.RoutingScope != 7 {
		t.Fatalf("scope-7 lookup = %+v", b)
	}
	if b := tbl.LookupScoped(src, 40000, "p1", 6, 0); b == nil || b.Protocol != 6 || b.RoutingScope != 0 {
		t.Fatalf("TCP default-scope lookup = %+v", b)
	}
	// Legacy Lookup still resolves the protocol/scope-less key.
	legacy := NewPersistentNATTable()
	legacy.Save(&PersistentNATBinding{
		SrcIP: src, SrcPort: 40000, NatIP: netip.MustParseAddr("203.0.113.1"),
		NatPort: 50000, PoolName: "p1", LastSeen: time.Now(), Timeout: time.Hour,
	})
	if legacy.Lookup(src, 40000, "p1") == nil {
		t.Fatal("legacy Lookup lost the protocol-less preserve binding")
	}
	// ReplaceAll must not merge either.
	snap := NewPersistentNATTable()
	snap.ReplaceAll([]*PersistentNATBinding{binding16647(6, 0), binding16647(17, 0), binding16647(6, 7)})
	if got := snap.Len(); got != 3 {
		t.Fatalf("ReplaceAll Len = %d, want 3", got)
	}
	// All() deep-copies grants: mutating a snapshot must not touch the table.
	all := snap.All()
	all[0].PermittedRemotes[0].Port = 9999
	for _, b := range snap.All() {
		if len(b.PermittedRemotes) > 0 && b.PermittedRemotes[0].Port == 9999 {
			t.Fatal("All() aliases the live PermittedRemotes slice")
		}
	}
}
