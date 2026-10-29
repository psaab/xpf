package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func binding17700(protocol uint8, scope uint32, natPort uint16) *PersistentNATBinding {
	return &PersistentNATBinding{
		SrcIP:        netip.MustParseAddr("10.0.0.1"),
		SrcPort:      40000,
		NatIP:        netip.MustParseAddr("203.0.113.1"),
		NatPort:      natPort,
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

func TestPersistentNATTableLookupScopedReturnsDetachedCopy17700(t *testing.T) {
	tbl := NewPersistentNATTable()
	src := netip.MustParseAddr("10.0.0.1")
	tbl.Save(binding17700(6, 0, 50000))
	tbl.Save(binding17700(17, 0, 50001))
	tbl.Save(binding17700(6, 7, 50002))

	for _, tc := range []struct {
		protocol uint8
		scope    uint32
		port     uint16
	}{
		{6, 0, 50000},
		{17, 0, 50001},
		{6, 7, 50002},
	} {
		got := tbl.LookupScoped(src, 40000, "p1", tc.protocol, tc.scope)
		if got == nil || got.NatPort != tc.port {
			t.Fatalf("LookupScoped(%d,%d) = %+v, want NatPort %d", tc.protocol, tc.scope, got, tc.port)
		}
		got.NatPort = 59999
		got.NatIP = netip.MustParseAddr("198.51.100.99")
		got.PermittedRemotes[0].Port = 9999
		got.PermittedRemotes = append(got.PermittedRemotes, PersistentNATRemote{
			IP: netip.MustParseAddr("9.9.9.9"), Port: 1,
		})

		again := tbl.LookupScoped(src, 40000, "p1", tc.protocol, tc.scope)
		if again == nil {
			t.Fatal("second LookupScoped = nil")
		}
		if again.NatPort != tc.port || again.NatIP.String() != "203.0.113.1" {
			t.Errorf("LookupScoped mutation reached stored binding: %+v", again)
		}
		if len(again.PermittedRemotes) != 1 || again.PermittedRemotes[0].Port != 53 {
			t.Errorf("LookupScoped grant mutation reached stored binding: %+v", again.PermittedRemotes)
		}
	}
}

func TestPersistentNATTableLegacyLookupDeterministic17700(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	rows := []*PersistentNATBinding{
		binding17700(6, 0, 50000),
		binding17700(17, 0, 50001),
		binding17700(6, 7, 50002),
	}
	// Without protocol/scope identity, Lookup deterministically chooses
	// the lowest protocol then routing scope, independent of insertion order.
	for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}} {
		tbl := NewPersistentNATTable()
		for _, i := range order {
			tbl.Save(rows[i])
		}
		for range 100 {
			got := tbl.Lookup(src, 40000, "p1")
			if got == nil || got.Protocol != 6 || got.RoutingScope != 0 || got.NatPort != 50000 {
				t.Fatalf("Lookup winner = %+v, want tcp/default-scope NatPort 50000", got)
			}
		}
	}

	// A protocol-less legacy row takes precedence over newly scoped rows.
	legacy := &PersistentNATBinding{
		SrcIP: src, SrcPort: 40000, NatIP: netip.MustParseAddr("203.0.113.1"),
		NatPort: 50009, PoolName: "p1", LastSeen: time.Now(), Timeout: time.Hour,
	}
	for _, legacyFirst := range []bool{true, false} {
		tbl := NewPersistentNATTable()
		if legacyFirst {
			tbl.Save(legacy)
			tbl.Save(rows[0])
		} else {
			tbl.Save(rows[0])
			tbl.Save(legacy)
		}
		if got := tbl.Lookup(src, 40000, "p1"); got == nil || got.Protocol != 0 || got.NatPort != 50009 {
			t.Fatalf("legacyFirst=%v: Lookup = %+v, want protocol-less legacy row", legacyFirst, got)
		}
	}
}
