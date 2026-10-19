package userspace

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15155 (B15-02): on a multi-address egress unit the snapshot sorted
// addresses lexicographically and carried no marker for the operator's
// `primary` designation, so every primary_v4/v6 consumer (interface SNAT,
// local-address tables, RST candidates) used whichever address happened
// to sort first as a string. These cells pin the configured marker from
// the Go builders through both pick functions, plus the no-marker
// fallback (first non-link-local, as before).
//
// FAIL-ON-REVERT: drop the Primary marking in
// buildConfiguredAddressSnapshots / mergeInterfaceAddressSnapshots, or
// the prefer-primary arms in pickInterfaceSnapshotV4/V6, and the
// discriminating cells below fail.

func TestPrimaryAddressSnapshot15155(t *testing.T) {
	// Discriminating shape: lexicographic string order picks
	// "10.0.0.10/24" over the designated "10.0.0.9/24" ('1' < '9'),
	// and "2001:db8::10/64" over "2001:db8::9/64". One builder call
	// carries a single PrimaryAddress slot (the config model), so each
	// family gets its own call below; the merged rows are then combined.
	v4 := buildConfiguredAddressSnapshots(
		[]string{"10.0.0.10/24", "10.0.0.9/24"}, "10.0.0.9/24")
	v6 := buildConfiguredAddressSnapshots(
		[]string{"2001:db8::10/64", "2001:db8::9/64"}, "2001:db8::9/64")
	configured := append(append([]InterfaceAddressSnapshot{}, v4...), v6...)
	if len(configured) != 4 {
		t.Fatalf("buildConfiguredAddressSnapshots = %+v, want 4 rows", configured)
	}
	marked := map[string]bool{}
	for _, a := range configured {
		marked[a.Address] = a.Primary
	}
	if !marked["10.0.0.9/24"] || !marked["2001:db8::9/64"] {
		t.Fatalf("configured primary not marked: %+v", configured)
	}
	if marked["10.0.0.10/24"] || marked["2001:db8::10/64"] {
		t.Fatalf("non-designated address marked primary: %+v", configured)
	}

	// Merge with live rows must keep the marker on both the
	// configured-only row and the row the kernel also reports.
	live := []InterfaceAddressSnapshot{
		{Family: "inet", Address: "10.0.0.9/24"},
		{Family: "inet", Address: "10.0.0.10/24"},
	}
	merged := mergeInterfaceAddressSnapshots(live, configured)
	for _, a := range merged {
		want := a.Address == "10.0.0.9/24" || a.Address == "2001:db8::9/64"
		if a.Primary != want {
			t.Fatalf("merged %s Primary=%v, want %v (%+v)", a.Address, a.Primary, want, merged)
		}
	}

	// Both Go picks must honour the marker over sort order.
	iface := InterfaceSnapshot{Addresses: merged}
	if got := pickInterfaceSnapshotV4(iface); got == nil || !got.Equal(net.ParseIP("10.0.0.9")) {
		t.Fatalf("pickInterfaceSnapshotV4() = %v, want 10.0.0.9 (configured primary)", got)
	}
	if got := pickInterfaceSnapshotV6(iface); got == nil || !got.Equal(net.ParseIP("2001:db8::9")) {
		t.Fatalf("pickInterfaceSnapshotV6() = %v, want 2001:db8::9 (configured primary)", got)
	}

	// A marker naming an address the unit does not carry must not
	// manufacture a primary: the ordinary first-non-link-local rule
	// applies instead.
	stale := buildConfiguredAddressSnapshots(
		[]string{"10.0.0.10/24", "10.0.0.9/24"}, "192.0.2.1/24")
	for _, a := range stale {
		if a.Primary {
			t.Fatalf("stale primary %q marked row %+v", "192.0.2.1/24", stale)
		}
	}
	if got := pickInterfaceSnapshotV4(InterfaceSnapshot{Addresses: stale}); got == nil || !got.Equal(net.ParseIP("10.0.0.10")) {
		t.Fatalf("stale-marker fallback pick = %v, want 10.0.0.10", got)
	}

	// Control: no marker anywhere — behaviour is exactly the old
	// first-non-link-local-in-snapshot-order rule.
	plain := InterfaceSnapshot{Addresses: []InterfaceAddressSnapshot{
		{Family: "inet", Address: "169.254.1.1/16"},
		{Family: "inet", Address: "192.0.2.20/24"},
		{Family: "inet6", Address: "fe80::1/64"},
		{Family: "inet6", Address: "2001:db8::20/64"},
	}}
	if got := pickInterfaceSnapshotV4(plain); got == nil || !got.Equal(net.ParseIP("192.0.2.20")) {
		t.Fatalf("unmarked pickInterfaceSnapshotV4() = %v, want 192.0.2.20", got)
	}
	if got := pickInterfaceSnapshotV6(plain); got == nil || !got.Equal(net.ParseIP("2001:db8::20")) {
		t.Fatalf("unmarked pickInterfaceSnapshotV6() = %v, want 2001:db8::20", got)
	}
}

// End-to-end through the real snapshot builder: a unit whose config
// designates 10.0.0.9/24 + 2001:db8::9/64 as primary (the single
// PrimaryAddress slot holds the v4 one, as the compiler fills inet
// first) must publish marked rows, and the Go picks must return the
// designated addresses even though string sort puts .10 / ::10 first.
func TestBuildSnapshotMarksConfiguredPrimary15155(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name:            "reth0",
			RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number:         0,
					Addresses:      []string{"10.0.0.10/24", "10.0.0.9/24", "2001:db8::10/64", "2001:db8::9/64"},
					PrimaryAddress: "10.0.0.9/24",
				},
			},
		},
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"reth0.0"}},
	}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{Workers: 2, RingEntries: 2048}, 1, 0)
	var unit *InterfaceSnapshot
	for i := range snap.Interfaces {
		if snap.Interfaces[i].Name == "reth0.0" {
			unit = &snap.Interfaces[i]
		}
	}
	if unit == nil {
		t.Fatalf("snapshot missing reth0.0: %+v", snap.Interfaces)
	}
	primaryByAddr := map[string]bool{}
	for _, a := range unit.Addresses {
		primaryByAddr[a.Address] = a.Primary
	}
	if !primaryByAddr["10.0.0.9/24"] {
		t.Fatalf("reth0.0 addresses carry no primary marker for 10.0.0.9/24: %+v", unit.Addresses)
	}
	if got := pickInterfaceSnapshotV4(*unit); got == nil || !got.Equal(net.ParseIP("10.0.0.9")) {
		t.Fatalf("snapshot pickInterfaceSnapshotV4() = %v, want 10.0.0.9", got)
	}
	// The v6 address has no per-family primary slot in config; with no
	// marker the v6 pick keeps the existing order-based result.
	if got := pickInterfaceSnapshotV6(*unit); got == nil || !got.Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("snapshot pickInterfaceSnapshotV6() = %v, want 2001:db8::10 (unmarked order)", got)
	}
}
