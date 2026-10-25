package userspace

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16513: a `primary` designation on any address of a zoned untagged
// unit 0 other than the string-first one made the Rust helper refuse
// every snapshot. The Go builder marked the designation only on the
// unit row; the base row the unit collapses onto (same linux name,
// same ifindex) is built from the kernel listing alone and carried no
// marker, so its order-based pick (10.0.0.10 / 2001:db8::10) disagreed
// with the unit's designated pick (10.0.0.9 / 2001:db8::9) and
// populate_egress reported InterfaceSharedIfindexAttributeConflict.
//
// These cells pin the Go half of the fix: when unit 0 collapses onto
// the base netdev (snapshotLinuxName(unit0) == linuxName, the #14331
// predicate), the base row carries the same configured marker as the
// unit row, so both rows pick the designated address.
//
// FAIL-ON-REVERT: drop the base-row overlay in
// buildInterfaceSnapshotsFrom and the base row below is unmarked
// (pick .10 / ::10) while the unit row stays marked (.9 / ::9).
func TestBuildSnapshotBaseRowCarriesCollapsingUnit0Primary16513(t *testing.T) {
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-1" {
			return 42, 1500, "02:00:00:00:00:42", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.0.10/24"},
				{Family: "inet", Address: "10.0.0.9/24"},
				{Family: "inet6", Address: "2001:db8::10/64"},
				{Family: "inet6", Address: "2001:db8::9/64"},
			}
		}
		return 0, 0, "", nil
	}

	cfg := routingDomainCfg7160(t,
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.10/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.9/24 primary",
		"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8::10/64",
		"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8::9/64 primary",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	)

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	base := snapshotByName9132(t, snap.Interfaces, "ge-0/0/1")
	unit := snapshotByName9132(t, snap.Interfaces, "ge-0/0/1.0")
	if base.Ifindex != 42 || unit.Ifindex != 42 {
		t.Fatalf("fixture: base ifindex=%d unit ifindex=%d, want both 42 (untagged collapse)", base.Ifindex, unit.Ifindex)
	}
	for _, row := range []struct {
		name string
		snap InterfaceSnapshot
	}{{"base", base}, {"unit", unit}} {
		marked := map[string]bool{}
		for _, a := range row.snap.Addresses {
			marked[a.Address] = a.Primary
		}
		if !marked["10.0.0.9/24"] || !marked["2001:db8::9/64"] {
			t.Fatalf("%s row %q lost the designated primary marker: %+v", row.name, row.snap.Name, row.snap.Addresses)
		}
		if marked["10.0.0.10/24"] || marked["2001:db8::10/64"] {
			t.Fatalf("%s row %q marked a non-designated address primary: %+v", row.name, row.snap.Name, row.snap.Addresses)
		}
		if got := pickInterfaceSnapshotV4(row.snap); got == nil || !got.Equal(net.ParseIP("10.0.0.9")) {
			t.Fatalf("%s row pickInterfaceSnapshotV4() = %v, want 10.0.0.9 (designated)", row.name, got)
		}
		if got := pickInterfaceSnapshotV6(row.snap); got == nil || !got.Equal(net.ParseIP("2001:db8::9")) {
			t.Fatalf("%s row pickInterfaceSnapshotV6() = %v, want 2001:db8::9 (designated)", row.name, got)
		}
	}
}

// Control: with no `primary` designation anywhere, the base row stays
// unmarked and both rows keep the order-based pick (.10 / ::10) — the
// overlay must not manufacture a designation.
func TestBuildSnapshotBaseRowUnmarkedWithoutDesignation16513(t *testing.T) {
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-1" {
			return 42, 1500, "02:00:00:00:00:42", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.0.0.10/24"},
				{Family: "inet", Address: "10.0.0.9/24"},
			}
		}
		return 0, 0, "", nil
	}

	cfg := routingDomainCfg7160(t,
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.10/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.9/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	)

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	base := snapshotByName9132(t, snap.Interfaces, "ge-0/0/1")
	for _, a := range base.Addresses {
		if a.Primary {
			t.Fatalf("base row marked %q primary with no designation: %+v", a.Address, base.Addresses)
		}
	}
	if got := pickInterfaceSnapshotV4(base); got == nil || !got.Equal(net.ParseIP("10.0.0.10")) {
		t.Fatalf("unmarked base pick = %v, want 10.0.0.10 (order rule)", got)
	}
}
