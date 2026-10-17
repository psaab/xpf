package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRevalidateSnapshotIfindexesRecomputesEgressZoneAndLinkMetadata is the
// #14333 regression: a link that materializes (Ifindex 0 -> 12) between
// snapshot build and apply must not ship the build-time empty link metadata.
// stampEgressZones skips Ifindex<=0 rows, so the row built while the link was
// absent carries EgressZone "", MTU 0, no HardwareAddr and no live Addresses;
// revalidateSnapshotIfindexesInPlace refreshed only the ifindex, so the
// published row kept all of that. prepareSnapshotForApply must rebuild the
// interface rows from the config (as RefreshInterfaceRowsForLink does) so the
// row carries its egress zone and live link metadata.
//
// FAIL-ON-REVERT: without the rebuild in rebuildDerivedSectionsAfterRevalidate
// the row keeps EgressZone "", MTU 0, HardwareAddr "" and no addresses.
func TestRevalidateSnapshotIfindexesRecomputesEgressZoneAndLinkMetadata(t *testing.T) {
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })

	live := false
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName != "ge-0-0-0" || !live {
			return 0, 0, "", nil
		}
		return 12, 9000, "02:00:00:00:00:0c", []InterfaceAddressSnapshot{
			{Family: "inet", Address: "192.0.2.1/24", Scope: 0},
		}
	}
	linkByNamePrev := linkByNameFn
	t.Cleanup(func() { linkByNameFn = linkByNamePrev })
	// linuxLinkUp samples via linkByNameFn; keep it down/unknown in tests.

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}

	// Build while the link is absent: Ifindex 0, no egress zone, no metadata.
	built := buildInterfaceSnapshotsFrom(cfg, map[string]bool{})
	var builtRow *InterfaceSnapshot
	for i := range built {
		if built[i].Name == "ge-0/0/0.0" {
			builtRow = &built[i]
		}
	}
	if builtRow == nil {
		t.Fatalf("built rows = %+v, want ge-0/0/0.0", built)
	}
	if builtRow.Ifindex != 0 || builtRow.EgressZone != "" {
		t.Fatalf("premise: built-at-0 row = %+v, want Ifindex 0 and empty EgressZone", *builtRow)
	}

	snap := &ConfigSnapshot{Config: cfg, Interfaces: built}
	live = true
	m := New()
	m.prepareSnapshotForApply(snap)

	var row *InterfaceSnapshot
	for i := range snap.Interfaces {
		if snap.Interfaces[i].Name == "ge-0/0/0.0" {
			row = &snap.Interfaces[i]
		}
	}
	if row == nil {
		t.Fatalf("interfaces after prepare = %+v, want ge-0/0/0.0", snap.Interfaces)
	}
	if row.Ifindex != 12 {
		t.Fatalf("Ifindex = %d, want 12 (materialized link)", row.Ifindex)
	}
	if row.EgressZone != "trust" {
		t.Fatalf("EgressZone = %q, want %q: row built at Ifindex 0 was never stamped and revalidation did not restamp it (#14333)", row.EgressZone, "trust")
	}
	if row.HardwareAddr != "02:00:00:00:00:0c" {
		t.Fatalf("HardwareAddr = %q, want live MAC", row.HardwareAddr)
	}
	if row.MTU != 9000 {
		t.Fatalf("MTU = %d, want 9000 (live MTU)", row.MTU)
	}
	wantAddrs := []InterfaceAddressSnapshot{{Family: "inet", Address: "192.0.2.1/24", Scope: 0}}
	if !reflect.DeepEqual(row.Addresses, wantAddrs) {
		t.Fatalf("Addresses = %+v, want %+v", row.Addresses, wantAddrs)
	}
	if row.LinkUp == nil {
		t.Fatal("LinkUp must be sampled at prepare")
	}
}

// TestRevalidateChangedIfindexAttachesXDP14333 pins the attach half: when
// prepareSnapshotForApply reports an ifindex change, applyCompiledSnapshot
// must attempt AttachXDP for the new ifindex before publish (the helper
// never attaches XDP itself). Driven at the prepare+reconcile seam because
// a full applyCompiledSnapshot needs privileged BPF maps.
//
// FAIL-ON-REVERT: dropping the revalidateChangedIfindex recording or the
// reconcile call in applyCompiledSnapshot leaves attaches empty.
func TestRevalidateChangedIfindexAttachesXDP14333(t *testing.T) {
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	live := false
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName != "ge-0-0-0" || !live {
			return 0, 0, "", nil
		}
		return 12, 9000, "02:00:00:00:00:0c", nil
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}
	built := buildInterfaceSnapshotsFrom(cfg, map[string]bool{})
	snap := &ConfigSnapshot{Config: cfg, Interfaces: built}
	m := New()
	var attaches []int
	m.attachInterfaceXDPHook = func(ifindex int, forceGeneric bool) error {
		attaches = append(attaches, ifindex)
		return nil
	}
	live = true
	m.prepareSnapshotForApply(snap)
	if !m.revalidateChangedIfindex {
		t.Fatal("prepareSnapshotForApply did not record the 0->12 ifindex change (#14333)")
	}
	// Mirror applyCompiledSnapshot's consume step.
	if m.revalidateChangedIfindex {
		m.reconcileInterfaceAttachmentsForRefreshLocked(snap)
		m.revalidateChangedIfindex = false
	}
	found := false
	for _, idx := range attaches {
		if idx == 12 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no AttachXDP attempt for materialized ifindex 12; attaches=%v (#14333)", attaches)
	}
}
