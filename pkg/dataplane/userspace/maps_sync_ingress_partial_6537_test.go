package userspace

import (
	"errors"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
)

// ingressSnapshot builds a ConfigSnapshot whose ingress-adjudicated ifindex set
// is exactly ifindexes, in order.
func ingressSnapshot(ifindexes ...int) *ConfigSnapshot {
	snap := &ConfigSnapshot{}
	for i, idx := range ifindexes {
		snap.Interfaces = append(snap.Interfaces, InterfaceSnapshot{
			Name:      "ge-0/0/" + string(rune('0'+i)),
			LinuxName: "ge-0-0-" + string(rune('0'+i)),
			Zone:      "trust",
			Ifindex:   idx,
		})
	}
	return snap
}

// newIngressManager returns a Manager with a userspace_ingress_ifaces map of
// the given type/size injected.
func newIngressManager(t *testing.T, typ ebpf.MapType, maxEntries uint32) (*Manager, *ebpf.Map) {
	t.Helper()
	m := New()
	ifaceMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       typ,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: maxEntries,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_ingress_ifaces map", err)
	}
	t.Cleanup(func() { ifaceMap.Close() })
	injectShimMap(t, m.bpfShim, mapNameUserspaceIngressIfaces, ifaceMap)
	domainMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: maxEntries,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_ingress_domains map", err)
	}
	t.Cleanup(func() { domainMap.Close() })
	injectShimMap(t, m.bpfShim, mapNameUserspaceIngressDomains, domainMap)
	return m, ifaceMap
}

// TestSyncIngressIfaceMapRecordsInventoryOnEveryPath is the #6537
// fail-on-revert test. It binds the AGREEMENT between the two paths through
// syncIngressIfaceMapLocked rather than one copy of it: whatever the sync
// installs into userspace_ingress_ifaces must be recorded in the delete
// inventory (m.lastIngressIfaces), because that inventory is the ONLY thing a
// later sync rescans when it reaps rows for interfaces that dropped out of the
// config.
//
// Pre-fix the inventory was written on the ALL-SUCCEEDED path only — the one
// path that needs no retry — so a row installed on a pass that later failed was
// permanently unreachable: no later sync could ever discover it, and the XDP
// shim kept treating a de-configured interface as ingress. The rows localise
// which path broke: `all-succeed` stays green under a mutation that only drops
// the partial-path record.
func TestSyncIngressIfaceMapRecordsInventoryOnEveryPath(t *testing.T) {
	tests := []struct {
		name string
		// mapType/maxEntries choose the failure injected into the sync.
		mapType    ebpf.MapType
		maxEntries uint32
		wantErr    bool
		// wantInventory is the set the delete inventory must CONTAIN after
		// the sync (order-insensitive).
		wantInventory []uint32
	}{
		{
			// Control: nothing fails, the inventory is exactly the new set.
			name:          "all-succeed",
			mapType:       ebpf.Hash,
			maxEntries:    8,
			wantErr:       false,
			wantInventory: []uint32{10, 11},
		},
		{
			// A Hash map with room for ONE entry: ifindex 10 installs, 11
			// fails with E2BIG. 10 is now a live row in the BPF map.
			name:          "partial-install-failure",
			mapType:       ebpf.Hash,
			maxEntries:    1,
			wantErr:       true,
			wantInventory: []uint32{10},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ifaceMap := newIngressManager(t, tc.mapType, tc.maxEntries)

			err := m.syncIngressIfaceMapLocked(ingressSnapshot(10, 11))
			if (err != nil) != tc.wantErr {
				t.Fatalf("syncIngressIfaceMapLocked err = %v, wantErr %v", err, tc.wantErr)
			}

			for _, want := range tc.wantInventory {
				if !slices.Contains(m.lastIngressIfaces, want) {
					t.Fatalf("delete inventory %v is missing ifindex %d, which this sync "+
						"INSTALLED into userspace_ingress_ifaces. The reap loop only "+
						"rescans this inventory, so the row is permanently unreachable "+
						"and the shim keeps steering a de-configured interface to "+
						"userspace (#6537)", m.lastIngressIfaces, want)
				}
			}

			// The row really is live in the map — otherwise "unreachable row"
			// would be a claim about an entry that does not exist.
			var val uint8
			for _, want := range tc.wantInventory {
				if err := ifaceMap.Lookup(want, &val); err != nil {
					t.Fatalf("ifindex %d not present in userspace_ingress_ifaces: %v", want, err)
				}
			}
		})
	}
}

// TestSyncIngressIfaceMapReapsRowInstalledOnAFailedPass is the end-to-end half:
// after a PARTIAL install, a later sync on a config that no longer lists the
// interface must actually delete its row. This is the consequence the inventory
// exists to produce, driven through the same production entry point.
func TestSyncIngressIfaceMapReapsRowInstalledOnAFailedPass(t *testing.T) {
	m, ifaceMap := newIngressManager(t, ebpf.Hash, 1)

	// Pass 1: ifindex 10 installs; 11 fails (map full).
	if err := m.syncIngressIfaceMapLocked(ingressSnapshot(10, 11)); err == nil {
		t.Fatal("premise broken: expected a partial-install failure with MaxEntries=1")
	}
	var val uint8
	if err := ifaceMap.Lookup(uint32(10), &val); err != nil {
		t.Fatalf("premise broken: ifindex 10 was not installed: %v", err)
	}

	// Pass 2: the config no longer lists ANY ingress interface. The row for
	// ifindex 10 must be reaped.
	if err := m.syncIngressIfaceMapLocked(ingressSnapshot()); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if err := ifaceMap.Lookup(uint32(10), &val); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("userspace_ingress_ifaces still holds ifindex 10 after it left the "+
			"config (lookup err = %v). The row was installed on a pass that failed "+
			"partway, so it never entered the delete inventory and no later sync can "+
			"reach it — the shim keeps redirecting that interface's traffic to "+
			"userspace (#6537)", err)
	}
	if len(m.lastIngressIfaces) != 0 {
		t.Fatalf("inventory %v not empty after a clean reap", m.lastIngressIfaces)
	}
}

// TestSyncIngressIfaceMapRetainsInventoryOnDeleteFailure covers the SECOND
// early return in the sync — the one inside the reap loop.
//
// This return is defensive rather than production-hot: the production map is a
// HashMap, whose Delete of a present key does not realistically fail, and
// ErrKeyNotExist is already tolerated. The fixture therefore forces the error
// with an Array map, where Delete is unsupported. What it binds is the same
// invariant as the partial-install row: a row installed on THIS pass must reach
// the inventory even when a later step of the same pass aborts. Pre-fix the
// early return left m.lastIngressIfaces at its prior value, which does not name
// the just-installed ifindex 12.
func TestSyncIngressIfaceMapRetainsInventoryOnDeleteFailure(t *testing.T) {
	m, _ := newIngressManager(t, ebpf.Array, 16)

	// Pass 1: seed the inventory with {10, 11}.
	if err := m.syncIngressIfaceMapLocked(ingressSnapshot(10, 11)); err != nil {
		t.Fatalf("premise broken: seeding sync failed: %v", err)
	}
	if !slices.Contains(m.lastIngressIfaces, uint32(11)) {
		t.Fatalf("premise broken: inventory %v does not name 11", m.lastIngressIfaces)
	}

	// Pass 2: 11 drops out (its Delete fails on an Array map) and 12 is new.
	err := m.syncIngressIfaceMapLocked(ingressSnapshot(10, 12))
	if err == nil {
		t.Skip("Array map Delete did not fail on this kernel; the delete early " +
			"return cannot be exercised through this fixture")
	}
	for _, want := range []uint32{11, 12} {
		if !slices.Contains(m.lastIngressIfaces, want) {
			t.Fatalf("delete inventory %v is missing ifindex %d after an aborted pass "+
				"(11 = the delete that must be retried, 12 = a row this pass "+
				"installed); an unrecorded row is unreachable to every later "+
				"sync (#6537)", m.lastIngressIfaces, want)
		}
	}
}
func TestSyncIngressIfaceMapRecordsRowBeforeDomainMapFailure13929(t *testing.T) {
	m, ifaceMap := newIngressManager(t, ebpf.Hash, 16)
	domainMap := m.bpfShim.Map(mapNameUserspaceIngressDomains)
	if domainMap == nil {
		t.Fatal("userspace_ingress_domains map not loaded")
	}
	if err := domainMap.Close(); err != nil {
		t.Fatalf("close domain map to force update failure: %v", err)
	}

	if err := m.syncIngressIfaceMapLocked(ingressSnapshot(10)); err == nil {
		t.Fatal("sync unexpectedly succeeded with the domain map closed")
	}
	var flags uint8
	if err := ifaceMap.Lookup(uint32(10), &flags); err != nil {
		t.Fatalf("ingress row was not installed before the domain update failure: %v", err)
	}
	if !slices.Contains(m.lastIngressIfaces, uint32(10)) {
		t.Fatalf("inventory %v omitted live ingress row 10 after domain-map failure", m.lastIngressIfaces)
	}

	replacement, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 16,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "replacement userspace_ingress_domains map", err)
	}
	t.Cleanup(func() { replacement.Close() })
	injectShimMap(t, m.bpfShim, mapNameUserspaceIngressDomains, replacement)
	if err := m.syncIngressIfaceMapLocked(ingressSnapshot()); err != nil {
		t.Fatalf("retry after restoring domain map: %v", err)
	}
	if err := ifaceMap.Lookup(uint32(10), &flags); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("retry did not reap orphaned ingress row 10: lookup error = %v", err)
	}
}
