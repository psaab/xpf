package userspace

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #16689: syncIngressDomainMapLocked wrote every desired row before it
// deleted stale rows, so peak occupancy was len(current union desired)
// on the 8192-entry pinned userspace_ingress_domains_vlan hash. An
// accepted re-plan (len(desired) <= 8192, preflighted by
// checkIngressDomainCapacity) whose union with the pinned plan exceeded
// 8192 hit E2BIG on a new-key insert. The same-plan caller then failed
// closed (ctrl Enabled=0, transit dropped until the status tick
// re-synced the old plan, the commit unapplied), and the bootstrap
// caller returned before ensureProcessLocked, so the pinned over-union
// plan wedged the box with ctrl disabled at the next restart.
//
// The fix prunes stale rows first (reconcileAddressMapKeys, the #13724
// pattern) in syncIngressDomainMapLocked, and prunes stale
// userspace_ingress_ifaces rows in syncIngressIfaceMapLocked before
// installing new ones. These cells drive the production syncs against
// real, capacity-bounded HASH maps: the small-capacity cells are the seam, and
// TestSyncIngressDomainMapAtReal8192Capacity16689 is the privileged
// twin at the shim's actual capacity. Every cell is RED pre-fix
// (E2BIG / ctrl Enabled=0) and GREEN after it.

func newDomainMap16689(t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()
	domainMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(userspaceIngressDomainKey{})),
		ValueSize:  4,
		MaxEntries: maxEntries,
	})
	if err != nil {
		skipIfBPFMapUnavailable(t, "new userspace_ingress_domains_vlan map", err)
	}
	t.Cleanup(func() { domainMap.Close() })
	return domainMap
}

func seedDomain16689(t *testing.T, domainMap *ebpf.Map, entries map[userspaceIngressDomainKey]uint32) {
	t.Helper()
	for k, v := range entries {
		if err := domainMap.Update(k, v, ebpf.UpdateAny); err != nil {
			t.Fatalf("seed userspace_ingress_domains_vlan %v: %v", k, err)
		}
	}
}

func assertDomain16689(t *testing.T, domainMap *ebpf.Map, want map[userspaceIngressDomainKey]uint32) {
	t.Helper()
	var k userspaceIngressDomainKey
	var v uint32
	got := make(map[userspaceIngressDomainKey]uint32)
	iter := domainMap.Iterate()
	for iter.Next(&k, &v) {
		got[k] = v
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate userspace_ingress_domains_vlan: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("domain map = %v, want %v", got, want)
	}
	for key, domain := range want {
		if got[key] != domain {
			t.Fatalf("domain map = %v, want %v", got, want)
		}
	}
}

// Direct domain sync: current is full, desired is disjoint-but-overlapping
// at the same size, so the union exceeds capacity while each plan alone
// fits. Pre-fix the first genuinely new insert hits E2BIG.
func TestSyncIngressDomainMapDeletesStaleBeforeAddingReplacement16689(t *testing.T) {
	m := New()
	domainMap := newDomainMap16689(t, 2)
	seedDomain16689(t, domainMap, map[userspaceIngressDomainKey]uint32{
		{Ifindex: 10, VLANID: 50}: 111,
		{Ifindex: 10, VLANID: 80}: 222,
	})
	desired := map[userspaceIngressDomainKey]uint32{
		{Ifindex: 10, VLANID: 50}:                                   111,
		{Ifindex: 20, VLANID: userspaceIngressDomainUntaggedVLANID}: 333,
	}
	if err := m.syncIngressDomainMapLocked(domainMap, desired); err != nil {
		t.Fatalf("syncIngressDomainMapLocked with a full stale map: %v "+
			"(stale rows must be pruned before new rows are written, #16689)", err)
	}
	assertDomain16689(t, domainMap, desired)
}

// Privileged twin at the shim's real capacity: 4097 stale rows plus
// 4097 disjoint desired rows union to 8194 > 8192, while each plan
// alone is accepted by checkIngressDomainCapacity.
func TestSyncIngressDomainMapAtReal8192Capacity16689(t *testing.T) {
	m := New()
	domainMap := newDomainMap16689(t, userspaceIngressDomainMapCapacity)
	const rows = 4097
	current := make(map[userspaceIngressDomainKey]uint32, rows)
	desired := make(map[userspaceIngressDomainKey]uint32, rows)
	for i := range rows {
		current[userspaceIngressDomainKey{Ifindex: uint32(1000 + i), VLANID: 1}] = 7
		desired[userspaceIngressDomainKey{Ifindex: uint32(100000 + i), VLANID: 1}] = 9
	}
	if err := checkIngressDomainCapacity(len(desired)); err != nil {
		t.Fatalf("premise broken: desired plan must pass preflight: %v", err)
	}
	seedDomain16689(t, domainMap, current)
	if err := m.syncIngressDomainMapLocked(domainMap, desired); err != nil {
		t.Fatalf("syncIngressDomainMapLocked at real 8192 capacity: %v "+
			"(union %d exceeds capacity but each plan fits; stale rows must be pruned first, #16689)",
			err, rows*2)
	}
	assertDomain16689(t, domainMap, desired)
}

func ingressDomainPlanSnapshot16689(ifindexes ...int) *ConfigSnapshot {
	snap := &ConfigSnapshot{}
	for _, idx := range ifindexes {
		snap.Interfaces = append(snap.Interfaces, InterfaceSnapshot{
			Name: "ge-0/0/x", LinuxName: "ge-0-0-x", Zone: "trust",
			Ifindex: idx, RoutingDomain: uint32(idx * 10),
		})
	}
	return snap
}

// End-to-end through syncIngressIfaceMapLocked (the entry both the
// same-plan and bootstrap classifier syncs share): a two-row plan is
// replaced by a disjoint two-row plan on a two-entry domain map.
func TestSyncIngressIfaceMapReplacesStaleAtDomainCapacity16689(t *testing.T) {
	m, ifaceMap := newIngressManager(t, ebpf.Hash, 16)
	domainMap := m.bpfShim.Map(mapNameUserspaceIngressDomains)
	if domainMap == nil {
		t.Fatal("userspace_ingress_domains_vlan map not loaded")
	}
	// Shrink the domain map to the plan size so the union overflows.
	small := newDomainMap16689(t, 2)
	injectShimMap(t, m.bpfShim, mapNameUserspaceIngressDomains, small)
	domainMap = small

	oldSnap := ingressDomainPlanSnapshot16689(10, 20)
	if err := m.syncIngressIfaceMapLocked(oldSnap); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	assertDomain16689(t, domainMap, buildUserspaceIngressDomainEntries(oldSnap))

	newSnap := ingressDomainPlanSnapshot16689(30, 40)
	if err := m.syncIngressIfaceMapLocked(newSnap); err != nil {
		t.Fatalf("re-plan sync at domain capacity: %v "+
			"(stale domain/iface rows must be pruned before new rows are written, #16689)", err)
	}
	assertDomain16689(t, domainMap, buildUserspaceIngressDomainEntries(newSnap))
	var flags uint8
	for _, idx := range []uint32{30, 40} {
		if err := ifaceMap.Lookup(idx, &flags); err != nil {
			t.Fatalf("new ingress ifindex %d missing after re-plan: %v", idx, err)
		}
	}
	for _, idx := range []uint32{10, 20} {
		if err := ifaceMap.Lookup(idx, &flags); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("stale ingress ifindex %d still present after re-plan (err=%v)", idx, err)
		}
	}
}

// injectClassifierManager16689 wires every classifier map
// syncUserspaceClassifierMapsLocked touches, with the domain map at
// domainCap entries, and returns the manager plus the ctrl/domain maps.
func injectClassifierManager16689(t *testing.T, domainCap uint32) (*Manager, *ebpf.Map, *ebpf.Map) {
	t.Helper()
	m := New()
	m.addrListForLocalSyncHook = func(_ netlink.Link, _ int) ([]netlink.Addr, error) { return nil, nil }
	ctrlMap, _ := injectCtrlAndBindingMaps(t, m)
	injectShimMapSpec(t, m.bpfShim, mapNameUserspaceIngressIfaces, &ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16,
	})
	domainMap := newDomainMap16689(t, domainCap)
	injectShimMap(t, m.bpfShim, mapNameUserspaceIngressDomains, domainMap)
	injectShimMapSpec(t, m.bpfShim, mapNameUserspaceLocalV4, &ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(unsafe.Sizeof(userspaceLocalV4Key{})), ValueSize: 1, MaxEntries: 1024,
	})
	injectShimMapSpec(t, m.bpfShim, mapNameUserspaceLocalV6, &ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(unsafe.Sizeof(userspaceShimLocalV6Key{})), ValueSize: 1, MaxEntries: 1024,
	})
	injectShimMapSpec(t, m.bpfShim, mapNameUserspaceInterfaceNATv4, &ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(unsafe.Sizeof(userspaceLocalV4Key{})), ValueSize: 1, MaxEntries: 1024,
	})
	injectShimMapSpec(t, m.bpfShim, mapNameUserspaceInterfaceNATv6, &ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(unsafe.Sizeof(userspaceLocalV6Key{})), ValueSize: 1, MaxEntries: 1024,
	})
	injectUserspaceWGZoneMaps(t, m)
	injectShimMapSpec(t, m.bpfShim, mapNameUserspaceLandScreen, &ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: userspaceLandScreenMapCapacity,
	})
	// #17849: classifier sync unconditionally syncs the proxy-NDP map
	// (maps_sync.go syncProxyNDPAddressMapsWithSetsLocked); the fixture
	// predates that requirement (#17493) and failed with "map not
	// loaded" on any BPF-capable run.
	injectShimMapSpec(t, m.bpfShim, mapNameUserspaceProxyNDPv6, &ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: uint32(unsafe.Sizeof(userspaceLocalV6Key{})), ValueSize: 1, MaxEntries: 8192,
	})
	return m, ctrlMap, domainMap
}

// Same-plan path: an accepted over-union re-plan must land and leave
// ctrl Enabled=1. Pre-fix the E2BIG was not the capacity-preflight
// message, so syncUserspaceClassifierMapsFailClosedLocked drove ctrl
// to Enabled=0 and returned the error (transit dropped, commit
// unapplied).
func TestSamePlanIngressDomainReplanAtCapacityKeepsCtrl16689(t *testing.T) {
	m, ctrlMap, domainMap := injectClassifierManager16689(t, 2)
	oldSnap := ingressDomainPlanSnapshot16689(10, 20)
	seedDomain16689(t, domainMap, buildUserspaceIngressDomainEntries(oldSnap))

	zero := uint32(0)
	if err := ctrlMap.Update(zero, userspaceCtrlValue{
		Enabled: 1, MetadataVersion: userspaceMetadataVersion, Workers: 1, QueueCount: 1,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_ctrl: %v", err)
	}
	m.ctrlWasEnabled = true

	newSnap := ingressDomainPlanSnapshot16689(30, 40)
	if err := m.syncUserspaceClassifierMapsFailClosedLocked(newSnap); err != nil {
		t.Fatalf("same-plan re-plan at domain capacity failed: %v (#16689)", err)
	}
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		t.Fatalf("lookup userspace_ctrl after re-plan: %v", err)
	}
	if ctrl.Enabled != 1 {
		t.Fatalf("userspace_ctrl.Enabled = %d after an accepted re-plan, want 1 "+
			"(the old plan must keep forwarding, #16689)", ctrl.Enabled)
	}
	assertDomain16689(t, domainMap, buildUserspaceIngressDomainEntries(newSnap))
}

// Bootstrap path (programBootstrapMapsLocked, the non-same-plan apply
// and every daemon restart): the same over-union re-plan against the
// pinned map must succeed. Pre-fix it returned the E2BIG before
// ensureProcessLocked ever ran, with ctrl already written Enabled=0 —
// a durable outage until rollback/reboot/manual unpin. Bootstrap
// still leaves ctrl Enabled=0 on success (the helper enables it via
// the status path); the discriminating observable is the nil error
// plus the new plan actually present in the domain map.
func TestBootstrapIngressDomainReplanAtCapacity16689(t *testing.T) {
	m, ctrlMap, domainMap := injectClassifierManager16689(t, 2)
	injectShimMapSpec(t, m.bpfShim, mapNameUserspaceHeartbeat, &ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 16,
	})
	oldSnap := ingressDomainPlanSnapshot16689(10, 20)
	seedDomain16689(t, domainMap, buildUserspaceIngressDomainEntries(oldSnap))

	newSnap := ingressDomainPlanSnapshot16689(30, 40)
	if err := m.programBootstrapMapsLocked(newSnap, config.UserspaceConfig{Workers: 1}); err != nil {
		t.Fatalf("bootstrap re-plan at domain capacity failed: %v "+
			"(a pinned over-union plan must not wedge restart, #16689)", err)
	}
	assertDomain16689(t, domainMap, buildUserspaceIngressDomainEntries(newSnap))
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(uint32(0), &ctrl); err != nil {
		t.Fatalf("lookup userspace_ctrl after bootstrap: %v", err)
	}
	if ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled = %d after bootstrap, want 0 until the helper status path enables it", ctrl.Enabled)
	}
}
