package userspace

import (
	"errors"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func stampPreInstallPostCaptureProvider10724(t *testing.T, m *Manager, pre CaptureEpochProvider) *IpsecPMechInventorySnapshot {
	t.Helper()
	// One owned route per tunnel ifindex these cells use (st-before 15,
	// st-after 33, st-old 65): the inventory retains only tunnel-relevant
	// routes, so each stamp keeps exactly its row's route.
	setPMechRouteDump9506(t, []netlink.Route{
		v96MainRoute(t, "10.99.15.0/24", unix.RTN_UNICAST, 15),
		v96MainRoute(t, "10.99.33.0/24", unix.RTN_UNICAST, 33),
		v96MainRoute(t, "10.99.65.0/24", unix.RTN_UNICAST, 65),
	}, nil)
	previousSource := pmechMainRouteSourceSelectorFn
	t.Cleanup(func() { pmechMainRouteSourceSelectorFn = previousSource })
	pmechMainRouteSourceSelectorFn = func() (bool, error) { return false, nil }
	m.SetCaptureEpochProvider(pre)
	stampCaptureAuthority(m.lastSnapshot, pre)
	inventory := m.lastSnapshot.PMechInventory
	if inventory == nil || inventory.Generation != m.lastSnapshot.Generation ||
		inventory.FIBGeneration != m.lastSnapshot.FIBGeneration || !inventory.Complete ||
		len(m.lastSnapshot.IpsecTunnelRows) != 1 || len(inventory.TunnelRows) != 1 ||
		!ownsOnlyRowRoute10724(inventory, m.lastSnapshot.IpsecTunnelRows[0]) ||
		inventory.TunnelRows[0].STN != m.lastSnapshot.IpsecTunnelRows[0].STN ||
		inventory.PolicyIdentity != pmechPolicyIdentity(m.lastSnapshot) {
		t.Fatalf("pre-provider stamp did not produce the baseline inventory: %+v", inventory)
	}
	m.SetCaptureEpochProvider(func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 29, []QueueEpochSnapshot{{Queue: 2000, Epoch: 21}}, 31,
			[]IpsecTunnelRowSnapshot{{STN: "st-after", IfID: 32, LogicalIfindex: 33}}
	})
	return inventory
}

// ownsOnlyRowRoute10724 reports whether the inventory retained exactly the
// route owned by row's logical ifindex.
func ownsOnlyRowRoute10724(inventory *IpsecPMechInventorySnapshot, row IpsecTunnelRowSnapshot) bool {
	return len(inventory.MainRoutes) == 1 && len(inventory.MainRoutes[0].NextHops) == 1 &&
		inventory.MainRoutes[0].NextHops[0].Ifindex == uint32(row.LogicalIfindex)
}

// TestBumpFIBGenerationRestoresBookkeepingOnRefusal10724 pins the retained
// userspace snapshot and allocator to the last helper-confirmed state. The
// helper rejection must not make local state describe an unpublished bump.
func TestBumpFIBGenerationRestoresBookkeepingOnRefusal10724(t *testing.T) {
	h := &fenceHook9696{
		mode: "fixed", fixed: 100,
		fibErr: newHelperRejection("fib generation rollback rejected"),
	}
	m := newFenceManager9696(t, h)
	m.lastSnapshot.FIBGeneration = 17
	m.lastSnapshot.Generation = 4
	m.generation = 4
	preProvider := func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 11, []QueueEpochSnapshot{{Queue: 101, Epoch: 12}}, 13,
			[]IpsecTunnelRowSnapshot{{STN: "st-before", IfID: 14, LogicalIfindex: 15}}
	}
	preInventory := stampPreInstallPostCaptureProvider10724(t, m, preProvider)

	_, err := m.BumpFIBGeneration()
	if !errors.Is(err, errHelperRejected) {
		t.Fatalf("BumpFIBGeneration error = %v, want in-band helper refusal", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot.FIBGeneration != 17 {
		t.Errorf("lastSnapshot.FIBGeneration = %d after refusal, want restored 17", m.lastSnapshot.FIBGeneration)
	}
	if m.lastSnapshot.Generation != 4 {
		t.Errorf("lastSnapshot.Generation = %d after refusal, want restored 4", m.lastSnapshot.Generation)
	}
	if m.generation != 4 {
		t.Errorf("generation allocator = %d after refusal, want restored 4", m.generation)
	}
	if m.lastSnapshot.PermitEpoch != 11 {
		t.Errorf("PermitEpoch after refusal = %d, want restored 11", m.lastSnapshot.PermitEpoch)
	}
	if want := []QueueEpochSnapshot{{Queue: 101, Epoch: 12}}; !reflect.DeepEqual(m.lastSnapshot.QueueEpochs, want) {
		t.Errorf("QueueEpochs after refusal = %+v, want restored %+v", m.lastSnapshot.QueueEpochs, want)
	}
	if m.lastSnapshot.IpsecTunnelSnapshotGeneration != 13 {
		t.Errorf("IpsecTunnelSnapshotGeneration after refusal = %d, want restored 13",
			m.lastSnapshot.IpsecTunnelSnapshotGeneration)
	}
	if want := []IpsecTunnelRowSnapshot{{STN: "st-before", IfID: 14, LogicalIfindex: 15}}; !reflect.DeepEqual(m.lastSnapshot.IpsecTunnelRows, want) {
		t.Errorf("IpsecTunnelRows after refusal = %+v, want restored %+v", m.lastSnapshot.IpsecTunnelRows, want)
	}
	if !reflect.DeepEqual(m.lastSnapshot.PMechInventory, preInventory) {
		t.Errorf("PMechInventory after refusal = %+v, want restored %+v",
			m.lastSnapshot.PMechInventory, preInventory)
	}
}

// A missing response does not prove refusal: the helper may have applied the
// bump before the socket timed out. Keep the advanced generation in that
// unknown-outcome case so the next full snapshot cannot publish a rollback.
// The prefetch here was filtered for the pre-bump tunnel (st-old/65) while
// the retained provider rows name st-after/33, so the locked no-fallback
// stamp must withhold route authority instead of reusing that stale dump.
func TestBumpFIBGenerationRetainsUnknownOutcomeBookkeeping10724(t *testing.T) {
	transportErr := errors.New("control response deadline expired")
	h := &fenceHook9696{mode: "fixed", fixed: 100, fibErr: transportErr}
	m := newFenceManager9696(t, h)
	m.lastSnapshot.FIBGeneration = 17
	m.lastSnapshot.Generation = 4
	m.generation = 4
	preProvider := func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 61, []QueueEpochSnapshot{{Queue: 601, Epoch: 62}}, 63,
			[]IpsecTunnelRowSnapshot{{STN: "st-old", IfID: 64, LogicalIfindex: 65}}
	}
	preInventory := stampPreInstallPostCaptureProvider10724(t, m, preProvider)

	_, err := m.BumpFIBGeneration()
	if !errors.Is(err, transportErr) {
		t.Fatalf("BumpFIBGeneration error = %v, want transport failure", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot.FIBGeneration != 0 {
		t.Errorf("lastSnapshot.FIBGeneration = %d after unknown outcome, want proposed generation 0 retained", m.lastSnapshot.FIBGeneration)
	}
	if m.lastSnapshot.Generation != 5 || m.generation != 5 {
		t.Errorf("unknown outcome must retain advanced generation: snapshot=%d allocator=%d, want 5/5",
			m.lastSnapshot.Generation, m.generation)
	}
	if m.lastSnapshot.PermitEpoch != 29 {
		t.Errorf("PermitEpoch after unknown outcome = %d, want retained provider value 29", m.lastSnapshot.PermitEpoch)
	}
	if want := []QueueEpochSnapshot{{Queue: 2000, Epoch: 21}}; !reflect.DeepEqual(m.lastSnapshot.QueueEpochs, want) {
		t.Errorf("QueueEpochs after unknown outcome = %+v, want retained provider value %+v",
			m.lastSnapshot.QueueEpochs, want)
	}
	if m.lastSnapshot.IpsecTunnelSnapshotGeneration != 31 {
		t.Errorf("IpsecTunnelSnapshotGeneration after unknown outcome = %d, want retained provider value 31",
			m.lastSnapshot.IpsecTunnelSnapshotGeneration)
	}
	if want := []IpsecTunnelRowSnapshot{{STN: "st-after", IfID: 32, LogicalIfindex: 33}}; !reflect.DeepEqual(m.lastSnapshot.IpsecTunnelRows, want) {
		t.Errorf("IpsecTunnelRows after unknown outcome = %+v, want retained provider rows %+v",
			m.lastSnapshot.IpsecTunnelRows, want)
	}
	inventory := m.lastSnapshot.PMechInventory
	if inventory == nil || inventory == preInventory || inventory.Generation != 5 ||
		inventory.FIBGeneration != 0 || inventory.Complete ||
		len(inventory.MainRoutes) != 0 ||
		len(inventory.TunnelRows) != 1 || inventory.TunnelRows[0].STN != "st-after" ||
		inventory.TunnelRows[0].InventoryComplete || inventory.TunnelRows[0].InventoryValid ||
		inventory.TunnelRows[0].InventoryReason != "MAIN_ROUTE_INVENTORY_STALE" ||
		inventory.PolicyIdentity != pmechPolicyIdentity(m.lastSnapshot) {
		t.Errorf("PMechInventory after unknown outcome = %+v, want withheld authority for gen 5/FIB 0 with retained provider tunnel row",
			inventory)
	}
}

// Control for the stale-prefetch case above: when the prefetch was filtered
// for the same tunnel rows the retained provider returns, the unknown
// outcome keeps a complete inventory carrying that tunnel's route.
func TestBumpFIBGenerationRetainsUnknownOutcomeMatchingPrefetch10724(t *testing.T) {
	transportErr := errors.New("control response deadline expired")
	h := &fenceHook9696{mode: "fixed", fixed: 100, fibErr: transportErr}
	m := newFenceManager9696(t, h)
	m.lastSnapshot.FIBGeneration = 17
	m.lastSnapshot.Generation = 4
	m.generation = 4
	preProvider := func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 61, []QueueEpochSnapshot{{Queue: 601, Epoch: 62}}, 63,
			[]IpsecTunnelRowSnapshot{{STN: "st-after", IfID: 32, LogicalIfindex: 33}}
	}
	preInventory := stampPreInstallPostCaptureProvider10724(t, m, preProvider)

	_, err := m.BumpFIBGeneration()
	if !errors.Is(err, transportErr) {
		t.Fatalf("BumpFIBGeneration error = %v, want transport failure", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot.FIBGeneration != 0 || m.lastSnapshot.Generation != 5 || m.generation != 5 {
		t.Errorf("unknown outcome must retain advanced generation: snapshot FIB=%d gen=%d allocator=%d, want 0/5/5",
			m.lastSnapshot.FIBGeneration, m.lastSnapshot.Generation, m.generation)
	}
	if want := []IpsecTunnelRowSnapshot{{STN: "st-after", IfID: 32, LogicalIfindex: 33}}; !reflect.DeepEqual(m.lastSnapshot.IpsecTunnelRows, want) {
		t.Errorf("IpsecTunnelRows after unknown outcome = %+v, want retained provider rows %+v",
			m.lastSnapshot.IpsecTunnelRows, want)
	}
	inventory := m.lastSnapshot.PMechInventory
	if inventory == nil || inventory == preInventory || inventory.Generation != 5 ||
		inventory.FIBGeneration != 0 || !inventory.Complete ||
		len(inventory.TunnelRows) != 1 || inventory.TunnelRows[0].STN != "st-after" ||
		!ownsOnlyRowRoute10724(inventory, m.lastSnapshot.IpsecTunnelRows[0]) ||
		inventory.PolicyIdentity != pmechPolicyIdentity(m.lastSnapshot) {
		t.Errorf("PMechInventory after unknown outcome = %+v, want retained provider inventory for gen 5/FIB 0",
			inventory)
	}
}
