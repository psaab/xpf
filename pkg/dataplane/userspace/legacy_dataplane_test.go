package userspace

import (
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

type legacyPolicySchedulerSeeder interface {
	SetPolicySchedulerActiveState(map[string]bool)
}

type legacyNeighborProvider interface {
	RegenerateNeighborSnapshot()
	LookupSnapshotNeighbor(ifindex int, ip net.IP) *NeighborSnapshot
	SnapshotHasIfindex(ifindex int) bool
	IsMonitoredIfindex(ifindex int) bool
	ForEachSnapshotNeighbor(fn func(ifindex int, ip net.IP))
	SnapshotNeighbors() []struct {
		Ifindex int
		IP      net.IP
		MAC     net.HardwareAddr
		Family  int
	}
}

type legacyUserspaceControl interface {
	Status() (ProcessStatus, error)
	SetForwardingArmed(bool) (ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (ProcessStatus, error)
	InjectPacket(InjectPacketRequest) (ProcessStatus, error)
}

var _ legacyPolicySchedulerSeeder = (*LegacyDataPlaneAdapter)(nil)
var _ legacyNeighborProvider = (*LegacyDataPlaneAdapter)(nil)
var _ legacyUserspaceControl = (*LegacyDataPlaneAdapter)(nil)

func TestLegacyDataPlaneAdapterForwardsOptionalInterfaces(t *testing.T) {
	m := New()
	adapter := NewLegacyDataPlaneAdapter(m)

	seeder, ok := any(adapter).(legacyPolicySchedulerSeeder)
	if !ok {
		t.Fatal("adapter does not expose policy scheduler seeding interface")
	}
	seeder.SetPolicySchedulerActiveState(map[string]bool{"workhours": true})
	m.mu.Lock()
	seeded := m.policySchedulerDesired["workhours"]
	m.mu.Unlock()
	if !seeded {
		t.Fatal("adapter did not forward policy scheduler active-state seed to desired state")
	}

	m.mu.Lock()
	m.lastSnapshot = &ConfigSnapshot{
		Neighbors: []NeighborSnapshot{
			{Ifindex: 7, IP: "192.0.2.10", MAC: "02:00:00:00:00:01", State: "reachable"},
			{Ifindex: 8, IP: "192.0.2.11", MAC: "02:00:00:00:00:02", State: "failed"},
		},
	}
	m.rebuildNeighborIndex()
	m.monitoredIfindexes = map[int]struct{}{7: {}}
	m.mu.Unlock()

	neighbors, ok := any(adapter).(legacyNeighborProvider)
	if !ok {
		t.Fatal("adapter does not expose neighbor snapshot provider interface")
	}
	if !neighbors.IsMonitoredIfindex(7) {
		t.Fatal("adapter did not forward IsMonitoredIfindex")
	}
	if !neighbors.SnapshotHasIfindex(7) {
		t.Fatal("adapter did not forward SnapshotHasIfindex")
	}
	if neighbors.SnapshotHasIfindex(8) {
		t.Fatal("SnapshotHasIfindex should use publishable neighbor index")
	}
	entry := neighbors.LookupSnapshotNeighbor(7, net.ParseIP("192.0.2.10"))
	if entry == nil || entry.MAC != "02:00:00:00:00:01" {
		t.Fatalf("LookupSnapshotNeighbor = %+v, want forwarded publishable neighbor", entry)
	}
	var enumerated []string
	neighbors.ForEachSnapshotNeighbor(func(ifindex int, ip net.IP) {
		enumerated = append(enumerated, ip.String())
	})
	if len(enumerated) != 1 || enumerated[0] != "192.0.2.10" {
		t.Fatalf("ForEachSnapshotNeighbor enumerated %v, want [192.0.2.10]", enumerated)
	}
	snapNeighbors := neighbors.SnapshotNeighbors()
	if len(snapNeighbors) == 0 || !snapNeighbors[0].IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("SnapshotNeighbors = %+v, want forwarded snapshot entries", snapNeighbors)
	}
	neighbors.RegenerateNeighborSnapshot()

	control, ok := any(adapter).(legacyUserspaceControl)
	if !ok {
		t.Fatal("adapter does not expose userspace control interface")
	}
	if _, err := control.Status(); err == nil {
		t.Fatal("Status returned nil error with helper stopped")
	}
	if _, err := control.SetForwardingArmed(true); err == nil {
		t.Fatal("SetForwardingArmed returned nil error with helper stopped")
	}
	if _, err := control.SetQueueState(1, true, true); err == nil {
		t.Fatal("SetQueueState returned nil error with helper stopped")
	}
	if _, err := control.SetBindingState(1, true, true); err == nil {
		t.Fatal("SetBindingState returned nil error with helper stopped")
	}
	if _, err := control.InjectPacket(InjectPacketRequest{}); err == nil {
		t.Fatal("InjectPacket returned nil error with helper stopped")
	}
}

func TestLegacyDataPlaneAdapterOptionalInterfacesNilSafe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		adapter *LegacyDataPlaneAdapter
	}{
		{name: "nil receiver"},
		{name: "nil manager", adapter: NewLegacyDataPlaneAdapter(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seeder legacyPolicySchedulerSeeder = tc.adapter
			seeder.SetPolicySchedulerActiveState(map[string]bool{"workhours": true})

			var neighbors legacyNeighborProvider = tc.adapter
			neighbors.RegenerateNeighborSnapshot()
			if got := neighbors.LookupSnapshotNeighbor(1, net.ParseIP("192.0.2.10")); got != nil {
				t.Fatalf("LookupSnapshotNeighbor = %+v, want nil", got)
			}
			if neighbors.IsMonitoredIfindex(1) {
				t.Fatal("IsMonitoredIfindex = true, want false")
			}
			if neighbors.SnapshotHasIfindex(1) {
				t.Fatal("SnapshotHasIfindex = true, want false")
			}
			neighbors.ForEachSnapshotNeighbor(func(int, net.IP) {
				t.Fatal("ForEachSnapshotNeighbor callback should not run")
			})
			if got := neighbors.SnapshotNeighbors(); got != nil {
				t.Fatalf("SnapshotNeighbors = %+v, want nil", got)
			}

			var control legacyUserspaceControl = tc.adapter
			if _, err := control.Status(); err == nil {
				t.Fatal("Status returned nil error")
			}
			if _, err := control.SetForwardingArmed(true); err == nil {
				t.Fatal("SetForwardingArmed returned nil error")
			}
			if _, err := control.SetQueueState(1, true, true); err == nil {
				t.Fatal("SetQueueState returned nil error")
			}
			if _, err := control.SetBindingState(1, true, true); err == nil {
				t.Fatal("SetBindingState returned nil error")
			}
			if _, err := control.InjectPacket(InjectPacketRequest{}); err == nil {
				t.Fatal("InjectPacket returned nil error")
			}
		})
	}
}

// #1516 sub-#1451 S1 — verify the cursor-iteration delegation
// methods (added so the gRPC pagination handler type assertion
// against an unexported sessionCursorIterator interface succeeds on
// userspace). Asserts both the production path (production bpfShim
// is a *dataplane.Manager, so the underlying type satisfies the
// cursor interface and the call delegates cleanly) and the
// nil/edge fallback path (sentinel ErrCursorIterationUnsupported
// is returned so the grpcapi handler can fall back to
// getSessionsLegacy instead of surfacing codes.Internal).
type legacyCursorIterator interface {
	IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

var _ legacyCursorIterator = (*LegacyDataPlaneAdapter)(nil)

func TestLegacyDataPlaneAdapterCursorIterationDelegation(t *testing.T) {
	t.Run("production manager satisfies cursor interface", func(t *testing.T) {
		m := New()
		adapter := NewLegacyDataPlaneAdapter(m)
		// The wrapped DataPlane is *dataplane.Manager which does
		// implement IterateSessionsFrom/V6From — the delegation
		// calls reach a real (unloaded) BPF manager and either
		// succeed (empty iteration) or return a non-sentinel error
		// from the underlying BPF map iter.  Either is acceptable;
		// what matters is the sentinel is NOT what we get back
		// when the wrapped manager DOES support cursor iteration.
		err4 := adapter.IterateSessionsFrom(nil, func(dataplane.SessionKey, dataplane.SessionValue) bool { return true })
		if errors.Is(err4, ErrCursorIterationUnsupported) {
			t.Fatalf("IterateSessionsFrom returned sentinel %v even though wrapped DataPlane is *dataplane.Manager", err4)
		}
		err6 := adapter.IterateSessionsV6From(nil, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool { return true })
		if errors.Is(err6, ErrCursorIterationUnsupported) {
			t.Fatalf("IterateSessionsV6From returned sentinel %v even though wrapped DataPlane is *dataplane.Manager", err6)
		}
	})

	t.Run("nil manager returns sentinel", func(t *testing.T) {
		adapter := NewLegacyDataPlaneAdapter(nil)
		err4 := adapter.IterateSessionsFrom(nil, func(dataplane.SessionKey, dataplane.SessionValue) bool { return true })
		if !errors.Is(err4, ErrCursorIterationUnsupported) {
			t.Fatalf("IterateSessionsFrom on nil-manager adapter = %v, want ErrCursorIterationUnsupported", err4)
		}
		err6 := adapter.IterateSessionsV6From(nil, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool { return true })
		if !errors.Is(err6, ErrCursorIterationUnsupported) {
			t.Fatalf("IterateSessionsV6From on nil-manager adapter = %v, want ErrCursorIterationUnsupported", err6)
		}
	})

	t.Run("nil receiver returns sentinel", func(t *testing.T) {
		var adapter *LegacyDataPlaneAdapter
		err4 := adapter.IterateSessionsFrom(nil, func(dataplane.SessionKey, dataplane.SessionValue) bool { return true })
		if !errors.Is(err4, ErrCursorIterationUnsupported) {
			t.Fatalf("IterateSessionsFrom on nil receiver = %v, want ErrCursorIterationUnsupported", err4)
		}
		err6 := adapter.IterateSessionsV6From(nil, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool { return true })
		if !errors.Is(err6, ErrCursorIterationUnsupported) {
			t.Fatalf("IterateSessionsV6From on nil receiver = %v, want ErrCursorIterationUnsupported", err6)
		}
	})
}
