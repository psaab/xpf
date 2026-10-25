// #16646: after #15656, ReadInterfaceCounters resolved a VLAN child's
// ifindex to its parent binding and returned the parent's whole trunk
// aggregate as the unit's own counters with a nil error. Sibling units
// reported identical numbers, and Prometheus (deduping by kernel
// ifindex, which differs per VLAN netdev) emitted the parent traffic
// under the parent label and again under every unit label.
//
// Fix direction (issue acceptance): for a logical child, return an
// explicit unavailable error until the helper exports per-(ifindex,vlan)
// counters. Fold H5-03's disabled/unzoned/non-VLAN rows into the same
// predicate: any row with ParentIfindex set and distinct from its own
// ifindex is a child, regardless of VLANID/AdminDisabled/Zone.
//
// Acceptance: two sibling units never both report the parent total, and
// the Prometheus family sum equals real traffic (parent emitted once,
// children omitted via the #3464 error path).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func seedChildCounters16646(m *Manager, child InterfaceSnapshot) {
	seedStatus13273(m, ProcessStatus{
		PID: 1234,
		Bindings: []BindingStatus{
			{Ifindex: 7, RXPackets: 600, RXBytes: 60000, TXPackets: 400, TXBytes: 40000},
			{Ifindex: 7, RXPackets: 400, RXBytes: 40000, TXPackets: 400, TXBytes: 40000},
		},
	})
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0", Ifindex: 7},
		child,
	}}
}

// Two sibling VLAN units with disjoint real traffic must never both
// report the parent total: both fail closed, the parent reports once.
func TestReadInterfaceCountersSiblingVLANChildrenFailClosed16646(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID: 1234,
		Bindings: []BindingStatus{
			{Ifindex: 7, RXPackets: 600, RXBytes: 60000, TXPackets: 400, TXBytes: 40000},
			{Ifindex: 7, RXPackets: 400, RXBytes: 40000, TXPackets: 400, TXBytes: 40000},
		},
	})
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/1", Ifindex: 7},
		{Name: "ge-0/0/1.50", Ifindex: 99, ParentIfindex: 7, VLANID: 50, Zone: "wan"},
		{Name: "ge-0/0/1.80", Ifindex: 100, ParentIfindex: 7, VLANID: 80, Zone: "wan"},
	}}

	for _, child := range []int{99, 100} {
		got, err := m.ReadInterfaceCounters(child)
		if err == nil {
			t.Fatalf("ReadInterfaceCounters(%d sibling VLAN child) = %+v, nil error; want explicit unavailable error, never the parent total", child, got)
		}
		if got != (dataplane.InterfaceCounterValue{}) {
			t.Fatalf("ReadInterfaceCounters(%d) = %+v on error, want zero value", child, got)
		}
	}

	parent, err := m.ReadInterfaceCounters(7)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters(7 parent): %v", err)
	}
	want := dataplane.InterfaceCounterValue{RxPackets: 1000, RxBytes: 100000, TxPackets: 800, TxBytes: 80000}
	if parent != want {
		t.Fatalf("ReadInterfaceCounters(7) = %+v, want parent aggregate %+v (emitted once)", parent, want)
	}
}

// H5-03 cohort: disabled, unzoned and non-VLAN child rows fold into the
// same predicate — none may report the parent total.
func TestReadInterfaceCountersChildVariantsFailClosed16646(t *testing.T) {
	cases := []struct {
		name  string
		child InterfaceSnapshot
	}{
		{"disabled VLAN child", InterfaceSnapshot{Name: "ge-0/0/1.50", Ifindex: 99, ParentIfindex: 7, VLANID: 50, Zone: "wan", AdminDisabled: true}},
		{"unzoned VLAN child", InterfaceSnapshot{Name: "ge-0/0/1.50", Ifindex: 99, ParentIfindex: 7, VLANID: 50}},
		{"non-VLAN child", InterfaceSnapshot{Name: "ge-0/0/1.1", Ifindex: 99, ParentIfindex: 7, Zone: "wan"}},
		{"disabled non-VLAN unzoned child", InterfaceSnapshot{Name: "ge-0/0/1.1", Ifindex: 99, ParentIfindex: 7, AdminDisabled: true}},
		{"logical-only RETH VLAN child", InterfaceSnapshot{Name: "reth0.50", Ifindex: 99, ParentIfindex: 7, VLANID: 50, Zone: "wan", LogicalOnly: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			seedChildCounters16646(m, tc.child)
			got, err := m.ReadInterfaceCounters(99)
			if err == nil {
				t.Fatalf("ReadInterfaceCounters(99 %s) = %+v, nil error; want explicit unavailable error", tc.name, got)
			}
			if got != (dataplane.InterfaceCounterValue{}) {
				t.Fatalf("ReadInterfaceCounters(99) = %+v on error, want zero value", got)
			}
			// Parent remains readable.
			if _, err := m.ReadInterfaceCounters(7); err != nil {
				t.Fatalf("ReadInterfaceCounters(7 parent): %v", err)
			}
		})
	}
}

// A unit-0 row collapsed onto its parent netdev (ParentIfindex ==
// Ifindex) shares the parent's kernel ifindex and must keep returning
// the direct binding counters — it is deduped by ifindex in Prometheus
// and is not a separate child.
func TestReadInterfaceCountersUnit0CollapseStillDirect16646(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID:      1234,
		Bindings: []BindingStatus{{Ifindex: 7, RXPackets: 10, RXBytes: 1000, TXPackets: 20, TXBytes: 2000}},
	})
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/1", Ifindex: 7},
		{Name: "ge-0/0/1.0", Ifindex: 7, ParentIfindex: 7, IsUnit: true},
	}}
	got, err := m.ReadInterfaceCounters(7)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters(7 unit-0 collapse): %v", err)
	}
	want := dataplane.InterfaceCounterValue{RxPackets: 10, RxBytes: 1000, TxPackets: 20, TxBytes: 2000}
	if got != want {
		t.Fatalf("ReadInterfaceCounters(7) = %+v, want %+v", got, want)
	}
}

// Even if a stray binding row existed for the child ifindex, the child
// must not report it as per-child counters before a per-VLAN source
// exists — the snapshot child predicate wins.
func TestReadInterfaceCountersChildWithStrayBindingFailsClosed16646(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID: 1234,
		Bindings: []BindingStatus{
			{Ifindex: 7, RXPackets: 1000, RXBytes: 100000},
			{Ifindex: 99, RXPackets: 5, RXBytes: 500},
		},
	})
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/1", Ifindex: 7},
		{Name: "ge-0/0/1.50", Ifindex: 99, ParentIfindex: 7, VLANID: 50, Zone: "wan"},
	}}
	if got, err := m.ReadInterfaceCounters(99); err == nil {
		t.Fatalf("ReadInterfaceCounters(99 child with stray binding) = %+v, nil error; want unavailable error", got)
	}
}
