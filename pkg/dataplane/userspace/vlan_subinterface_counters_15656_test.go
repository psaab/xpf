// #15656: Manager.ReadInterfaceCounters matched only the exact
// BindingStatus.Ifindex. The AF_XDP helper binds the parent physical
// netdev, so a VLAN subinterface (ge-0/0/0.<vlan>, own kernel ifindex)
// never matched and returned authoritative (0,0,0,0),nil while the
// parent carried traffic — consumed as real counters by REST
// /interfaces, /stats/interfaces, gRPC, CLI and Prometheus (#3464
// surfaces only flag Unavailable on error, so success+zero was final).
//
// Regression criterion (issue #15656): physical+tagged/VLAN snapshot
// binding fixture — the VLAN subinterface returns the parent's
// aggregated counters or an explicit error, never authoritative zero.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// Physical parent (ifindex 7, two queues) carrying traffic, plus a VLAN
// child row (ge-0/0/0.50, kernel ifindex 99, parent 7) in the retained
// snapshot. Reading the child must return the parent aggregate.
func TestReadInterfaceCountersVLANChildResolvesToParent15656(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID: 1234,
		Bindings: []BindingStatus{
			{Ifindex: 7, RXPackets: 10, RXBytes: 1000, TXPackets: 20, TXBytes: 2000},
			{Ifindex: 7, RXPackets: 5, RXBytes: 500, TXPackets: 3, TXBytes: 300},
		},
	})
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0", Ifindex: 7},
		{Name: "ge-0/0/0.50", Ifindex: 99, ParentIfindex: 7, VLANID: 50},
	}}

	got, err := m.ReadInterfaceCounters(99)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters(99 VLAN child): %v", err)
	}
	want := dataplane.InterfaceCounterValue{RxPackets: 15, RxBytes: 1500, TxPackets: 23, TxBytes: 2300}
	if got != want {
		t.Fatalf("ReadInterfaceCounters(99) = %+v, want parent aggregate %+v", got, want)
	}
	if got == (dataplane.InterfaceCounterValue{}) {
		t.Fatal("VLAN child returned authoritative zero while parent carried traffic")
	}

	// Parent read is unchanged.
	parent, err := m.ReadInterfaceCounters(7)
	if err != nil || parent != want {
		t.Fatalf("ReadInterfaceCounters(7) = %+v, %v; want %+v", parent, err, want)
	}
}

// A VLAN child whose parent has no binding must fail closed, not
// return authoritative zero.
func TestReadInterfaceCountersVLANChildUnboundParent15656(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID:      1234,
		Bindings: []BindingStatus{{Ifindex: 8, RXPackets: 99, RXBytes: 9900}},
	})
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0.50", Ifindex: 99, ParentIfindex: 7, VLANID: 50},
	}}
	got, err := m.ReadInterfaceCounters(99)
	if err == nil {
		t.Fatalf("ReadInterfaceCounters(99) = %+v, nil error; want fail-closed error", got)
	}
}

// An ifindex covered by neither a binding nor a snapshot parent row
// fails closed (never success+zero).
func TestReadInterfaceCountersUncoveredIfindexFailsClosed15656(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID:      1234,
		Bindings: []BindingStatus{{Ifindex: 7, RXPackets: 10, RXBytes: 1000}},
	})
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0", Ifindex: 7},
		{Name: "ge-0/0/0.50", Ifindex: 99, ParentIfindex: 7, VLANID: 50},
	}}
	if got, err := m.ReadInterfaceCounters(4242); err == nil {
		t.Fatalf("ReadInterfaceCounters(4242) = %+v, nil error; want fail-closed error", got)
	}
}

// A genuinely idle bound interface still returns its real (zero)
// counters with no error — only uncovered ifindexes fail closed.
func TestReadInterfaceCountersIdleBoundInterfaceZero15656(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID:      1234,
		Bindings: []BindingStatus{{Ifindex: 7}},
	})
	got, err := m.ReadInterfaceCounters(7)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters(7 idle bound): %v", err)
	}
	if got != (dataplane.InterfaceCounterValue{}) {
		t.Fatalf("ReadInterfaceCounters(7) = %+v, want zero", got)
	}
}

// Without a retained snapshot, a non-bound ifindex cannot be resolved
// to a parent and must fail closed rather than report zero.
func TestReadInterfaceCountersNoSnapshotFailsClosed15656(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID:      1234,
		Bindings: []BindingStatus{{Ifindex: 7, RXPackets: 10}},
	})
	if got, err := m.ReadInterfaceCounters(99); err == nil {
		t.Fatalf("ReadInterfaceCounters(99) = %+v, nil error; want fail-closed error", got)
	}
}
