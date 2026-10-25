// #15656: Manager.ReadInterfaceCounters matched only the exact
// BindingStatus.Ifindex. The AF_XDP helper binds the parent physical
// netdev, so a VLAN subinterface (ge-0/0/0.<vlan>, own kernel ifindex)
// never matched and returned authoritative (0,0,0,0),nil while the
// parent carried traffic — consumed as real counters by REST
// /interfaces, /stats/interfaces, gRPC, CLI and Prometheus (#3464
// surfaces only flag Unavailable on error, so success+zero was final).
//
// #16646 supersedes the parent-aggregate arm of #15656: returning the
// parent's whole trunk total under every sibling unit's label made
// siblings report identical numbers and made Prometheus (deduping by
// kernel ifindex) emit the parent traffic N+1 times. Until the helper
// exports per-(ifindex,vlan) counters, a VLAN child now fails closed
// with an explicit unavailable error (consumers omit/Unavailable).
//
// Regression criterion (issue #15656, as amended by #16646):
// physical+tagged/VLAN snapshot binding fixture — the VLAN
// subinterface returns an explicit error, never authoritative zero
// and never the parent aggregate.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// Physical parent (ifindex 7, two queues) carrying traffic, plus a VLAN
// child row (ge-0/0/0.50, kernel ifindex 99, parent 7) in the retained
// snapshot. Reading the child must fail closed (#16646), not return
// the parent aggregate and not return authoritative zero.
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
	if err == nil {
		t.Fatalf("ReadInterfaceCounters(99 VLAN child) = %+v, nil error; want explicit unavailable error (#16646: never the parent aggregate)", got)
	}
	if got != (dataplane.InterfaceCounterValue{}) {
		t.Fatalf("ReadInterfaceCounters(99) = %+v on error, want zero value", got)
	}

	// Parent read is unchanged and returns the aggregate once.
	want := dataplane.InterfaceCounterValue{RxPackets: 15, RxBytes: 1500, TxPackets: 23, TxBytes: 2300}
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
