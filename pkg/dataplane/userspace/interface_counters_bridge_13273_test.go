// #13273 D1-01: userspace-mode interface traffic counters.
//
// Contract:
//   - ReadInterfaceCounters sums RX/TX packets/bytes across all cached helper
//     bindings for the requested ifindex (multi-queue).
//   - Unknown ifindex reads as zero with no error (idle interface).
//   - No cached helper status fails closed with an error so callers do not emit
//     confident zeros when counters cannot be read.
//   - The published LegacyDataPlaneAdapter delegates to Manager rather than
//     exposing the promoted empty-BPF-shim counter method.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func seedStatus13273(m *Manager, status ProcessStatus) {
	st := status
	m.helperStatusView.Store(&st)
}

func TestReadInterfaceCountersAggregatesBindings13273(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID: 1234,
		Bindings: []BindingStatus{
			{Ifindex: 7, RXPackets: 10, RXBytes: 1000, TXPackets: 20, TXBytes: 2000},
			{Ifindex: 7, RXPackets: 5, RXBytes: 500, TXPackets: 3, TXBytes: 300},
			{Ifindex: 8, RXPackets: 99, RXBytes: 9900, TXPackets: 88, TXBytes: 8800},
		},
	})
	reader := NewLegacyDataPlaneAdapter(m)
	got, err := reader.ReadInterfaceCounters(7)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters(7): %v", err)
	}
	want := dataplane.InterfaceCounterValue{RxPackets: 15, RxBytes: 1500, TxPackets: 23, TxBytes: 2300}
	if got != want {
		t.Fatalf("ReadInterfaceCounters(7) = %+v, want %+v", got, want)
	}
	got, err = reader.ReadInterfaceCounters(8)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters(8): %v", err)
	}
	want = dataplane.InterfaceCounterValue{RxPackets: 99, RxBytes: 9900, TxPackets: 88, TxBytes: 8800}
	if got != want {
		t.Fatalf("ReadInterfaceCounters(8) = %+v, want %+v", got, want)
	}
}

func TestReadInterfaceCountersUnknownIfindexZero13273(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{PID: 1234, Bindings: []BindingStatus{{Ifindex: 7, RXPackets: 10}}})
	got, err := NewLegacyDataPlaneAdapter(m).ReadInterfaceCounters(999)
	if err != nil {
		t.Fatalf("ReadInterfaceCounters(999): %v", err)
	}
	if got != (dataplane.InterfaceCounterValue{}) {
		t.Fatalf("ReadInterfaceCounters(999) = %+v, want zero", got)
	}
}

func TestReadInterfaceCountersUnavailableFailClosed13273(t *testing.T) {
	m := New()
	reader := NewLegacyDataPlaneAdapter(m)
	if _, err := reader.ReadInterfaceCounters(7); err == nil {
		t.Fatal("ReadInterfaceCounters with no cached status = nil error, want fail-closed error")
	}
	seedStatus13273(m, ProcessStatus{PID: 0, Bindings: []BindingStatus{{Ifindex: 7, RXPackets: 10}}})
	if _, err := reader.ReadInterfaceCounters(7); err == nil {
		t.Fatal("ReadInterfaceCounters with PID=0 status = nil error, want fail-closed error")
	}
}

func TestLegacyAdapterForwardsReadInterfaceCounters13273(t *testing.T) {
	m := New()
	seedStatus13273(m, ProcessStatus{
		PID:      1234,
		Bindings: []BindingStatus{{Ifindex: 7, RXPackets: 42, RXBytes: 4200, TXPackets: 24, TXBytes: 2400}},
	})
	adapter := NewLegacyDataPlaneAdapter(m)
	var dp dataplane.DataPlane = adapter
	got, err := dp.ReadInterfaceCounters(7)
	if err != nil {
		t.Fatalf("adapter ReadInterfaceCounters(7): %v", err)
	}
	want := dataplane.InterfaceCounterValue{RxPackets: 42, RxBytes: 4200, TxPackets: 24, TxBytes: 2400}
	if got != want {
		t.Fatalf("adapter ReadInterfaceCounters(7) = %+v, want %+v", got, want)
	}
	if _, err := NewLegacyDataPlaneAdapter(New()).ReadInterfaceCounters(7); err == nil {
		t.Fatal("adapter ReadInterfaceCounters with no status = nil error, want fail-closed")
	}
	var nilAdapter *LegacyDataPlaneAdapter
	if _, err := nilAdapter.ReadInterfaceCounters(7); err == nil {
		t.Fatal("nil adapter ReadInterfaceCounters = nil error, want error")
	}
}
