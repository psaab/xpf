package userspace

import (
	"strings"
	"testing"
)

func TestFormatSystemBuffersUsesPerBindingAggregatesBeforeDetails(t *testing.T) {
	status := ProcessStatus{
		Bindings: []BindingStatus{
			{Slot: 10, WorkerID: 1, QueueID: 2, Ifindex: 7, Interface: "ge-0-0-1"},
			{Slot: 11, WorkerID: 1, QueueID: 3, Ifindex: 8, Interface: "ge-0-0-2"},
		},
		PerBinding: []BindingCountersSnapshot{
			{WorkerID: 1, QueueID: 2, Ifindex: 7, UmemTotalFrames: 1000, UmemInflightFrames: 800, TxRingCapacity: 100, OutstandingTX: 90},
			{WorkerID: 1, QueueID: 3, Ifindex: 8, UmemTotalFrames: 1000, UmemInflightFrames: 100, TxRingCapacity: 100, OutstandingTX: 10},
		},
	}

	out := FormatSystemBuffers(status, true)
	for _, want := range []string{
		"Userspace Buffer Utilization:",
		"AF_XDP UMEM frames",
		"AF_XDP TX ring",
		"aggregate/2",
		"2000",
		"900",
		"45.0% OK",
		"100",
		"90",
		"90.0% CRITICAL",
		"worker 1/queue 2/slot 10/ge-0-0-1",
		"worker 1/queue 3/slot 11/ge-0-0-2",
		"userspace buffer row(s) at high utilization",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatSystemBuffers output missing %q:\n%s", want, out)
		}
	}

	agg := strings.Index(out, "aggregate/2")
	detail := strings.Index(out, "worker 1/queue 2")
	if agg < 0 || detail < 0 || agg > detail {
		t.Fatalf("aggregate rows must render before detail rows:\n%s", out)
	}
}

func TestFormatSystemBuffersFallsBackToBindingsAndWarnsAtEighty(t *testing.T) {
	status := ProcessStatus{
		Bindings: []BindingStatus{
			{Slot: 0, WorkerID: 0, QueueID: 0, Interface: "ge-0-0-0", UmemTotalFrames: 100, UmemInflightFrames: 80},
		},
	}

	out := FormatSystemBuffers(status, false)
	for _, want := range []string{
		"AF_XDP UMEM frames",
		"aggregate/1",
		"80.0% WARNING",
		"worker 0/queue 0/slot 0/ge-0-0-0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatSystemBuffers output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatSystemBuffersDocumentsMissingStatusFields(t *testing.T) {
	out := FormatSystemBuffers(ProcessStatus{
		PerBinding: []BindingCountersSnapshot{{WorkerID: 0, QueueID: 0, OutstandingTX: 10}},
	}, false)

	for _, want := range []string{
		"unavailable: helper status does not include bounded AF_XDP capacity gauges",
		"per_binding[].umem_total_frames",
		"per_binding[].tx_ring_capacity",
		"bindings[] mirrors",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatSystemBuffers output missing %q:\n%s", want, out)
		}
	}
}
