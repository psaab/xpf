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
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatSystemBuffers output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "worker 0/queue 0/slot 0/ge-0-0-0") {
		t.Fatalf("non-detail output included per-binding row:\n%s", out)
	}
	detail := FormatSystemBuffers(status, true)
	if !strings.Contains(detail, "worker 0/queue 0/slot 0/ge-0-0-0") {
		t.Fatalf("detail output missing per-binding row:\n%s", detail)
	}
}

func TestFormatSystemBuffersFallsBackWhenPerBindingLacksCapacity(t *testing.T) {
	status := ProcessStatus{
		Bindings: []BindingStatus{
			{Slot: 2, WorkerID: 1, QueueID: 0, Interface: "ge-0-0-1", UmemTotalFrames: 256, UmemInflightFrames: 64},
		},
		PerBinding: []BindingCountersSnapshot{
			{WorkerID: 1, QueueID: 0, OutstandingTX: 10},
		},
	}

	out := FormatSystemBuffers(status, true)
	for _, want := range []string{
		"aggregate/1",
		"256",
		"64",
		"worker 1/queue 0/slot 2/ge-0-0-1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatSystemBuffers output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatSystemBuffersFallsBackPerSparsePerBindingRow(t *testing.T) {
	status := ProcessStatus{
		Bindings: []BindingStatus{
			{Slot: 2, WorkerID: 1, QueueID: 0, Ifindex: 7, Interface: "ge-0-0-1", UmemTotalFrames: 256, UmemInflightFrames: 64},
			{Slot: 3, WorkerID: 1, QueueID: 1, Ifindex: 8, Interface: "ge-0-0-2", UmemTotalFrames: 512, UmemInflightFrames: 128},
		},
		PerBinding: []BindingCountersSnapshot{
			{WorkerID: 1, QueueID: 0, Ifindex: 7, UmemTotalFrames: 1000, UmemInflightFrames: 500},
			{WorkerID: 1, QueueID: 1, Ifindex: 8, OutstandingTX: 10},
		},
	}

	out := FormatSystemBuffers(status, true)
	for _, want := range []string{
		"aggregate/2",
		"1512",
		"628",
		"worker 1/queue 0/slot 2/ge-0-0-1",
		"worker 1/queue 1/slot 3/ge-0-0-2",
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

func TestFormatSystemBuffersIncludesCoSAndRuntimePressure(t *testing.T) {
	owner := uint32(2)
	status := ProcessStatus{
		NeighborEntries: 12,
		Bindings: []BindingStatus{
			{
				Slot:                        4,
				WorkerID:                    2,
				QueueID:                     7,
				Ifindex:                     9,
				Interface:                   "ge-0-0-9",
				UmemTotalFrames:             1000,
				UmemInflightFrames:          100,
				TxRingCapacity:              100,
				OutstandingTX:               10,
				ActiveFlowCount:             29,
				FlowCacheCollisionEvictions: 31,
				DebugPendingFillFrames:      3,
				DebugSpareFillFrames:        5,
				DebugPendingTXPrepared:      7,
				DebugPendingTXLocal:         11,
				DbgTxRingFull:               13,
				DbgSendtoENOBUFS:            17,
				DbgBoundPendingOverflow:     19,
				DbgCoSQueueOverflow:         23,
				RxFillRingEmptyDescs:        37,
				RedirectInboxOverflowDrops:  41,
				PendingTXLocalOverflowDrops: 43,
				TxSubmitErrorDrops:          47,
			},
		},
		CoSInterfaces: []CoSInterfaceStatus{
			{
				Ifindex:       9,
				InterfaceName: "ge-0-0-9",
				Queues: []CoSQueueStatus{
					{
						QueueID:         2,
						OwnerWorkerID:   &owner,
						ForwardingClass: "ef",
						BufferBytes:     1000,
						QueuedBytes:     850,
					},
				},
			},
		},
	}

	out := FormatSystemBuffers(status, true)
	for _, want := range []string{
		"CoS queue bytes",
		"aggregate/1",
		"850",
		"85.0% WARNING",
		"ge-0-0-9/queue 2/ef/worker 2",
		"Userspace Status Counters:",
		"Neighbor cache entries",
		"Flow cache active flows",
		"Flow cache collision evict",
		"Pending fill frames",
		"Spare fill frames",
		"Pending TX prepared",
		"Pending TX local",
		"TX ring full events",
		"sendto ENOBUFS",
		"Bound pending overflow",
		"CoS queue overflow",
		"RX fill-ring empty descs",
		"Redirect inbox overflow",
		"Pending TX local overflow",
		"TX submit error drops",
		"worker 2/queue 7/slot 4/ge-0-0-9",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatSystemBuffers output missing %q:\n%s", want, out)
		}
	}
}

func TestFormatSystemBuffersKeepsDynamicCountsOutOfUtilizationTable(t *testing.T) {
	status := ProcessStatus{
		NeighborEntries: 42,
		Bindings: []BindingStatus{
			{Slot: 1, WorkerID: 0, QueueID: 0, Interface: "ge-0-0-0", UmemTotalFrames: 1000, UmemInflightFrames: 250},
		},
		PerBinding: []BindingCountersSnapshot{
			{WorkerID: 0, QueueID: 0, ActiveFlowCount: 128},
		},
	}

	out := FormatSystemBuffers(status, false)
	sections := strings.SplitN(out, "Userspace Status Counters:", 2)
	if len(sections) != 2 {
		t.Fatalf("FormatSystemBuffers missing status counter section:\n%s", out)
	}
	utilSection, counterSection := sections[0], sections[1]
	for _, dynamic := range []string{"Neighbor cache entries", "Flow cache active flows"} {
		if strings.Contains(utilSection, dynamic) {
			t.Fatalf("%s appeared in utilization table without a bounded capacity:\n%s", dynamic, out)
		}
		if !strings.Contains(counterSection, dynamic) {
			t.Fatalf("%s missing from status counter section:\n%s", dynamic, out)
		}
	}
	if strings.Contains(counterSection, "%") {
		t.Fatalf("status counters rendered a fill percentage without a denominator:\n%s", out)
	}
}

func TestFormatSystemBuffersCoSAggregateSumsCapacityWithUsage(t *testing.T) {
	status := ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{
			{
				Ifindex:       80,
				InterfaceName: "reth0.80",
				Queues: []CoSQueueStatus{
					{QueueID: 4, ForwardingClass: "iperf-a", BufferBytes: 1000, QueuedBytes: 700},
					{QueueID: 5, ForwardingClass: "iperf-b", BufferBytes: 1000, QueuedBytes: 100},
				},
			},
		},
	}

	out := FormatSystemBuffers(status, false)
	for _, want := range []string{
		"CoS queue bytes",
		"aggregate/2",
		"2000",
		"800",
		"40.0% OK",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("FormatSystemBuffers output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "80.0%") {
		t.Fatalf("CoS aggregate used max capacity instead of summed capacity:\n%s", out)
	}
}
