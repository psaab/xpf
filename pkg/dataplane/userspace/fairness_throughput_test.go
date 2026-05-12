package userspace

import (
	"math"
	"testing"
	"time"
)

func TestFairnessThroughputWindowComputesRollingCoVAndSaturation(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 1_000, 1_000)

	if got := window.Update(now, status); len(got) != 0 {
		t.Fatalf("first update produced %d summaries, want 0", len(got))
	}

	status.FlowWorkerMap[0].ObservedBytes = 6_000
	status.FlowWorkerMap[1].ObservedBytes = 2_000
	got := window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("second update produced %d summaries, want 1", len(got))
	}
	summary := got[0]
	if !summary.Saturated {
		t.Fatalf("Saturated = false, want true: %+v", summary)
	}
	if summary.FlowCount != 2 {
		t.Fatalf("FlowCount = %d, want 2", summary.FlowCount)
	}
	if math.Abs(summary.ObservedCoV-(2.0/3.0)) > 0.0001 {
		t.Fatalf("ObservedCoV = %.6f, want %.6f", summary.ObservedCoV, 2.0/3.0)
	}
	if summary.ObservedBytes != 6_000 {
		t.Fatalf("ObservedBytes = %d, want 6000", summary.ObservedBytes)
	}
	if summary.WindowSeconds != 10 {
		t.Fatalf("WindowSeconds = %.1f, want 10", summary.WindowSeconds)
	}
}

func TestFairnessThroughputWindowCountsStarvedFlowsOnce(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 1_000, 1_000)

	window.Update(now, status)
	status.FlowWorkerMap[0].ObservedBytes = 101_000
	status.FlowWorkerMap[1].ObservedBytes = 1_100
	got := window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("second update produced %d summaries, want 1", len(got))
	}
	if got[0].StarvedFlowsTotal != 1 {
		t.Fatalf("StarvedFlowsTotal = %d, want 1", got[0].StarvedFlowsTotal)
	}

	status.FlowWorkerMap[0].ObservedBytes = 201_000
	status.FlowWorkerMap[1].ObservedBytes = 1_200
	got = window.Update(now.Add(20*time.Second), status)
	if got[0].StarvedFlowsTotal != 1 {
		t.Fatalf("StarvedFlowsTotal after repeated starvation = %d, want 1", got[0].StarvedFlowsTotal)
	}
}

func TestFairnessThroughputWindowAdvancesDuringIdleScrapes(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 1_000, 1_000)

	window.Update(now, status)
	status.FlowWorkerMap[0].ObservedBytes = 6_000
	got := window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("second update produced %d summaries, want 1", len(got))
	}
	if !got[0].Saturated {
		t.Fatalf("Saturated after 500 B/s sample = false, want true: %+v", got[0])
	}

	status.FlowWorkerMap = nil
	got = window.Update(now.Add(20*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("idle update produced %d summaries, want 1", len(got))
	}
	if got[0].Saturated {
		t.Fatalf("Saturated after idle wall-clock advance = true, want false: %+v", got[0])
	}
	if got[0].WindowSeconds != 20 {
		t.Fatalf("WindowSeconds after idle update = %.1f, want 20", got[0].WindowSeconds)
	}
}

func TestFairnessThroughputWindowTruncationResetsWindow(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 1_000, 1_000)

	window.Update(now, status)
	status.FlowWorkerMap[0].ObservedBytes = 6_000
	got := window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("second update produced %d summaries, want 1", len(got))
	}

	truncated := status
	truncated.FlowWorkerMapTruncated = true
	if got := window.Update(now.Add(20*time.Second), truncated); len(got) != 0 {
		t.Fatalf("truncated update produced %d summaries, want 0", len(got))
	}

	status.FlowWorkerMap[0].ObservedBytes = 7_000
	got = window.Update(now.Add(30*time.Second), status)
	if len(got) != 0 {
		t.Fatalf("post-truncation baseline update produced stale summaries: %+v", got)
	}

	status.FlowWorkerMap[0].ObservedBytes = 8_000
	got = window.Update(now.Add(40*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("post-truncation delta update produced %d summaries, want 1", len(got))
	}
	if got[0].WindowSeconds != 10 {
		t.Fatalf("post-truncation WindowSeconds = %.1f, want 10", got[0].WindowSeconds)
	}
}

func TestFairnessThroughputWindowPrunesStarvedFlowDedup(t *testing.T) {
	window := NewFairnessThroughputWindow(5 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 1_000, 1_000)

	window.Update(now, status)
	status.FlowWorkerMap[0].ObservedBytes = 101_000
	status.FlowWorkerMap[1].ObservedBytes = 1_001
	got := window.Update(now.Add(time.Second), status)
	if len(got) != 1 {
		t.Fatalf("second update produced %d summaries, want 1", len(got))
	}
	if got[0].StarvedFlowsTotal != 1 {
		t.Fatalf("StarvedFlowsTotal = %d, want 1", got[0].StarvedFlowsTotal)
	}

	status.FlowWorkerMap = status.FlowWorkerMap[:1]
	status.FlowWorkerMap[0].ObservedBytes = 201_000
	got = window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("after prune produced %d summaries, want 1", len(got))
	}

	second := throughputStatus(queueID, 0, 5_000).FlowWorkerMap[1]
	status.FlowWorkerMap = append(status.FlowWorkerMap, second)
	status.FlowWorkerMap[0].ObservedBytes = 202_000
	window.Update(now.Add(11*time.Second), status)

	status.FlowWorkerMap[0].ObservedBytes = 302_000
	status.FlowWorkerMap[1].ObservedBytes = 5_001
	got = window.Update(now.Add(12*time.Second), status)
	if got[0].StarvedFlowsTotal != 2 {
		t.Fatalf("StarvedFlowsTotal after re-entry = %d, want 2", got[0].StarvedFlowsTotal)
	}
}

func TestFairnessThroughputWindowPrunesOldSamples(t *testing.T) {
	window := NewFairnessThroughputWindow(15 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 1_000, 1_000)

	window.Update(now, status)
	status.FlowWorkerMap[0].ObservedBytes = 2_000
	status.FlowWorkerMap[1].ObservedBytes = 2_000
	got := window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 || got[0].ObservedBytes != 2_000 {
		t.Fatalf("after first delta got %+v, want 2000 observed bytes", got)
	}

	status.FlowWorkerMap[0].ObservedBytes = 3_000
	status.FlowWorkerMap[1].ObservedBytes = 3_000
	got = window.Update(now.Add(30*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("after prune got %d summaries, want 1", len(got))
	}
	if got[0].ObservedBytes != 2_000 {
		t.Fatalf("ObservedBytes after prune = %d, want 2000", got[0].ObservedBytes)
	}
}

func throughputStatus(queueID uint8, firstBytes uint64, secondBytes uint64) ProcessStatus {
	return ProcessStatus{
		CoSInterfaces: []CoSInterfaceStatus{{
			Ifindex: 80,
			Queues: []CoSQueueStatus{{
				QueueID:           int(queueID),
				TransmitRateBytes: 500,
			}},
		}},
		FlowWorkerMap: []FlowWorkerStatus{
			{
				EgressIfindex: 80,
				CoSQueueID:    &queueID,
				ForwardWireKey: FlowTupleStatus{
					AddrFamily: 2,
					Protocol:   6,
					SrcIP:      "10.0.0.1",
					DstIP:      "198.51.100.1",
					SrcPort:    10001,
					DstPort:    5201,
				},
				ObservedBytes: firstBytes,
			},
			{
				EgressIfindex: 80,
				CoSQueueID:    &queueID,
				ForwardWireKey: FlowTupleStatus{
					AddrFamily: 2,
					Protocol:   6,
					SrcIP:      "10.0.0.2",
					DstIP:      "198.51.100.1",
					SrcPort:    10002,
					DstPort:    5201,
				},
				ObservedBytes: secondBytes,
			},
		},
	}
}
