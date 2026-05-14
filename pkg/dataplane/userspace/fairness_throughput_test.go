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

func TestFairnessThroughputWindowPrunesBoundarySampleWithoutCapping(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 1_000, 1_000)

	window.Update(now, status)
	for step := 1; step <= 4; step++ {
		status.FlowWorkerMap[0].ObservedBytes += 5_000
		got := window.Update(now.Add(time.Duration(step)*10*time.Second), status)
		if len(got) != 1 {
			t.Fatalf("step %d produced %d summaries, want 1", step, len(got))
		}
		if step == 4 {
			if got[0].ObservedBytes != 15_000 {
				t.Fatalf("ObservedBytes after boundary prune = %d, want 15000", got[0].ObservedBytes)
			}
			if got[0].WindowSeconds != 30 {
				t.Fatalf("WindowSeconds after boundary prune = %.1f, want 30", got[0].WindowSeconds)
			}
		}
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

func TestFairnessThroughputWindowDoesNotInflateSaturationAtWindowBoundary(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 0, 0)

	window.Update(now, status)

	var got []FairnessThroughputSummary
	for i := 1; i <= 4; i++ {
		status.FlowWorkerMap[0].ObservedBytes += 2_000
		status.FlowWorkerMap[1].ObservedBytes += 2_000
		got = window.Update(now.Add(time.Duration(i)*10*time.Second), status)
	}
	if len(got) != 1 {
		t.Fatalf("boundary update produced %d summaries, want 1", len(got))
	}
	if got[0].Saturated {
		t.Fatalf("Saturated at steady 400 B/s = true, want false: %+v", got[0])
	}
	if got[0].ObservedBytes != 12_000 {
		t.Fatalf("ObservedBytes at boundary = %d, want 12000", got[0].ObservedBytes)
	}
	if got[0].WindowSeconds != 30 {
		t.Fatalf("WindowSeconds at boundary = %.1f, want 30", got[0].WindowSeconds)
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

func TestFairnessThroughputWindowEqualFlowEstimate(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 0, 0)
	status.CoSActiveFlowCounts = []CoSActiveFlowCountStatus{
		{Ifindex: 80, QueueID: queueID, WorkerID: 0, ActiveFlowCount: 3},
		{Ifindex: 80, QueueID: queueID, WorkerID: 1, ActiveFlowCount: 1},
	}

	window.Update(now, status)
	status.FlowWorkerMap[0].ObservedBytes = 12_000
	status.FlowWorkerMap[1].ObservedBytes = 8_000
	got := window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("second update produced %d summaries, want 1", len(got))
	}
	estimate := got[0].EqualFlowEstimate
	if !estimate.Valid {
		t.Fatalf("EqualFlowEstimate.Valid = false, want true: %+v", estimate)
	}
	if estimate.ActiveWorkers != 2 || estimate.SampledActiveWorkers != 2 || estimate.UnsampledActiveWorkers != 0 {
		t.Fatalf("worker counts = active %d sampled %d unsampled %d, want 2/2/0",
			estimate.ActiveWorkers, estimate.SampledActiveWorkers, estimate.UnsampledActiveWorkers)
	}
	if math.Abs(estimate.TargetPerFlowBPS-3_200) > 0.0001 {
		t.Fatalf("TargetPerFlowBPS = %.3f, want 3200", estimate.TargetPerFlowBPS)
	}
	if math.Abs(estimate.ObservedBPS-16_000) > 0.0001 {
		t.Fatalf("ObservedBPS = %.3f, want 16000", estimate.ObservedBPS)
	}
	if math.Abs(estimate.CappedBPS-12_800) > 0.0001 {
		t.Fatalf("CappedBPS = %.3f, want 12800", estimate.CappedBPS)
	}
	if math.Abs(estimate.SuppressedBPS-3_200) > 0.0001 {
		t.Fatalf("SuppressedBPS = %.3f, want 3200", estimate.SuppressedBPS)
	}
	if math.Abs(estimate.ThroughputLossRatio-0.2) > 0.0001 {
		t.Fatalf("ThroughputLossRatio = %.6f, want 0.2", estimate.ThroughputLossRatio)
	}
	if got := estimate.Workers[0].CapBPS; math.Abs(got-9_600) > 0.0001 {
		t.Fatalf("worker 0 CapBPS = %.3f, want 9600", got)
	}
	if got := estimate.Workers[1].CapBPS; math.Abs(got-3_200) > 0.0001 {
		t.Fatalf("worker 1 CapBPS = %.3f, want 3200", got)
	}
	if got := estimate.Workers[1].SuppressedBPS; math.Abs(got-3_200) > 0.0001 {
		t.Fatalf("worker 1 SuppressedBPS = %.3f, want 3200", got)
	}
}

func TestFairnessThroughputWindowEqualFlowEstimateRequiresUntruncatedActiveCounts(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 0, 0)

	window.Update(now, status)
	status.FlowWorkerMap[0].ObservedBytes = 12_000
	status.FlowWorkerMap[1].ObservedBytes = 8_000
	status.CoSActiveFlowCountsTruncated = true
	got := window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("second update produced %d summaries, want 1", len(got))
	}
	if got[0].EqualFlowEstimate.Valid {
		t.Fatalf("EqualFlowEstimate.Valid = true with truncated CoS active-flow counts: %+v", got[0].EqualFlowEstimate)
	}
	if got[0].EqualFlowEstimate.ActiveWorkers != 0 {
		t.Fatalf("ActiveWorkers = %d with truncated CoS active-flow counts, want 0", got[0].EqualFlowEstimate.ActiveWorkers)
	}
}

func TestFairnessThroughputWindowEqualFlowEstimateValidityBoundaries(t *testing.T) {
	t.Run("single sampled worker is invalid", func(t *testing.T) {
		window := NewFairnessThroughputWindow(30 * time.Second)
		now := time.Unix(100, 0)
		queueID := uint8(4)
		status := throughputStatus(queueID, 0, 0)
		status.FlowWorkerMap = status.FlowWorkerMap[:1]
		status.CoSActiveFlowCounts = []CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: queueID, WorkerID: 0, ActiveFlowCount: 1},
		}

		window.Update(now, status)
		status.FlowWorkerMap[0].ObservedBytes = 12_000
		got := window.Update(now.Add(10*time.Second), status)
		if len(got) != 1 {
			t.Fatalf("second update produced %d summaries, want 1", len(got))
		}
		estimate := got[0].EqualFlowEstimate
		if estimate.Valid {
			t.Fatalf("EqualFlowEstimate.Valid = true for single sampled worker: %+v", estimate)
		}
		if estimate.ActiveWorkers != 1 || estimate.SampledActiveWorkers != 1 {
			t.Fatalf("worker counts = active %d sampled %d, want 1/1", estimate.ActiveWorkers, estimate.SampledActiveWorkers)
		}
	})

	t.Run("all active workers unsampled is invalid", func(t *testing.T) {
		window := NewFairnessThroughputWindow(30 * time.Second)
		now := time.Unix(100, 0)
		queueID := uint8(4)
		status := throughputStatus(queueID, 0, 0)
		status.Workers = 4
		status.CoSActiveFlowCounts = []CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: queueID, WorkerID: 2, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: queueID, WorkerID: 3, ActiveFlowCount: 1},
		}

		window.Update(now, status)
		status.FlowWorkerMap[0].ObservedBytes = 12_000
		status.FlowWorkerMap[1].ObservedBytes = 8_000
		got := window.Update(now.Add(10*time.Second), status)
		if len(got) != 1 {
			t.Fatalf("second update produced %d summaries, want 1", len(got))
		}
		estimate := got[0].EqualFlowEstimate
		if estimate.Valid {
			t.Fatalf("EqualFlowEstimate.Valid = true when all active workers are unsampled: %+v", estimate)
		}
		if estimate.ActiveWorkers != 2 || estimate.SampledActiveWorkers != 0 || estimate.UnsampledActiveWorkers != 2 {
			t.Fatalf("worker counts = active %d sampled %d unsampled %d, want 2/0/2",
				estimate.ActiveWorkers, estimate.SampledActiveWorkers, estimate.UnsampledActiveWorkers)
		}
	})

	t.Run("zero window seconds is invalid", func(t *testing.T) {
		q := &fairnessQueueThroughputWindow{
			bytesByFlow: map[fairnessFlowThroughputKey]uint64{
				{queue: fairnessQueueKey{ifindex: 80, queueID: 4}, tuple: FlowTupleStatus{AddrFamily: 2, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "198.51.100.1", SrcPort: 10001, DstPort: 5201}}: 12_000,
			},
			bytesByWorker: map[uint32]uint64{0: 12_000, 1: 8_000},
			starvedFlows:  make(map[fairnessFlowThroughputKey]struct{}),
		}
		summary := q.summary(fairnessQueueKey{ifindex: 80, queueID: 4}, 0, map[uint32]uint32{0: 1, 1: 1})
		if summary.WindowSeconds != 0 {
			t.Fatalf("WindowSeconds = %.3f, want 0", summary.WindowSeconds)
		}
		if summary.EqualFlowEstimate.Valid {
			t.Fatalf("EqualFlowEstimate.Valid = true with zero window seconds: %+v", summary.EqualFlowEstimate)
		}
	})
}

func TestFairnessThroughputWindowEqualFlowEstimateCapsWorkerIDs(t *testing.T) {
	window := NewFairnessThroughputWindow(30 * time.Second)
	now := time.Unix(100, 0)
	queueID := uint8(4)
	status := throughputStatus(queueID, 0, 0)
	status.Workers = 2
	status.FlowWorkerMap[1].WorkerID = 4_096
	status.CoSActiveFlowCounts = append(status.CoSActiveFlowCounts,
		CoSActiveFlowCountStatus{Ifindex: 80, QueueID: queueID, WorkerID: 4_096, ActiveFlowCount: 1},
	)

	window.Update(now, status)
	status.FlowWorkerMap[0].ObservedBytes = 12_000
	status.FlowWorkerMap[1].ObservedBytes = 8_000
	got := window.Update(now.Add(10*time.Second), status)
	if len(got) != 1 {
		t.Fatalf("second update produced %d summaries, want 1", len(got))
	}
	queueState := window.queues[fairnessQueueKey{ifindex: 80, queueID: queueID}]
	if queueState == nil {
		t.Fatalf("queue state missing after update")
	}
	if got := queueState.bytesByWorker[0]; got != 12_000 {
		t.Fatalf("bytesByWorker[0] = %d, want 12000", got)
	}
	if _, ok := queueState.bytesByWorker[4_096]; ok {
		t.Fatalf("out-of-range worker ID leaked into bytesByWorker: %+v", queueState.bytesByWorker)
	}
	if len(queueState.bytesByWorker) != 1 {
		t.Fatalf("bytesByWorker length = %d, want 1: %+v", len(queueState.bytesByWorker), queueState.bytesByWorker)
	}
	estimate := got[0].EqualFlowEstimate
	if estimate.Valid {
		t.Fatalf("EqualFlowEstimate.Valid = true after out-of-range worker was ignored: %+v", estimate)
	}
	if estimate.ActiveWorkers != 2 || estimate.SampledActiveWorkers != 1 || estimate.UnsampledActiveWorkers != 1 {
		t.Fatalf("worker counts = active %d sampled %d unsampled %d, want 2/1/1",
			estimate.ActiveWorkers, estimate.SampledActiveWorkers, estimate.UnsampledActiveWorkers)
	}
	for _, worker := range estimate.Workers {
		if worker.WorkerID >= 2 {
			t.Fatalf("out-of-range worker ID leaked into estimate: %+v", estimate.Workers)
		}
	}
}

func throughputStatus(queueID uint8, firstBytes uint64, secondBytes uint64) ProcessStatus {
	return ProcessStatus{
		Workers: 2,
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
				WorkerID:      0,
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
				WorkerID:      1,
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
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: queueID, WorkerID: 0, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: queueID, WorkerID: 1, ActiveFlowCount: 1},
		},
	}
}
