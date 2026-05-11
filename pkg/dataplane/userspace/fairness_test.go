package userspace

import (
	"strings"
	"testing"
)

func TestCoSFairnessRSSSummariesBoundsSparseWorkerID(t *testing.T) {
	status := ProcessStatus{
		Workers: 2,
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: 4, WorkerID: ^uint32(0), ActiveFlowCount: 2},
		},
	}

	rows := CoSFairnessRSSSummaries(status)
	if len(rows) != 1 {
		t.Fatalf("CoSFairnessRSSSummaries returned %d rows, want 1", len(rows))
	}
	if got, max := len(rows[0].WorkerFlowCounts), maxFairnessRSSWorkerSlots+1; got > max {
		t.Fatalf("worker distribution length = %d, want <= %d", got, max)
	}
	if got := rows[0].ActiveFlows; got != 3 {
		t.Fatalf("ActiveFlows = %d, want 3", got)
	}
	if got := rows[0].ActiveWorkers; got != 2 {
		t.Fatalf("ActiveWorkers = %d, want 2", got)
	}
}

func TestCoSFairnessRSSSummariesMultipleOverflowWorkers(t *testing.T) {
	status := ProcessStatus{
		Workers: 2,
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: 4, WorkerID: 4096, ActiveFlowCount: 2},
			{Ifindex: 80, QueueID: 4, WorkerID: ^uint32(0), ActiveFlowCount: 3},
		},
	}

	rows := CoSFairnessRSSSummaries(status)
	if len(rows) != 1 {
		t.Fatalf("CoSFairnessRSSSummaries returned %d rows, want 1", len(rows))
	}
	if got := rows[0].ActiveFlows; got != 6 {
		t.Fatalf("ActiveFlows = %d, want 6", got)
	}
	if got := rows[0].ActiveWorkers; got != 3 {
		t.Fatalf("ActiveWorkers = %d, want 3", got)
	}
	if got := len(rows[0].WorkerFlowCounts); got != 4 {
		t.Fatalf("worker distribution length = %d, want 4", got)
	}
}

func TestBoundedFairnessRSSWorkerSlots(t *testing.T) {
	tests := []struct {
		name     string
		workers  int
		fallback int
		want     int
	}{
		{name: "negative workers and fallback", workers: -1, fallback: -1, want: 0},
		{name: "zero workers uses fallback", workers: 0, fallback: 8, want: 8},
		{name: "positive workers ignore fallback", workers: 4, fallback: 8, want: 4},
		{name: "workers capped", workers: maxFairnessRSSWorkerSlots + 1, fallback: 1, want: maxFairnessRSSWorkerSlots},
		{name: "fallback capped", workers: 0, fallback: maxFairnessRSSWorkerSlots + 1, want: maxFairnessRSSWorkerSlots},
		{name: "worker cap boundary", workers: maxFairnessRSSWorkerSlots, fallback: 1, want: maxFairnessRSSWorkerSlots},
		{name: "fallback cap boundary", workers: 0, fallback: maxFairnessRSSWorkerSlots, want: maxFairnessRSSWorkerSlots},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boundedFairnessRSSWorkerSlots(tt.workers, tt.fallback); got != tt.want {
				t.Fatalf("boundedFairnessRSSWorkerSlots(%d, %d) = %d, want %d", tt.workers, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestEvaluateFairnessRSSExpectationsFailsMissingQueue(t *testing.T) {
	results := EvaluateFairnessRSSExpectations(ProcessStatus{Workers: 4}, []FairnessRSSExpectation{
		{Ifindex: 80, QueueID: 4, RSSExpectation: "max-worker-flow-share:0.5"},
	})
	if len(results) != 1 {
		t.Fatalf("EvaluateFairnessRSSExpectations returned %d rows, want 1", len(results))
	}
	if results[0].Pass {
		t.Fatalf("missing queue expectation passed: %+v", results[0])
	}
	if !strings.Contains(results[0].Reason, "no active flows observed") {
		t.Fatalf("missing queue reason = %q, want no active flows observed", results[0].Reason)
	}
}
