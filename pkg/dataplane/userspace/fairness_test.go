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
