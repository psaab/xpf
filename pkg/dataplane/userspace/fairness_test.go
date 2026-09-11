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
	// The interface resolves (present in the snapshot) but has no active
	// flows on the queue → "no active flows observed".
	status := ProcessStatus{
		Workers:  4,
		Bindings: []BindingStatus{{Interface: "ge-0-0-2", Ifindex: 80}},
	}
	results := EvaluateFairnessRSSExpectations(status, []FairnessRSSExpectation{
		{Interface: "ge-0-0-2", QueueID: 4, RSSExpectation: "max-worker-flow-share:0.5"},
	})
	if len(results) != 1 {
		t.Fatalf("EvaluateFairnessRSSExpectations returned %d rows, want 1", len(results))
	}
	if results[0].Pass {
		t.Fatalf("missing queue expectation passed: %+v", results[0])
	}
	if results[0].Ifindex != 80 {
		t.Fatalf("resolved ifindex = %d, want 80", results[0].Ifindex)
	}
	if !strings.Contains(results[0].Reason, "no active flows observed") {
		t.Fatalf("missing queue reason = %q, want no active flows observed", results[0].Reason)
	}
}

// #hb166 G-9: an rss-expectation keyed by a STABLE interface name must
// track the named interface across NIC re-enumeration. When the kernel
// ifindex of "ge-0-0-2" changes from 80 to 91 between snapshots, the
// expectation must resolve to the CURRENT ifindex (91) and evaluate the
// distribution reported under 91 — not the stale 80. RED on revert: the
// pre-fix ifindex-keyed config baked in the ifindex and would judge
// whichever interface now holds 80 (here, none), or the wrong port.
func TestEvaluateFairnessRSSExpectationsNameKeyedSurvivesReenumeration(t *testing.T) {
	// After re-enumeration ge-0-0-2 is ifindex 91 and carries a balanced
	// 2-worker distribution; ifindex 80 now belongs to a different port
	// (ge-0-0-1) with a single-worker (skewed) distribution.
	status := ProcessStatus{
		Workers: 2,
		Bindings: []BindingStatus{
			{Interface: "ge-0-0-2", Ifindex: 91},
			{Interface: "ge-0-0-1", Ifindex: 80},
		},
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{
			// ge-0-0-2 (ifindex 91): balanced across two workers, 10 flows.
			{Ifindex: 91, QueueID: 4, WorkerID: 0, ActiveFlowCount: 5},
			{Ifindex: 91, QueueID: 4, WorkerID: 1, ActiveFlowCount: 5},
			// ge-0-0-1 (ifindex 80): all 7 flows on one worker (skewed).
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 7},
		},
	}
	results := EvaluateFairnessRSSExpectations(status, []FairnessRSSExpectation{
		{Interface: "ge-0-0-2", QueueID: 4, RSSExpectation: "balanced"},
	})
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1: %+v", len(results), results)
	}
	if results[0].Ifindex != 91 {
		t.Fatalf("resolved ifindex = %d, want 91 (re-enumerated ge-0-0-2)", results[0].Ifindex)
	}
	if !results[0].Pass {
		t.Fatalf("balanced expectation on ge-0-0-2 (ifindex 91) failed: %+v", results[0])
	}
	if results[0].ActiveFlows != 10 {
		t.Fatalf("evaluated the wrong interface: active flows = %d, want 10 (ge-0-0-2)", results[0].ActiveFlows)
	}
}

// #hb166 G-9: a name that is not present in the current dataplane
// snapshot is reported explicitly instead of silently judging ifindex 0.
func TestEvaluateFairnessRSSExpectationsUnresolvedInterface(t *testing.T) {
	results := EvaluateFairnessRSSExpectations(ProcessStatus{Workers: 4}, []FairnessRSSExpectation{
		{Interface: "ge-9-9-9", QueueID: 4, RSSExpectation: "balanced"},
	})
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if results[0].Pass {
		t.Fatalf("unresolved interface passed: %+v", results[0])
	}
	if !strings.Contains(results[0].Reason, "not present in dataplane status") {
		t.Fatalf("unresolved reason = %q, want not present in dataplane status", results[0].Reason)
	}
}

// #9369: an rss-expectation verdict must be INDETERMINATE when the CoS
// active-flow snapshot is truncated. The coordinator retains the first 4096
// sorted (ifindex, queue, worker) triples and flags more than that. The witness
// is the issue's: 4095 lower-key triples fill the snapshot, and the target
// queue keeps only worker 0's count of 1 while worker 1's count of 3 is cut. A
// truncated prefix flips the verdict in BOTH directions (cstruct-max:0.1 and
// balanced would falsely PASS, max-worker-flow-share:0.8 would falsely FAIL), so
// every constrained kind must be indeterminate and never PASS.
//
// The controls stop this cell from passing on a gate that suppresses or
// declares everything indeterminate:
//   - complete [1,0,...] must PASS cstruct-max:0.1, determinately;
//   - complete [1,3,0,...] must FAIL cstruct-max:0.1, determinately;
//   - `any` constrains nothing and still PASSES on the truncated snapshot.
func TestRSSExpectationIsIndeterminateOnTruncatedSnapshot_9369(t *testing.T) {
	const workers = 16
	binding := []BindingStatus{{Interface: "reth0", Ifindex: 80}}
	filler := make([]CoSActiveFlowCountStatus, 0, 4095)
	for i := 0; len(filler) < 4095; i++ {
		filler = append(filler, CoSActiveFlowCountStatus{
			Ifindex: 1 + i/(8*workers), QueueID: uint8((i / workers) % 8), WorkerID: uint32(i % workers), ActiveFlowCount: 1,
		})
	}
	truncatedRows := append(append([]CoSActiveFlowCountStatus(nil), filler...),
		CoSActiveFlowCountStatus{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1})
	truncated := ProcessStatus{Workers: workers, Bindings: binding, CoSActiveFlowCounts: truncatedRows, CoSActiveFlowCountsTruncated: true}

	results := EvaluateFairnessRSSExpectations(truncated, []FairnessRSSExpectation{
		{Interface: "reth0", QueueID: 4, RSSExpectation: "cstruct-max:0.1"},
		{Interface: "reth0", QueueID: 4, RSSExpectation: "balanced"},
		{Interface: "reth0", QueueID: 4, RSSExpectation: "max-worker-flow-share:0.8"},
		{Interface: "reth0", QueueID: 4, RSSExpectation: "any"},
	})
	if len(results) != 4 {
		t.Fatalf("results len = %d, want 4 (presence is part of the contract): %+v", len(results), results)
	}
	byExpectation := map[string]FairnessRSSExpectationResult{}
	for _, r := range results {
		byExpectation[r.Expectation] = r
	}
	for _, want := range []string{"cstruct-max:0.1", "balanced", "max-worker-flow-share:0.8"} {
		r, ok := byExpectation[want]
		if !ok {
			t.Fatalf("no result row for %q: %+v", want, results)
		}
		if !r.Resolved || r.Ifindex != 80 {
			t.Fatalf("%q must evaluate the resolved target queue (ifindex 80): %+v", want, r)
		}
		if !r.Indeterminate || r.Pass {
			t.Fatalf("#9369: %q on a TRUNCATED snapshot must be INDETERMINATE and not PASS; got Indeterminate=%v Pass=%v Reason=%q",
				want, r.Indeterminate, r.Pass, r.Reason)
		}
		if !strings.Contains(r.Reason, "indeterminate") {
			t.Fatalf("%q indeterminate reason = %q", want, r.Reason)
		}
	}
	if r := byExpectation["any"]; !r.Pass || r.Indeterminate {
		t.Fatalf("`any` constrains nothing and must still PASS on a truncated snapshot: %+v", r)
	}

	// CONTROLS on complete (untruncated) data.
	for _, tc := range []struct {
		name     string
		counts   []uint32
		wantPass bool
	}{
		{name: "complete [1,0,...] passes cstruct-max:0.1", counts: []uint32{1, 0}, wantPass: true},
		{name: "complete [1,3,0,...] fails cstruct-max:0.1", counts: []uint32{1, 3}, wantPass: false},
	} {
		rows := []CoSActiveFlowCountStatus{}
		for w, c := range tc.counts {
			rows = append(rows, CoSActiveFlowCountStatus{Ifindex: 80, QueueID: 4, WorkerID: uint32(w), ActiveFlowCount: c})
		}
		st := ProcessStatus{Workers: workers, Bindings: binding, CoSActiveFlowCounts: rows}
		got := EvaluateFairnessRSSExpectations(st, []FairnessRSSExpectation{{Interface: "reth0", QueueID: 4, RSSExpectation: "cstruct-max:0.1"}})
		if len(got) != 1 {
			t.Fatalf("%s: results len = %d, want 1", tc.name, len(got))
		}
		if got[0].Indeterminate || got[0].Pass != tc.wantPass {
			t.Fatalf("%s: got Pass=%v Indeterminate=%v Reason=%q, want Pass=%v determinate",
				tc.name, got[0].Pass, got[0].Indeterminate, got[0].Reason, tc.wantPass)
		}
	}
}
