package userspace

import "testing"

// #15680: two terms referencing the same configured policer must resolve
// to their own scoped counters, never to a name-keyed aggregate.
func TestBuildThreeColorPolicerStatusIndexScopesByTerm15680(t *testing.T) {
	status := &ProcessStatus{
		ThreeColorPolicerCounters: []ThreeColorPolicerStatus{
			{ID: 7, Name: "shared", Family: "inet", FilterName: "edge", TermName: "first", Mode: "single-rate", GreenPackets: 10, GreenBytes: 1000},
			{ID: 3, Name: "shared", Family: "inet", FilterName: "edge", TermName: "second", Mode: "single-rate", GreenPackets: 2, GreenBytes: 200, RedPackets: 1, RedBytes: 100},
			{ID: 9, Name: "shared", Family: "inet6", FilterName: "edge", TermName: "first", Mode: "single-rate", GreenPackets: 5, GreenBytes: 500},
			// Unreferenced definition: no term scope, must not leak into
			// any term's rendering.
			{ID: 1, Name: "shared", Mode: "single-rate", GreenPackets: 99, GreenBytes: 9900},
		},
	}
	index := BuildThreeColorPolicerStatusIndex(status)
	if len(index) != 3 {
		t.Fatalf("index has %d entries, want 3 scoped rows: %+v", len(index), index)
	}
	first, ok := index[ThreeColorPolicerStatusKey{Family: "inet", FilterName: "edge", TermName: "first", Policer: "shared"}]
	if !ok {
		t.Fatalf("missing inet/edge/first entry: %+v", index)
	}
	if first.GreenPackets != 10 || first.GreenBytes != 1000 {
		t.Fatalf("first term counters = %+v, want only its own 10/1000", first)
	}
	second, ok := index[ThreeColorPolicerStatusKey{Family: "inet", FilterName: "edge", TermName: "second", Policer: "shared"}]
	if !ok {
		t.Fatalf("missing inet/edge/second entry: %+v", index)
	}
	if second.GreenPackets != 2 || second.RedPackets != 1 {
		t.Fatalf("second term counters = %+v, want only its own 2 green / 1 red", second)
	}
}

func TestBuildThreeColorPolicerStatusIndexNilAndUnscoped15680(t *testing.T) {
	if got := BuildThreeColorPolicerStatusIndex(nil); len(got) != 0 {
		t.Fatalf("nil status index = %+v, want empty", got)
	}
	status := &ProcessStatus{
		ThreeColorPolicerCounters: []ThreeColorPolicerStatus{
			{Name: "legacy", Mode: "single-rate", GreenPackets: 4},
		},
	}
	if got := BuildThreeColorPolicerStatusIndex(status); len(got) != 0 {
		t.Fatalf("unscoped rows must be skipped, got %+v", got)
	}
}

// Name-scoped consumers fold the scoped rows back without losing counts.
func TestAggregateThreeColorPolicerCountersByName15680(t *testing.T) {
	status := &ProcessStatus{
		ThreeColorPolicerCounters: []ThreeColorPolicerStatus{
			{ID: 7, Name: "shared", Family: "inet", FilterName: "edge", TermName: "first", GreenPackets: 10, GreenBytes: 1000},
			{ID: 3, Name: "shared", Family: "inet", FilterName: "edge", TermName: "second", GreenPackets: 2, GreenBytes: 200, DropPackets: 1, DropBytes: 50},
			{ID: 1, Name: "shared", GreenPackets: 99, GreenBytes: 9900},
			{ID: 2, Name: "other", GreenPackets: 4, GreenBytes: 400},
		},
	}
	rows := AggregateThreeColorPolicerCountersByName(status)
	if len(rows) != 2 {
		t.Fatalf("aggregate rows = %+v, want shared+other", rows)
	}
	var shared *ThreeColorPolicerStatus
	for i := range rows {
		if rows[i].Name == "shared" {
			shared = &rows[i]
		}
	}
	if shared == nil {
		t.Fatalf("missing shared aggregate: %+v", rows)
	}
	if shared.GreenPackets != 111 || shared.GreenBytes != 11100 || shared.DropPackets != 1 {
		t.Fatalf("shared aggregate = %+v, want summed 111/11100 drop 1", shared)
	}
	if shared.ID != 1 {
		t.Fatalf("shared aggregate ID = %d, want min 1", shared.ID)
	}
	if got := AggregateThreeColorPolicerCountersByName(nil); got != nil {
		t.Fatalf("nil aggregate = %+v, want nil", got)
	}
}
