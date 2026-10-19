package userspace

import "testing"

// #15192: BuildFirewallFilterTermCounterIndex must SUM a duplicated
// (family,filter,term) key, not last-wins. Two same-named terms in one
// filter each own a runtime counter; every consumer (Prometheus, CLI,
// gRPC) keys by the same triple, so last-wins silently dropped one
// term's hits.
//
// FAIL-ON-REVERT: restoring `index[key] = counter` makes the summed
// assertion below read the second entry only (20/200).
func TestBuildFirewallFilterTermCounterIndexSumsDuplicate15192(t *testing.T) {
	status := &ProcessStatus{
		FilterTermCounters: []FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "F", TermName: "T", Packets: 10, Bytes: 100},
			{Family: "inet", FilterName: "F", TermName: "T", Packets: 20, Bytes: 200},
			{Family: "inet", FilterName: "F", TermName: "U", Packets: 7, Bytes: 70},
		},
	}
	idx := BuildFirewallFilterTermCounterIndex(status)
	key := FirewallFilterTermCounterKey{Family: "inet", FilterName: "F", TermName: "T"}
	got, ok := idx[key]
	if !ok {
		t.Fatalf("missing aggregated counter for %v", key)
	}
	if got.Packets != 30 || got.Bytes != 300 {
		t.Fatalf("duplicate key = %d packets/%d bytes, want summed 30/300 (#15192)", got.Packets, got.Bytes)
	}
	// Control: a distinct term key is untouched by the aggregation.
	u := idx[FirewallFilterTermCounterKey{Family: "inet", FilterName: "F", TermName: "U"}]
	if u.Packets != 7 || u.Bytes != 70 {
		t.Fatalf("distinct term U = %d/%d, want 7/70", u.Packets, u.Bytes)
	}
	if len(idx) != 2 {
		t.Fatalf("index has %d keys, want 2 (T aggregated, U distinct)", len(idx))
	}
}
