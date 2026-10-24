package userspace

import "testing"

// #15192 / #16460: two same-named terms in one filter each own a runtime
// counter. The per-instance index must key them by ordinal so
// `show firewall` prints each instance's OWN counter (30 under the
// first `t`, 70 under the second), never the summed 100 under both.
// The name-scoped aggregation keeps the #15192 sum so Prometheus
// emits exactly one series per (filter,family,term).
//
// FAIL-ON-REVERT: keying the index by name again (or dropping
// TermOrdinal from the key) collapses both rows onto one key and the
// per-instance assertions below read the sum or last-wins.
func TestBuildFirewallFilterTermCounterIndexSumsDuplicate15192(t *testing.T) {
	status := &ProcessStatus{
		FilterTermCounters: []FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "F", TermName: "T", TermOrdinal: 0, Packets: 10, Bytes: 100},
			{Family: "inet", FilterName: "F", TermName: "T", TermOrdinal: 1, Packets: 20, Bytes: 200},
			{Family: "inet", FilterName: "F", TermName: "U", TermOrdinal: 2, Packets: 7, Bytes: 70},
		},
	}
	idx := BuildFirewallFilterTermCounterIndex(status)
	first, ok := idx[FirewallFilterTermCounterKey{Family: "inet", FilterName: "F", TermOrdinal: 0}]
	if !ok {
		t.Fatalf("missing counter for ordinal 0")
	}
	if first.Packets != 10 || first.Bytes != 100 {
		t.Fatalf("ordinal 0 = %d packets/%d bytes, want its own 10/100 (#16460)", first.Packets, first.Bytes)
	}
	second, ok := idx[FirewallFilterTermCounterKey{Family: "inet", FilterName: "F", TermOrdinal: 1}]
	if !ok {
		t.Fatalf("missing counter for ordinal 1")
	}
	if second.Packets != 20 || second.Bytes != 200 {
		t.Fatalf("ordinal 1 = %d packets/%d bytes, want its own 20/200 (#16460)", second.Packets, second.Bytes)
	}
	// Control: a distinct term is untouched by the split.
	u := idx[FirewallFilterTermCounterKey{Family: "inet", FilterName: "F", TermOrdinal: 2}]
	if u.Packets != 7 || u.Bytes != 70 {
		t.Fatalf("distinct term U = %d/%d, want 7/70", u.Packets, u.Bytes)
	}
	if len(idx) != 3 {
		t.Fatalf("index has %d keys, want 3 (one per instance)", len(idx))
	}

	// #15192 preserved: the name-scoped fold sums both instances.
	byName := AggregateFirewallFilterTermCountersByName(status)
	summed, ok := byName[FirewallFilterTermCounterNameKey{Family: "inet", FilterName: "F", TermName: "T"}]
	if !ok {
		t.Fatalf("missing name-aggregated counter for T")
	}
	if summed.Packets != 30 || summed.Bytes != 300 {
		t.Fatalf("name-aggregated T = %d/%d, want summed 30/300 (#15192)", summed.Packets, summed.Bytes)
	}
	if len(byName) != 2 {
		t.Fatalf("name index has %d keys, want 2 (T aggregated, U distinct)", len(byName))
	}
}

// #16460 legacy fallback: a helper that predates `term_ordinal`
// publishes every row at ordinal 0. Those rows must still SUM at
// ordinal 0 (the pre-#16460 behaviour), never last-wins, so the name
// cohort keeps all its hits during a mixed-version window.
func TestBuildFirewallFilterTermCounterIndexLegacyOrdinalZeroSums16460(t *testing.T) {
	status := &ProcessStatus{
		FilterTermCounters: []FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "F", TermName: "T", Packets: 10, Bytes: 100},
			{Family: "inet", FilterName: "F", TermName: "T", Packets: 20, Bytes: 200},
		},
	}
	idx := BuildFirewallFilterTermCounterIndex(status)
	got, ok := idx[FirewallFilterTermCounterKey{Family: "inet", FilterName: "F", TermOrdinal: 0}]
	if !ok {
		t.Fatalf("missing ordinal-0 counter")
	}
	if got.Packets != 30 || got.Bytes != 300 {
		t.Fatalf("legacy ordinal-0 = %d/%d, want summed 30/300", got.Packets, got.Bytes)
	}
	if len(idx) != 1 {
		t.Fatalf("index has %d keys, want 1", len(idx))
	}
}
