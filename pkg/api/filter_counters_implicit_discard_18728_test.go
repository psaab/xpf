package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18728: the synthetic implicit-discard term is not a config term, so
// collectFilterCounters emits its helper counter as its own
// xpf_filter_hits_total{term="implicit-discard"} series — once, never
// duplicating the labelset of an authored term with the same name (#15192),
// and never for a filter with a terminal catch-all.
func TestCollectFilterCountersImplicitDiscardSeries18728(t *testing.T) {
	store := newFilterStore(t, []string{
		"set firewall family inet filter A term ssh from destination-port 22",
		"set firewall family inet filter A term ssh then count cS",
		"set firewall family inet filter A term ssh then accept",
		// An authored term that happens to use the synthetic name.
		"set firewall family inet filter B term implicit-discard from destination-port 23",
		"set firewall family inet filter B term implicit-discard then count cB",
		"set firewall family inet filter B term implicit-discard then accept",
		// Permit-by-default: no synthetic term.
		"set firewall family inet filter C term ssh from destination-port 22",
		"set firewall family inet filter C term ssh then count cC",
		"set firewall family inet filter C term ssh then accept",
		"set firewall family inet filter C term default then accept",
	})
	c := newCollector(&Server{store: store})
	dp := &dupTermDP15192{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "A", TermName: "ssh", TermOrdinal: 0, Packets: 5},
			{Family: "inet", FilterName: "A", TermName: "implicit-discard", TermOrdinal: 1, Packets: 7},
			{Family: "inet", FilterName: "B", TermName: "implicit-discard", TermOrdinal: 0, Packets: 3},
			{Family: "inet", FilterName: "B", TermName: "implicit-discard", TermOrdinal: 1, Packets: 4},
			// A stale row for a catch-all filter must not surface.
			{Family: "inet", FilterName: "C", TermName: "implicit-discard", TermOrdinal: 2, Packets: 9},
		}},
	}
	ch := make(chan prometheus.Metric, 64)
	c.collectFilterCounters(ch, dp, fetchUserspaceStatus(dp))
	close(ch)
	got := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		labels := map[string]string{}
		for _, l := range pb.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		key := labels["filter"] + "/" + labels["term"]
		if _, dup := got[key]; dup {
			t.Fatalf("duplicate series %s — Gather would fail (#15192)", key)
		}
		got[key] = pb.GetCounter().GetValue()
	}
	if got["A/implicit-discard"] != 7 || got["A/ssh"] != 5 {
		t.Fatalf("filter A series = %v, want ssh=5 implicit-discard=7", got)
	}
	// B: one series for the shared name (authored + synthetic folded by the
	// by-name aggregate), not two.
	if got["B/implicit-discard"] != 7 {
		t.Fatalf("filter B series = %v, want one implicit-discard series of 7", got)
	}
	if _, ok := got["C/implicit-discard"]; ok {
		t.Fatalf("catch-all filter C must not export an implicit-discard series: %v", got)
	}
}

// #18728 fold: an AUTHORed term named implicit-discard WITHOUT `then count`
// is not instrumented (#16454), so its counter row must not be mistaken for
// the synthetic term's row. The synthetic row at the ordinal after all
// authored terms must still surface as one series; suppressing it by name
// existence alone leaves the filter's implicit-discard hits invisible.
//
// FAIL-ON-REVERT: the old `!authored` guard drops this series; using the
// by-name counter total instead of the synthetic ordinal yields 13 rather
// than 11. Either regression makes this assertion go RED.
func TestCollectFilterCountersImplicitDiscardUncountedAuthored18728(t *testing.T) {
	store := newFilterStore(t, []string{
		"set firewall family inet filter D term implicit-discard from destination-port 23",
		"set firewall family inet filter D term implicit-discard then discard",
		"set firewall family inet filter D term ssh from destination-port 22",
		"set firewall family inet filter D term ssh then count cS",
		"set firewall family inet filter D term ssh then accept",
	})
	c := newCollector(&Server{store: store})
	dp := &dupTermDP15192{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "D", TermName: "ssh", TermOrdinal: 1, Packets: 5},
			// The uncounted authored row has the same name and labelset as
			// the synthetic row, but must not itself cause a series to emit.
			{Family: "inet", FilterName: "D", TermName: "implicit-discard", TermOrdinal: 0, Packets: 2},
			// The synthetic row: ordinal after every authored term.
			{Family: "inet", FilterName: "D", TermName: "implicit-discard", TermOrdinal: 2, Packets: 11},
		}},
	}
	ch := make(chan prometheus.Metric, 64)
	c.collectFilterCounters(ch, dp, fetchUserspaceStatus(dp))
	close(ch)
	got := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		labels := map[string]string{}
		for _, l := range pb.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		key := labels["filter"] + "/" + labels["term"]
		if _, dup := got[key]; dup {
			t.Fatalf("duplicate series %s — Gather would fail (#15192)", key)
		}
		got[key] = pb.GetCounter().GetValue()
	}
	if got["D/implicit-discard"] != 11 {
		t.Fatalf("filter D series = %v, want synthetic implicit-discard=11 only (not the uncounted authored term's 2 hits)", got)
	}
	if got["D/ssh"] != 5 {
		t.Fatalf("filter D series = %v, want ssh=5", got)
	}
}

// If an uncounted authored term has the reserved name but the helper has no
// synthetic-ordinal row, the authored row alone must not create an implicit-
// discard series. This also pins the synthetic row's identity to its ordinal.
func TestCollectFilterCountersOmitsAuthoredOnlyImplicitDiscard18728(t *testing.T) {
	store := newFilterStore(t, []string{
		"set firewall family inet filter D term implicit-discard from destination-port 23",
		"set firewall family inet filter D term implicit-discard then discard",
		"set firewall family inet filter D term ssh from destination-port 22",
		"set firewall family inet filter D term ssh then count cS",
		"set firewall family inet filter D term ssh then accept",
	})
	c := newCollector(&Server{store: store})
	dp := &dupTermDP15192{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "D", TermName: "implicit-discard", TermOrdinal: 0, Packets: 2},
		}},
	}
	got := filterHitsByTerm(t, c, dp)
	if _, ok := got["implicit-discard"]; ok {
		t.Fatalf(
			"authored-only implicit-discard row emitted %g hits; only the synthetic ordinal may produce that series",
			got["implicit-discard"],
		)
	}
}
