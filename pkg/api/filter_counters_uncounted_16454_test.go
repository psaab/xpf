package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16454: an uncounted term must never emit an xpf_filter_hits_total
// series, even when a legacy helper publishes a row for it or the
// retired map path would emit; a counted-but-idle term still emits 0,
// and a counted term with hits emits its value.
//
// FAIL-ON-REVERT: dropping `term.Count != ""` from the emit condition in
// collectFilterCounters re-emits the uncounted `block` series and the
// absence assertion goes RED.
func TestCollectFilterCountersOmitsUncountedTerms16454(t *testing.T) {
	store := newFilterStore(t, []string{
		"set firewall family inet filter edge term block from destination-port 22",
		"set firewall family inet filter edge term block then discard",
		"set firewall family inet filter edge term counted-idle from destination-port 80",
		"set firewall family inet filter edge term counted-idle then count hits",
		"set firewall family inet filter edge term counted-idle then accept",
		"set firewall family inet filter edge term counted-hit from destination-port 443",
		"set firewall family inet filter edge term counted-hit then count hits2",
		"set firewall family inet filter edge term counted-hit then accept",
	})
	c := newCollector(&Server{store: store})
	dp := &filterUserspaceDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{
			FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
				// Legacy-helper row for the UNCOUNTED term: must be ignored.
				{Family: "inet", FilterName: "edge", TermName: "block", Packets: 99},
				{Family: "inet", FilterName: "edge", TermName: "counted-idle", Packets: 0},
				{Family: "inet", FilterName: "edge", TermName: "counted-hit", Packets: 42},
			},
		},
	}

	got := filterHitsByTerm(t, c, dp)
	if _, ok := got["block"]; ok {
		t.Errorf("uncounted term block emitted xpf_filter_hits_total=%v; want no series (#16454)", got["block"])
	}
	if v, ok := got["counted-idle"]; !ok || v != 0 {
		t.Errorf("counted-idle = %v (present=%v), want present 0 series (#16454)", v, ok)
	}
	if got["counted-hit"] != 42 {
		t.Errorf("counted-hit = %v, want 42 (#16454)", got["counted-hit"])
	}
}
