package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #8177 row 7 is ALREADY CORRECT and this cell exists so it stays that way.
//
// collectPolicyCounters does `if !statsEnabled && !rule.Count { continue }` —
// it SKIPS the series rather than emitting a zero. That is the right answer for
// a time series and the opposite of what the other six surfaces needed: an
// absent sample is not a zero sample, and a zero here would be indistinguishable
// from a policy that genuinely matched no traffic, forever, in every dashboard
// and alert built on it.
//
// The risk this guards is a future audit "fixing" the inconsistency the wrong
// way — seeing five surfaces that now report the stats-disabled state and
// making this one report it too, by emitting a 0 with a flag. #8177 deliberately
// did not touch this function; a red here means someone turned a skip into a
// sample.
func TestPolicyCountersSkipRatherThanEmitZeroWhenStatsDisabled_8177(t *testing.T) {
	store := newStatsFlagRESTStore(t, false) // knob OFF, one count-less rule
	c := &xpfCollector{deps: collectorDeps{store: store}}
	c.initPolicyDescriptors()

	dp := &schedulerCounterAPIDP{
		Manager:  dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{},
	}

	ch := make(chan prometheus.Metric)
	go func() {
		c.collectPolicyCounters(ch, dp)
		close(ch)
	}()
	var got []prometheus.Metric
	for m := range ch {
		got = append(got, m)
	}

	// Scoped to the per-policy HIT series, and matched on fqName rather than
	// anywhere in the descriptor. Two ways to get this wrong, both of which I
	// did before landing it: asserting "no metrics at all" fails on correct code
	// (the collector emits xpf_policy_counters_unpublished_rules on every path
	// by design, a meta-gauge about the scrape rather than a per-policy sample);
	// and a substring search over Desc().String() matches that gauge too,
	// because its HELP TEXT contains the words "xpf_policy_hits_total". A loose
	// match here reports the defect this cell exists to deny.
	hits := 0
	for _, m := range got {
		if strings.Contains(m.Desc().String(), `fqName: "xpf_policy_hits_total"`) {
			hits++
		}
	}
	if hits != 0 {
		t.Errorf("collectPolicyCounters emitted %d xpf_policy_hits_total series with policy-stats DISABLED and no "+
			"rule carrying `count`. It must SKIP: a zero sample is indistinguishable from a "+
			"policy that matched no traffic, and unlike the text and structured surfaces a "+
			"time series has no place to carry the note that would disambiguate it. "+
			"#8177 left this function alone on purpose.", hits)
	}
}

// The control that makes the cell above mean something: with the knob ON the
// same fixture DOES emit. Without it, a collector that emitted nothing ever —
// broken descriptors, a nil dataplane, an early return — would pass.
func TestPolicyCountersDoEmitWhenStatsEnabled_8177(t *testing.T) {
	store := newStatsFlagRESTStore(t, true)
	c := &xpfCollector{deps: collectorDeps{store: store}}
	c.initPolicyDescriptors()

	dp := &schedulerCounterAPIDP{
		Manager:  dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{},
	}
	ch := make(chan prometheus.Metric)
	go func() {
		c.collectPolicyCounters(ch, dp)
		close(ch)
	}()
	n := 0
	for m := range ch {
		if strings.Contains(m.Desc().String(), `fqName: "xpf_policy_hits_total"`) {
			n++
		}
	}
	if n == 0 {
		t.Error("collectPolicyCounters emitted nothing with policy-stats ENABLED, so the " +
			"skip asserted above is not evidence of the gate — this collector emits nothing " +
			"either way and that cell would pass on a broken one")
	}
}
