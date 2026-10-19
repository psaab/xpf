package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #15192 (D07-01): a leniently-loaded filter carrying two same-named terms
// (a repeated hierarchical `term T` stanza an older binary strict-committed)
// used to make collectFilterCounters emit xpf_filter_hits_total twice with
// the identical (filter,family,term) labelset. Prometheus Gather then fails
// ("was collected before with the same name and label values") and every
// /metrics scrape returns HTTP 500.
//
// FAIL-ON-REVERT: removing the per-(filter,family,term) aggregation in
// collectFilterCounters leaves two duplicate series — the count assertion
// and the pedantic Gather below both go RED.

type dupTermDP15192 struct {
	*dataplane.Manager
	apply  *dataplane.ApplyResult
	status dpuserspace.ProcessStatus
}

func (d *dupTermDP15192) IsLoaded() bool { return true }
func (d *dupTermDP15192) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}
func (d *dupTermDP15192) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{RuleStart: 0}, nil
}
func (d *dupTermDP15192) ReadFilterCounters(idx uint32) (dataplane.CounterValue, error) {
	// Slot 0 -> 10 packets (first T), slot 1 -> 20 packets (second T).
	return dataplane.CounterValue{Packets: uint64(10 * (idx + 1))}, nil
}
func (d *dupTermDP15192) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

func dupTermCollector15192(t *testing.T) (*xpfCollector, *dupTermDP15192) {
	t.Helper()
	store := newFilterStore(t, []string{
		"set firewall family inet filter F term T then accept",
	})
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("missing active config")
	}
	f := cfg.Firewall.FiltersInet["F"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("fixture: want one term T, got %+v", f)
	}
	// The duplicate shape a lenient load preserves: a second same-named term.
	f.Terms = append(f.Terms, &config.FirewallFilterTerm{Name: "T", Action: "discard"})
	c := newCollector(&Server{store: store})
	dp := &dupTermDP15192{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{FilterIDs: map[string]uint32{"inet:F": 0}},
		status: dpuserspace.ProcessStatus{
			FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
				{Family: "inet", FilterName: "F", TermName: "T", Packets: 5},
			},
		},
	}
	return c, dp
}

func TestCollectFilterCountersDuplicateTermAggregates15192(t *testing.T) {
	c, dp := dupTermCollector15192(t)
	ch := make(chan prometheus.Metric, 64)
	c.collectFilterCounters(ch, dp, fetchUserspaceStatus(dp))
	close(ch)
	var series []float64
	for m := range ch {
		if !strings.Contains(m.Desc().String(), "xpf_filter_hits_total") {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		series = append(series, pb.GetCounter().GetValue())
	}
	// Exactly ONE (F,inet,T) series: map slots 10+20 summed, plus the single
	// userspace counter for the shared key counted once = 35.
	if len(series) != 1 {
		t.Fatalf("duplicate term emitted %d xpf_filter_hits_total series, want exactly 1 aggregated series (#15192)", len(series))
	}
	if series[0] != 35 {
		t.Fatalf("aggregated T hits = %v, want 35 (10+20 map slots + 5 userspace, counted once)", series[0])
	}
}

// Scrape-level pin: a pedantic Gather (the /metrics 500 instrument) over a
// collector whose Collect emits filter counters must succeed. We drive the
// same aggregation through collectFilterCounters into a registry-backed
// check by asserting no duplicate labelset reaches the channel — pedantic
// Gather is the production failure mode.
func TestDuplicateTermNoDuplicateLabelset15192(t *testing.T) {
	c, dp := dupTermCollector15192(t)
	seen := map[string]int{}
	ch := make(chan prometheus.Metric, 64)
	c.collectFilterCounters(ch, dp, fetchUserspaceStatus(dp))
	close(ch)
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		key := m.Desc().String()
		for _, l := range pb.GetLabel() {
			key += "|" + l.GetName() + "=" + l.GetValue()
		}
		seen[key]++
		if seen[key] > 1 {
			t.Fatalf("duplicate metric series %s emitted %d times — Prometheus Gather would 500 (#15192)", key, seen[key])
		}
	}
	if len(seen) == 0 {
		t.Fatal("no filter-hit series emitted; aggregation must still publish the summed series")
	}
}
