package api

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #5317: the Prometheus metrics Collect() path used to call the userspace
// helper's control-socket Status() TWICE per scrape — collectFilterCounters
// (filter-term hit merge) and collectUserspaceStatus (CoS / worker / fairness /
// neighbor families) each fetched it independently. The control socket is
// contention-critical during bulk session sync (CLAUDE.md "Control socket
// contention"), so a scrape must issue at most ONE `status` RPC. These pins
// count the round trips a single Collect() makes and assert the shared-fetch
// behavior on both the success and status-error paths.

// statusCountingDP wraps the fully-wired descriptorCoverageDP and counts the
// control-socket Status() round trips a scrape performs, so the #5317 dedupe is
// directly observable. It embeds *descriptorCoverageDP for every other
// apiRuntimeDataPlane method; the outer Status() shadows the embedded one and
// bumps the counter.
type statusCountingDP struct {
	*descriptorCoverageDP
	statusCalls int
	statusErr   error
}

func (d *statusCountingDP) Status() (dpuserspace.ProcessStatus, error) {
	d.statusCalls++
	if d.statusErr != nil {
		return dpuserspace.ProcessStatus{}, d.statusErr
	}
	return d.descriptorCoverageDP.status, nil
}

// newStatusCountingScrape builds a real active config + a Status()-counting
// dataplane and returns the collector and dp ready for a full Collect().
func newStatusCountingScrape(t *testing.T, status dpuserspace.ProcessStatus, statusErr error) (*xpfCollector, *statusCountingDP) {
	t.Helper()
	store := newDescriptorCoverageStore(t)
	srv := &Server{store: store, gc: conntrack.NewGC(nil, time.Minute), startTime: time.Now()}
	dp := &statusCountingDP{
		descriptorCoverageDP: &descriptorCoverageDP{
			Manager: dataplane.New(),
			status:  status,
			apply: &dataplane.ApplyResult{
				ZoneIDs:   map[string]uint16{"trust": 1, "untrust": 2},
				FilterIDs: map[string]uint32{"inet:fin": 0, "inet6:fin6": 100},
			},
		},
		statusErr: statusErr,
	}
	srv.dp = dp
	return newCollector(srv), dp
}

type gatheredSample struct {
	desc   string
	labels map[string]string
	value  float64
}

// gatherCollect drives the REAL Collect() (production ordering) and returns
// every emitted sample as {descriptor, labels, value}.
func gatherCollect(t *testing.T, c *xpfCollector) []gatheredSample {
	t.Helper()
	ch := make(chan prometheus.Metric)
	done := make(chan struct{})
	var out []gatheredSample
	go func() {
		for m := range ch {
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Errorf("metric write: %v", err)
				continue
			}
			labels := make(map[string]string, len(pb.GetLabel()))
			for _, l := range pb.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			var v float64
			switch {
			case pb.Counter != nil:
				v = pb.GetCounter().GetValue()
			case pb.Gauge != nil:
				v = pb.GetGauge().GetValue()
			}
			out = append(out, gatheredSample{desc: m.Desc().String(), labels: labels, value: v})
		}
		close(done)
	}()
	c.Collect(ch)
	close(ch)
	<-done
	return out
}

func findSample(samples []gatheredSample, nameSubstr string, wantLabels map[string]string) (float64, bool) {
	for _, s := range samples {
		if !strings.Contains(s.desc, nameSubstr) {
			continue
		}
		match := true
		for k, v := range wantLabels {
			if s.labels[k] != v {
				match = false
				break
			}
		}
		if match {
			return s.value, true
		}
	}
	return 0, false
}

// TestMetricsCollectFetchesUserspaceStatusOncePerScrape is the #5317
// RED-on-revert pin: a single Collect()/scrape must issue exactly ONE
// control-socket Status() round trip, and the shared snapshot must feed BOTH
// the filter-term merge (collectFilterCounters) and the userspace-status
// families (collectUserspaceStatus) with byte-identical values.
//
// FAIL-ON-REVERT: restoring a second independent Status() fetch (either
// collector fetching on its own, or any extra fetchUserspaceStatus(dp) in
// Collect) makes statusCalls == 2 and the count assertion goes RED.
func TestMetricsCollectFetchesUserspaceStatusOncePerScrape(t *testing.T) {
	status := dpuserspace.ProcessStatus{
		// Consumed by collectFilterCounters (userspace merge into
		// xpf_filter_hits_total).
		FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "fin", TermName: "t1", Packets: 777},
		},
		// Consumed ONLY by collectUserspaceStatus (emitNeighborColdStartCapture),
		// emitted unconditionally. Refusal counters are intentionally distinct
		// values so a missing or cross-wired export fails this end-to-end pin.
		NegNeighFastFailTotal:             42,
		DynamicNeighborLearnCapDropsTotal: 41,
		NDPNAFragRefusedTotal:             43,
		NDPNABadSourceRefusedTotal:        44,
	}
	c, dp := newStatusCountingScrape(t, status, nil)

	samples := gatherCollect(t, c)

	if dp.statusCalls != 1 {
		t.Fatalf("Status() called %d times in one scrape; want exactly 1 — #5317: "+
			"collectFilterCounters and collectUserspaceStatus must SHARE one "+
			"control-socket round trip, not each issue their own", dp.statusCalls)
	}

	// Success path: the shared status feeds the filter-term merge.
	if got, ok := findSample(samples, "xpf_filter_hits_total",
		map[string]string{"filter": "fin", "family": "inet", "term": "t1"}); !ok || got != 777 {
		t.Errorf("xpf_filter_hits_total{filter=fin,family=inet,term=t1} = %v (present=%v); "+
			"want 777 from the shared status FilterTermCounters", got, ok)
	}
	// Success path: the same shared status feeds the userspace-only family.
	if got, ok := findSample(samples, "xpf_userspace_neg_neigh_fast_fail_total", nil); !ok || got != 42 {
		t.Errorf("xpf_userspace_neg_neigh_fast_fail_total = %v (present=%v); "+
			"want 42 from the shared status NegNeighFastFailTotal", got, ok)
	}
	// Existing neighbor refusal counter remains independently observable.
	if got, ok := findSample(samples, "xpf_userspace_dynamic_neighbor_learn_cap_drops_total", nil); !ok || got != 41 {
		t.Errorf("xpf_userspace_dynamic_neighbor_learn_cap_drops_total = %v (present=%v); want 41", got, ok)
	}
	if got, ok := findSample(samples, "xpf_userspace_ndp_na_frag_refused_total", nil); !ok || got != 43 {
		t.Errorf("xpf_userspace_ndp_na_frag_refused_total = %v (present=%v); want 43", got, ok)
	}
	if got, ok := findSample(samples, "xpf_userspace_ndp_na_bad_source_refused_total", nil); !ok || got != 44 {
		t.Errorf("xpf_userspace_ndp_na_bad_source_refused_total = %v (present=%v); want 44", got, ok)
	}
}

// TestMetricsCollectStatusErrorFetchesOnceAndDegrades pins the error path: when
// the single Status() round trip fails, the scrape must NOT retry it (still
// exactly one call), and both dependent collectors degrade consistently — the
// filter merge falls back to the map path (xpf_filter_hits_total = map-only
// value, 0 here) and the userspace-status families emit nothing.
//
// FAIL-ON-REVERT: a "retry" second fetch (or either collector fetching on its
// own) makes statusCalls == 2 and the count assertion goes RED.
func TestMetricsCollectStatusErrorFetchesOnceAndDegrades(t *testing.T) {
	// The FilterTermCounters/NegNeigh values would show through IF the error
	// path erroneously consumed the status; they must NOT, because Status()
	// returns an error.
	status := dpuserspace.ProcessStatus{
		FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "fin", TermName: "t1", Packets: 777},
		},
		NegNeighFastFailTotal: 42,
	}
	c, dp := newStatusCountingScrape(t, status, errors.New("control socket unavailable"))

	samples := gatherCollect(t, c)

	if dp.statusCalls != 1 {
		t.Fatalf("Status() called %d times on the status-error scrape; want exactly 1 "+
			"— #5317: the single failed round trip must not be retried into a second "+
			"control-socket request", dp.statusCalls)
	}

	// Filter counters degrade to the map path (ReadFilterCounters == 0 here),
	// so the term still emits, at the map-only value (no userspace merge).
	if got, ok := findSample(samples, "xpf_filter_hits_total",
		map[string]string{"filter": "fin", "family": "inet", "term": "t1"}); !ok || got != 0 {
		t.Errorf("xpf_filter_hits_total{filter=fin,family=inet,term=t1} = %v (present=%v) on "+
			"Status() error; want 0 (map-only, no userspace merge) — the 777 helper "+
			"counter must not leak through a failed status", got, ok)
	}
	// The userspace-status family must be absent (collectUserspaceStatus emits
	// nothing on a nil/failed status), exactly as before the dedupe.
	if got, ok := findSample(samples, "xpf_userspace_neg_neigh_fast_fail_total", nil); ok {
		t.Errorf("xpf_userspace_neg_neigh_fast_fail_total present (=%v) despite a Status() "+
			"error; want absent (degraded), matching the prior status-error behavior", got)
	}
}
