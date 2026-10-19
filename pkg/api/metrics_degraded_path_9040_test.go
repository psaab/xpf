package api

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

const degradedPathMetric9040 = "xpf_dataplane_degraded_path_total"

// collectDegraded9040 drives the collector's REAL Collect against a dataplane
// that reports a status.
//
// It does NOT call emitDegradedPathCounters directly, and that is the point.
// The defect being fixed is that a counter existed and NOTHING READ IT —
// DegradedPathCounters reached the status JSON and the `show` text render and
// stopped. A cell that calls the emitter proves the emitter works while leaving
// Collect free never to call it, which reproduces the original failure exactly.
func collectDegraded9040(t *testing.T, counters map[string]uint64) map[string]float64 {
	t.Helper()
	store := newDescriptorCoverageStore(t)
	srv := &Server{store: store, gc: conntrack.NewGC(nil, time.Minute), startTime: time.Now()}
	srv.dp = &descriptorCoverageDP{
		Manager: dataplane.New(),
		status:  dpuserspace.ProcessStatus{DegradedPathCounters: counters},
	}
	c := newCollector(srv)

	ch := make(chan prometheus.Metric, 4096)
	done := make(chan struct{})
	out := map[string]float64{}
	go func() {
		defer close(done)
		for m := range ch {
			var pbm dto.Metric
			if err := m.Write(&pbm); err != nil {
				continue
			}
			if !hasDescName9040(m.Desc().String(), degradedPathMetric9040) {
				continue
			}
			for _, lp := range pbm.GetLabel() {
				if lp.GetName() == "reason" {
					out[lp.GetValue()] = pbm.GetCounter().GetValue()
				}
			}
		}
	}()
	c.Collect(ch)
	close(ch)
	<-done
	return out
}

func hasDescName9040(desc, name string) bool {
	return len(desc) > 0 && len(name) > 0 && containsStr9040(desc, `"`+name+`"`)
}

func containsStr9040(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

// #9040: the drops an over-wide NIC takes on unbound queues were counted and
// unexportable. `binding_missing` is the reason that matters: an interface with
// more than 16 RX queues has its bound set capped at 16, and (since the #9040
// capability probe) only an interface xpfd could not reshape keeps hashing
// across all its queues, so transit landing on the unbound rest is dropped
// at roughly (Q-16)/Q while the box reads up. (#15253)
func TestDegradedPathCountersReachAScrape9040(t *testing.T) {
	got := collectDegraded9040(t, map[string]uint64{
		"binding_missing": 4242,
		"no_route":        7,
	})
	if v, ok := got["binding_missing"]; !ok || v != 4242 {
		t.Errorf("binding_missing = %v (present=%v), want 4242. The counter is "+
			"incremented by the dataplane and read by nothing, which is #9040", v, ok)
	}
	if v, ok := got["no_route"]; !ok || v != 7 {
		t.Errorf("no_route = %v (present=%v), want 7 — every reason on the status "+
			"must be exported, not a hand-picked subset", v, ok)
	}
}

// NARROWNESS, and it is the half that is easy to get wrong.
//
// The map is SPARSE: a reason that has never fired has no entry. So there is no
// fixed label set to emit zeroes over, unlike the authz-denial family whose
// labels are enumerable. Inventing a zero for an unseen reason would create a
// series whose ABSENCE is meaningful, and would make "this box has never taken
// a degraded drop" indistinguishable from "this reason exists in the code".
func TestDegradedPathEmitsNothingForAnEmptyStatus9040(t *testing.T) {
	if got := collectDegraded9040(t, nil); len(got) != 0 {
		t.Errorf("a status with no degraded drops emitted %v; the family must be "+
			"absent, not zero-filled", got)
	}
	if got := collectDegraded9040(t, map[string]uint64{}); len(got) != 0 {
		t.Errorf("an empty (non-nil) counter map emitted %v", got)
	}
}

// The descriptor must be advertised, or a strict registry rejects the whole
// collector at registration and every metric on it disappears — including the
// ones that work.
func TestDegradedPathIsDescribed9040(t *testing.T) {
	c := newCollector(&Server{})
	ch := make(chan *prometheus.Desc, 2048)
	go func() { c.Describe(ch); close(ch) }()
	for d := range ch {
		if hasDescName9040(d.String(), degradedPathMetric9040) {
			return
		}
	}
	t.Errorf("%s is collected but not described", degradedPathMetric9040)
}
