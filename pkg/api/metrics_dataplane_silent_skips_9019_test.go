package api

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

const (
	napiSkipMetric9019          = "xpf_napi_probe_target_skips_total"
	routeCapMetric9019          = "xpf_learned_route_cap_hits_total"
	protocolRouteCapMetric10824 = "xpf_learned_route_cap_group_sheds_total"
)

// collectAll9019 drives the collector's REAL Collect, not emitDataplaneSilentSkips.
//
// That distinction is the whole point of this file. The defect #9019 leaves
// behind is not a broken counter -- both counters increment correctly and each
// has a passing unit test in its own package. The defect is that NOTHING READ
// THEM: outside their own file and their own test, the only mention of
// LearnedRouteCapHits in the entire tree was a comment. A cell that calls
// emitDataplaneSilentSkips directly would reproduce exactly that mistake --
// it would prove the emitter works while the collector still never calls it.
func collectAll9019(t *testing.T) map[string]float64 {
	t.Helper()
	// NO DATAPLANE. srv.dp is left nil deliberately: Collect returns early at
	// the dataplane gate, and these two counters must still arrive. That is the
	// case they exist for -- a box whose dataplane did not come up completely
	// is exactly when a scrape must still say so, and gating them behind a
	// healthy dataplane would hide them precisely then.
	c := newCollector(&Server{store: newDescriptorCoverageStore(t), startTime: time.Now()})
	ch := make(chan prometheus.Metric, 512)
	done := make(chan struct{})
	out := map[string]float64{}
	go func() {
		defer close(done)
		for m := range ch {
			var pbm dto.Metric
			if err := m.Write(&pbm); err != nil {
				continue
			}
			d := m.Desc().String()
			for _, name := range []string{napiSkipMetric9019, routeCapMetric9019} {
				if strings.Contains(d, name) {
					out[name] = pbm.GetCounter().GetValue()
				}
			}
		}
	}()
	c.Collect(ch)
	close(ch)
	<-done
	return out
}

// The counters must reach a scrape THROUGH the collector, and at zero.
//
// Zero is the normal state for both, which is what makes emitting it
// load-bearing: a counter that appears only once it fires cannot be alerted on,
// and cannot distinguish "never skipped" from "not scraped" (#3464 / #8312).
func TestDataplaneSilentSkipsAreScrapable9019(t *testing.T) {
	got := collectAll9019(t)
	for _, name := range []string{napiSkipMetric9019, routeCapMetric9019} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s did not reach a scrape; the counter is incremented by the "+
				"dataplane and read by nothing, which is the #9019 defect restated", name)
		}
	}
}

// Describe must advertise every emitted counter, or a strict registry rejects
// the collector and every metric on it disappears -- including the ones that
// work.
func TestDataplaneSilentSkipsAreDescribed9019(t *testing.T) {
	c := newCollector(nil)
	ch := make(chan *prometheus.Desc, 1024)
	go func() { c.Describe(ch); close(ch) }()
	seen := map[string]bool{}
	for d := range ch {
		for _, name := range []string{napiSkipMetric9019, routeCapMetric9019, protocolRouteCapMetric10824} {
			if strings.Contains(d.String(), name) {
				seen[name] = true
			}
		}
	}
	for _, name := range []string{napiSkipMetric9019, routeCapMetric9019, protocolRouteCapMetric10824} {
		if !seen[name] {
			t.Errorf("%s is collected but not described", name)
		}
	}
}
func TestLearnedRouteCapGroupShedsScrapableByProtocol10824(t *testing.T) {
	c := newCollector(&Server{store: newDescriptorCoverageStore(t), startTime: time.Now()})
	ch := make(chan prometheus.Metric, 512)
	done := make(chan struct{})
	got := make(map[string]float64)
	go func() {
		defer close(done)
		for metric := range ch {
			if !strings.Contains(metric.Desc().String(), protocolRouteCapMetric10824) {
				continue
			}
			var pbm dto.Metric
			if err := metric.Write(&pbm); err != nil {
				continue
			}
			for _, label := range pbm.GetLabel() {
				if label.GetName() == "protocol" {
					got[label.GetValue()] = pbm.GetCounter().GetValue()
				}
			}
		}
	}()
	c.Collect(ch)
	close(ch)
	<-done

	for protocol, count := range userspace.LearnedRouteCapHitsByProtocol() {
		value, ok := got[protocol]
		if !ok || value != float64(count) {
			t.Errorf("%s{protocol=%q} = %v (present=%t), accessor says %d",
				protocolRouteCapMetric10824, protocol, value, ok, count)
		}
	}
}

// The emitted value must be the LIVE counter, not a constant that happens to
// agree with it.
//
// Stated limitation: the increment seams (`noteNAPIProbeTargetSkip` and the
// learned-route cap path) are unexported, so this package cannot move either
// counter and cannot observe the value CHANGE. What it can do is bind the
// emitted number to the accessor, which is the half that lives here; the other
// half -- that the accessor moves when a skip actually happens -- is pinned in
// pkg/dataplane/userspace by TestNAPIProbeTargetSkipIsCounted9019. Neither cell
// is sufficient alone and the pair spans the two packages the value crosses.
func TestDataplaneSilentSkipsReadTheLiveCounter9019(t *testing.T) {
	got := collectAll9019(t)
	if want := float64(userspace.NAPIProbeTargetSkips()); got[napiSkipMetric9019] != want {
		t.Errorf("%s = %v, accessor says %v", napiSkipMetric9019, got[napiSkipMetric9019], want)
	}
	if want := float64(userspace.LearnedRouteCapHits()); got[routeCapMetric9019] != want {
		t.Errorf("%s = %v, accessor says %v", routeCapMetric9019, got[routeCapMetric9019], want)
	}
}
