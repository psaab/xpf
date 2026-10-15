package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// The cache is process-wide, so its telemetry must be available even when no
// exporters or collector health callback are configured.
func TestFlowExportRouteMaskCacheMetrics_13306(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(&Server{}))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := []string{
		"xpf_flowexport_routemask_cache_hits_total",
		"xpf_flowexport_routemask_cache_misses_total",
		"xpf_flowexport_routemask_cache_clears_total",
		"xpf_flowexport_routemask_cache_inflight_drops_total",
		"xpf_flowexport_routemask_cache_lookup_errors_total",
		"xpf_flowexport_routemask_cache_entries",
	}
	found := make(map[string]bool, len(want))
	for _, mf := range mfs {
		found[mf.GetName()] = true
	}
	for _, name := range want {
		if !found[name] {
			t.Errorf("metric %q not emitted", name)
		}
	}
}
