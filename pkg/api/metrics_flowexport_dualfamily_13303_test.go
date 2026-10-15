package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/flowexport"
)

// TestFlowExportDualFamilyMetricsDistinctLabelset pins #13303 (D6-01):
// a dual-family (inet+inet6) sampling instance produces two exporter
// groups with identical Instance/Template (differing only in GroupIsV6).
// Before the fix neither ExporterCollectorHealth nor ExporterBatchStats
// carried the family, and no descriptor had a "family" label, so both
// groups emitted identical labelsets: a pedantic Gather() fails with
// duplicate-series errors and /metrics returns HTTP 500.
//
// FAIL-ON-REVERT: removing the family label from descriptors/emission
// makes the two rows below collide -> Gather() error.
func TestFlowExportDualFamilyMetricsDistinctLabelset(t *testing.T) {
	mkHealth := func(family string, attempts uint64) flowexport.ExporterCollectorHealth {
		return flowexport.ExporterCollectorHealth{
			Protocol: "netflow-v9", Instance: "s1", Template: "t1", Family: family,
			CollectorHealth: flowexport.CollectorHealth{
				Address: "10.0.0.1:2055", WriteAttempts: attempts, Healthy: true,
			},
		}
	}
	mkBatch := func(family string, depth uint64) flowexport.ExporterBatchStats {
		return flowexport.ExporterBatchStats{
			Protocol: "netflow-v9", Instance: "s1", Template: "t1", Family: family,
			Depth: depth, MaxDepth: depth, Dropped: 1,
		}
	}
	s := &Server{
		flowCollectorHealthFn: func() []flowexport.ExporterCollectorHealth {
			return []flowexport.ExporterCollectorHealth{mkHealth("inet", 10), mkHealth("inet6", 20)}
		},
		flowExportBatchStatsFn: func() []flowexport.ExporterBatchStats {
			return []flowexport.ExporterBatchStats{mkBatch("inet", 3), mkBatch("inet6", 7)}
		},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("pedantic Gather() error — dual-family groups collided on one labelset (#13303): %v", err)
	}
	valueByFamily := func(name, family string) (float64, bool) {
		for _, mf := range mfs {
			if mf.GetName() != name {
				continue
			}
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "family" && lp.GetValue() == family {
						if g := m.GetGauge(); g != nil {
							return g.GetValue(), true
						}
						if c := m.GetCounter(); c != nil {
							return c.GetValue(), true
						}
					}
				}
			}
		}
		return 0, false
	}
	if v, ok := valueByFamily("xpf_flow_export_collector_write_attempts_total", "inet"); !ok || v != 10 {
		t.Errorf("inet write_attempts = %v (ok=%v), want 10", v, ok)
	}
	if v, ok := valueByFamily("xpf_flow_export_collector_write_attempts_total", "inet6"); !ok || v != 20 {
		t.Errorf("inet6 write_attempts = %v (ok=%v), want 20", v, ok)
	}
	if v, ok := valueByFamily("xpf_flow_export_batch_depth", "inet"); !ok || v != 3 {
		t.Errorf("inet batch_depth = %v (ok=%v), want 3", v, ok)
	}
	if v, ok := valueByFamily("xpf_flow_export_batch_depth", "inet6"); !ok || v != 7 {
		t.Errorf("inet6 batch_depth = %v (ok=%v), want 7", v, ok)
	}
	// All nine metric families have exactly two series, one per address family.
	for _, name := range []string{
		"xpf_flow_export_batch_depth",
		"xpf_flow_export_batch_max_depth",
		"xpf_flow_export_batch_dropped_total",
		"xpf_flow_export_collector_write_attempts_total",
		"xpf_flow_export_collector_write_failures_total",
		"xpf_flow_export_collector_write_skipped_total",
		"xpf_flow_export_collector_healthy",
		"xpf_flow_export_collector_last_success_timestamp_seconds",
		"xpf_flow_export_collector_last_failure_timestamp_seconds",
	} {
		n := 0
		for _, mf := range mfs {
			if mf.GetName() == name {
				n = len(mf.GetMetric())
			}
		}
		if n != 2 {
			t.Errorf("%s series count = %d, want 2 (inet+inet6)", name, n)
		}
	}
}
