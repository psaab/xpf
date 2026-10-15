package api

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/flowexport"
)

// TestFlowExportCollectorMetrics pins #2464: per-collector NetFlow v9 /
// IPFIX write-health must be emitted as the xpf_flow_export_collector_*
// family, labeled by protocol + collector address, even when the
// dataplane is NOT loaded (the exporters are control-plane and run
// independent of dataplane load). A collector going silently unreachable
// was previously invisible; these metrics make write_failures and the
// healthy flag observable to an operator's dashboard.
//
// FAIL-ON-REVERT: without the FlowCollectorHealthFn wiring and the
// collectFlowExportMetrics emitter, none of these metric families are
// produced and every lookup below misses → the test fails.
func TestFlowExportCollectorMetrics(t *testing.T) {
	lastSuccess := time.Unix(1_700_000_000, 0)
	lastFailure := time.Unix(1_700_000_100, 0)
	s := &Server{ // dp intentionally nil — flow-export is control-plane
		flowCollectorHealthFn: func() []flowexport.ExporterCollectorHealth {
			return []flowexport.ExporterCollectorHealth{
				{
					Protocol: "netflow-v9",
					Instance: "inst1",
					Template: "",
					CollectorHealth: flowexport.CollectorHealth{
						Address:         "10.0.0.1:2055",
						WriteAttempts:   100,
						WriteFailures:   0,
						Healthy:         true,
						LastSuccessTime: lastSuccess,
					},
				},
				{
					Protocol: "ipfix",
					Instance: "inst2",
					CollectorHealth: flowexport.CollectorHealth{
						Address:         "10.0.0.2:4739",
						WriteAttempts:   50,
						WriteFailures:   50,
						Healthy:         false,
						LastError:       "connection refused",
						LastFailureTime: lastFailure,
					},
				},
			}
		},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	// metricValue looks up one labeled sample value by metric name +
	// (protocol, collector) label pair.
	metricValue := func(name, proto, collector string) (float64, bool) {
		for _, mf := range mfs {
			if mf.GetName() != name {
				continue
			}
			for _, m := range mf.GetMetric() {
				var p, c string
				for _, lp := range m.GetLabel() {
					switch lp.GetName() {
					case "protocol":
						p = lp.GetValue()
					case "collector":
						c = lp.GetValue()
					}
				}
				if p == proto && c == collector {
					if g := m.GetGauge(); g != nil {
						return g.GetValue(), true
					}
					if ctr := m.GetCounter(); ctr != nil {
						return ctr.GetValue(), true
					}
				}
			}
		}
		return 0, false
	}

	// Healthy netflow-v9 collector.
	if v, ok := metricValue("xpf_flow_export_collector_write_attempts_total", "netflow-v9", "10.0.0.1:2055"); !ok || v != 100 {
		t.Errorf("netflow-v9 write_attempts = %v (ok=%v), want 100", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_write_failures_total", "netflow-v9", "10.0.0.1:2055"); !ok || v != 0 {
		t.Errorf("netflow-v9 write_failures = %v (ok=%v), want 0", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_healthy", "netflow-v9", "10.0.0.1:2055"); !ok || v != 1 {
		t.Errorf("netflow-v9 healthy = %v (ok=%v), want 1", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_last_success_timestamp_seconds", "netflow-v9", "10.0.0.1:2055"); !ok || v != float64(lastSuccess.Unix()) {
		t.Errorf("netflow-v9 last_success = %v (ok=%v), want %d", v, ok, lastSuccess.Unix())
	}

	// Unhealthy ipfix collector.
	if v, ok := metricValue("xpf_flow_export_collector_write_failures_total", "ipfix", "10.0.0.2:4739"); !ok || v != 50 {
		t.Errorf("ipfix write_failures = %v (ok=%v), want 50", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_healthy", "ipfix", "10.0.0.2:4739"); !ok || v != 0 {
		t.Errorf("ipfix healthy = %v (ok=%v), want 0", v, ok)
	}
	if v, ok := metricValue("xpf_flow_export_collector_last_failure_timestamp_seconds", "ipfix", "10.0.0.2:4739"); !ok || v != float64(lastFailure.Unix()) {
		t.Errorf("ipfix last_failure = %v (ok=%v), want %d", v, ok, lastFailure.Unix())
	}
}

// TestFlowExportExportedStatsInPrometheus pins #13304 (D6-02): the
// per-exporter exportedFlows/exportedPkts counters maintained by
// Exporter.Stats()/IPFIXExporter.Stats() were never wired into
// ExporterBatchStats or Prometheus, so operators had zero visibility
// into how many flow records / data datagrams were actually exported
// while write_attempts_total also counted template refreshes.
//
// FAIL-ON-REVERT: without ExportedFlows/ExportedPackets on
// ExporterBatchStats and the two new descriptors/emissions, both
// lookups below miss and this test fails.
func TestFlowExportExportedStatsInPrometheus(t *testing.T) {
	s := &Server{
		flowExportBatchStatsFn: func() []flowexport.ExporterBatchStats {
			return []flowexport.ExporterBatchStats{
				{Protocol: "netflow-v9", Instance: "s1", Template: "t1", Family: "inet", ExportedFlows: 42, ExportedPackets: 7},
				{Protocol: "ipfix", Instance: "s1", Template: "t1", Family: "inet6", ExportedFlows: 13, ExportedPackets: 3},
			}
		},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	lookup := func(name, proto string) (float64, bool) {
		for _, mf := range mfs {
			if mf.GetName() != name {
				continue
			}
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "protocol" && lp.GetValue() == proto {
						return m.GetCounter().GetValue(), true
					}
				}
			}
		}
		return 0, false
	}
	if v, ok := lookup("xpf_flow_export_flows_exported_total", "netflow-v9"); !ok || v != 42 {
		t.Errorf("netflow-v9 flows_exported = %v (ok=%v), want 42", v, ok)
	}
	if v, ok := lookup("xpf_flow_export_data_packets_exported_total", "netflow-v9"); !ok || v != 7 {
		t.Errorf("netflow-v9 data_packets_exported = %v (ok=%v), want 7", v, ok)
	}
	if v, ok := lookup("xpf_flow_export_flows_exported_total", "ipfix"); !ok || v != 13 {
		t.Errorf("ipfix flows_exported = %v (ok=%v), want 13", v, ok)
	}
	if v, ok := lookup("xpf_flow_export_data_packets_exported_total", "ipfix"); !ok || v != 3 {
		t.Errorf("ipfix data_packets_exported = %v (ok=%v), want 3", v, ok)
	}
}

// TestFlowExportCollectorMetricsOmittedWhenUnwired proves the family is
// omitted entirely (no spurious zero series) when no FlowCollectorHealthFn
// is wired — matching the DDNS / feeds families.
func TestFlowExportCollectorMetricsOmittedWhenUnwired(t *testing.T) {
	s := &Server{} // no flowCollectorHealthFn
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_flow_export_collector_write_attempts_total",
			"xpf_flow_export_collector_write_failures_total",
			"xpf_flow_export_collector_healthy":
			t.Errorf("%s emitted with no health fn wired", mf.GetName())
		}
	}
}

// TestFlowExportCollectorMetricsDistinctLabelsetPerGroup pins #3741: the
// daemon legitimately returns MULTIPLE FlowCollectorHealth rows for the
// SAME (protocol, collector, source) triple — one per template group, one
// per family-disjoint sampling instance. Before this fix the descriptor
// carried only {protocol, collector, source}, so those rows collapsed to
// an IDENTICAL labelset: a PEDANTIC registry rejects the duplicate series
// (scrape error) and a plain gather silently collapses the failing group,
// hiding a partial flow-export failure. The instance + template labels
// make each group a distinct series.
//
// FAIL-ON-REVERT: drop instance/template from the descriptor + emission
// and the two rows below share one labelset →
// prometheus.NewPedanticRegistry().Gather() returns a duplicate-series
// error and this test fails. It also asserts BOTH groups' distinct values
// survive (the "silently collapses / hides the failing group" half).
func TestFlowExportCollectorMetricsDistinctLabelsetPerGroup(t *testing.T) {
	s := &Server{
		flowCollectorHealthFn: func() []flowexport.ExporterCollectorHealth {
			return []flowexport.ExporterCollectorHealth{
				// Same protocol + collector address + source, different
				// template group. Group "t-healthy" is up; "t-failing" is
				// down — the failing group must remain attributable.
				{
					Protocol: "netflow-v9",
					Instance: "sampler",
					Template: "t-healthy",
					CollectorHealth: flowexport.CollectorHealth{
						Address:       "10.0.0.9:2055",
						SourceAddress: "10.0.0.2",
						WriteAttempts: 200,
						WriteFailures: 0,
						Healthy:       true,
					},
				},
				{
					Protocol: "netflow-v9",
					Instance: "sampler",
					Template: "t-failing",
					CollectorHealth: flowexport.CollectorHealth{
						Address:       "10.0.0.9:2055",
						SourceAddress: "10.0.0.2",
						WriteAttempts: 200,
						WriteFailures: 200,
						Healthy:       false,
					},
				},
			}
		},
	}
	// PEDANTIC registry: this is the instrument that turns a duplicate
	// labelset into a Gather() error (the scrape-breaking half of #3741).
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("pedantic Gather() returned an error — two health rows that "+
			"share (protocol, collector, source) but differ by "+
			"instance/template collided on one labelset (the #3741 "+
			"duplicate-series bug). Error: %v", err)
	}

	// byTemplate returns the value of `name` for the given template label.
	byTemplate := func(name, template string) (float64, bool) {
		for _, mf := range mfs {
			if mf.GetName() != name {
				continue
			}
			for _, m := range mf.GetMetric() {
				var tmpl string
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "template" {
						tmpl = lp.GetValue()
					}
				}
				if tmpl != template {
					continue
				}
				if g := m.GetGauge(); g != nil {
					return g.GetValue(), true
				}
				if ctr := m.GetCounter(); ctr != nil {
					return ctr.GetValue(), true
				}
			}
		}
		return 0, false
	}

	// Both distinct groups must survive as separate series (the failing
	// group is not collapsed / hidden).
	if v, ok := byTemplate("xpf_flow_export_collector_healthy", "t-healthy"); !ok || v != 1 {
		t.Errorf("healthy group healthy = %v (ok=%v), want 1 — the healthy "+
			"template group is missing or was overwritten", v, ok)
	}
	if v, ok := byTemplate("xpf_flow_export_collector_healthy", "t-failing"); !ok || v != 0 {
		t.Errorf("failing group healthy = %v (ok=%v), want 0 — the FAILING "+
			"template group is hidden (collapsed onto the healthy row)", v, ok)
	}
	if v, ok := byTemplate("xpf_flow_export_collector_write_failures_total", "t-failing"); !ok || v != 200 {
		t.Errorf("failing group write_failures = %v (ok=%v), want 200", v, ok)
	}
}

// TestFlowExportCollectorMetricsLabelSet is the descriptor↔emission label
// canary: every sample in the xpf_flow_export_collector_* family must carry
// EXACTLY {protocol, instance, template, family, collector, source}.
// The emitted label names come from the prometheus.Desc and
// MustNewConstMetric panics for wrong value arity, so this verifies agreement.
func TestFlowExportCollectorMetricsLabelSet(t *testing.T) {
	s := &Server{
		flowCollectorHealthFn: func() []flowexport.ExporterCollectorHealth {
			return []flowexport.ExporterCollectorHealth{
				{
					Protocol: "ipfix",
					Instance: "inst",
					Template: "tmpl",
					CollectorHealth: flowexport.CollectorHealth{
						Address:       "10.0.0.1:4739",
						SourceAddress: "10.0.0.2",
						WriteAttempts: 1,
						Healthy:       true,
					},
				},
			}
		},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	wantLabels := map[string]bool{
		"protocol": true, "instance": true, "template": true, "family": true,
		"collector": true, "source": true,
	}
	families := map[string]bool{
		"xpf_flow_export_collector_write_attempts_total":           true,
		"xpf_flow_export_collector_write_failures_total":           true,
		"xpf_flow_export_collector_healthy":                        true,
		"xpf_flow_export_collector_last_success_timestamp_seconds": true,
		"xpf_flow_export_collector_last_failure_timestamp_seconds": true,
	}
	seen := map[string]bool{}
	for _, mf := range mfs {
		if !families[mf.GetName()] {
			continue
		}
		seen[mf.GetName()] = true
		for _, m := range mf.GetMetric() {
			got := map[string]bool{}
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = true
			}
			if len(got) != len(wantLabels) {
				t.Errorf("%s has %d labels %v, want %d %v", mf.GetName(),
					len(got), got, len(wantLabels), wantLabels)
			}
			for l := range wantLabels {
				if !got[l] {
					t.Errorf("%s missing label %q (labels=%v)", mf.GetName(), l, got)
				}
			}
		}
	}
	for f := range families {
		if !seen[f] {
			t.Errorf("family %q not emitted", f)
		}
	}
}
