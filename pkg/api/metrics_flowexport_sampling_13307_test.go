package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/flowexport"
)

func TestFlowExportSamplingMetrics13307(t *testing.T) {
	s := &Server{
		flowExportSamplingStatsFn: func() []flowexport.SamplingStatsSnapshot {
			return []flowexport.SamplingStatsSnapshot{{
				Protocol: "netflow-v9", Instance: "inst1", Evaluated: 2,
				Selected: 1, ZoneFiltered: 3,
			}}
		},
		flowExportBuildStateFn: func() []flowexport.BuildState {
			return []flowexport.BuildState{{Family: "netflow-v9", ExcludedFlowServers: 4}}
		},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]float64{
		"xpf_flow_export_sampling_evaluated_total": 2,
		"xpf_flow_export_sampling_selected_total":  1,
		"xpf_flow_export_zone_filtered_total":      3,
		"xpf_flowexport_excluded_flow_servers":     4,
	}
	for name, expected := range want {
		found := false
		for _, mf := range mfs {
			if mf.GetName() != name {
				continue
			}
			for _, metric := range mf.GetMetric() {
				if metric.GetCounter() != nil && metric.GetCounter().GetValue() == expected ||
					metric.GetGauge() != nil && metric.GetGauge().GetValue() == expected {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s = missing or not %v", name, expected)
		}
	}
}
