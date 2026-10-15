package api

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestMetricsDataplaneSafetyAndDivergenceSeries13302(t *testing.T) {
	dp := dataplane.New()
	dp.SetDetachDebtForTest(17)
	dp.ProveArmCoverage(&dataplane.CompileResult{})
	c := newCollector(&Server{dp: dp, store: newDescriptorCoverageStore(t), startTime: time.Now()})
	ch := make(chan prometheus.Metric, 512)
	go func() { c.Collect(ch); close(ch) }()
	got := map[string]float64{}
	for metric := range ch {
		var wire dto.Metric
		if err := metric.Write(&wire); err != nil {
			t.Fatal(err)
		}
		name := metric.Desc().String()
		for _, expected := range []string{
			"xpf_dataplane_obsolete_registry_accesses_total",
			"xpf_dataplane_xdp_detach_debt_interfaces",
			"xpf_dataplane_host_divergence_mutations",
			"xpf_dataplane_arm_uncovered_surfaces",
			"xpf_dataplane_arm_total_surfaces",
			"xpf_dataplane_xdp_attach_mode_surfaces",
		} {
			if strings.Contains(name, expected) {
				value := 0.0
				if wire.Gauge != nil {
					value = wire.GetGauge().GetValue()
				}
				if wire.Counter != nil {
					value = wire.GetCounter().GetValue()
				}
				got[expected] = value
			}
		}
	}
	if got["xpf_dataplane_xdp_detach_debt_interfaces"] != 1 {
		t.Errorf("detach debt=%v, want 1", got["xpf_dataplane_xdp_detach_debt_interfaces"])
	}
	if _, ok := got["xpf_dataplane_arm_total_surfaces"]; !ok {
		t.Error("arm coverage series absent after a completed proof")
	}
	if _, ok := got["xpf_dataplane_xdp_attach_mode_surfaces"]; !ok {
		t.Error("attach mode series absent after a completed proof")
	}
	for _, name := range []string{"xpf_dataplane_obsolete_registry_accesses_total", "xpf_dataplane_xdp_detach_debt_interfaces", "xpf_dataplane_host_divergence_mutations", "xpf_dataplane_arm_uncovered_surfaces", "xpf_dataplane_arm_total_surfaces", "xpf_dataplane_xdp_attach_mode_surfaces"} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s did not reach a real collector scrape", name)
		}
	}
}
