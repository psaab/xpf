package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// #16760: the live-feed miss counter must reach Prometheus as
// xpf_flow_export_live_feed_misses_total, and NewServer must not drop
// the hook.
func TestFlowExportLiveFeedMissesMetric16760(t *testing.T) {
	srv := NewServer(Config{FlowExportLiveFeedMissesFn: func() uint64 { return 42 }})
	if srv.flowExportLiveFeedMissesFn == nil {
		t.Fatal("NewServer dropped FlowExportLiveFeedMissesFn")
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(srv))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "xpf_flow_export_live_feed_misses_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			if m.GetCounter() != nil && m.GetCounter().GetValue() == 42 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("xpf_flow_export_live_feed_misses_total = missing or not 42")
	}
}

func TestFlowExportLiveFeedMissesOmittedWhenUnwired16760(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(&Server{}))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "xpf_flow_export_live_feed_misses_total" {
			t.Fatal("live-feed misses family must be omitted when unwired")
		}
	}
}
