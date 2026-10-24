package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// #16478: the fabric gRPC connection-bound series must be driven by the
// daemon-wired FabricConnStatsFn hook through the real collector emitter,
// and both samples must be present at zero (#3464 always-emit).
//
// FAIL-ON-REVERT: dropping the fabricConnStats deps copy (or the
// emitFabricConnBound defer) leaves the series at zero / absent and the
// after-hook assertions red; dropping the descriptor family reds the
// Describe cell below.
func TestFabricConnRefusalsMetric16478(t *testing.T) {
	var refusals uint64 = 3
	var active int64 = 5
	s := NewServer(Config{
		Addr:              "127.0.0.1:0",
		FabricConnStatsFn: func() (uint64, int64) { return refusals, active },
	})
	c := newCollector(s)
	collect := func() map[string]float64 {
		ch := make(chan prometheus.Metric, 8)
		c.emitFabricConnBound(ch)
		close(ch)
		out := map[string]float64{}
		for m := range ch {
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatalf("write metric: %v", err)
			}
			switch {
			case strings.Contains(m.Desc().String(), "xpf_fabric_conn_refusals_total"):
				out["refusals"] = pb.GetCounter().GetValue()
			case strings.Contains(m.Desc().String(), "xpf_fabric_conn_active"):
				out["active"] = pb.GetGauge().GetValue()
			}
		}
		return out
	}
	got := collect()
	if got["refusals"] != 3 {
		t.Fatalf("xpf_fabric_conn_refusals_total = %v, want 3 from hook", got["refusals"])
	}
	if got["active"] != 5 {
		t.Fatalf("xpf_fabric_conn_active = %v, want 5 from hook", got["active"])
	}

	// Nil hook (unwired): both samples still emitted at zero.
	s2 := NewServer(Config{Addr: "127.0.0.1:0"})
	c2 := newCollector(s2)
	ch := make(chan prometheus.Metric, 8)
	c2.emitFabricConnBound(ch)
	close(ch)
	seen := map[string]bool{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		switch {
		case strings.Contains(m.Desc().String(), "xpf_fabric_conn_refusals_total"):
			seen["refusals"] = true
			if pb.GetCounter().GetValue() != 0 {
				t.Fatalf("unwired refusals = %v, want 0", pb.GetCounter().GetValue())
			}
		case strings.Contains(m.Desc().String(), "xpf_fabric_conn_active"):
			seen["active"] = true
			if pb.GetGauge().GetValue() != 0 {
				t.Fatalf("unwired active = %v, want 0", pb.GetGauge().GetValue())
			}
		}
	}
	if !seen["refusals"] {
		t.Fatal("xpf_fabric_conn_refusals_total not emitted at zero")
	}
	if !seen["active"] {
		t.Fatal("xpf_fabric_conn_active not emitted at zero")
	}
}

// TestFabricConnDescriptorIsDeclared16478: removing fabricConnRefusalsTotal
// from collectorDescFamilies must red (checked collector would error the
// scrape on an undeclared emit).
func TestFabricConnDescriptorIsDeclared16478(t *testing.T) {
	c := newCollector(nil)
	ch := make(chan *prometheus.Desc, 4096)
	go func() { c.Describe(ch); close(ch) }()
	for d := range ch {
		if strings.Contains(d.String(), "xpf_fabric_conn_refusals_total") {
			return
		}
	}
	t.Error("xpf_fabric_conn_refusals_total is not declared in Describe(); the collector " +
		"is checked, so emitting it would error the scrape")
}
