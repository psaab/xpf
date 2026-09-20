package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestIpsecCaptureDispositionMetricsJoinWitnessLabels10478(t *testing.T) {
	srv := &Server{
		ipsecCaptureWitnessFn: func() IpsecCaptureWitness {
			return IpsecCaptureWitness{
				Available:          true,
				RunID:              "run-10478",
				ActorActive:        true,
				PermitState:        "OPEN",
				Generation:         9,
				PermitEpoch:        11,
				Consumed:           12,
				Adjudicated:        13,
				Reinjected:         14,
				Written:            3,
				Uncertain:          2,
				LateCompletions:    1,
				Timeouts:           4,
				Stale:              5,
				Cancelled:          6,
				Refused:            7,
				DeliveredAvailable: true,
				Delivered:          8,
			}
		},
	}
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(newCollector(srv)); err != nil {
		t.Fatalf("register: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	want := map[string]float64{
		"xpf_ipsec_capture_consumed_total":         12,
		"xpf_ipsec_capture_adjudicated_total":      13,
		"xpf_ipsec_capture_reinjected_total":       14,
		"xpf_ipsec_capture_written_total":          3,
		"xpf_ipsec_capture_uncertain_total":        2,
		"xpf_ipsec_capture_late_completions_total": 1,
		"xpf_ipsec_capture_timeouts_total":         4,
		"xpf_ipsec_capture_stale_total":            5,
		"xpf_ipsec_capture_cancelled_total":        6,
		"xpf_ipsec_capture_refused_total":          7,
		"xpf_ipsec_capture_delivered_total":        8,
	}
	seen := map[string]bool{}
	for _, family := range families {
		value, ok := want[family.GetName()]
		if !ok {
			continue
		}
		if len(family.GetMetric()) != 1 {
			t.Fatalf("%s: got %d metrics, want one joined witness", family.GetName(), len(family.GetMetric()))
		}
		metric := family.GetMetric()[0]
		labels := map[string]string{}
		for _, label := range metric.GetLabel() {
			labels[label.GetName()] = label.GetValue()
		}
		for key, expected := range map[string]string{
			"run_id": "run-10478", "generation": "9", "permit_epoch": "11",
		} {
			if labels[key] != expected {
				t.Errorf("%s: %s label=%q, want %q", family.GetName(), key, labels[key], expected)
			}
		}
		if metric.GetCounter().GetValue() != value {
			t.Errorf("%s: value=%v, want %v", family.GetName(), metric.GetCounter().GetValue(), value)
		}
		seen[family.GetName()] = true
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s was not emitted", name)
		}
	}
}
