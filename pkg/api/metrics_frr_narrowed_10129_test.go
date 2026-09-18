package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestFRRNarrowedPolicyChainShapeGauge10129(t *testing.T) {
	s := &Server{
		frrNarrowedPolicyChainsFn: func() []string {
			return []string{"a", "b", "c", "d"}
		},
		frrNarrowedPolicyChainsDenySafeFn: func() []string {
			return []string{"a", "b"}
		},
		frrNarrowedPolicyChainShapesFn: func() map[string]int {
			return map[string]int{"fall-through": 1, "empty": 2, "match-all": 1}
		},
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	foundTotal, foundDenySafe, foundShape := false, false, false
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_frr_policy_chains_narrowed":
			foundTotal = true
			if len(mf.GetMetric()) != 1 || mf.GetMetric()[0].GetGauge().GetValue() != 4 {
				t.Fatalf("total narrowed gauge = %#v, want 4", mf)
			}
		case "xpf_frr_policy_chains_narrowed_deny_safe":
			foundDenySafe = true
			if len(mf.GetMetric()) != 1 || mf.GetMetric()[0].GetGauge().GetValue() != 2 {
				t.Fatalf("deny-safe gauge = %#v, want 2", mf)
			}
		case "xpf_frr_policy_chains_narrowed_shape":
			foundShape = true
			want := map[string]float64{
				"fall-through":        1,
				"empty":               2,
				"match-all":           1,
				"quarantined":         0,
				"terminating-default": 0,
				"unknown":             0,
			}
			if len(mf.GetMetric()) != len(want) {
				t.Fatalf("shape series = %d, want %d", len(mf.GetMetric()), len(want))
			}
			for _, metric := range mf.GetMetric() {
				if len(metric.GetLabel()) != 1 || metric.GetLabel()[0].GetName() != "shape" {
					t.Fatalf("shape metric labels = %#v", metric)
				}
				shape := metric.GetLabel()[0].GetValue()
				if got, ok := want[shape]; !ok || metric.GetGauge().GetValue() != got {
					t.Errorf("shape %q gauge=%v, want %v", shape, metric.GetGauge().GetValue(), got)
				}
			}
		}
	}
	if !foundTotal || !foundDenySafe || !foundShape {
		t.Fatalf("missing narrowed metric family: total=%v deny_safe=%v shape=%v", foundTotal, foundDenySafe, foundShape)
	}
}
