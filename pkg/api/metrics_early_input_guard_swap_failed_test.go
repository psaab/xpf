package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestEarlyInputGuardSwapFailedGauge pins #10751: the
// xpf_early_input_guard_swap_failed gauge must be emitted even when the
// dataplane is NOT loaded (a failed bootstrap guard swap strands remote
// recovery with no dataplane up — the signal matters most precisely then),
// and it must track the wired fn's value. Alert on == 1.
func TestEarlyInputGuardSwapFailedGauge(t *testing.T) {
	for _, tc := range []struct {
		name     string
		degraded bool
		want     float64
	}{
		{"degraded", true, 1},
		{"healthy", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil — gauge must still emit
				earlyInputGuardSwapFailedFn: func() bool { return tc.degraded },
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(newCollector(s))
			mfs, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			found := false
			for _, mf := range mfs {
				if mf.GetName() != "xpf_early_input_guard_swap_failed" {
					continue
				}
				found = true
				if len(mf.GetMetric()) != 1 {
					t.Fatalf("metric count = %d, want 1", len(mf.GetMetric()))
				}
				if got := mf.GetMetric()[0].GetGauge().GetValue(); got != tc.want {
					t.Errorf("gauge = %v, want %v", got, tc.want)
				}
			}
			if !found {
				t.Error("xpf_early_input_guard_swap_failed not emitted with dataplane unloaded")
			}
		})
	}
}
