package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestInterfaceLinkSnapshotRefreshPendingGauge11530(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending bool
		want    float64
	}{
		{"retry owed", true, 1},
		{"converged", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{ // dp intentionally nil: refresh debt is control-plane health
				interfaceLinkSnapshotPendingFn: func() bool { return tc.pending },
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(newCollector(s))
			mfs, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			for _, mf := range mfs {
				if mf.GetName() != "xpf_interface_link_snapshot_refresh_pending" {
					continue
				}
				if len(mf.GetMetric()) != 1 {
					t.Fatalf("metric count = %d, want 1", len(mf.GetMetric()))
				}
				if got := mf.GetMetric()[0].GetGauge().GetValue(); got != tc.want {
					t.Fatalf("gauge = %v, want %v", got, tc.want)
				}
				return
			}
			t.Fatal("xpf_interface_link_snapshot_refresh_pending not emitted with dataplane unloaded")
		})
	}
}
