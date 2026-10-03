package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestRemoteArchiveDebtMetrics11806 emits current-config site debt and its
// failure counter even when the dataplane is not loaded.
func TestRemoteArchiveDebtMetrics11806(t *testing.T) {
	s := &Server{ // dp intentionally nil — control-plane metrics must still emit
		remoteArchiveStatusFn: func() (uint64, uint64) { return 2, 5 },
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	foundPending, foundFailures := false, false
	for _, mf := range mfs {
		switch mf.GetName() {
		case "xpf_config_remote_archive_pending_sites":
			foundPending = true
			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 2 {
				t.Errorf("pending remote archive sites = %v, want 2", got)
			}
		case "xpf_config_remote_archive_failures_total":
			foundFailures = true
			if got := mf.GetMetric()[0].GetCounter().GetValue(); got != 5 {
				t.Errorf("remote archive failures = %v, want 5", got)
			}
		}
	}
	if !foundPending || !foundFailures {
		t.Fatalf("remote archive metrics missing with dataplane unloaded: pending=%v failures=%v",
			foundPending, foundFailures)
	}
}
