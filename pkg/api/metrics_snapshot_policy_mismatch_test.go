package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// HARDENING (#15742 follow-up): the mismatch counter and last-applied
// policy count ride the existing userspace status collect; both series
// must carry the status values.
func TestEmitSnapshotPolicyMismatchValues(t *testing.T) {
	c := newCollector(nil)
	status := dpuserspace.ProcessStatus{SnapshotPolicyMismatchTotal: 3, LastSnapshotPolicyCount: 2}
	ch := make(chan prometheus.Metric, 4)
	c.emitSnapshotPolicyMismatch(ch, status)
	close(ch)
	byName := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if pb.Counter != nil {
			byName[m.Desc().String()] = pb.Counter.GetValue()
		} else {
			byName[m.Desc().String()] = pb.Gauge.GetValue()
		}
	}
	found := map[string]float64{}
	for desc, v := range byName {
		switch {
		case strings.Contains(desc, "snapshot_policy_mismatch_total"):
			found["mismatch"] = v
		case strings.Contains(desc, "last_snapshot_policy_count"):
			found["count"] = v
		}
	}
	if found["mismatch"] != 3 || found["count"] != 2 || len(byName) != 2 {
		t.Fatalf("emitted %v, want mismatch_total=3 and last_snapshot_policy_count=2", byName)
	}
}
