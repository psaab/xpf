package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestEmitSessionGCMetricsAggregatesAllClassifications13281(t *testing.T) {
	c := newCollector(nil)
	status := dpuserspace.ProcessStatus{WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{
		{SessionGCScanned: 1, SessionGCDroppedGone: 2, SessionGCDroppedStale: 3, SessionGCReBucketed: 4, SessionGCHeldStandby: 5, SessionGCReapedStaleSynced: 6, SessionGCHealedOnPromote: 7, SessionGCAgedOwnerRGZeroActiveNode: 8, SessionGCKeptAliveByCompanion: 9},
		{SessionGCScanned: 10, SessionGCDroppedGone: 20, SessionGCDroppedStale: 30, SessionGCReBucketed: 40, SessionGCHeldStandby: 50, SessionGCReapedStaleSynced: 60, SessionGCHealedOnPromote: 70, SessionGCAgedOwnerRGZeroActiveNode: 80, SessionGCKeptAliveByCompanion: 90},
	}}
	ch := make(chan prometheus.Metric, 9)
	c.emitSessionGCMetrics(ch, status)
	close(ch)
	got := map[string]float64{}
	for metric := range ch {
		var sample dto.Metric
		if err := metric.Write(&sample); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		got[descName(metric.Desc())] = sample.GetCounter().GetValue()
	}
	want := map[string]float64{
		"xpf_userspace_session_gc_scanned_total":                        11,
		"xpf_userspace_session_gc_dropped_gone_total":                   22,
		"xpf_userspace_session_gc_dropped_stale_total":                  33,
		"xpf_userspace_session_gc_re_bucketed_total":                    44,
		"xpf_userspace_session_gc_held_standby_total":                   55,
		"xpf_userspace_session_gc_reaped_stale_synced_total":            66,
		"xpf_userspace_session_gc_healed_on_promote_total":              77,
		"xpf_userspace_session_gc_aged_owner_rg_zero_active_node_total": 88,
		"xpf_userspace_session_gc_kept_alive_by_companion_total":        99,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d session GC metrics, want %d: %#v", len(got), len(want), got)
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Errorf("%s = %v, want %v", name, got[name], expected)
		}
	}
}
