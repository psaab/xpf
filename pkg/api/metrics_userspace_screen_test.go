package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestUserspaceScreenStateMetricsAggregateWorkerTransportSlots(t *testing.T) {
	c := &xpfCollector{
		userspaceScreenSubstitutedDefaultDrops: prometheus.NewDesc("xpf_userspace_screen_substituted_default_drops_total", "", nil, nil),
		userspaceScreenSYNFloodDstDrops:        prometheus.NewDesc("xpf_userspace_screen_syn_flood_dst_drops_total", "", nil, nil),
		userspaceScreenSYNFloodSrcDrops:        prometheus.NewDesc("xpf_userspace_screen_syn_flood_src_drops_total", "", nil, nil),
		userspaceScreenSYNFloodAlarmEvents:     prometheus.NewDesc("xpf_userspace_screen_syn_flood_alarm_events_total", "", nil, nil),
		userspaceScreenAlarmWithoutDropEvents:  prometheus.NewDesc("xpf_userspace_screen_alarm_without_drop_events_total", "", nil, nil),
		userspaceScreenProfileWarns:            prometheus.NewDesc("xpf_userspace_screen_profile_warns_total", "", []string{"profile"}, nil),
		userspaceScreenTrackerPressureEvents:   prometheus.NewDesc("xpf_userspace_screen_tracker_pressure_events_total", "", []string{"action"}, nil),
	}
	status := dpuserspace.ProcessStatus{Bindings: []dpuserspace.BindingStatus{
		{ScreenSubstitutedDefaultDrops: 2, ScreenSYNFloodDstDrops: 3, ScreenSYNFloodSrcDrops: 5, ScreenSYNFloodAlarmEvents: 7, ScreenAlarmWithoutDropEvents: 11, ScreenMissingProfileWarns: 13, ScreenInertProfileWarns: 17, ScreenScanSweepSkippedPressure: 19, ScreenScanSweepEvictedPressure: 23},
		{ScreenSubstitutedDefaultDrops: 29, ScreenSYNFloodDstDrops: 31, ScreenSYNFloodSrcDrops: 37, ScreenSYNFloodAlarmEvents: 41, ScreenAlarmWithoutDropEvents: 43, ScreenMissingProfileWarns: 47, ScreenInertProfileWarns: 53, ScreenScanSweepSkippedPressure: 59, ScreenScanSweepEvictedPressure: 61},
	}}

	ch := make(chan prometheus.Metric, 9)
	c.emitUserspaceScreenStateMetrics(ch, status)
	close(ch)
	want := []float64{31, 34, 42, 48, 54, 60, 70, 78, 84}
	wantLabels := []string{"", "", "", "", "", "missing", "inert", "skipped", "evicted"}
	count := 0
	for i, metric := range ch {
		count++
		var got dto.Metric
		if err := metric.Write(&got); err != nil {
			t.Fatalf("write metric %d: %v", i, err)
		}
		if value := got.GetCounter().GetValue(); value != want[i] {
			t.Errorf("metric %d = %v, want %v", i, value, want[i])
		}
		if wantLabels[i] != "" {
			if len(got.GetLabel()) != 1 || got.GetLabel()[0].GetValue() != wantLabels[i] {
				t.Errorf("metric %d labels = %v, want %s", i, got.GetLabel(), wantLabels[i])
			}
		} else if len(got.GetLabel()) != 0 {
			t.Errorf("metric %d has unexpected labels %v", i, got.GetLabel())
		}
	}
	if count != len(want) {
		t.Fatalf("emitted %d metrics, want %d", count, len(want))
	}
}
