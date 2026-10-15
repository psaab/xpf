package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// This exercises the production status collector using only the wire payload,
// so the test compiles on master: without the D3-11 fields and emitters, the
// requested Prometheus series are absent rather than the test failing to build.
func TestUserspaceScreenStateMetricsAggregateWorkerTransportSlots(t *testing.T) {
	var status dpuserspace.ProcessStatus
	payload := []byte(`{"bindings":[
		{"screen_substituted_default_drops":2,"screen_syn_flood_dst_drops":3,"screen_syn_flood_src_drops":5,"screen_syn_flood_alarm_events":7,"screen_alarm_without_drop_events":11,"screen_missing_profile_warns":13,"screen_inert_profile_warns":17,"screen_scan_sweep_skipped_pressure":19,"screen_scan_sweep_evicted_pressure":23},
		{"screen_substituted_default_drops":29,"screen_syn_flood_dst_drops":31,"screen_syn_flood_src_drops":37,"screen_syn_flood_alarm_events":41,"screen_alarm_without_drop_events":43,"screen_missing_profile_warns":47,"screen_inert_profile_warns":53,"screen_scan_sweep_skipped_pressure":59,"screen_scan_sweep_evicted_pressure":61}
	]}`)
	if err := json.Unmarshal(payload, &status); err != nil {
		t.Fatalf("unmarshal worker status: %v", err)
	}

	c := newCollector(nil)
	ch := make(chan prometheus.Metric, 512)
	c.collectUserspaceStatus(ch, &status)
	close(ch)

	want := map[string]float64{
		"xpf_userspace_screen_substituted_default_drops_total": 31,
		"xpf_userspace_screen_syn_flood_dst_drops_total":        34,
		"xpf_userspace_screen_syn_flood_src_drops_total":        42,
		"xpf_userspace_screen_syn_flood_alarm_events_total":     48,
		"xpf_userspace_screen_alarm_without_drop_events_total":  54,
		"xpf_userspace_screen_profile_warns_total|missing":      60,
		"xpf_userspace_screen_profile_warns_total|inert":        70,
		"xpf_userspace_screen_tracker_pressure_events_total|skipped": 78,
		"xpf_userspace_screen_tracker_pressure_events_total|evicted": 84,
	}
	got := make(map[string]float64, len(want))
	for metric := range ch {
		var sample dto.Metric
		if err := metric.Write(&sample); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		desc := metric.Desc().String()
		for key, value := range want {
			name, labelValue, hasLabel := strings.Cut(key, "|")
			if !strings.Contains(desc, `fqName: "`+name+`"`) {
				continue
			}
			if hasLabel {
				labels := sample.GetLabel()
				if len(labels) != 1 || labels[0].GetValue() != labelValue {
					continue
			}
			}
			if _, duplicate := got[key]; duplicate {
				t.Fatalf("duplicate metric sample %q", key)
			}
			got[key] = sample.GetCounter().GetValue()
			if got[key] != value {
				t.Errorf("%s = %v, want %v", key, got[key], value)
			}
		}
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("missing metric sample %q", key)
		}
	}
}
