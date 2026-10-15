package api

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type takeoverReadinessDP13301 struct {
	*descriptorCoverageDP
	readiness dpuserspace.HATakeoverReadiness
}

func (d *takeoverReadinessDP13301) HATakeoverReadiness() dpuserspace.HATakeoverReadiness {
	return d.readiness
}

func (d *takeoverReadinessDP13301) Unwrap() any { return d }

func TestMetricsUserspaceHATakeoverReadyAndBlockerSeries13301(t *testing.T) {
	c := newCollector(nil)
	dp := &takeoverReadinessDP13301{
		descriptorCoverageDP: &descriptorCoverageDP{Manager: dataplane.New()},
		readiness: dpuserspace.HATakeoverReadiness{
			Ready: false, Blockers: []string{"session_mirror_failed"},
			SessionMirrorFailed: true, SessionSocketRequests: 4,
			SessionSocketErrors: 2, SessionSocketTimeouts: 1, SyncedImportRefusals: 3,
		},
	}
	ch := make(chan prometheus.Metric, 32)
	c.emitHATakeoverReadiness13301(ch, dp)
	close(ch)
	metrics := make([]prometheus.Metric, 0, len(ch))
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	checks := []struct {
		name, label string
		want        float64
	}{
		{"xpf_userspace_ha_takeover_ready", "", 0},
		{"xpf_userspace_ha_takeover_blocker", "session_mirror_failed", 1},
		{"xpf_userspace_session_socket_requests_total", "", 4},
		{"xpf_userspace_session_socket_errors_total", "", 2},
		{"xpf_userspace_session_socket_timeouts_total", "", 1},
		{"xpf_userspace_ha_synced_import_refusals_total", "", 3},
	}
	for _, check := range checks {
		found := false
		for _, metric := range metrics {
			if !strings.Contains(metric.Desc().String(), check.name) {
				continue
			}
			var pb dto.Metric
			if err := metric.Write(&pb); err != nil {
				t.Fatalf("write metric: %v", err)
			}
			if check.label != "" {
				matched := false
				for _, label := range pb.GetLabel() {
					if label.GetValue() == check.label {
						matched = true
					}
				}
				if !matched {
					continue
				}
			}
			found = true
			value := pb.GetCounter().GetValue()
			if pb.Gauge != nil {
				value = pb.GetGauge().GetValue()
			}
			if value != check.want {
				t.Errorf("%s=%v, want %v", check.name, value, check.want)
			}
			break
		}
		if !found {
			t.Errorf("missing metric %s label %s", check.name, check.label)
		}
	}
}
