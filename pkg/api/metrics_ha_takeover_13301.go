package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

var haTakeoverBlockers13301 = [...]string{
	"helper_down", "not_enabled", "forwarding_unsupported", "not_armed",
	"not_active", "xsk_liveness_failed", "xsk_unproven", "session_mirror_failed",
	"repair_overflow", "inventory_debt_owed", "snapshot_retry_debt",
	"pending_ha_clear", "pending_ha_replay", "event_stream_unbound",
}

func (c *xpfCollector) emitHATakeoverReadiness13301(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	provider, ok := dataplane.Unwrap(dp).(interface {
		HATakeoverReadiness() dpuserspace.HATakeoverReadiness
	})
	if !ok {
		return
	}
	s := provider.HATakeoverReadiness()
	ready := 0.0
	if s.Ready {
		ready = 1
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceHATakeoverReady, prometheus.GaugeValue, ready)
	for _, blocker := range haTakeoverBlockers13301 {
		v := 0.0
		for _, current := range s.Blockers {
			if current == blocker {
				v = 1
				break
			}
		}
		ch <- prometheus.MustNewConstMetric(c.userspaceHATakeoverBlocker, prometheus.GaugeValue, v, blocker)
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionSocketRequestsTotal, prometheus.CounterValue, float64(s.SessionSocketRequests))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionSocketErrorsTotal, prometheus.CounterValue, float64(s.SessionSocketErrors))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionSocketTimeoutsTotal, prometheus.CounterValue, float64(s.SessionSocketTimeouts))
	ch <- prometheus.MustNewConstMetric(c.userspaceSyncedImportRefusalsTotal, prometheus.CounterValue, float64(s.SyncedImportRefusals))
}
