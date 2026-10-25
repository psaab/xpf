package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/dataplane/mgmtview"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *xpfCollector) emitHATakeoverReadiness13301(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	provider, ok := mgmtview.Probe(dp).(interface {
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
	c.emitConstMetric(ch, c.userspaceHATakeoverReady, prometheus.GaugeValue, ready)
	// The vocabulary is owned by pkg/dataplane/userspace (#16730): every
	// name the mapper can return is emitted, and any value outside the
	// vocabulary still surfaces under "other" instead of being dropped
	// (fabric blockers, #15918) — a future mapper addition cannot be
	// silently invisible to Prometheus.
	active := make(map[string]bool, len(s.Blockers))
	for _, current := range s.Blockers {
		active[current] = true
	}
	for _, blocker := range dpuserspace.HATakeoverBlockers {
		v := 0.0
		if active[blocker] {
			v = 1
		} else if blocker == dpuserspace.HATakeoverBlockerOther {
			// Unknown names (not in the shared vocabulary) fold into other.
			for current := range active {
				if !dpuserspace.IsHATakeoverBlocker(current) {
					v = 1
					break
				}
			}
		}
		c.emitConstMetric(ch, c.userspaceHATakeoverBlocker, prometheus.GaugeValue, v, blocker)
	}
	c.emitConstMetric(ch, c.userspaceSessionSocketRequestsTotal, prometheus.CounterValue, float64(s.SessionSocketRequests))
	c.emitConstMetric(ch, c.userspaceSessionSocketErrorsTotal, prometheus.CounterValue, float64(s.SessionSocketErrors))
	c.emitConstMetric(ch, c.userspaceSessionSocketTimeoutsTotal, prometheus.CounterValue, float64(s.SessionSocketTimeouts))
	c.emitConstMetric(ch, c.userspaceSyncedImportRefusalsTotal, prometheus.CounterValue, float64(s.SyncedImportRefusals))
}
