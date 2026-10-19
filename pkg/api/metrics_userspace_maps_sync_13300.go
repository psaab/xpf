package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *xpfCollector) emitUserspaceMapsSyncTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	degraded := 0.0
	if status.RSTSuppressionDegraded {
		degraded = 1
	}
	c.emitConstMetric(ch, c.userspaceRSTSuppressionDegraded, prometheus.GaugeValue, degraded)
	c.emitConstMetric(ch, c.userspaceRSTSuppressionFailures, prometheus.CounterValue, float64(status.RSTSuppressionFailures))
	c.emitConstMetric(ch, c.userspaceBindingsWatchdogRepairs, prometheus.CounterValue, float64(status.BindingsWatchdogRepairs))
	c.emitConstMetric(ch, c.userspaceBindingsWatchdogErrors, prometheus.CounterValue, float64(status.BindingsWatchdogErrors))
	c.emitConstMetric(ch, c.userspaceLocalAddrPruneSkipped, prometheus.CounterValue, float64(status.LocalAddrPruneSkipped))
}
