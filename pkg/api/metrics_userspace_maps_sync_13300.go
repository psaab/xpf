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
	ch <- prometheus.MustNewConstMetric(c.userspaceRSTSuppressionDegraded, prometheus.GaugeValue, degraded)
	ch <- prometheus.MustNewConstMetric(c.userspaceRSTSuppressionFailures, prometheus.CounterValue, float64(status.RSTSuppressionFailures))
	ch <- prometheus.MustNewConstMetric(c.userspaceBindingsWatchdogRepairs, prometheus.CounterValue, float64(status.BindingsWatchdogRepairs))
	ch <- prometheus.MustNewConstMetric(c.userspaceBindingsWatchdogErrors, prometheus.CounterValue, float64(status.BindingsWatchdogErrors))
	ch <- prometheus.MustNewConstMetric(c.userspaceLocalAddrPruneSkipped, prometheus.CounterValue, float64(status.LocalAddrPruneSkipped))
}
