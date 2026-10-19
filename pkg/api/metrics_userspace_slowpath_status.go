package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitUserspaceSlowPathStatus exports both slow-path outlets with one stable
// label set. Keeping trusted and delegated together prevents a delegated MTU
// failure from being mistaken for a healthy single-outlet status (#10069).
func (c *xpfCollector) emitUserspaceSlowPathStatus(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	outlets := []struct {
		name string
		data dpuserspace.SlowPathStatus
	}{
		{name: "trusted", data: status.SlowPath},
		{name: "delegated", data: status.SlowPathDelegated},
	}
	for _, outlet := range outlets {
		label := outlet.name
		active := 0.0
		if outlet.data.Active {
			active = 1
		}
		degraded := 0.0
		if outlet.data.Degraded {
			degraded = 1
		}
		c.emitConstMetric(ch, c.userspaceSlowPathActive, prometheus.GaugeValue, active, label)
		c.emitConstMetric(ch, c.userspaceSlowPathDegraded, prometheus.GaugeValue, degraded, label)
		c.emitConstMetric(ch, c.userspaceSlowPathLiveMTU, prometheus.GaugeValue, float64(outlet.data.LiveMTU), label)
		c.emitConstMetric(ch, c.userspaceSlowPathQueuedPackets, prometheus.GaugeValue, float64(outlet.data.QueuedPackets), label)
		c.emitConstMetric(ch, c.userspaceSlowPathInjectedPackets, prometheus.CounterValue, float64(outlet.data.InjectedPackets), label)
		c.emitConstMetric(ch, c.userspaceSlowPathInjectedBytes, prometheus.CounterValue, float64(outlet.data.InjectedBytes), label)
		c.emitConstMetric(ch, c.userspaceSlowPathDroppedPackets, prometheus.CounterValue, float64(outlet.data.DroppedPackets), label)
		c.emitConstMetric(ch, c.userspaceSlowPathDroppedBytes, prometheus.CounterValue, float64(outlet.data.DroppedBytes), label)
		c.emitConstMetric(ch, c.userspaceSlowPathRateLimited, prometheus.CounterValue, float64(outlet.data.RateLimitedPackets), label)
		c.emitConstMetric(ch, c.userspaceSlowPathQueueFull, prometheus.CounterValue, float64(outlet.data.QueueFullPackets), label)
		c.emitConstMetric(ch, c.userspaceSlowPathWriteErrors, prometheus.CounterValue, float64(outlet.data.WriteErrors), label)
		c.emitConstMetric(ch, c.userspaceSlowPathMTUDroppedPackets, prometheus.CounterValue, float64(outlet.data.MTUDroppedPackets), label)
	}
}
