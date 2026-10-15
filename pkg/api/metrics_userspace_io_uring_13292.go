package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitUserspaceIoUring13292 exports the io_uring mode and retained-buffer
// counters unconditionally: zero counters and inactive mode are meaningful
// states, not missing telemetry.
func (c *xpfCollector) emitUserspaceIoUring13292(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	active := 0.0
	if status.IOUringActive {
		active = 1
	}
	ch <- prometheus.MustNewConstMetric(c.userspaceIoUringActive,
		prometheus.GaugeValue, active)
	ch <- prometheus.MustNewConstMetric(c.userspaceIoUringRetainedBuffers,
		prometheus.CounterValue, float64(status.IoUringRetainedBuffersTotal))
	ch <- prometheus.MustNewConstMetric(c.userspaceIoUringRetainedBytes,
		prometheus.CounterValue, float64(status.IoUringRetainedBytesTotal))
}
