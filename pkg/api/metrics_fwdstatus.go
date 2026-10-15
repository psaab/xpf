package api

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

func (c *xpfCollector) initFwdStatusDescriptors() {
	c.forwardingState = prometheus.NewDesc("xpf_forwarding_state", "Forwarding health state (one-hot: online, degraded, or unknown).", []string{"state"}, nil)
	c.forwardingHeapUtilization = prometheus.NewDesc("xpf_forwarding_heap_utilization_ratio", "Daemon RSS as a ratio of its memory limit, omitted when unavailable.", nil, nil)
	c.forwardingBufferUtilization = prometheus.NewDesc("xpf_forwarding_buffer_utilization_ratio", "Maximum userspace UMEM or TX-ring utilization ratio, omitted when unavailable.", nil, nil)
	c.forwardingDaemonCPU = prometheus.NewDesc("xpf_forwarding_daemon_cpu_utilization_ratio", "Daemon per-core CPU utilization by rolling window.", []string{"window"}, nil)
	c.forwardingWorkerCPU = prometheus.NewDesc("xpf_forwarding_worker_cpu_utilization_ratio", "Average userspace worker CPU utilization by rolling window.", []string{"window"}, nil)
	c.forwardingCPUDataStale = prometheus.NewDesc("xpf_forwarding_cpu_data_stale", "Whether forwarding CPU sampler data is stale.", nil, nil)
	c.forwardingSamplerErrors = prometheus.NewDesc("xpf_forwarding_sampler_errors_total", "Cumulative /proc/self/stat read failures by the forwarding CPU sampler.", nil, nil)
}

type forwardingMetricsDP struct{ dp apiRuntimeDataPlane }

func (d forwardingMetricsDP) IsLoaded() bool { return d.dp.IsLoaded() }
func (d forwardingMetricsDP) GetMapStats() []fwdstatus.MapStats {
	stats := d.dp.GetMapStats()
	out := make([]fwdstatus.MapStats, len(stats))
	for i, s := range stats {
		out[i] = fwdstatus.MapStats{Type: s.Type, MaxEntries: s.MaxEntries, UsedCount: s.UsedCount}
	}
	return out
}

type forwardingMetricsUserspaceDP struct {
	forwardingMetricsDP
	status interface {
		Status() (userspace.ProcessStatus, error)
	}
}

func (d forwardingMetricsUserspaceDP) Status() (userspace.ProcessStatus, error) {
	return d.status.Status()
}

func (c *xpfCollector) collectFwdStatus(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.fwdSampler == nil {
		return
	}
	var dp fwdstatus.DataPlaneAccessor
	if c.srv.dp != nil {
		base := forwardingMetricsDP{dp: c.srv.dp}
		dp = base
		if status, ok := c.srv.dp.(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			dp = forwardingMetricsUserspaceDP{forwardingMetricsDP: base, status: status}
		}
	}
	snap := c.srv.fwdSampler.Snapshot()
	fs, err := fwdstatus.Build(dp, fwdstatus.OSProcReader{}, c.srv.startTime, snap)
	if err != nil {
		return
	}
	for _, state := range []fwdstatus.State{fwdstatus.StateOnline, fwdstatus.StateDegraded, fwdstatus.StateUnknown} {
		v := 0.0
		if fs.State == state {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.forwardingState, prometheus.GaugeValue, v, strings.ToLower(string(state)))
	}
	if fs.HeapPercentValid {
		ch <- prometheus.MustNewConstMetric(c.forwardingHeapUtilization, prometheus.GaugeValue, fs.HeapPercent/100)
	}
	if fs.BufferKnown {
		ch <- prometheus.MustNewConstMetric(c.forwardingBufferUtilization, prometheus.GaugeValue, fs.BufferPercent/100)
	}
	windows := [...]string{"5s", "1m", "5m"}
	for i, window := range windows {
		if fs.DaemonCPUWindowValid[i] {
			ch <- prometheus.MustNewConstMetric(c.forwardingDaemonCPU, prometheus.GaugeValue, fs.DaemonCPUWindows[i]/100, window)
		}
		if fs.WorkerCPUWindowValid[i] {
			ch <- prometheus.MustNewConstMetric(c.forwardingWorkerCPU, prometheus.GaugeValue, fs.WorkerCPUWindows[i]/100, window)
		}
	}
	stale := 0.0
	if fs.CPUDataStale {
		stale = 1
	}
	ch <- prometheus.MustNewConstMetric(c.forwardingCPUDataStale, prometheus.GaugeValue, stale)
	ch <- prometheus.MustNewConstMetric(c.forwardingSamplerErrors, prometheus.CounterValue, float64(fs.SamplerReadErrors))
}
