package api

import (
	"errors"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psaab/xpf/pkg/dataplane"
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
	status *userspace.ProcessStatus
}

func (d forwardingMetricsUserspaceDP) Status() (userspace.ProcessStatus, error) {
	if d.status == nil {
		return userspace.ProcessStatus{}, errors.New("userspace status unavailable")
	}
	return *d.status, nil
}

func (c *xpfCollector) collectFwdStatus(
	ch chan<- prometheus.Metric,
	dp apiRuntimeDataPlane,
	userspaceStatus *userspace.ProcessStatus,
) {
	if c.srv == nil || c.srv.fwdSampler == nil {
		return
	}
	var buildDP fwdstatus.DataPlaneAccessor
	if dp != nil && dp.IsLoaded() {
		base := forwardingMetricsDP{dp: dp}
		buildDP = base
		if _, ok := dataplane.Unwrap(dp).(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			// Supply the same status already fetched for all userspace
			// metric families. Do not issue another status RPC here.
			buildDP = forwardingMetricsUserspaceDP{forwardingMetricsDP: base, status: userspaceStatus}
		}
	}
	snap := c.srv.fwdSampler.Snapshot()
	fs, err := fwdstatus.Build(buildDP, fwdstatus.OSProcReader{}, c.srv.startTime, snap)
	if err != nil {
		return
	}
	for _, state := range []fwdstatus.State{fwdstatus.StateOnline, fwdstatus.StateDegraded, fwdstatus.StateUnknown} {
		v := 0.0
		if fs.State == state {
			v = 1
		}
		c.emitConstMetric(ch, c.forwardingState, prometheus.GaugeValue, v, strings.ToLower(string(state)))
	}
	if fs.HeapPercentValid {
		c.emitConstMetric(ch, c.forwardingHeapUtilization, prometheus.GaugeValue, fs.HeapPercent/100)
	}
	if fs.BufferKnown {
		c.emitConstMetric(ch, c.forwardingBufferUtilization, prometheus.GaugeValue, fs.BufferPercent/100)
	}
	windows := [...]string{"5s", "1m", "5m"}
	for i, window := range windows {
		if fs.DaemonCPUWindowValid[i] {
			c.emitConstMetric(ch, c.forwardingDaemonCPU, prometheus.GaugeValue, fs.DaemonCPUWindows[i]/100, window)
		}
		if fs.WorkerCPUWindowValid[i] {
			c.emitConstMetric(ch, c.forwardingWorkerCPU, prometheus.GaugeValue, fs.WorkerCPUWindows[i]/100, window)
		}
	}
	stale := 0.0
	if fs.CPUDataStale {
		stale = 1
	}
	c.emitConstMetric(ch, c.forwardingCPUDataStale, prometheus.GaugeValue, stale)
	c.emitConstMetric(ch, c.forwardingSamplerErrors, prometheus.CounterValue, float64(fs.SamplerReadErrors))
}
