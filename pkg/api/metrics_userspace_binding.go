package api

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Prometheus emitters for the userspace dataplane's PER-BINDING telemetry —
// active flow count, TX completion, and vmin throttle counters.
// Split out of metrics_userspace.go for the #7700 modularity floor; this is a
// move, not a behaviour change.

// #1219: emit per-binding distinct active flow count for the fairness
// harness. Reads BindingStatus.ActiveFlowCount populated by the
// helper's ~65ms debug-state tick (see plan §3.2-3.3).
func (c *xpfCollector) emitBindingActiveFlowCount(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		ch <- prometheus.MustNewConstMetric(
			c.bindingActiveFlowCount,
			prometheus.GaugeValue,
			float64(b.ActiveFlowCount),
			strconv.FormatUint(uint64(b.Slot), 10),
			strconv.FormatUint(uint64(b.QueueID), 10),
			strconv.FormatUint(uint64(b.WorkerID), 10),
			b.Interface,
		)
	}
}

// #1241: emit per-binding AF_XDP TX completion service telemetry for
// flow-fairness qualification runs. `tx_completions_total` gives the
// per-queue completion rate via Prometheus `rate()`. The two gauges
// expose latest and peak completion-ring backlog observed by the owner
// worker before drain, without introducing a hot-path shared counter.
func (c *xpfCollector) emitBindingTXCompletionTelemetry(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletions,
			prometheus.CounterValue,
			float64(b.TXCompletions),
			slot, queueID, workerID, b.Interface,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletionRingAvailable,
			prometheus.GaugeValue,
			float64(b.TXCompletionRingAvailable),
			slot, queueID, workerID, b.Interface,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingTXCompletionRingAvailableMax,
			prometheus.GaugeValue,
			float64(b.TXCompletionRingAvailableMax),
			slot, queueID, workerID, b.Interface,
		)
	}
}

// #1831 (follow-up to #1766): emit the per-binding V_min
// fairness-throttle counters (#941 work item D / #943). Both have been
// on the BindingStatus wire since #941/#943 (flushed from per-queue
// scratch fields at the helper's ~65ms debug tick) but were never
// exported. Emitted unconditionally per binding so a 0 is a real
// "brake never fired" signal rather than an absent series.
func (c *xpfCollector) emitBindingVMinThrottleCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.bindingVMinThrottles,
			prometheus.CounterValue,
			float64(b.VMinThrottles),
			slot, queueID, workerID, b.Interface,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingVMinThrottleHardCapOverrides,
			prometheus.CounterValue,
			float64(b.VMinThrottleHardCapOverrides),
			slot, queueID, workerID, b.Interface,
		)
	}
}

// #10131: emit binding-local fragment-overlap attribution counters. These are
// emitted unconditionally so zero means the binding observed no such event.
func (c *xpfCollector) emitBindingFragmentOverlapCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		labels := []string{slot, queueID, workerID, b.Interface}
		ch <- prometheus.MustNewConstMetric(
			c.bindingFragOverlapDropped,
			prometheus.CounterValue,
			float64(b.FragOverlapDropped),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingFragOverlapOverflowDropped,
			prometheus.CounterValue,
			float64(b.FragOverlapOverflowDropped),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingFragOverlapShardFullDropped,
			prometheus.CounterValue,
			float64(b.FragOverlapShardFullDropped),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingFragOverlapPostNATDropped,
			prometheus.CounterValue,
			float64(b.FragOverlapPostNATDropped),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.bindingFragOverlapMaxLifetimeEvictions,
			prometheus.CounterValue,
			float64(b.FragOverlapMaxLifetimeEvictions),
			labels...,
		)
	}
}
