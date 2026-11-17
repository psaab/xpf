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
		c.emitConstMetric(ch, c.bindingActiveFlowCount,
			prometheus.GaugeValue,
			float64(b.ActiveFlowCount),
			strconv.FormatUint(uint64(b.Slot), 10),
			strconv.FormatUint(uint64(b.QueueID), 10),
			strconv.FormatUint(uint64(b.WorkerID), 10),
			b.Interface)
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
		c.emitConstMetric(ch, c.bindingTXCompletions,
			prometheus.CounterValue,
			float64(b.TXCompletions),
			slot, queueID, workerID, b.Interface)
		c.emitConstMetric(ch, c.bindingTXCompletionRingAvailable,
			prometheus.GaugeValue,
			float64(b.TXCompletionRingAvailable),
			slot, queueID, workerID, b.Interface)
		c.emitConstMetric(ch, c.bindingTXCompletionRingAvailableMax,
			prometheus.GaugeValue,
			float64(b.TXCompletionRingAvailableMax),
			slot, queueID, workerID, b.Interface)
	}
}

// #15285: emit the per-binding kernel XDP rx_ring_full counter.
// Emitted unconditionally per binding so a 0 is a real "no ring-full
// loss" signal rather than an absent series.
func (c *xpfCollector) emitBindingKernelRXRingFull(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		c.emitConstMetric(ch, c.bindingKernelRXRingFull,
			prometheus.CounterValue,
			float64(b.KernelRXRingFull),
			slot, queueID, workerID, b.Interface)
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
		c.emitConstMetric(ch, c.bindingVMinThrottles,
			prometheus.CounterValue,
			float64(b.VMinThrottles),
			slot, queueID, workerID, b.Interface)
		c.emitConstMetric(ch, c.bindingVMinThrottleHardCapOverrides,
			prometheus.CounterValue,
			float64(b.VMinThrottleHardCapOverrides),
			slot, queueID, workerID, b.Interface)
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
		c.emitConstMetric(ch, c.bindingFragOverlapDropped,
			prometheus.CounterValue,
			float64(b.FragOverlapDropped),
			labels...)
		c.emitConstMetric(ch, c.bindingFragOverlapOverflowDropped,
			prometheus.CounterValue,
			float64(b.FragOverlapOverflowDropped),
			labels...)
		c.emitConstMetric(ch, c.bindingFragOverlapShardFullDropped,
			prometheus.CounterValue,
			float64(b.FragOverlapShardFullDropped),
			labels...)
		c.emitConstMetric(ch, c.bindingFragOverlapPostNATDropped,
			prometheus.CounterValue,
			float64(b.FragOverlapPostNATDropped),
			labels...)
		c.emitConstMetric(ch, c.bindingFragOverlapMaxLifetimeEvictions,
			prometheus.CounterValue,
			float64(b.FragOverlapMaxLifetimeEvictions),
			labels...)
	}
}

// #13299: publish the frame inventory components independently from the
// in-flight utilization ratio. The fill queue is idle capacity, not saturation.
func (c *xpfCollector) emitBindingUMEMFrames(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		labels := []string{slot, queueID, workerID, b.Interface}
		c.emitConstMetric(ch, c.bindingUMEMTotalFrames,
			prometheus.GaugeValue, float64(b.UmemTotalFrames), labels...)
		c.emitConstMetric(ch, c.bindingUMEMInflightFrames,
			prometheus.GaugeValue, float64(b.UmemInflightFrames), labels...)
		c.emitConstMetric(ch, c.bindingPendingFillFrames,
			prometheus.GaugeValue, float64(b.DebugPendingFillFrames), labels...)
		c.emitConstMetric(ch, c.bindingPendingTXPreparedFrames,
			prometheus.GaugeValue, float64(b.DebugPendingTXPrepared), labels...)
		c.emitConstMetric(ch, c.bindingPendingTXLocalFrames,
			prometheus.GaugeValue, float64(b.DebugPendingTXLocal), labels...)
		c.emitConstMetric(ch, c.bindingPendingRecycleFrames,
			prometheus.GaugeValue, float64(b.DebugInFlightRecycles), labels...)
	}
}

// flowCacheEvictionArmLabels maps the Rust FlowCacheEvictionArm ordinal
// (protocol BindingStatus.FlowCacheEvictionsByArm index) to its label.
var flowCacheEvictionArmLabels = []string{
	"lookup_generation",
	"lookup_rg_epoch",
	"lookup_lease",
	"lookup_deny_expiry",
	"lookup_scheduler",
	"scheduler_phase_flush",
	"collision",
	"post_hit_neighbor_mac",
	"post_hit_decision_invalid",
	"post_hit_deny_superseded",
	"post_hit_session_dead",
	"post_hit_enforce_changed",
	"post_hit_owner_active_redirect",
	"post_hit_fabric_local_wins",
	"post_hit_fabric_ingress_local_wins",
	"post_hit_fabric_redirect_on_fabric_ingress",
	"post_hit_fabric_local_wins_same_owner",
	"post_hit_fabric_ingress_discard_now_local",
	"post_hit_forward_candidate_egress_departed",
	"post_hit_fabric_redirect_destination_now_local",
	"post_hit_session_dead_no_record",
	"post_hit_session_dead_idle_crossed",
}

// #16220: emit per-arm flow-cache evictions so a cache-retention failure
// is attributable from Prometheus without perf.
func (c *xpfCollector) emitBindingFlowCacheEvictionsByArm(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	for _, b := range status.Bindings {
		slot := strconv.FormatUint(uint64(b.Slot), 10)
		queueID := strconv.FormatUint(uint64(b.QueueID), 10)
		workerID := strconv.FormatUint(uint64(b.WorkerID), 10)
		for i, arm := range flowCacheEvictionArmLabels {
			var n uint64
			if i < len(b.FlowCacheEvictionsByArm) {
				n = b.FlowCacheEvictionsByArm[i]
			}
			c.emitConstMetric(ch, c.bindingFlowCacheEvictionsArm,
				prometheus.CounterValue, float64(n),
				slot, queueID, workerID, b.Interface, arm)
		}
	}
}
