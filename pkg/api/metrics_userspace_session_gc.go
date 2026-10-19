package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitSessionGCMetrics aggregates the per-worker cumulative timer-wheel
// classifications into process-wide counters, keeping the exported series
// stable across worker-count changes.
func (c *xpfCollector) emitSessionGCMetrics(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	var scanned, droppedGone, droppedStale, reBucketed uint64
	var heldStandby, reapedStaleSynced, healedOnPromote uint64
	var agedOwnerRGZeroActiveNode, keptAliveByCompanion uint64
	for _, worker := range status.WorkerRuntime {
		scanned += worker.SessionGCScanned
		droppedGone += worker.SessionGCDroppedGone
		droppedStale += worker.SessionGCDroppedStale
		reBucketed += worker.SessionGCReBucketed
		heldStandby += worker.SessionGCHeldStandby
		reapedStaleSynced += worker.SessionGCReapedStaleSynced
		healedOnPromote += worker.SessionGCHealedOnPromote
		agedOwnerRGZeroActiveNode += worker.SessionGCAgedOwnerRGZeroActiveNode
		keptAliveByCompanion += worker.SessionGCKeptAliveByCompanion
	}
	c.emitConstMetric(ch, c.userspaceSessionGCScanned, prometheus.CounterValue, float64(scanned))
	c.emitConstMetric(ch, c.userspaceSessionGCDroppedGone, prometheus.CounterValue, float64(droppedGone))
	c.emitConstMetric(ch, c.userspaceSessionGCDroppedStale, prometheus.CounterValue, float64(droppedStale))
	c.emitConstMetric(ch, c.userspaceSessionGCReBucketed, prometheus.CounterValue, float64(reBucketed))
	c.emitConstMetric(ch, c.userspaceSessionGCHeldStandby, prometheus.CounterValue, float64(heldStandby))
	c.emitConstMetric(ch, c.userspaceSessionGCReapedStaleSynced, prometheus.CounterValue, float64(reapedStaleSynced))
	c.emitConstMetric(ch, c.userspaceSessionGCHealedOnPromote, prometheus.CounterValue, float64(healedOnPromote))
	c.emitConstMetric(ch, c.userspaceSessionGCAgedOwnerRGZeroActiveNode, prometheus.CounterValue, float64(agedOwnerRGZeroActiveNode))
	c.emitConstMetric(ch, c.userspaceSessionGCKeptAliveByCompanion, prometheus.CounterValue, float64(keptAliveByCompanion))
}
