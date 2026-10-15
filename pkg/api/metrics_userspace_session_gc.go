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
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCScanned, prometheus.CounterValue, float64(scanned))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCDroppedGone, prometheus.CounterValue, float64(droppedGone))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCDroppedStale, prometheus.CounterValue, float64(droppedStale))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCReBucketed, prometheus.CounterValue, float64(reBucketed))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCHeldStandby, prometheus.CounterValue, float64(heldStandby))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCReapedStaleSynced, prometheus.CounterValue, float64(reapedStaleSynced))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCHealedOnPromote, prometheus.CounterValue, float64(healedOnPromote))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCAgedOwnerRGZeroActiveNode, prometheus.CounterValue, float64(agedOwnerRGZeroActiveNode))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionGCKeptAliveByCompanion, prometheus.CounterValue, float64(keptAliveByCompanion))
}
