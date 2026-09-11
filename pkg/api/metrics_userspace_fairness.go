package api

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Prometheus emitters for the userspace dataplane's FAIRNESS telemetry — RSS
// gauges and expectations, throughput, and the equal-flow estimate.
// Split out of metrics_userspace.go for the #7700 modularity floor; this is a
// move, not a behaviour change.

// #1247: expose production RSS/workload health gauges from the same
// per-CoS active-flow distribution used by the fairness harness. This
// remains a status-snapshot calculation; it does not feed scheduling and
// does not add packet-path shared state.
func (c *xpfCollector) emitFairnessRSSGauges(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	truncated := 0.0
	if status.CoSActiveFlowCountsTruncated {
		truncated = 1.0
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessCoSCountsTruncated,
		prometheus.GaugeValue,
		truncated,
	)

	for _, row := range dpuserspace.CoSFairnessRSSSummaries(status) {
		ifindexLabel := strconv.Itoa(row.Ifindex)
		queueLabel := strconv.FormatUint(uint64(row.QueueID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessCstruct,
			prometheus.GaugeValue,
			row.Cstruct,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessActiveWorkers,
			prometheus.GaugeValue,
			float64(row.ActiveWorkers),
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessActiveFlows,
			prometheus.GaugeValue,
			float64(row.ActiveFlows),
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessMaxWorkerFlowShare,
			prometheus.GaugeValue,
			row.MaxWorkerFlowShare,
			ifindexLabel,
			queueLabel,
		)
	}
	c.emitFairnessRSSExpectationGauges(ch, status, c.configuredFairnessRSSExpectations())
}

func (c *xpfCollector) configuredFairnessRSSExpectations() []dpuserspace.FairnessRSSExpectation {
	if c == nil || c.srv == nil || c.srv.store == nil {
		return nil
	}
	return dpuserspace.FairnessRSSExpectationsFromConfig(c.srv.store.ActiveConfig())
}

func (c *xpfCollector) emitFairnessRSSExpectationGauges(
	ch chan<- prometheus.Metric,
	status dpuserspace.ProcessStatus,
	expectations []dpuserspace.FairnessRSSExpectation,
) {
	for _, result := range dpuserspace.EvaluateFairnessRSSExpectations(status, expectations) {
		// #hb166 F2: skip expectations whose interface name did not resolve
		// to a live kernel ifindex. Their Ifindex is 0, so two distinct
		// unresolved names on the same queue+kind would emit identical
		// (ifindex=0, queue_id, kind) label sets — a duplicate-metric error
		// that Gather() turns into an HTTP 500 for the ENTIRE /metrics
		// scrape. Operator visibility of the unresolved expectation is
		// retained on the `show ... fairness` text path (no uniqueness
		// constraint there); only the Prometheus gauge is suppressed.
		if !result.Resolved {
			continue
		}
		ifindexLabel := strconv.Itoa(result.Ifindex)
		queueLabel := strconv.FormatUint(uint64(result.QueueID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessRSSExpectation,
			prometheus.GaugeValue,
			1,
			ifindexLabel,
			queueLabel,
			result.ExpectationKind,
		)
		if result.HasExpectationValue {
			ch <- prometheus.MustNewConstMetric(
				c.fairnessRSSExpectationValue,
				prometheus.GaugeValue,
				result.ExpectationValue,
				ifindexLabel,
				queueLabel,
				result.ExpectationKind,
			)
		}
		// #9369: an indeterminate expectation (truncated snapshot) emits NO
		// violation sample. A 0 would read as a clean fairness board and a 1 as
		// a false alarm; the truncated prefix supports neither. The
		// indeterminate gauge says why the violation series is missing.
		indeterminate := 0.0
		if result.Indeterminate {
			indeterminate = 1
		}
		ch <- prometheus.MustNewConstMetric(
			c.fairnessRSSIndeterminate,
			prometheus.GaugeValue,
			indeterminate,
			ifindexLabel,
			queueLabel,
			result.ExpectationKind,
		)
		if result.Indeterminate {
			continue
		}
		violation := 1.0
		if result.Pass {
			violation = 0
		}
		ch <- prometheus.MustNewConstMetric(
			c.fairnessRSSSkewViolation,
			prometheus.GaugeValue,
			violation,
			ifindexLabel,
			queueLabel,
			result.ExpectationKind,
		)
	}
}

func (c *xpfCollector) emitFairnessThroughputGauges(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	c.mu.Lock()
	if c.fairnessThroughputWindow == nil {
		c.fairnessThroughputWindow = dpuserspace.NewFairnessThroughputWindow(30 * time.Second)
	}
	summaries := c.fairnessThroughputWindow.Update(time.Now(), status)
	c.mu.Unlock()

	for _, row := range summaries {
		if row.SourceTruncated || row.FlowCount == 0 || row.WindowSeconds <= 0 {
			continue
		}
		ifindexLabel := strconv.Itoa(row.Ifindex)
		queueLabel := strconv.FormatUint(uint64(row.QueueID), 10)
		saturated := 0.0
		if row.Saturated {
			saturated = 1
		}
		ch <- prometheus.MustNewConstMetric(
			c.fairnessSaturated,
			prometheus.GaugeValue,
			saturated,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessObservedCoV,
			prometheus.GaugeValue,
			row.ObservedCoV,
			ifindexLabel,
			queueLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessStarvedFlows,
			prometheus.CounterValue,
			float64(row.StarvedFlowsTotal),
			ifindexLabel,
			queueLabel,
		)
		c.emitFairnessEqualFlowEstimateGauges(ch, row, ifindexLabel, queueLabel)
	}
}

func (c *xpfCollector) emitFairnessEqualFlowEstimateGauges(
	ch chan<- prometheus.Metric,
	row dpuserspace.FairnessThroughputSummary,
	ifindexLabel string,
	queueLabel string,
) {
	estimate := row.EqualFlowEstimate
	if estimate.ActiveWorkers == 0 {
		return
	}
	valid := 0.0
	if estimate.Valid {
		valid = 1
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowEstimateValid,
		prometheus.GaugeValue,
		valid,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowSampledActiveWorkers,
		prometheus.GaugeValue,
		float64(estimate.SampledActiveWorkers),
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowUnsampledActiveWorkers,
		prometheus.GaugeValue,
		float64(estimate.UnsampledActiveWorkers),
		ifindexLabel,
		queueLabel,
	)
	if !estimate.Valid {
		return
	}
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowTargetPerFlowBPS,
		prometheus.GaugeValue,
		estimate.TargetPerFlowBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowObservedBPS,
		prometheus.GaugeValue,
		estimate.ObservedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowCappedBPS,
		prometheus.GaugeValue,
		estimate.CappedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowSuppressedBPS,
		prometheus.GaugeValue,
		estimate.SuppressedBPS,
		ifindexLabel,
		queueLabel,
	)
	ch <- prometheus.MustNewConstMetric(
		c.fairnessEqualFlowThroughputLossRatio,
		prometheus.GaugeValue,
		estimate.ThroughputLossRatio,
		ifindexLabel,
		queueLabel,
	)
	for _, worker := range estimate.Workers {
		workerLabel := strconv.FormatUint(uint64(worker.WorkerID), 10)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerObservedBPS,
			prometheus.GaugeValue,
			worker.ObservedBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerObservedPerFlowBPS,
			prometheus.GaugeValue,
			worker.ObservedPerFlow,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerCapBPS,
			prometheus.GaugeValue,
			worker.CapBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.fairnessEqualFlowWorkerSuppressedBPS,
			prometheus.GaugeValue,
			worker.SuppressedBPS,
			ifindexLabel,
			queueLabel,
			workerLabel,
		)
	}
}
