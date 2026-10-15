package api

import (
	"math"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Prometheus emitters for the userspace dataplane's CLASS-OF-SERVICE telemetry —
// owner profile, drain phase, park reasons, waterfill, lease-claim flow, sojourn,
// flow-fair occupancy and equal-flow enforcement.
// Split out of metrics_userspace.go for the #7700 modularity floor; this is a
// move, not a behaviour change.

// #1248: emit class-specific active flow counts for each egress CoS
// `(ifindex, queue_id, worker_id)` tuple. This is intentionally a
// gauge snapshot from userspace-dp's debug cadence, not a line-rate
// packet counter.
func (c *xpfCollector) emitCoSActiveFlowCount(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for _, row := range status.CoSActiveFlowCounts {
		ch <- prometheus.MustNewConstMetric(
			c.cosActiveFlowCount,
			prometheus.GaugeValue,
			float64(row.ActiveFlowCount),
			strconv.Itoa(row.Ifindex),
			strconv.FormatUint(uint64(row.QueueID), 10),
			strconv.FormatUint(uint64(row.WorkerID), 10),
		)
	}
}

// #709: export owner-profile telemetry when the dataplane is the
// userspace-dp helper. The eBPF-only build path doesn't have this
// shape (it has no CoS scheduler), so we type-assert on the optional
// `Status() (dpuserspace.ProcessStatus, error)` interface — if the
// assertion fails we skip silently (not an error).
func (c *xpfCollector) emitCoSOwnerProfile(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosOwnerProfileMetric, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

// #1369: queue-scoped drain-phase bytes for exact-vs-best-effort
// contention diagnosis. These counters are intentionally not gated on
// OwnerWorkerID: non-exact queues are the critical source for
// `*_while_exact_backlogged`, and shared-exact queues still produce a
// truthful guarantee/surplus phase split.
func (c *xpfCollector) emitCoSDrainPhaseTelemetry(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosDrainPhaseMetric, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

// #1359: per-queue park-reason counters. The Rust helper already carries
// these on the CoS snapshot (root_token_starvation_parks /
// queue_token_starvation_parks at the shaper, drain_park_root_tokens /
// drain_park_queue_tokens in the per-batch drain loop) but they were
// never exported to Prometheus. They are the existing dataplane evidence
// that ATTRIBUTES a surplus-sharing mouse-latency tail: a best-effort/
// mouse queue parked on ROOT-token starvation while a surplus-sharing
// borrower drains points at root-surplus arbitration, NOT this queue's
// own per-queue cap or worker scheduling. Not gated on OwnerWorkerID:
// the queue row is already owner-attributed, and a parked best-effort
// queue is precisely the row an operator needs to see.
func (c *xpfCollector) emitCoSParkReasonTelemetry(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosParkReasonMetric, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

// #1628: per-class waterfill-selector trace counters. Per-queue
// admissions/visits plus per-interface epochs/breaks (counters) and the
// min-epochs-per-worker stalled-core flag (gauge). Diagnostic only —
// these never feed a scheduling decision; they exist to make the
// #1630-verified Phase-2 lock-in + queue-ownership fragmentation
// empirically visible. Zero on the Proportional (legacy RR) selector
// path. Not gated on OwnerWorkerID: a queue's row is owner-attributed
// already, and the per-interface MIN is computed coordinator-side.
func (c *xpfCollector) emitCoSWaterfillTelemetry(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		c.emitCoSWaterfillInterface(ch, iface, ifindexLabel)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosWaterfillMetric, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

// #1863 Step-0: per-(queue, worker) v8 lease claim-flow counters +
// per-queue admission-path counters. The claim-flow pair is emitted
// only for queues whose status row carries the per-worker vectors
// (v8 leases; legacy/non-v8 rows have empty slices), so cardinality is
// bounded by exact-queue count x worker count. Admission counters are
// emitted per queue row unconditionally (they already exist on the
// wire; this surfaces them to Prometheus for drop-site attribution).
func (c *xpfCollector) emitCoSLeaseClaimFlow(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosLeaseClaimMetric, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

// #1829 Phase 1: dequeue-time sojourn gauges, emitted unconditionally
// for every queue row (cardinality = interfaces x queues): a windowed
// min of 0 is a real "no standing queue in the last ~2 windows"
// signal — gating on non-zero would make the gate evidence's
// strongest negative result (queues never stand) invisible. All three
// are MAX-merged across worker instances and workers upstream (worst
// instance); see the AGGREGATION contract on the Rust CoSQueueStatus.
func (c *xpfCollector) emitCoSSojourn(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosSojournMetric, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

// #1830 (g): bucket-vs-flow occupancy gauges for collision-vs-demand
// unfairness diagnosis. Emitted unconditionally for every queue row
// (cardinality = interfaces x queues): a 0 is a real "idle / no
// flow-fair backlog" signal, and gating on FlowFair would hide the
// buckets==0 vs flows>0 idle shape the ratio caveat documents.
// FlowFairFlowsActive equals the sum over workers of the existing
// per-worker xpf_userspace_cos_active_flow_count (#1248), pre-aggregated
// to exactly match the buckets gauge's (ifindex, queue_id) grain.
func (c *xpfCollector) emitCoSFlowFairOccupancy(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosFlowOccupancyMetric, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

func (c *xpfCollector) emitCoSEqualFlowEnforcement(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosEqualFlowMetric, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

type cosQueueMetricSet uint16

const (
	cosOwnerProfileMetric cosQueueMetricSet = 1 << iota
	cosDrainPhaseMetric
	cosParkReasonMetric
	cosWaterfillMetric
	cosLeaseClaimMetric
	cosSojournMetric
	cosFlowOccupancyMetric
	cosEqualFlowMetric
	cosAllQueueMetrics = cosOwnerProfileMetric | cosDrainPhaseMetric | cosParkReasonMetric |
		cosWaterfillMetric | cosLeaseClaimMetric | cosSojournMetric |
		cosFlowOccupancyMetric | cosEqualFlowMetric
)

// emitCoSTelemetry traverses the status snapshot once. The single pointer-
// indexed pass avoids copying the large interface/queue rows and reuses the
// decimal labels across every CoS metric emitted for a queue.
func (c *xpfCollector) emitCoSTelemetry(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus) {
	for i := range status.CoSInterfaces {
		iface := &status.CoSInterfaces[i]
		ifindexLabel := strconv.Itoa(iface.Ifindex)
		c.emitCoSWaterfillInterface(ch, iface, ifindexLabel)
		for j := range iface.Queues {
			queue := &iface.Queues[j]
			c.emitCoSQueueTelemetry(ch, cosAllQueueMetrics, queue, ifindexLabel, strconv.Itoa(queue.QueueID))
		}
	}
}

func (c *xpfCollector) emitCoSWaterfillInterface(
	ch chan<- prometheus.Metric,
	iface *dpuserspace.CoSInterfaceStatus,
	ifindexLabel string,
) {
	ch <- prometheus.MustNewConstMetric(c.cosWaterfillEpochs,
		prometheus.CounterValue, float64(iface.WaterfillEpochs), ifindexLabel)
	ch <- prometheus.MustNewConstMetric(c.cosWaterfillPhase1BudgetBreaks,
		prometheus.CounterValue, float64(iface.WaterfillPhase1BudgetBreaks), ifindexLabel)
	// The max sentinel means there is no active-backlog candidate, so it
	// is omitted; zero is a real, alertable hard-lock-in value.
	if iface.WaterfillMinEpochsPerWorker != math.MaxUint64 {
		ch <- prometheus.MustNewConstMetric(c.cosWaterfillMinEpochsPerWorker,
			prometheus.GaugeValue, float64(iface.WaterfillMinEpochsPerWorker), ifindexLabel)
	}
}

func (c *xpfCollector) emitCoSQueueTelemetry(
	ch chan<- prometheus.Metric,
	metrics cosQueueMetricSet,
	queue *dpuserspace.CoSQueueStatus,
	ifindexLabel, queueLabel string,
) {
	if metrics&cosOwnerProfileMetric != 0 && queue.OwnerWorkerID != nil {
		emitHistogram(ch, c.cosDrainLatencyBucket, queue.DrainLatencyHist, ifindexLabel, queueLabel)
		emitHistogram(ch, c.cosRedirectAcquireBucket, queue.RedirectAcquireHist, ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosDrainInvocationsTotal,
			prometheus.CounterValue, float64(queue.DrainInvocations), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosOwnerPPS,
			prometheus.GaugeValue, float64(queue.OwnerPPS), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosPeerPPS,
			prometheus.GaugeValue, float64(queue.PeerPPS), ifindexLabel, queueLabel)
	}
	if metrics&cosDrainPhaseMetric != 0 {
		ch <- prometheus.MustNewConstMetric(c.cosDrainGuaranteeSentBytes,
			prometheus.CounterValue, float64(queue.DrainGuaranteeSentBytes), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosDrainSurplusSentBytes,
			prometheus.CounterValue, float64(queue.DrainSurplusSentBytes), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosDrainNonExactSentBytesWhileExactBacklogged,
			prometheus.CounterValue, float64(queue.DrainNonExactSentBytesWhileExactBacklogged), ifindexLabel, queueLabel)
	}
	if metrics&cosParkReasonMetric != 0 {
		ch <- prometheus.MustNewConstMetric(c.cosRootTokenStarvationParks,
			prometheus.CounterValue, float64(queue.RootTokenStarvationParks), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosQueueTokenStarvationParks,
			prometheus.CounterValue, float64(queue.QueueTokenStarvationParks), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosDrainParkRootTokens,
			prometheus.CounterValue, float64(queue.DrainParkRootTokens), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosDrainParkQueueTokens,
			prometheus.CounterValue, float64(queue.DrainParkQueueTokens), ifindexLabel, queueLabel)
	}
	if metrics&cosWaterfillMetric != 0 {
		ch <- prometheus.MustNewConstMetric(c.cosWaterfillPhase1Admissions,
			prometheus.CounterValue, float64(queue.WaterfillPhase1Admissions), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosWaterfillPhase2Admissions,
			prometheus.CounterValue, float64(queue.WaterfillPhase2Admissions), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosWaterfillEligibleVisits,
			prometheus.CounterValue, float64(queue.WaterfillEligibleVisits), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosWaterfillPhase1SelectedNoProgress,
			prometheus.CounterValue, float64(queue.WaterfillPhase1SelectedNoProgress), ifindexLabel, queueLabel)
	}
	if metrics&cosLeaseClaimMetric != 0 {
		for workerID, requested := range queue.LeaseV8WorkerRequestedBytes {
			ch <- prometheus.MustNewConstMetric(c.cosLeaseV8RequestedBytes,
				prometheus.CounterValue, float64(requested), ifindexLabel, queueLabel, strconv.Itoa(workerID))
		}
		for workerID, granted := range queue.LeaseV8WorkerGrantedBytes {
			ch <- prometheus.MustNewConstMetric(c.cosLeaseV8GrantedBytes,
				prometheus.CounterValue, float64(granted), ifindexLabel, queueLabel, strconv.Itoa(workerID))
		}
		ch <- prometheus.MustNewConstMetric(c.cosAdmissionFlowShareDrops,
			prometheus.CounterValue, float64(queue.AdmissionFlowShareDrops), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosAdmissionBufferDrops,
			prometheus.CounterValue, float64(queue.AdmissionBufferDrops), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosAdmissionEcnMarked,
			prometheus.CounterValue, float64(queue.AdmissionEcnMarked), ifindexLabel, queueLabel)
	}
	if metrics&cosSojournMetric != 0 {
		ch <- prometheus.MustNewConstMetric(c.cosSojournEwmaNS,
			prometheus.GaugeValue, float64(queue.SojournEwmaNS), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosSojournPeakNS,
			prometheus.GaugeValue, float64(queue.SojournPeakNS), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosSojournWindowedMinNS,
			prometheus.GaugeValue, float64(queue.SojournWindowedMinNS), ifindexLabel, queueLabel)
	}
	if metrics&cosFlowOccupancyMetric != 0 {
		ch <- prometheus.MustNewConstMetric(c.cosFlowFairBucketsOccupied,
			prometheus.GaugeValue, float64(queue.FlowFairBucketsOccupied), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosFlowFairFlowsActive,
			prometheus.GaugeValue, float64(queue.FlowFairFlowsActive), ifindexLabel, queueLabel)
	}
	if metrics&cosEqualFlowMetric != 0 && queue.EqualFlowEnforcement {
		enforced := 0.0
		if queue.EqualFlowEnforced {
			enforced = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.cosEqualFlowEnforcementEnabled,
			prometheus.GaugeValue, 1, ifindexLabel, queueLabel)
		if queue.EqualFlowTargetPolicy != "" {
			ch <- prometheus.MustNewConstMetric(c.cosEqualFlowTargetPolicy,
				prometheus.GaugeValue, 1, ifindexLabel, queueLabel, queue.EqualFlowTargetPolicy)
		}
		ch <- prometheus.MustNewConstMetric(c.cosEqualFlowEnforced,
			prometheus.GaugeValue, enforced, ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosEqualFlowTargetPerFlowBPS,
			prometheus.GaugeValue, float64(queue.EqualFlowTargetPerFlowBPS), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosEqualFlowMaxWorkerCapBytes,
			prometheus.GaugeValue, float64(queue.EqualFlowMaxWorkerCapBytes), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosEqualFlowCapHitEvents,
			prometheus.CounterValue, float64(queue.EqualFlowCapHitEvents), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosEqualFlowSuppressedGrantBytes,
			prometheus.CounterValue, float64(queue.EqualFlowSuppressedGrantBytes), ifindexLabel, queueLabel)
		ch <- prometheus.MustNewConstMetric(c.cosEqualFlowStaleOrTagMismatchEvents,
			prometheus.CounterValue, float64(queue.EqualFlowStaleOrTagMismatchEvents), ifindexLabel, queueLabel)
		reason := queue.EqualFlowFailOpenReason
		if reason == "" {
			reason = "none"
		}
		ch <- prometheus.MustNewConstMetric(c.cosEqualFlowFailOpen,
			prometheus.GaugeValue, 1, ifindexLabel, queueLabel, reason)
	}
}
