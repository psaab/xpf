package api

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *xpfCollector) initFairnessDescriptors() {
	c.cosActiveFlowCount = prometheus.NewDesc(
		"xpf_userspace_cos_active_flow_count",
		"Distinct active flows observed for this egress CoS queue on this worker "+
			"in the last ~650ms. This class-specific distribution is the preferred "+
			"fairness harness input for mixed workloads (#1248).",
		[]string{"ifindex", "queue_id", "worker_id"}, nil,
	)
	c.fairnessCstruct = prometheus.NewDesc(
		"xpf_fairness_cstruct",
		"Structural per-flow CoV ceiling for this egress CoS queue, derived from "+
			"xpf_userspace_cos_active_flow_count and the fairness-regimes contract (#1247).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessActiveWorkers = prometheus.NewDesc(
		"xpf_fairness_active_workers",
		"Number of workers with at least one active flow for this egress CoS queue (#1247).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessActiveFlows = prometheus.NewDesc(
		"xpf_fairness_active_flows",
		"Total active flows observed for this egress CoS queue in the current userspace snapshot (#1247).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessMaxWorkerFlowShare = prometheus.NewDesc(
		"xpf_fairness_max_worker_flow_share",
		"Largest fraction of this egress CoS queue's active flows owned by one worker (#1247).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessCoSCountsTruncated = prometheus.NewDesc(
		"xpf_fairness_cos_active_flow_counts_truncated",
		"1 when the userspace CoS active-flow snapshot was truncated before fairness RSS gauges were derived; 0 otherwise (#1247).",
		nil, nil,
	)
	c.fairnessRSSExpectation = prometheus.NewDesc(
		"xpf_fairness_rss_expectation_configured",
		"1 for each configured opt-in RSS/workload expectation evaluated against this egress CoS queue (#1247).",
		[]string{"ifindex", "queue_id", "kind"}, nil,
	)
	c.fairnessRSSExpectationValue = prometheus.NewDesc(
		"xpf_fairness_rss_expectation_value",
		"Configured numeric value for RSS/workload expectation kinds that take one, such as active-worker count or threshold (#1265).",
		[]string{"ifindex", "queue_id", "kind"}, nil,
	)
	c.fairnessRSSSkewViolation = prometheus.NewDesc(
		"xpf_fairness_rss_skew_violation",
		"1 when the configured RSS/workload expectation fails for this egress CoS queue; 0 when it passes (#1247). Absent while the expectation is indeterminate (#9369).",
		[]string{"ifindex", "queue_id", "kind"}, nil,
	)
	c.fairnessRSSIndeterminate = prometheus.NewDesc(
		"xpf_fairness_rss_expectation_indeterminate",
		"1 when the configured RSS/workload expectation cannot be judged because the CoS active-flow snapshot was truncated, so xpf_fairness_rss_skew_violation is withheld; 0 otherwise (#9369).",
		[]string{"ifindex", "queue_id", "kind"}, nil,
	)
	c.fairnessSaturated = prometheus.NewDesc(
		"xpf_fairness_saturated",
		"1 when the rolling per-flow byte window is at or above 95% of the configured egress CoS queue transmit rate (#1264).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessObservedCoV = prometheus.NewDesc(
		"xpf_fairness_observed_cov",
		"Rolling observed coefficient of variation across per-flow byte totals for this egress CoS queue (#1264).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessStarvedFlows = prometheus.NewDesc(
		"xpf_fairness_starved_flows",
		"Monotonic count of flows that enter below 1% of the rolling mean per-flow bytes for this egress CoS queue, de-duplicated while the flow remains in the rolling window (#1264).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowEstimateValid = prometheus.NewDesc(
		"xpf_fairness_equal_flow_estimate_valid",
		"1 when the measurement-only equal-flow suppression estimator has at least two currently-active-flow workers with rolling byte samples for this egress CoS queue (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowSampledActiveWorkers = prometheus.NewDesc(
		"xpf_fairness_equal_flow_sampled_active_workers",
		"Currently-active-flow workers with non-zero rolling byte samples in the measurement-only equal-flow suppression estimator (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowUnsampledActiveWorkers = prometheus.NewDesc(
		"xpf_fairness_equal_flow_unsampled_active_workers",
		"Currently-active-flow workers with no rolling byte samples in the measurement-only equal-flow suppression estimator (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowTargetPerFlowBPS = prometheus.NewDesc(
		"xpf_fairness_equal_flow_target_per_flow_bps",
		"Slowest sampled currently-active worker's observed per-flow bit rate used as the measurement-only equal-flow suppression target for this egress CoS queue; low values may reflect source artifacts such as idle or receiver-limited flows, not only dataplane unfairness (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowObservedBPS = prometheus.NewDesc(
		"xpf_fairness_equal_flow_observed_bps",
		"Observed aggregate bits per second across currently-active-flow workers in the rolling estimator window before hypothetical equal-flow suppression (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowCappedBPS = prometheus.NewDesc(
		"xpf_fairness_equal_flow_capped_bps",
		"Estimated aggregate bits per second across currently-active-flow workers after applying the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowSuppressedBPS = prometheus.NewDesc(
		"xpf_fairness_equal_flow_suppressed_bps",
		"Estimated currently-active-flow worker bits per second that would be withheld by the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowThroughputLossRatio = prometheus.NewDesc(
		"xpf_fairness_equal_flow_throughput_loss_ratio",
		"Estimated suppressed_bps / observed_bps ratio for the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
		[]string{"ifindex", "queue_id"}, nil,
	)
	c.fairnessEqualFlowWorkerObservedBPS = prometheus.NewDesc(
		"xpf_fairness_equal_flow_worker_observed_bps",
		"Observed bits per second for one currently-active-flow worker in the rolling equal-flow suppression estimator (#1304).",
		[]string{"ifindex", "queue_id", "worker_id"}, nil,
	)
	c.fairnessEqualFlowWorkerObservedPerFlowBPS = prometheus.NewDesc(
		"xpf_fairness_equal_flow_worker_observed_per_flow_bps",
		"Observed per-flow bits per second for one currently-active-flow worker in the rolling equal-flow suppression estimator (#1304).",
		[]string{"ifindex", "queue_id", "worker_id"}, nil,
	)
	c.fairnessEqualFlowWorkerCapBPS = prometheus.NewDesc(
		"xpf_fairness_equal_flow_worker_cap_bps",
		"Estimated bits-per-second cap for one currently-active-flow worker under measurement-only equal-flow suppression; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
		[]string{"ifindex", "queue_id", "worker_id"}, nil,
	)
	c.fairnessEqualFlowWorkerSuppressedBPS = prometheus.NewDesc(
		"xpf_fairness_equal_flow_worker_suppressed_bps",
		"Estimated bits per second withheld from one currently-active-flow worker by measurement-only equal-flow suppression; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
		[]string{"ifindex", "queue_id", "worker_id"}, nil,
	)
	c.fairnessThroughputWindow = dpuserspace.NewFairnessThroughputWindow(30 * time.Second)
}
