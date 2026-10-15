package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initFlowExportDescriptors() {
	// #2464: per-collector flow-export write-health.
	c.flowExportCollectorWriteAttemptsTotal = prometheus.NewDesc(
		"xpf_flow_export_collector_write_attempts_total",
		"Total NetFlow v9 / IPFIX UDP write attempts per collector, labeled by protocol, instance, template, address family, collector and source.",
		[]string{"protocol", "instance", "template", "family", "collector", "source"}, nil,
	)
	c.flowExportCollectorWriteFailuresTotal = prometheus.NewDesc(
		"xpf_flow_export_collector_write_failures_total",
		"Total NetFlow v9 / IPFIX UDP write failures per collector, labeled by protocol, instance, template, address family, collector and source.",
		[]string{"protocol", "instance", "template", "family", "collector", "source"}, nil,
	)
	c.flowExportCollectorWriteSkippedTotal = prometheus.NewDesc(
		"xpf_flow_export_collector_write_skipped_total",
		"Total NetFlow v9 / IPFIX writes skipped during collector probe backoff, labeled by protocol, instance, template, address family, collector and source.",
		[]string{"protocol", "instance", "template", "family", "collector", "source"}, nil,
	)
	c.flowExportCollectorHealthy = prometheus.NewDesc(
		"xpf_flow_export_collector_healthy",
		"1 when the last write to this flow-export collector succeeded, 0 when it failed; labeled by protocol, instance, template, address family, collector and source.",
		[]string{"protocol", "instance", "template", "family", "collector", "source"}, nil,
	)
	c.flowExportCollectorLastSuccessSeconds = prometheus.NewDesc(
		"xpf_flow_export_collector_last_success_timestamp_seconds",
		"Unix timestamp of the last successful write to this flow-export collector (0 if none yet).",
		[]string{"protocol", "instance", "template", "family", "collector", "source"}, nil,
	)
	c.flowExportCollectorLastFailureSeconds = prometheus.NewDesc(
		"xpf_flow_export_collector_last_failure_timestamp_seconds",
		"Unix timestamp of the last failed write to this flow-export collector (0 if none yet).",
		[]string{"protocol", "instance", "template", "family", "collector", "source"}, nil,
	)

	// #3747: per-exporter pending-batch queue observability.
	c.flowExportBatchDepth = prometheus.NewDesc(
		"xpf_flow_export_batch_depth",
		"Current number of flow records pending in the export batch for this exporter group, labeled by protocol, instance, template and address family.",
		[]string{"protocol", "instance", "template", "family"}, nil,
	)
	c.flowExportBatchMaxDepth = prometheus.NewDesc(
		"xpf_flow_export_batch_max_depth",
		"High-water mark of pending flow records for this exporter group, labeled by protocol, instance, template and address family.",
		[]string{"protocol", "instance", "template", "family"}, nil,
	)
	c.flowExportBatchDroppedTotal = prometheus.NewDesc(
		"xpf_flow_export_batch_dropped_total",
		"Total flow records dropped because the pending export batch was at capacity, labeled by protocol, instance, template and address family.",
		[]string{"protocol", "instance", "template", "family"}, nil,
	)
}
