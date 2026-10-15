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
	c.flowExportFlowsExportedTotal = prometheus.NewDesc(
		"xpf_flow_export_flows_exported_total",
		"Total successfully exported flow records, excluding template refreshes, labeled by protocol, instance, template and address family (#13304).",
		[]string{"protocol", "instance", "template", "family"}, nil,
	)
	c.flowExportPacketsExportedTotal = prometheus.NewDesc(
		"xpf_flow_export_data_packets_exported_total",
		"Total successfully exported data packets, excluding template refreshes, labeled by protocol, instance, template and address family (#13304).",
		[]string{"protocol", "instance", "template", "family"}, nil,
	)

	// #13306: process-wide FIB mask cache pressure and lookup failures.
	c.routeMaskCacheHits = prometheus.NewDesc(
		"xpf_flowexport_routemask_cache_hits_total",
		"Successful route-mask FIB cache lookups served from cache.", nil, nil,
	)
	c.routeMaskCacheMisses = prometheus.NewDesc(
		"xpf_flowexport_routemask_cache_misses_total",
		"Route-mask cache misses, including cold and expired keys.", nil, nil,
	)
	c.routeMaskCacheFullClears = prometheus.NewDesc(
		"xpf_flowexport_routemask_cache_clears_total",
		"Full route-mask cache clears after expiry purging failed to make room.", nil, nil,
	)
	c.routeMaskCacheInflightDrops = prometheus.NewDesc(
		"xpf_flowexport_routemask_cache_inflight_drops_total",
		"Route-mask FIB lookups not scheduled because the concurrent lookup cap was reached.", nil, nil,
	)
	c.routeMaskCacheLookupErrors = prometheus.NewDesc(
		"xpf_flowexport_routemask_cache_lookup_errors_total",
		"Route-mask FIB lookups that returned no route or an error.", nil, nil,
	)
	c.routeMaskCacheEntries = prometheus.NewDesc(
		"xpf_flowexport_routemask_cache_entries",
		"Current number of cached route-mask entries.", nil, nil,
	)
	// #13305: flow-record data-quality events, per configured exporter group.
	labels := []string{"protocol", "instance", "template", "family"}
	c.flowExportRouteMaskUnresolvedTotal = prometheus.NewDesc(
		"xpf_flow_export_route_mask_unresolved_total",
		"Total exported source/destination route-mask halves unresolved in the FIB.",
		labels, nil,
	)
	c.flowExportMissingStartTimeTotal = prometheus.NewDesc(
		"xpf_flow_export_missing_start_time_total",
		"Total exported close records without a session creation timestamp.",
		labels, nil,
	)
	c.flowExportClockSkewClampedTotal = prometheus.NewDesc(
		"xpf_flow_export_clock_skew_clamped_total",
		"Total exported close records whose future creation timestamp was clamped to the close time.",
		labels, nil,
	)
}
