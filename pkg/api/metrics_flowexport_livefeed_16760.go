package api

import "github.com/prometheus/client_golang/prometheus"

// initFlowExportLiveFeedDescriptors declares the #16760 live-feed miss counter.
func (c *xpfCollector) initFlowExportLiveFeedDescriptors() {
	c.flowExportLiveFeedMissesTotal = prometheus.NewDesc(
		"xpf_flow_export_live_feed_misses_total",
		"Total live-counter lookups that found no session-store entry for a tracked flow (#16760). A sustained climb while flows are tracked means the live feed cannot reach the session store, so active interims export zero counters.",
		nil, nil,
	)
}

func (c *xpfCollector) emitFlowExportLiveFeedMisses(ch chan<- prometheus.Metric) {
	if c.deps.flowExportLiveFeedMissesFn == nil {
		return
	}
	c.emitConstMetric(ch, c.flowExportLiveFeedMissesTotal, prometheus.CounterValue, float64(c.deps.flowExportLiveFeedMissesFn()))
}
