package api

import (
	"github.com/prometheus/client_golang/prometheus"
)

// initFlowExportBuildDescriptors declares the #9166 build-health family.
func (c *xpfCollector) initFlowExportBuildDescriptors() {
	c.flowExportConfiguredGroups = prometheus.NewDesc(
		"xpf_flowexport_configured_groups",
		// This gauge exists to be the DENOMINATOR. Without it, a failed build
		// and an unconfigured box produce the same observation — the
		// xpf_flow_export_collector_* family is omitted in both cases — so
		// "flow export is dead" and "flow export was never turned on" are the
		// same reading, and only one of them is worth waking someone for.
		"Configured flow-export template groups, by family. Zero means flow "+
			"export is not configured for that family.",
		[]string{"family"}, nil,
	)
	c.flowExportBuildFailed = prometheus.NewDesc(
		"xpf_flowexport_build_failed",
		// A previously-running exporter set keeps exporting across a failed
		// rebuild (#3742 build-before-swap), so this is "the CONFIGURED set
		// could not be constructed", not "export is down". Read it together
		// with xpf_flowexport_configured_groups.
		"1 when the last flow-export reconcile could not build this family's "+
			"exporters, 0 otherwise.",
		[]string{"family"}, nil,
	)
	c.flowExportExcludedFlowServers = prometheus.NewDesc(
		"xpf_flowexport_excluded_flow_servers",
		"Configured flow-server stanzas excluded because they cannot receive records, by family.",
		[]string{"family"}, nil,
	)
}

// collectFlowExportBuildState emits the #9166 build-health family.
//
// Both gauges are emitted for BOTH families on every scrape, including at zero.
// That is the whole point: the three states must be three distinguishable
// observations.
//
//	configured=0, failed=0  ->  not configured
//	configured>0, failed=0  ->  configured and healthy
//	configured>0, failed=1  ->  configured and the build FAILED
//
// Emitting only the failure would collapse the first two into "the series is
// absent", which is also what a scrape that never reached this code looks like
// — the exact ambiguity #9166 is about.
//
// Control-plane: the flow exporters are built whether or not the dataplane
// loaded, so the caller emits this BEFORE the dataplane gate.
func (c *xpfCollector) collectFlowExportBuildState(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.flowExportBuildStateFn == nil {
		return
	}
	for _, st := range c.srv.flowExportBuildStateFn() {
		c.emitConstMetric(ch, c.flowExportConfiguredGroups,
			prometheus.GaugeValue, float64(st.ConfiguredGroups), st.Family)
		failed := 0.0
		if st.BuildFailed {
			failed = 1
		}
		c.emitConstMetric(ch, c.flowExportBuildFailed,
			prometheus.GaugeValue, failed, st.Family)
		c.emitConstMetric(ch, c.flowExportExcludedFlowServers,
			prometheus.GaugeValue, float64(st.ExcludedFlowServers), st.Family)
	}
}
