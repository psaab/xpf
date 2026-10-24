package api

import (
	"github.com/prometheus/client_golang/prometheus"
)

// metrics_fabric_conn_16478.go — #16478: export the fabric gRPC
// connection-count bound's refusals and occupancy.
//
// ALWAYS EMITTED, INCLUDING AT ZERO, per the #3464 convention: a counter
// that appears only once it fires cannot be alerted on and cannot
// distinguish "never refused" from "not scraped". These are control-plane
// signals, so they are emitted through the same deferred pre-gate route as
// the REST conn bound (#16081): a scrape during dataplane degradation —
// exactly when an operator would look — must still carry them.

func (c *xpfCollector) emitFabricConnBound(ch chan<- prometheus.Metric) {
	var refusals uint64
	var active int64
	if c != nil && c.deps.fabricConnStats != nil {
		refusals, active = c.deps.fabricConnStats()
	}
	c.emitConstMetric(ch, c.fabricConnRefusalsTotal,
		prometheus.CounterValue, float64(refusals))
	c.emitConstMetric(ch, c.fabricConnActive,
		prometheus.GaugeValue, float64(active))
}

// #16478: descriptors for the fabric gRPC connection-count bound. Kept
// beside the emitter following the #16081 pattern.
func (c *xpfCollector) initFabricConnDescriptors() {
	c.fabricConnRefusalsTotal = prometheus.NewDesc(
		"xpf_fabric_conn_refusals_total",
		"Total fabric gRPC connections refused at the pre-auth "+
			"connection-count bound (#16478). Always emitted, "+
			"including at zero.",
		nil, nil,
	)
	c.fabricConnActive = prometheus.NewDesc(
		"xpf_fabric_conn_active",
		"Currently admitted fabric gRPC connections across all "+
			"fabric listeners of this server (#16478).",
		nil, nil,
	)
}
