package api

import (
	"github.com/prometheus/client_golang/prometheus"
)

// metrics_rest_conn_16081.go — #16081: export the REST connection-count
// bound's refusals and occupancy.
//
// ALWAYS EMITTED, INCLUDING AT ZERO, per the #3464 convention: a counter
// that appears only once it fires cannot be alerted on and cannot
// distinguish "never refused" from "not scraped". These are control-plane
// signals, so they are emitted through the same deferred pre-gate route as
// the admission refusals (#8312): a scrape during dataplane degradation —
// exactly when an operator would look — must still carry them.

func (c *xpfCollector) describeRESTConnBound(ch chan<- *prometheus.Desc) {
	ch <- c.restConnRefusalsTotal
	ch <- c.restConnActive
}

func (c *xpfCollector) emitRESTConnBound(ch chan<- prometheus.Metric) {
	var refusals uint64
	var active int64
	if c != nil && c.srv != nil {
		refusals = c.srv.RestConnRefusals()
		active = c.srv.RestConnActive()
	}
	c.emitConstMetric(ch, c.restConnRefusalsTotal,
		prometheus.CounterValue, float64(refusals))
	c.emitConstMetric(ch, c.restConnActive,
		prometheus.GaugeValue, float64(active))
}
