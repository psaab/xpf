package api

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/denyaudit"
)

// #9042: export the authorization-denial counts.
//
// THE COUNTER IS WHY THE LOG COULD BE BOUNDED AT ALL. Five denial sites emitted
// an unconditional per-request slog.Warn -- two on the network-exposed fabric
// listener -- and there was no denial metric anywhere: `grep xpf_.*(authz|
// denied|rbac)` returned nothing and the audit journal records no
// authorization events. So demoting those lines WITHOUT a counter would have
// deleted the only signal that a denial happened, which is a worse outcome than
// the flood. Bounding the volume must not hide the volume.
//
// ALWAYS EMITTED, INCLUDING AT ZERO, per the #3464 convention and for the same
// reason #8312 gives: a counter that appears only once it fires cannot be
// alerted on and cannot distinguish "never denied" from "not scraped". Zero is
// the reading an operator most needs to be able to trust here, because it is
// the normal state and any departure from it is the event.
//
// Cumulative and process-lifetime; a restart resets it, which is the ordinary
// Prometheus counter contract and is handled by rate() at query time.
func (c *xpfCollector) describeAuthzDenials(ch chan<- *prometheus.Desc) {
	ch <- c.authzDenialsTotal
}

func (c *xpfCollector) emitAuthzDenials(ch chan<- prometheus.Metric) {
	// denyaudit.Surfaces() is THE list -- the collector reads the same
	// enumeration the recording sites do rather than restating it, which is the
	// drift #8312 called out.
	for _, s := range denyaudit.Surfaces() {
		c.emitConstMetric(ch, c.authzDenialsTotal,
			prometheus.CounterValue, float64(denyaudit.Total(s)), string(s))
	}
}
