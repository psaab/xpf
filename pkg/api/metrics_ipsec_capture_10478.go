package api

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// collectIpsecCaptureWitness emits only a product-owned actor snapshot. A nil
// callback or Available=false means the surface is absent, not an
// authoritative all-zero actor. Delivered is intentionally emitted only when
// an independent witness downstream of the Rust TUN write exists; Written is
// not a delivery witness (#10478).
func (c *xpfCollector) collectIpsecCaptureWitness(ch chan<- prometheus.Metric) {
	if c == nil || c.srv == nil || c.srv.ipsecCaptureWitnessFn == nil {
		return
	}
	w := c.srv.ipsecCaptureWitnessFn()
	if !w.Available {
		return
	}
	runID := w.RunID
	generation := strconv.FormatUint(w.Generation, 10)
	permitEpoch := strconv.FormatUint(w.PermitEpoch, 10)
	labels := []string{runID, generation, permitEpoch}
	active := 0.0
	if w.ActorActive {
		active = 1
	}
	c.emitConstMetric(ch, c.ipsecCaptureActorActive, prometheus.GaugeValue, active, labels...)
	state := w.PermitState
	if state == "" {
		state = "UNKNOWN"
	}
	for _, candidate := range []string{"OPEN", "CLOSING", "CLOSED", "UNKNOWN"} {
		value := 0.0
		if state == candidate {
			value = 1
		}
		c.emitConstMetric(ch, c.ipsecCapturePermitState, prometheus.GaugeValue, value, runID, generation, permitEpoch, candidate)
	}
	c.emitConstMetric(ch, c.ipsecCaptureConsumedTotal, prometheus.CounterValue, float64(w.Consumed), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureAdjudicatedTotal, prometheus.CounterValue, float64(w.Adjudicated), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureReinjectedTotal, prometheus.CounterValue, float64(w.Reinjected), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureWrittenTotal, prometheus.CounterValue, float64(w.Written), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureUncertainTotal, prometheus.CounterValue, float64(w.Uncertain), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureLateCompletionsTotal, prometheus.CounterValue, float64(w.LateCompletions), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureTimeoutsTotal, prometheus.CounterValue, float64(w.Timeouts), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureStaleTotal, prometheus.CounterValue, float64(w.Stale), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureCancelledTotal, prometheus.CounterValue, float64(w.Cancelled), labels...)
	c.emitConstMetric(ch, c.ipsecCaptureRefusedTotal, prometheus.CounterValue, float64(w.Refused), labels...)
	if w.D11Available {
		d11Labels := []string{w.D11RunID, strconv.FormatUint(w.D11Generation, 10), strconv.FormatUint(w.D11PermitEpoch, 10)}
		c.emitConstMetric(ch, c.ipsecCaptureD11SuppressedTotal, prometheus.CounterValue, float64(w.D11Suppressed), d11Labels...)
		c.emitConstMetric(ch, c.ipsecCaptureD11Deny52Total, prometheus.CounterValue, float64(w.D11Deny52), w.D11RunID, strconv.FormatUint(w.D11Generation, 10), strconv.FormatUint(w.D11PermitEpoch, 10), "52")
	}
	deliveredAvailable := 0.0
	if w.DeliveredAvailable {
		deliveredAvailable = 1
	}
	c.emitConstMetric(ch, c.ipsecCaptureDeliveredAvail, prometheus.GaugeValue, deliveredAvailable, labels...)
	if w.DeliveredAvailable {
		c.emitConstMetric(ch, c.ipsecCaptureDeliveredTotal, prometheus.CounterValue, float64(w.Delivered), labels...)
	}
}
