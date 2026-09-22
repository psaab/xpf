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
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureActorActive, prometheus.GaugeValue, active, labels...)
	state := w.PermitState
	if state == "" {
		state = "UNKNOWN"
	}
	for _, candidate := range []string{"OPEN", "CLOSING", "CLOSED", "UNKNOWN"} {
		value := 0.0
		if state == candidate {
			value = 1
		}
		ch <- prometheus.MustNewConstMetric(c.ipsecCapturePermitState, prometheus.GaugeValue, value, runID, generation, permitEpoch, candidate)
	}
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureConsumedTotal, prometheus.CounterValue, float64(w.Consumed), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureAdjudicatedTotal, prometheus.CounterValue, float64(w.Adjudicated), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureReinjectedTotal, prometheus.CounterValue, float64(w.Reinjected), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureWrittenTotal, prometheus.CounterValue, float64(w.Written), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureUncertainTotal, prometheus.CounterValue, float64(w.Uncertain), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureLateCompletionsTotal, prometheus.CounterValue, float64(w.LateCompletions), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureTimeoutsTotal, prometheus.CounterValue, float64(w.Timeouts), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureStaleTotal, prometheus.CounterValue, float64(w.Stale), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureCancelledTotal, prometheus.CounterValue, float64(w.Cancelled), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureRefusedTotal, prometheus.CounterValue, float64(w.Refused), labels...)
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureD11SuppressedTotal, prometheus.CounterValue, float64(w.D11Suppressed), runID, generation, permitEpoch, "would_permit")
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureD11Deny52Total, prometheus.CounterValue, float64(w.D11Deny52), runID, generation, permitEpoch, "evaluator_unavailable")
	deliveredAvailable := 0.0
	if w.DeliveredAvailable {
		deliveredAvailable = 1
	}
	ch <- prometheus.MustNewConstMetric(c.ipsecCaptureDeliveredAvail, prometheus.GaugeValue, deliveredAvailable, labels...)
	if w.DeliveredAvailable {
		ch <- prometheus.MustNewConstMetric(c.ipsecCaptureDeliveredTotal, prometheus.CounterValue, float64(w.Delivered), labels...)
	}
}
