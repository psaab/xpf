package api

import (
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane/mgmtview"
)

// helperLivenessProvider is the userspace Manager's #18685 liveness surface.
// Every method is lock-free with respect to the Manager's m.mu.
type helperLivenessProvider interface {
	HelperAnswerAge() time.Duration
	HelperElectionNotReady() bool
	HelperWedgeKills() uint64
}

// collectHelperLiveness emits the #18685 helper liveness families. A runtime
// without the surface (legacy, or no dataplane) emits nothing.
func (c *xpfCollector) collectHelperLiveness(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	if dp == nil {
		return
	}
	p, ok := mgmtview.Probe(dp).(helperLivenessProvider)
	if !ok {
		return
	}
	notReady := 0.0
	if p.HelperElectionNotReady() {
		notReady = 1
	}
	// A negative age means no live helper generation (none started yet, or
	// one retired by an intentional stop): NaN, not 0, which would read as
	// "just answered".
	age := math.NaN()
	if d := p.HelperAnswerAge(); d >= 0 {
		age = d.Seconds()
	}
	c.emitConstMetric(ch, c.helperAnswerAgeSeconds, prometheus.GaugeValue, age)
	c.emitConstMetric(ch, c.helperElectionNotReady, prometheus.GaugeValue, notReady)
	c.emitConstMetric(ch, c.helperWedgeKillsTotal, prometheus.CounterValue, float64(p.HelperWedgeKills()))
}
