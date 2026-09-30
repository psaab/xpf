package api

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/grpcapi"
)

// #11082: export the legacy method-only stream fallback count. Always
// emitted, including at zero: zero is the migration target (all peers
// binding arguments), and Phase 2 removes the fallback once it holds.
func (c *xpfCollector) describeFabricStreamArgsUnbound(ch chan<- *prometheus.Desc) {
	ch <- c.fabricStreamArgsUnboundTotal
}

func (c *xpfCollector) emitFabricStreamArgsUnbound(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.fabricStreamArgsUnboundTotal,
		prometheus.CounterValue, float64(grpcapi.FabricStreamArgsUnboundTotal()))
}
