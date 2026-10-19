package api

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metricsHandler struct {
	available chan *metricsLane
	timeout   time.Duration
}

type metricsLane struct {
	handler   http.Handler
	owner     *metricsHandler
	collector *xpfCollector
	ctx       context.Context
}

func newMetricsHandler(collector *xpfCollector, timeout time.Duration) http.Handler {
	h := &metricsHandler{
		available: make(chan *metricsLane, metricsMaxInFlight),
		timeout:   timeout,
	}
	// Build a fixed pool of handlers once. Each lane is admitted for one scrape
	// at a time, and its context remains attached to that scrape's collector
	// until Collect returns. Returning lanes only after ServeHTTP would allow
	// timed-out scrapes to exceed the #4162 concurrent-pass limit.
	for range metricsMaxInFlight {
		lane := &metricsLane{owner: h, collector: collector}
		registry := prometheus.NewRegistry()
		registry.MustRegister(lane)
		lane.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{Timeout: timeout})
		h.available <- lane
	}
	return h
}

func (h *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var lane *metricsLane
	select {
	case lane = <-h.available:
	default:
		http.Error(w, "too many concurrent metric scrapes", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	lane.ctx = ctx
	// Shared census refreshes detach from this request context, but the scrape
	// itself may stop waiting when its caller disconnects or times out.
	lane.handler.ServeHTTP(w, r.WithContext(ctx))
	cancel()
	// The handler may return on promhttp's timeout while its collector is still
	// running. The lane is returned by Collect, not here, so a timed-out pass
	// continues to count against the three-pass cap for its full lifetime.
}

func (lane *metricsLane) Describe(ch chan<- *prometheus.Desc) {
	lane.collector.Describe(ch)
}

func (lane *metricsLane) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		lane.ctx = nil
		lane.owner.available <- lane
	}()
	// #15086 (A44-01): Registry.Gather runs Collect in its own goroutine,
	// so a collector panic crashes the whole daemon — net/http recovery
	// never applies. Label values are sanitized at the emit choke point
	// (metrics_emit_15086.go), which makes the known panic unreachable;
	// this recover is the fail-closed backstop for any residual panic:
	// count it, let Gather return what it has (promhttp then answers a
	// failed scrape), and still return the lane above. The deferred
	// emits inside collectContext unwind through here while Gather may
	// already have stopped receiving, so the count is certified by the
	// next scrape's xpf_metrics_collector_panics_total sample.
	defer func() {
		if recover() != nil && lane.collector != nil {
			lane.collector.collectorPanics.Add(1)
		}
	}()
	lane.collector.collectContext(lane.ctx, ch)
}
