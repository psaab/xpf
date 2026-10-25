package api

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
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

// gatherCountingGatherer wraps a lane registry so every Gather error is
// counted on the collector before promhttp sees it (#16707). With
// ContinueOnError promhttp serves the families Gather did return and
// drops only the offending series; without a count that drop would be
// silent except for promhttp's own per-registry error counter, which
// is not part of the xpf_* exposition. The count is cumulative and is
// published as xpf_metrics_gather_errors_total on the next scrape.
type gatherCountingGatherer struct {
	registry  *prometheus.Registry
	collector *xpfCollector
}

func (g gatherCountingGatherer) Gather() ([]*dto.MetricFamily, error) {
	mfs, err := g.registry.Gather()
	if err != nil && g.collector != nil {
		g.collector.gatherErrors.Add(1)
	}
	return mfs, err
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
		// #16707: ContinueOnError so a duplicate series (the many-to-one
		// sanitization collision, or the Y49-03 zone-pair vs scoped-global
		// same-name case) drops only that series instead of answering 500
		// for the whole exposition. Gather errors are counted via the
		// wrapping gatherer above and surfaced as
		// xpf_metrics_gather_errors_total on the next scrape. When Gather
		// returns zero families promhttp still answers 500, preserving
		// the fail-visible behaviour for a wholly failed scrape.
		lane.handler = promhttp.HandlerFor(
			gatherCountingGatherer{registry: registry, collector: collector},
			promhttp.HandlerOpts{Timeout: timeout, ErrorHandling: promhttp.ContinueOnError})
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
