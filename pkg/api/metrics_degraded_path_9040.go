package api

import (
	"github.com/prometheus/client_golang/prometheus"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9040: export the dataplane's degraded-path drop counters.
//
// THE COUNTERS ALREADY EXISTED AND WERE UNALERTABLE. `DegradedPathCounters` is
// a reason-keyed map on the helper status; it reaches the status JSON and the
// `show` text render (format/status_sections.go) and stopped there. There was
// no Prometheus series for it anywhere -- so a box dropping transit was visible
// only to an operator who ALREADY suspected it and knew which `show` to run.
// That is the difference between an observable failure and a discoverable one.
//
// The reason that prompted this is `binding_missing`. An interface with more
// than 16 RX queues has its bound set silently capped at
// BINDING_QUEUES_PER_IFACE by the helper planner. Since #9040 the daemon
// reshapes RSS to fit that bound on any allowlisted interface whose
// indirection table it can read (a per-interface `ethtool -x` capability
// probe in pkg/daemon/rss_indirection.go, not a driver-name gate), so only
// an interface whose table cannot be read -- or whose reshape does not
// apply -- keeps hashing across all Q queues while only 16 are bound, and
// transit landing on the rest takes drop_degraded_transit. The loss is
// roughly (Q-16)/Q on such an interface, steady, while the box reads up.
// (#15253: this comment and the helper's over-stride warning previously
// claimed the reshape was mlx5_core-only; that was stale in both
// directions -- a probed i40e/ice box that was reshaped was described as
// dropping, and an mlx5 box whose reshape was skipped was implied safe.)
//
// EMITTED ONLY WHEN A STATUS WAS READ, and this is the deliberate half. The
// map is reason-keyed and sparse: a reason that has never fired has no entry,
// so there is no fixed label set to emit zeroes over -- unlike the
// authz-denial and probe-skip counters, whose label sets are enumerable and
// which therefore always emit. Emitting a synthetic zero for a reason we have
// not seen would invent a series whose absence is meaningful, and the absence
// of the whole family already carries the information "no status was read this
// scrape". Same contract as emitZoneCounterOverflow, and stated here rather
// than inherited so a later refactor cannot drop it silently.
//
// Cumulative and process-lifetime; a helper restart resets it, the ordinary
// Prometheus counter contract, handled by rate() at query time.
func (c *xpfCollector) emitDegradedPathCounters(ch chan<- prometheus.Metric, statusPtr *dpuserspace.ProcessStatus) {
	if statusPtr == nil {
		return
	}
	for reason, n := range statusPtr.DegradedPathCounters {
		c.emitConstMetric(ch, c.degradedPathTotal,
			prometheus.CounterValue, float64(n), reason)
	}
}
