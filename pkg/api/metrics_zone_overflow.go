package api

import (
	"github.com/prometheus/client_golang/prometheus"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitZoneCounterOverflow publishes xpf_zone_counters_overflow_active (#6845).
//
// It lives on the STATUS path rather than beside collectZoneCounters, and that
// placement is the design rather than convenience. collectZoneCounters runs
// ABOVE the dataplane gate on purpose: its gauge is config-derived and must keep
// reporting the full configured zone count through a degraded / config-only boot.
// This flag is the opposite — it is a property of the RUNNING helper's slot
// table. With no helper there is no slot table and no overflow to report, so
// emitting a 0 there would be a false all-clear about a machine that has not
// been asked.
//
// Hence: emitted on every scrape that read a status, absent on every scrape that
// did not. It takes the POINTER and returns early on nil, so that contract is
// stated here and directly testable, rather than inherited from a sibling
// collector's early return where a later refactor could drop it silently.
func (c *xpfCollector) emitZoneCounterOverflow(ch chan<- prometheus.Metric, statusPtr *dpuserspace.ProcessStatus) {
	if statusPtr == nil {
		return
	}
	status := *statusPtr
	v := 0.0
	if status.ZoneCounterOverflowActive {
		v = 1
	}
	c.emitConstMetric(ch, c.zoneCountersOverflowActive,
		prometheus.GaugeValue, v)
}
