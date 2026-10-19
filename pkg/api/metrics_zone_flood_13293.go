package api

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitZoneFloodCounters exports the helper's per-zone screen-drop counters and
// slot-overflow status (#13293). Both describe the live helper snapshot, so a
// missing or failed status read emits neither family. Zone IDs are resolved
// through the last successful apply and the shared collision-survivor rule;
// unknown IDs are omitted rather than assigned a misleading zone label.
func (c *xpfCollector) emitZoneFloodCounters(ch chan<- prometheus.Metric, status *dpuserspace.ProcessStatus, cfg *config.Config) {
	if status == nil {
		return
	}
	v := 0.0
	if status.FloodCounterOverflowActive {
		v = 1
	}
	c.emitConstMetric(ch, c.floodCounterOverflowActive, prometheus.GaugeValue, v)

	if c.srv == nil || c.srv.dp == nil {
		return
	}
	cr := dataplane.LastApplyResultOf(c.srv.dp)
	if cr == nil {
		return
	}
	zoneNames := config.SurvivorZoneNames(cr.ZoneIDs, cfg)
	for _, row := range status.ZoneFloodCounters {
		zone, ok := zoneNames[row.ZoneID]
		if !ok {
			continue
		}
		for _, counter := range []struct {
			kind  string
			value uint64
		}{
			{"syn_flood", row.SynFloodEvents},
			{"icmp_flood", row.ICMPFloodEvents},
			{"udp_flood", row.UDPFloodEvents},
		} {
			if counter.value == 0 {
				continue
			}
			c.emitConstMetric(ch, c.zoneFloodDropsTotal, prometheus.CounterValue,
				float64(counter.value), zone, counter.kind)
		}
	}
}
