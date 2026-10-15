package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitUserspaceStatus13280 exports the operational and HA counters carried in
// ProcessStatus by Rust. Emit zeroes too: these additive counters are expected
// to be zero on healthy nodes, and an absent series is not evidence of zero.
func (c *xpfCollector) emitUserspaceStatus13280(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstMetric(c.userspaceCosNoOwnerBindingDrops,
		prometheus.CounterValue, float64(status.CosNoOwnerBindingDropsTotal))
	ch <- prometheus.MustNewConstMetric(c.userspaceIoUringWriteRefused,
		prometheus.CounterValue, float64(status.IoUringWriteRefusedTotal))
	ch <- prometheus.MustNewConstMetric(c.userspaceIoUringWriteRefusedBytes,
		prometheus.CounterValue, float64(status.IoUringWriteRefusedBytesTotal))
	ch <- prometheus.MustNewConstMetric(c.userspaceRouteChangeUnrejudgedSessions,
		prometheus.CounterValue, float64(status.RouteChangeUnrejudgedSessionsTotal))
	ch <- prometheus.MustNewConstMetric(c.userspaceOwnerRGFilingsDeclined,
		prometheus.CounterValue, float64(status.OwnerRGFilingsDeclinedTotal))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionDeleteRefusedIdentity,
		prometheus.CounterValue, float64(status.SessionDeleteRefusedIdentity))
	ch <- prometheus.MustNewConstMetric(c.userspaceSessionDeleteDroppedReleased,
		prometheus.CounterValue, float64(status.SessionDeleteDroppedReleased))
	ch <- prometheus.MustNewConstMetric(c.userspaceTunnelPurgeReservationsReleased,
		prometheus.CounterValue, float64(status.TunnelPurgeReservationsReleased))
	ch <- prometheus.MustNewConstMetric(c.userspaceSyncedReverseRederived,
		prometheus.CounterValue, float64(status.SyncedReverseRederived))

	ch <- prometheus.MustNewConstMetric(c.userspaceHATransitionDropped,
		prometheus.CounterValue, float64(status.HATransitionDemoteDropped), "demote")
	ch <- prometheus.MustNewConstMetric(c.userspaceHATransitionDropped,
		prometheus.CounterValue, float64(status.HATransitionRefreshDropped), "refresh")
	ch <- prometheus.MustNewConstMetric(c.userspaceHATransitionDropped,
		prometheus.CounterValue, float64(status.HATransitionVacateDropped), "vacate")
	ch <- prometheus.MustNewConstMetric(c.userspaceHATransitionStaleSkipped,
		prometheus.CounterValue, float64(status.HATransitionDemoteStaleSkipped), "demote")
	ch <- prometheus.MustNewConstMetric(c.userspaceHATransitionStaleSkipped,
		prometheus.CounterValue, float64(status.HATransitionRefreshStaleSkipped), "refresh")
	if status.S5Reinject != nil {
		ch <- prometheus.MustNewConstMetric(c.userspaceS5Reinject, prometheus.CounterValue,
			float64(status.S5Reinject.Reinjected))
	}
}
