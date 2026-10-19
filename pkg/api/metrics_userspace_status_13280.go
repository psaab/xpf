package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitUserspaceStatus13280 exports the operational and HA counters carried in
// ProcessStatus by Rust. Emit zeroes too: these additive counters are expected
// to be zero on healthy nodes, and an absent series is not evidence of zero.
func (c *xpfCollector) emitUserspaceStatus13280(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	c.emitConstMetric(ch, c.userspaceCosNoOwnerBindingDrops,
		prometheus.CounterValue, float64(status.CosNoOwnerBindingDropsTotal))
	c.emitConstMetric(ch, c.userspaceIoUringWriteRefused,
		prometheus.CounterValue, float64(status.IoUringWriteRefusedTotal))
	c.emitConstMetric(ch, c.userspaceIoUringWriteRefusedBytes,
		prometheus.CounterValue, float64(status.IoUringWriteRefusedBytesTotal))
	c.emitConstMetric(ch, c.userspaceRouteChangeUnrejudgedSessions,
		prometheus.CounterValue, float64(status.RouteChangeUnrejudgedSessionsTotal))
	c.emitConstMetric(ch, c.userspaceOwnerRGFilingsDeclined,
		prometheus.CounterValue, float64(status.OwnerRGFilingsDeclinedTotal))
	c.emitConstMetric(ch, c.userspaceSharedNatAmbiguityKeys,
		prometheus.GaugeValue, float64(status.SharedNatAmbiguityKeys))
	c.emitConstMetric(ch, c.userspaceSharedNatAmbiguitySaturated,
		prometheus.GaugeValue, float64(status.SharedNatAmbiguitySaturated))
	c.emitConstMetric(ch, c.userspaceSharedWireAmbiguityKeys,
		prometheus.GaugeValue, float64(status.SharedWireAmbiguityKeys))
	c.emitConstMetric(ch, c.userspaceSharedWireAmbiguitySaturated,
		prometheus.GaugeValue, float64(status.SharedWireAmbiguitySaturated))
	c.emitConstMetric(ch, c.userspaceSessionDeleteRefusedIdentity,
		prometheus.CounterValue, float64(status.SessionDeleteRefusedIdentity))
	c.emitConstMetric(ch, c.userspaceSessionDeleteDroppedReleased,
		prometheus.CounterValue, float64(status.SessionDeleteDroppedReleased))
	c.emitConstMetric(ch, c.userspaceTunnelPurgeReservationsReleased,
		prometheus.CounterValue, float64(status.TunnelPurgeReservationsReleased))
	c.emitConstMetric(ch, c.userspaceSyncedReverseRederived,
		prometheus.CounterValue, float64(status.SyncedReverseRederived))

	c.emitConstMetric(ch, c.userspacePeerDeleteRefusedLocalOwned,
		prometheus.CounterValue, float64(status.PeerDeleteRefusedLocalOwned))
	c.emitConstMetric(ch, c.userspaceSessionDeleteReplicaDropped,
		prometheus.CounterValue, float64(status.SessionDeleteReplicaDropped))
	c.emitConstMetric(ch, c.userspaceSessionDeleteReplicaDropRepaired,
		prometheus.CounterValue, float64(status.SessionDeleteReplicaDropRepaired))
	c.emitConstMetric(ch, c.userspaceHATransitionDropped,
		prometheus.CounterValue, float64(status.HATransitionDemoteDropped), "demote")
	c.emitConstMetric(ch, c.userspaceHATransitionDropped,
		prometheus.CounterValue, float64(status.HATransitionRefreshDropped), "refresh")
	c.emitConstMetric(ch, c.userspaceHATransitionDropped,
		prometheus.CounterValue, float64(status.HATransitionVacateDropped), "vacate")
	c.emitConstMetric(ch, c.userspaceHATransitionStaleSkipped,
		prometheus.CounterValue, float64(status.HATransitionDemoteStaleSkipped), "demote")
	c.emitConstMetric(ch, c.userspaceHATransitionStaleSkipped,
		prometheus.CounterValue, float64(status.HATransitionRefreshStaleSkipped), "refresh")
	for _, outcome := range []struct {
		name  string
		value uint64
	}{
		{"enqueued", status.WgUncoveredEnqueuedTotal},
		{"stale", status.WgUncoveredStaleTotal},
		{"malformed", status.WgUncoveredMalformedTotal},
		{"nonlocal", status.WgUncoveredNonlocalTotal},
		{"queue_full", status.WgUncoveredQueueFullTotal},
		{"queue_shed", status.WgUncoveredQueueShedTotal},
		{"queue_orphan", status.WgUncoveredQueueOrphanTotal},
	} {
		c.emitConstMetric(ch, c.userspaceWGUncoveredPacketsTotal,
			prometheus.CounterValue, float64(outcome.value), outcome.name)
	}
	c.emitConstMetric(ch, c.userspaceWGUncoveredQueuePoison,
		prometheus.CounterValue, float64(status.WgUncoveredQueuePoisonRecoveries))
	if status.S5Reinject != nil {
		c.emitConstMetric(ch, c.userspaceS5Reinject, prometheus.CounterValue,
			float64(status.S5Reinject.Reinjected))
		for _, outcome := range []struct {
			name  string
			value uint64
		}{
			{"permitted", status.S5Reinject.CompletedPermitted},
			{"fenced", status.S5Reinject.CompletedFenced},
			{"denied", status.S5Reinject.CompletedDenied},
			{"refused", status.S5Reinject.CompletedRefused},
		} {
			c.emitConstMetric(ch, c.userspaceS5ReinjectCompletions,
				prometheus.CounterValue, float64(outcome.value), outcome.name)
		}
	}
}
