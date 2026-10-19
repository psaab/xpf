package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitIpsecSaCounters exposes the userspace helper's XFRM-SA snapshot-gate
// counters. Every field is emitted when a status snapshot was read, including
// zero, so an absent series still unambiguously means no status was available.
func (c *xpfCollector) emitIpsecSaCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	c.emitConstMetric(ch, c.ipsecSAMissDroppedPacketsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissDroppedPacketsTotal))
	c.emitConstMetric(ch, c.ipsecSAMissNoSATotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissNoSATotal))
	c.emitConstMetric(ch, c.ipsecSAMissTruncatedTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissTruncatedTotal))
	c.emitConstMetric(ch, c.ipsecSAMissMalformedIKETotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissMalformedIKETotal))
	c.emitConstMetric(ch, c.ipsecSAMissKeepaliveTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissKeepaliveTotal))
	c.emitConstMetric(ch, c.ipsecSASnapshotStaleDenyTotal,
		prometheus.CounterValue,
		float64(status.IpsecSASnapshotStaleDenyTotal))
	c.emitConstMetric(ch, c.ipsecSAInsertsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAInsertsTotal))
	c.emitConstMetric(ch, c.ipsecSARemovesTotal,
		prometheus.CounterValue,
		float64(status.IpsecSARemovesTotal))
	c.emitConstMetric(ch, c.ipsecSAExpiryRemovesTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAExpiryRemovesTotal))
	c.emitConstMetric(ch, c.ipsecSAEvictionsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAEvictionsTotal))
	c.emitConstMetric(ch, c.ikeExchangeEvictionsTotal,
		prometheus.CounterValue,
		float64(status.IkeExchangeEvictionsTotal))
	c.emitConstMetric(ch, c.ikeExchangeEntries,
		prometheus.GaugeValue,
		float64(status.IkeExchangeEntries))
	c.emitConstMetric(ch, c.ipsecSAMultiSourceCollisionsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMultiSourceCollisionsTotal))
	c.emitConstMetric(ch, c.ipsecSANetlinkEnobufsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSANetlinkEnobufsTotal))
	c.emitConstMetric(ch, c.ipsecSANetlinkRedumpsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSANetlinkRedumpsTotal))
	c.emitConstMetric(ch, c.ipsecSANetlinkRedumpUpsertsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSANetlinkRedumpUpsertsTotal))
}
