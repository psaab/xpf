package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// emitIpsecSaCounters exposes the userspace helper's XFRM-SA snapshot-gate
// counters. Every field is emitted when a status snapshot was read, including
// zero, so an absent series still unambiguously means no status was available.
func (c *xpfCollector) emitIpsecSaCounters(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAMissDroppedPacketsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissDroppedPacketsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAMissNoSATotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissNoSATotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAMissTruncatedTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissTruncatedTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAMissMalformedIKETotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissMalformedIKETotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAMissKeepaliveTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMissKeepaliveTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSASnapshotStaleDenyTotal,
		prometheus.CounterValue,
		float64(status.IpsecSASnapshotStaleDenyTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAInsertsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAInsertsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSARemovesTotal,
		prometheus.CounterValue,
		float64(status.IpsecSARemovesTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAExpiryRemovesTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAExpiryRemovesTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAEvictionsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAEvictionsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSAMultiSourceCollisionsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSAMultiSourceCollisionsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSANetlinkEnobufsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSANetlinkEnobufsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSANetlinkRedumpsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSANetlinkRedumpsTotal),
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipsecSANetlinkRedumpUpsertsTotal,
		prometheus.CounterValue,
		float64(status.IpsecSANetlinkRedumpUpsertsTotal),
	)
}
