package api

import "github.com/prometheus/client_golang/prometheus"

// initIpsecSaDescriptors defines the operator-visible XFRM-SA snapshot-gate
// counters reported by the userspace helper. They are additive so mixed
// helper versions decode and emit zero for fields they do not provide.
func (c *xpfCollector) initIpsecSaDescriptors() {
	c.ipsecSAMissDroppedPacketsTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_miss_dropped_packets_total",
		"IPsec packets dropped because the Stage-11 SA gate could not prove an eligible inbound SA.",
		nil, nil,
	)
	c.ipsecSAMissNoSATotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_miss_no_sa_total",
		"IPsec packets dropped because no matching inbound SA was present in the snapshot.",
		nil, nil,
	)
	c.ipsecSAMissTruncatedTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_miss_truncated_total",
		"IPsec packets dropped because the ESP-in-UDP frame was truncated or malformed.",
		nil, nil,
	)
	c.ipsecSAMissMalformedIKETotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_miss_malformed_ike_total",
		"IPsec packets dropped because the IKE payload was malformed on an exempt UDP path.",
		nil, nil,
	)
	c.ipsecSAMissKeepaliveTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_miss_keepalive_total",
		"Inbound NAT-T keepalives dropped by the Stage-11 IPsec gate.",
		nil, nil,
	)
	c.ipsecSASnapshotStaleDenyTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_snapshot_stale_deny_total",
		"IPsec packets denied while the XFRM-SA snapshot was stale.",
		nil, nil,
	)
	c.ipsecSAInsertsTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_inserts_total",
		"Inbound XFRM-SA records inserted or refreshed in the snapshot.",
		nil, nil,
	)
	c.ipsecSARemovesTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_removes_total",
		"Inbound XFRM-SA records removed from the snapshot.",
		nil, nil,
	)
	c.ipsecSAExpiryRemovesTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_expiry_removes_total",
		"Inbound XFRM-SA records removed after an XFRM expiry event.",
		nil, nil,
	)
	c.ipsecSAEvictionsTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_evictions_total",
		"Inbound XFRM-SA records evicted by the snapshot capacity cap.",
		nil, nil,
	)
	c.ipsecSAMultiSourceCollisionsTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_multi_source_collisions_total",
        "Multi-source collision observations for one destination and SPI from full dumps and incremental upserts.",
		nil, nil,
	)
	c.ipsecSANetlinkEnobufsTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_netlink_enobufs_total",
		"ENOBUFS receives on the XFRM-SA monitor netlink socket.",
		nil, nil,
	)
	c.ipsecSANetlinkRedumpsTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_netlink_redumps_total",
        "Full XFRM-SA dumps issued for initial readiness, periodic drift sync, and monitor recovery.",
		nil, nil,
	)
	c.ipsecSANetlinkRedumpUpsertsTotal = prometheus.NewDesc(
		"xpf_userspace_ipsec_sa_netlink_redump_upserts_total",
        "Eligible XFRM-SA records returned by successful full dumps; counts every eligible record in each dump, not only new records.",
		nil, nil,
	)
}
