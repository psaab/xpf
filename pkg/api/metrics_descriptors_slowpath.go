package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initSlowPathDescriptors() {
	labels := []string{"outlet"}
	c.userspaceSlowPathActive = prometheus.NewDesc(
		"xpf_userspace_slow_path_active",
		"Whether the userspace slow-path outlet worker is active (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathDegraded = prometheus.NewDesc(
		"xpf_userspace_slow_path_degraded",
		"Whether the userspace slow-path outlet is degraded, including an MTU programming failure (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathLiveMTU = prometheus.NewDesc(
		"xpf_userspace_slow_path_live_mtu",
		"Live MTU programmed on the userspace slow-path outlet (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathQueuedPackets = prometheus.NewDesc(
		"xpf_userspace_slow_path_queued_packets",
		"Current queued packets for the userspace slow-path outlet (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathInjectedPackets = prometheus.NewDesc(
		"xpf_userspace_slow_path_injected_packets_total",
		"Packets injected through the userspace slow-path outlet (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathInjectedBytes = prometheus.NewDesc(
		"xpf_userspace_slow_path_injected_bytes_total",
		"Bytes injected through the userspace slow-path outlet (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathDroppedPackets = prometheus.NewDesc(
		"xpf_userspace_slow_path_dropped_packets_total",
		"Packets dropped by the userspace slow-path outlet (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathDroppedBytes = prometheus.NewDesc(
		"xpf_userspace_slow_path_dropped_bytes_total",
		"Bytes dropped by the userspace slow-path outlet (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathRateLimited = prometheus.NewDesc(
		"xpf_userspace_slow_path_rate_limited_packets_total",
		"Packets rate-limited by the userspace slow-path outlet (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathQueueFull = prometheus.NewDesc(
		"xpf_userspace_slow_path_queue_full_packets_total",
		"Packets refused because the userspace slow-path outlet queue was full (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathWriteErrors = prometheus.NewDesc(
		"xpf_userspace_slow_path_write_errors_total",
		"Write errors reported by the userspace slow-path outlet (#10069).",
		labels, nil,
	)
	c.userspaceSlowPathMTUDroppedPackets = prometheus.NewDesc(
		"xpf_userspace_slow_path_mtu_dropped_packets_total",
		"Packets refused because they exceed the live userspace slow-path MTU (#10069).",
		labels, nil,
	)
}
