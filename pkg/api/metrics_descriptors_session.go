package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initSessionDescriptors() {
	c.sessionsActive = prometheus.NewDesc(
		"xpf_sessions_active",
		"Current number of active session entries.",
		nil, nil,
	)
	c.sessionsEstablished = prometheus.NewDesc(
		"xpf_sessions_established",
		"Current number of established sessions.",
		nil, nil,
	)
	c.sessionsIPv4 = prometheus.NewDesc(
		"xpf_sessions_ipv4",
		"Current number of IPv4 sessions.",
		nil, nil,
	)
	c.sessionsIPv6 = prometheus.NewDesc(
		"xpf_sessions_ipv6",
		"Current number of IPv6 sessions.",
		nil, nil,
	)
	c.sessionsSNAT = prometheus.NewDesc(
		"xpf_sessions_snat",
		"Current number of SNAT sessions.",
		nil, nil,
	)
	c.sessionsDNAT = prometheus.NewDesc(
		"xpf_sessions_dnat",
		"Current number of DNAT sessions.",
		nil, nil,
	)
	c.sessionScrapeOK = prometheus.NewDesc(
		"xpf_sessions_breakdown_scrape_ok",
		"1 if the last session-breakdown scrape (ipv4/ipv6/snat/dnat gauges) "+
			"enumerated the full session table; 0 if a backend iterator "+
			"error truncated the scan (the breakdown gauges are then omitted).",
		nil, nil,
	)
	c.gcSweepDuration = prometheus.NewDesc(
		"xpf_gc_sweep_duration_seconds",
		"Duration of the last GC sweep in seconds.",
		nil, nil,
	)
	c.gcSweepTimestamp = prometheus.NewDesc(
		"xpf_conntrack_gc_last_sweep_timestamp_seconds",
		"Unix timestamp of the last completed conntrack GC sweep.",
		nil, nil,
	)
	c.gcSweepsTotal = prometheus.NewDesc(
		"xpf_conntrack_gc_sweeps_total",
		"Total number of completed conntrack GC sweeps.",
		nil, nil,
	)
	c.gcExpiredDeletedTotal = prometheus.NewDesc(
		"xpf_conntrack_gc_expired_deleted_total",
		"Total expired conntrack sessions deleted by GC.",
		nil, nil,
	)
	c.gcDeadlinesSaturatedTotal = prometheus.NewDesc(
		"xpf_conntrack_gc_deadlines_saturated_total",
		"Total conntrack GC deadlines saturated at uint64 maximum.",
		nil, nil,
	)
	c.gcPersistentNATExpiredTotal = prometheus.NewDesc(
		"xpf_conntrack_gc_persistent_nat_expired_total",
		"Total persistent NAT bindings expired by GC.",
		nil, nil,
	)
	c.gcErrorsTotal = prometheus.NewDesc(
		"xpf_conntrack_gc_errors_total",
		"Total conntrack GC operation errors by operation.",
		[]string{"op"}, nil,
	)
	c.gcAggressiveAging = prometheus.NewDesc(
		"xpf_conntrack_gc_aggressive_aging_active",
		"1 when conntrack GC aggressive aging is active, otherwise 0.",
		nil, nil,
	)
}
