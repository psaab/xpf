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
}
