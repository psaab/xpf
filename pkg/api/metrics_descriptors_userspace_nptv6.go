package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initUserspaceNptv6Descriptors() {
	c.userspaceNptv6TranslationsTotal = prometheus.NewDesc(
		"xpf_userspace_nptv6_translations_total",
		"Total NPTv6 packets translated by direction (inbound or outbound).",
		[]string{"direction"}, nil,
	)
	c.userspaceNptv6UntranslatableDrops = prometheus.NewDesc(
		"xpf_userspace_nptv6_untranslatable_drops_total",
		"NPTv6 packets dropped because an RFC 6296 mapping could not be made.",
		nil, nil,
	)
}
