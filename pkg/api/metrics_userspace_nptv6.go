package api

import (
	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *xpfCollector) emitUserspaceNptv6(ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus) {
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNptv6TranslationsTotal,
		prometheus.CounterValue,
		float64(status.Nptv6InboundTranslations),
		"inbound",
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNptv6TranslationsTotal,
		prometheus.CounterValue,
		float64(status.Nptv6OutboundTranslations),
		"outbound",
	)
	ch <- prometheus.MustNewConstMetric(
		c.userspaceNptv6UntranslatableDrops,
		prometheus.CounterValue,
		float64(status.Nptv6UntranslatableDrops),
	)
}
