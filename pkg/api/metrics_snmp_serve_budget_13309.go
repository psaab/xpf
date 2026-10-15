package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initSNMPServeBudgetDescriptors() {
	c.snmpRequestsShedTotal = prometheus.NewDesc(
		"xpf_snmp_requests_shed_total",
		"Total SNMP requests refused by the per-source or global serve budget (#13309).",
		nil, nil,
	)
	c.snmpSourceBucketEvictionsTotal = prometheus.NewDesc(
		"xpf_snmp_source_bucket_evictions_total",
		"Total SNMP source-budget buckets evicted to admit a new source at table capacity (#13309).",
		nil, nil,
	)
	c.snmpTrackedSources = prometheus.NewDesc(
		"xpf_snmp_tracked_sources",
		"Current number of source IPs tracked by the SNMP serve budget (#13309).",
		nil, nil,
	)
}

func (c *xpfCollector) describeSNMPServeBudget(ch chan<- *prometheus.Desc) {
	ch <- c.snmpRequestsShedTotal
	ch <- c.snmpSourceBucketEvictionsTotal
	ch <- c.snmpTrackedSources
}

func (c *xpfCollector) emitSNMPServeBudget(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.snmpServeBudgetStatsFn == nil {
		return
	}
	shed, evictions, tracked := c.srv.snmpServeBudgetStatsFn()
	ch <- prometheus.MustNewConstMetric(c.snmpRequestsShedTotal, prometheus.CounterValue, float64(shed))
	ch <- prometheus.MustNewConstMetric(c.snmpSourceBucketEvictionsTotal, prometheus.CounterValue, float64(evictions))
	ch <- prometheus.MustNewConstMetric(c.snmpTrackedSources, prometheus.GaugeValue, float64(tracked))
}
