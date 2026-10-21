package api

import (
	"github.com/prometheus/client_golang/prometheus"
)

// #16081: descriptors for the REST connection-count bound. Kept beside the
// emitter (metrics_rest_conn_16081.go) following the #8312 pattern.
func (c *xpfCollector) initRESTConnDescriptors() {
	c.restConnRefusalsTotal = prometheus.NewDesc(
		"xpf_rest_conn_refusals_total",
		"Total REST (management HTTP/HTTPS) connections refused at the "+
			"server-wide connection-count bound (#16081). Always emitted, "+
			"including at zero.",
		nil, nil,
	)
	c.restConnActive = prometheus.NewDesc(
		"xpf_rest_conn_active",
		"Currently admitted REST (management HTTP/HTTPS) connections "+
			"across all listeners of this server (#16081).",
		nil, nil,
	)
}
