package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initUserspaceMapsSync13300Descriptors() {
	c.userspaceRSTSuppressionDegraded = prometheus.NewDesc("xpf_userspace_rst_suppression_degraded", "Whether interface-NAT addresses lack kernel TCP RST suppression.", nil, nil)
	c.userspaceRSTSuppressionFailures = prometheus.NewDesc("xpf_userspace_rst_suppression_failures_total", "Failed attempts to install kernel TCP RST suppression for interface NAT.", nil, nil)
	c.userspaceBindingsWatchdogRepairs = prometheus.NewDesc("xpf_userspace_bindings_watchdog_repairs_total", "Stale userspace binding BPF map entries repaired by the watchdog.", nil, nil)
	c.userspaceBindingsWatchdogErrors = prometheus.NewDesc("xpf_userspace_bindings_watchdog_errors_total", "Userspace binding watchdog lookup and repair errors.", nil, nil)
	c.userspaceLocalAddrPruneSkipped = prometheus.NewDesc("xpf_userspace_local_address_prune_skipped_total", "Local-address stale-key pruning skipped after incomplete netlink enumeration.", nil, nil)
}
