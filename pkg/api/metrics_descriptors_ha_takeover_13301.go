package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initHATakeoverDescriptors13301() {
	c.userspaceHATakeoverReady = prometheus.NewDesc(
		"xpf_userspace_ha_takeover_ready",
		"Whether the local userspace dataplane is ready for HA takeover.", nil, nil)
	c.userspaceHATakeoverBlocker = prometheus.NewDesc(
		"xpf_userspace_ha_takeover_blocker",
		"Whether a bounded userspace HA takeover blocker is active.", []string{"blocker"}, nil)
	c.userspaceSessionSocketRequestsTotal = prometheus.NewDesc(
		"xpf_userspace_session_socket_requests_total",
		"Session-socket RPC attempts.", nil, nil)
	c.userspaceSessionSocketErrorsTotal = prometheus.NewDesc(
		"xpf_userspace_session_socket_errors_total",
		"Failed session-socket RPC attempts.", nil, nil)
	c.userspaceSessionSocketTimeoutsTotal = prometheus.NewDesc(
		"xpf_userspace_session_socket_timeouts_total",
		"Timed-out session-socket RPC attempts.", nil, nil)
	c.userspaceSyncedImportRefusalsTotal = prometheus.NewDesc(
		"xpf_userspace_ha_synced_import_refusals_total",
		"HA synced-session imports refused by the local userspace helper.", nil, nil)
}
