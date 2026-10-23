package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initDHCPDescriptors() {
	c.dhcpLeasesActive = prometheus.NewDesc(
		"xpf_dhcp_leases_active",
		"Number of active DHCP leases.",
		[]string{"family"}, nil,
	)

	// #1387 inc-2: DHCP dynamic-DNS counters. Label cardinality is
	// CLOSED (plan §4.4 m4): result in {ok,fail}; reason in
	// {no-name,no-backend,conflict,ptr-notauth,ptr-deferred,coowned} —
	// never a raw rcode. "coowned" (#5709) counts wire deletes suppressed
	// because the RR is still co-owned by another DDNS scope.
	c.dhcpDDNSUpsertsTotal = prometheus.NewDesc(
		"xpf_dhcp_ddns_upserts_total",
		"Total DHCP dynamic-DNS forward/reverse record upserts by result.",
		[]string{"result"}, nil,
	)
	c.dhcpDDNSDeletesTotal = prometheus.NewDesc(
		"xpf_dhcp_ddns_deletes_total",
		"Total DHCP dynamic-DNS record deletes by result.",
		[]string{"result"}, nil,
	)
	c.dhcpDDNSReconcileRunsTotal = prometheus.NewDesc(
		"xpf_dhcp_ddns_reconcile_runs_total",
		"Total DHCP dynamic-DNS reconcile passes by result.",
		[]string{"result"}, nil,
	)
	c.dhcpDDNSSkippedTotal = prometheus.NewDesc(
		"xpf_dhcp_ddns_skipped_total",
		"Total DHCP dynamic-DNS records skipped by reason.",
		[]string{"reason"}, nil,
	)
	c.dhcpDDNSOwnedRecords = prometheus.NewDesc(
		"xpf_dhcp_ddns_owned_records",
		"Current number of DHCP dynamic-DNS records this node owns in DNS.",
		nil, nil,
	)
	c.dhcpDDNSPTRPending = prometheus.NewDesc(
		"xpf_dhcp_ddns_ptr_pending",
		"Current number of owned DHCP dynamic-DNS records whose forward "+
			"A/AAAA is published but whose reverse PTR is still owed "+
			"(distinct from the cumulative ptr-deferred counter; #2708).",
		nil, nil,
	)
	c.dhcpDDNSDegraded = prometheus.NewDesc(
		"xpf_dhcp_ddns_degraded",
		"1 when the DHCP dynamic-DNS ownership state failed to load "+
			"(corrupt / unsupported-version / unreadable) and the manager is "+
			"FAILING CLOSED: publishing and withdrawals are suspended until the "+
			"operator resolves the quarantined state file (#2650).",
		nil, nil,
	)
	c.dhcpDDNSUnsignedActive = prometheus.NewDesc(
		"xpf_dhcp_ddns_unsigned_nonloopback_active",
		"1 while any enabled RFC2136 DHCP DDNS family targets a non-loopback "+
			"update-server with no TSIG key, so its rcode is forgeable (#15992), else 0.",
		nil, nil,
	)
	c.dhcpDDNSLastReconcileTs = prometheus.NewDesc(
		"xpf_dhcp_ddns_last_reconcile_timestamp_seconds",
		"Unix timestamp of the last DHCP dynamic-DNS reconcile pass.",
		nil, nil,
	)
	c.dhcpDDNSLastReconcileN = prometheus.NewDesc(
		"xpf_dhcp_ddns_last_reconcile_leases",
		"Active leases seen on the last DHCP dynamic-DNS reconcile pass.",
		nil, nil,
	)

	c.surfaceADDNSUpsertsTotal = prometheus.NewDesc(
		"xpf_ddns_surface_a_upserts_total",
		"Total Surface A (router/interface-address) DDNS publishes by result.",
		[]string{"result"}, nil,
	)
	c.surfaceADDNSDeletesTotal = prometheus.NewDesc(
		"xpf_ddns_surface_a_deletes_total",
		"Total Surface A DDNS record withdrawals by result.",
		[]string{"result"}, nil,
	)
	c.surfaceADDNSSkippedTotal = prometheus.NewDesc(
		"xpf_ddns_surface_a_skipped_total",
		"Total Surface A DDNS reconcile skips by reason.",
		[]string{"reason"}, nil,
	)
	c.surfaceADDNSScopes = prometheus.NewDesc(
		"xpf_ddns_surface_a_scopes",
		"Current number of Surface A DDNS records this node owns in DNS.",
		nil, nil,
	)
	c.surfaceADDNSOrphaned = prometheus.NewDesc(
		"xpf_ddns_surface_a_orphaned",
		"Current number of Surface A DDNS records stale at a PREVIOUS provider "+
			"endpoint that a provider identity change (rename to a different "+
			"endpoint / in-place server-zone edit / removed binding after an edit) "+
			"left un-withdrawable through the current catalog (#3735). Non-zero "+
			"means an old record needs MANUAL operator cleanup — auto-withdrawal is "+
			"deferred (old creds are redacted and the old endpoint is usually gone).",
		nil, nil,
	)
	c.surfaceADDNSDegraded = prometheus.NewDesc(
		"xpf_ddns_surface_a_degraded",
		"1 when the Surface A DDNS ownership state is unloadable and the "+
			"manager is fail-closed (publishing/withdrawals suspended), else 0.",
		nil, nil,
	)
	c.surfaceADDNSUnsignedActive = prometheus.NewDesc(
		"xpf_ddns_surface_a_unsigned_nonloopback_active",
		"1 while any RFC2136 Surface A provider targets a non-loopback "+
			"update-server with no TSIG key, so its rcode is forgeable (#15992), else 0.",
		nil, nil,
	)
}
