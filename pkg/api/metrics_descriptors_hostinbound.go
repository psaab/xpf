package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initHostInboundDescriptors() {
	c.hostInboundDeny = prometheus.NewDesc(
		"xpf_host_inbound_denies_total",
		"Total host-inbound traffic denials on the userspace-dp (AF_XDP) path.",
		nil, nil,
	)
	// #3361: host-bound traffic to a firewall interface IP / VRRP VIP is
	// shunted to the kernel by the XDP shim before userspace-dp sees it, so
	// the PRIMARY host-inbound enforcement is the kernel nftables
	// `inet xpf_hostinbound` chain. Its catch-all DROP rules now carry a
	// named per-zone/family nft counter (pkg/daemon/daemon_nft.go), scraped
	// here. This is a DISTINCT enforcement path from
	// xpf_host_inbound_denies_total (the userspace-dp #3326 path) — they are
	// not double counts. The counter resets when the daemon rebuilds the
	// table (every commit / DHCP address change); Prometheus rate() handles
	// the reset.
	c.hostInboundKernelDenies = prometheus.NewDesc(
		"xpf_host_inbound_kernel_denies_total",
		"Total host-inbound traffic denials by the kernel nftables host-inbound "+
			"chain, per zone/family (distinct from the userspace-dp "+
			"xpf_host_inbound_denies_total path).",
		[]string{"zone", "family"}, nil,
	)
	// #4146: per-scope/family drop counters for the kernel `to-zone
	// junos-host` DENY rules on the same `inet xpf_hostinbound` chain. These
	// are the fine per-source/per-application host-inbound denies enforced on
	// the DIRECT host-bound path — DISTINCT from xpf_host_inbound_kernel_denies
	// _total (coarse "no service opened this") and from the userspace-dp
	// xpf_host_inbound_denies_total path, so the three do not double-count.
	// This does NOT populate per-Junos-policy hit counters / `then count` /
	// RT_FLOW deny attribution (nft cannot attribute a drop to a policy object,
	// #4146 §6.7). The counter resets on table rebuild; rate() handles it. On a
	// read failure the series is skipped and xpf_counter_read_errors_total is
	// bumped.
	c.hostInboundJunosHostDenies = prometheus.NewDesc(
		"xpf_host_inbound_junos_host_denies_total",
		"Total direct host-bound traffic denials by the kernel nftables "+
			"`to-zone junos-host` DENY rules, per ingress-zone scope and family "+
			"(distinct from the coarse xpf_host_inbound_kernel_denies_total and "+
			"the userspace-dp xpf_host_inbound_denies_total paths).",
		[]string{"scope", "family"}, nil,
	)
	// #4759: per-type-class hit counters for the GLOBAL ICMP-error / ND accept
	// rules on the same kernel `inet xpf_hostinbound` chain. Those rules admit
	// ICMPv6 Neighbor Discovery (types 133-137), ICMPv6 error/PMTUD (types
	// 1-4), and ICMPv4 error/PMTUD (destination-unreachable, time-exceeded,
	// parameter-problem) regardless of any per-zone host-inbound service set,
	// so core L3 operation is never black-holed; before #4759 those accepts
	// were UNCOUNTED. The counts are AGGREGATE — the accept rules are GLOBAL,
	// not per-zone, so there is no per-zone `type` breakdown (a per-zone split
	// would need per-zone rule duplication, the #4759 Low-severity caveat).
	// The counter resets when the daemon rebuilds the table (every commit /
	// DHCP address change); Prometheus rate() handles the reset. On a read
	// failure the series is skipped (no misleading 0) and
	// xpf_counter_read_errors_total is bumped.
	c.hostInboundICMPNDAccept = prometheus.NewDesc(
		"xpf_host_inbound_icmp_nd_accept_total",
		"Total ICMP-error / ND control-message accepts by the kernel nftables "+
			"host-inbound chain, per type-class (icmp6_nd, icmp6_error, "+
			"icmp4_error). Aggregate across all zones (the accept rules are "+
			"global, not per-zone).",
		[]string{"type"}, nil,
	)
	// #3698: 1 while a configured host-inbound-enforcing zone is in the
	// transient fail-open admit window — it has a non-lifeline interface but
	// no resolvable address yet (DHCP WAN before first lease, backup node
	// before VIP install), so the kernel host-inbound chain emits no deny for
	// it. A control-plane signal (config-derived, independent of dataplane
	// load), emitted BEFORE the dataplane gate in Collect. The series is
	// present only for zones currently in the window (absent = enforced), so
	// `max_over_time(...)` alerts on any zone that ever fails open.
	c.hostInboundAddresslessZones = prometheus.NewDesc(
		"xpf_host_inbound_addressless_zones",
		"1 while a configured host-inbound-enforcing zone has no resolvable "+
			"address yet and is therefore omitted from host-inbound deny "+
			"scoping (transient fail-open admit window), labeled by zone.",
		[]string{"zone"}, nil,
	)
	// #3710: the per-interface/per-family refinement of the addressless-zone
	// signal above. 1 while a non-lifeline logical unit in a configured
	// host-inbound-enforcing zone has a DHCP/DHCPv6 client configured for a
	// family but has not yet resolved an address in that family — a transient
	// fail-open window that the zone-level series hides whenever an addressed
	// sibling interface (or the other family) already scopes the zone.
	// Config-derived, independent of dataplane load, emitted BEFORE the
	// dataplane gate. Present only while the window is open (absent =
	// enforced), labeled by zone, interface (logical unit), family and reason.
	c.hostInboundAddresslessIface = prometheus.NewDesc(
		"xpf_host_inbound_addressless_interfaces",
		"1 while a non-lifeline interface unit in a configured host-inbound-"+
			"enforcing zone has a DHCP/DHCPv6 client for a family but no "+
			"resolved address in that family yet (per-interface/per-family "+
			"transient fail-open admit window, #3710), labeled by zone, "+
			"interface, family and reason.",
		[]string{"zone", "interface", "family", "reason"}, nil,
	)
	// #3718 (Option B): 1 per firewall-local address that is
	// host-inbound-reachable from more than one security zone with DIFFERING
	// host-inbound service/protocol sets. The kernel host-inbound nftables
	// chain matches on destination address only (no ingress predicate) over a
	// single global input chain, so such an address's admission verdict is
	// decided order-dependently by whichever zone sorts first, and can
	// disagree with the ingress-scoped userspace-dp path (split-brain). The
	// strict commit gate hard-rejects this; a tolerant / peer-synced load
	// (#1960) can slip one through, and unlike the addressless window it is
	// NOT self-healing — so this control-plane signal (config-derived,
	// emitted BEFORE the dataplane gate) stays 1 until the ambiguity is
	// resolved. Absent = no ambiguous address.
	c.hostInboundAmbiguousAddrs = prometheus.NewDesc(
		"xpf_host_inbound_ambiguous_addresses",
		"1 per firewall-local address that is host-inbound-reachable from "+
			"multiple security zones with differing host-inbound service/"+
			"protocol sets, making the kernel destination-address-only "+
			"host-inbound verdict order-dependent (#3718), labeled by "+
			"address and family.",
		[]string{"address", "family"}, nil,
	)
	// #7991: 1 per cross-routing-instance L3 overlap on a box whose config also
	// carries a PBR `then routing-instance` term. That COMBINATION is what the
	// strict commit gate refuses (#7924); a tolerant / peer-synced load admits
	// it, and until #7991 the only surface was a log line on apply.
	//
	// It is not a hygiene advisory. On an affected box a second flow sharing a
	// 5-tuple hits the FIRST flow's conntrack entry: the established-session
	// fast path runs BEFORE the PBR table override and makes no policy call at
	// all, so tenant-b's packets leave via tenant-a's egress with tenant-a's NAT
	// having never been adjudicated by any policy. The HELP text says so,
	// because a metric whose meaning lives only in an issue is a metric nobody
	// can act on. Absent = the config is not in the tolerant-admitted state.
	c.vrfOverlapPBRAdmitted = prometheus.NewDesc(
		"xpf_vrf_overlap_pbr_admitted",
		"1 per cross-routing-instance L3 overlap admitted together with PBR "+
			"`then routing-instance` steering — a combination the strict commit "+
			"path REFUSES (#7924) and only a tolerant/peer-synced load admits. "+
			"Sessions are keyed on the bare 5-tuple with no routing-instance "+
			"discriminator and the established-session fast path runs before the "+
			"PBR table override with no policy call, so a colliding 5-tuple in "+
			"the second instance is forwarded out the FIRST instance's egress "+
			"with its NAT and without policy adjudication (#2387/#7160). "+
			"Labeled by the two routing instances and the overlapping prefix.",
		[]string{"instance_a", "instance_b", "prefix"}, nil,
	)
	// #11060: tolerant boot quarantines every cross-RI Linux-device membership
	// and leaves that device in the default routing context. This persistent
	// fail-closed disposition is not visible through a commit response, so keep
	// an explicit zero/nonzero config-derived signal for operators.
	c.riMemberDeviceConflicts = prometheus.NewDesc(
		"xpf_routing_instance_member_device_conflicts",
		"Number of Linux netdevices claimed by multiple routing instances and "+
			"quarantined on tolerant load (#11060). Conflicting memberships are "+
			"removed and the device remains unbound, so its traffic uses the "+
			"default routing table instead of either intended tenant VRF. Alert "+
			"on > 0; the apply log names each device and its competing members.",
		nil, nil,
	)
	// #4422: per-`then count` hit counters for the kernel lo0 loopback input
	// filter (`inet xpf_lo0` table). lo0 host-inbound traffic is enforced by
	// the KERNEL nftables chain (not the userspace fast path), so its
	// firewall-filter `then count <name>` counts live in nft named-counter
	// objects, DISTINCT from xpf_filter_hits_total (which merges the
	// userspace-dp fast-path per-term hits for data-interface filters,
	// including FBF steering). Before #4422 nothing scraped the lo0 counters.
	// The table is installed independent of dataplane load, so this is a
	// control-plane signal emitted BEFORE the dataplane gate. The counter
	// object is shared by name across terms/families (Junos named-counter
	// semantics), so the series is labeled by the count name only. Counters
	// reset on every table rebuild (commit / DHCP re-render); rate() handles
	// the reset. On a read failure the series is skipped (no misleading 0) and
	// xpf_counter_read_errors_total is bumped.
	c.lo0CounterHits = prometheus.NewDesc(
		"xpf_lo0_counter_hits_total",
		"Total lo0 loopback input-filter hits by firewall-filter `then count` "+
			"name, read from the kernel nftables lo0 chain (distinct from the "+
			"userspace-dp xpf_filter_hits_total fast-path counters).",
		[]string{"counter"}, nil,
	)
}
