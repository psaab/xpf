package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initForwardingDescriptors() {
	// #4422: policy-based-routing (filter-based-forwarding) build health.
	// xpf_pbr_rules_installed is the number of kernel `ip rule` FBF entries
	// the active config's routing-instance filter terms yield (the
	// desired-install set). Config-derived (routing.PBRBuildStats, a pure
	// function of config), emitted BEFORE the dataplane gate.
	// #7422 row 12: the name says "installed" and the value is DESIRED. It is
	// a published metric, so it keeps its CURRENT config-derived meaning and
	// becomes an alias of xpf_pbr_rules_desired below — never of _applied.
	// Redefining a published metric's meaning under existing alert expressions
	// is the same hazard as redefining a wire field across a version skew: the
	// consumer is unchanged, the semantics move underneath it, and neither side
	// reports the switch. Renaming outright fails to an alert that STOPS
	// FIRING, which is invisible until the moment it is needed.
	//
	// DEPRECATED. Replaced by xpf_pbr_rules_desired (identical value) and
	// xpf_pbr_rules_applied (kernel readback). REMOVAL IS NOT SCHEDULED HERE:
	// the compatibility surface belongs to whoever owns the dashboards and
	// alert rules, and that decision needs a named owner. Before it is removed,
	// every alert expression and dashboard panel selecting
	// xpf_pbr_rules_installed must have been moved to one of the two
	// replacements — "deprecated for a release" with no removal trigger becomes
	// permanent, so the trigger is stated as a condition rather than a date.
	c.pbrRulesInstalled = prometheus.NewDesc(
		"xpf_pbr_rules_installed",
		"DEPRECATED alias of xpf_pbr_rules_desired — the number of kernel "+
			"ip-rule filter-based-forwarding entries the active config's "+
			"routing-instance filter terms YIELD, not the number the kernel "+
			"accepted. Use xpf_pbr_rules_desired, or xpf_pbr_rules_applied for "+
			"the readback (#4422, #7422).",
		nil, nil,
	)
	// #7422 row 12: the honest name for the config-derived value. Identical to
	// xpf_pbr_rules_installed by construction — both are emitted from the same
	// PBRBuildStats call, and a test asserts they carry the SAME VALUE rather
	// than merely both existing. An alias that drifts is two metrics with one
	// name's worth of trust.
	c.pbrRulesDesired = prometheus.NewDesc(
		"xpf_pbr_rules_desired",
		"Number of kernel ip-rule filter-based-forwarding entries the active "+
			"config's routing-instance filter terms yield — the DESIRED set, "+
			"config-derived and emitted before the dataplane gate (#7422).",
		nil, nil,
	)
	// #7422/#11440: this is band occupancy, not proof that the in-band lookup
	// rules match the active config. `xpf_pbr_rules_mismatched` reports missing
	// and structurally different expected slots for the netlink-visible fields.
	// Both readback metrics are OMITTED when either family listing fails.
	c.pbrRulesApplied = prometheus.NewDesc(
		"xpf_pbr_rules_applied",
		"Number of even-priority slots occupied in the PBR rule priority band "+
			"(band occupancy only; this does not prove the rules match the active "+
			"config). Absent when netlink readback fails (#7422, #11440).",
		nil, nil,
	)
	c.pbrRulesMismatched = prometheus.NewDesc(
		"xpf_pbr_rules_mismatched",
		"Number of missing, mismatched, unexpected, or duplicate PBR lookup slots "+
			"compared with the desired rules using netlink-visible fields. "+
			"netlink v1.3.1 RuleList does not expose FRA_DSCP or rule action, so "+
			"those fields cannot be checked. Absent when readback fails (#11440).",
		nil, nil,
	)
	// #4422/#11307: number of routing-instance filter terms DROPPED from the
	// kernel FBF mirror (fail-closed under-steer to the main table) — an
	// unrepresentable except set or DSCP-0 match, a contradictory
	// routing-instance+discard/reject term (#4534), an ip-rule-unrepresentable
	// L4/per-packet predicate (#3730), an undefined routing-instance target or
	// unconstrained routing-instance term (#11307), a loopback attachment
	// (#9810), or the priority-window overflow (#3430 M3). Non-zero means the
	// kernel slow path under-steers vs the userspace fast path (which still
	// enforces every term exactly). There is no "widened" state — the builder
	// refuses to widen an unrepresentable match.
	c.pbrDegradedTerms = prometheus.NewDesc(
		"xpf_pbr_degraded_terms",
		"Number of routing-instance filter terms dropped from the kernel "+
			"filter-based-forwarding mirror by fail-closed handling of "+
			"unrepresentable predicates, unconstrained terms, or undefined "+
			"routing instances (#4422, #11307).",
		nil, nil,
	)
	c.tcEgressPacketsTotal = prometheus.NewDesc(
		"xpf_tc_egress_packets_total",
		"Total TC egress packets processed.",
		nil, nil,
	)
	c.syncookieTotal = prometheus.NewDesc(
		"xpf_screen_syncookie_total",
		"SYN cookie counters by type.",
		[]string{"type"}, nil,
	)
	c.flowCacheTotal = prometheus.NewDesc(
		"xpf_flow_cache_total",
		"Flow cache counters by type (IPv4 + IPv6).",
		[]string{"type"}, nil,
	)
}
