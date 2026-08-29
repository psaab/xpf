package api

import (
	"github.com/prometheus/client_golang/prometheus"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func (c *xpfCollector) initGlobalDescriptors() {
	c.packetsTotal = prometheus.NewDesc(
		"xpf_packets_total",
		"Total packets processed.",
		[]string{"direction"}, nil,
	)
	c.dropsTotal = prometheus.NewDesc(
		"xpf_drops_total",
		// #4508: enforcement drops only — policy deny + screen/IDS +
		// host-inbound deny + source-NAT alloc fail (the GlobalCtrDrops
		// bridge, #4477). This does NOT include no-route/missing-neighbor,
		// fabric-forwarding (idx 32), VLAN-push (idx 40), or NAT64
		// fail-closed drops, so it undercounts total discards. No-route
		// drops surface separately in the userspace helper status
		// ("Route misses"). Kept the mirror of the vSRX "Packets dropped"
		// field name/scope; see docs/junos-cli-reference.md.
		"Packets dropped by enforcement (policy deny, screen/IDS, "+
			"host-inbound deny, source-NAT alloc fail). Does NOT include "+
			"no-route, fabric-forwarding, VLAN-push, or NAT64 fail-closed "+
			"drops, so it undercounts total discards.",
		nil, nil,
	)
	// #3345/#3408: scrape-error signal for counter reads across the global,
	// per-zone, per-policy, and per-filter dataplane collectors AND the
	// kernel-nftables host-inbound collector (#3361, pre-gate). A failed read
	// omits the affected counter sample instead of emitting a misleading 0,
	// and bumps this monotonic counter so a degraded counter bridge is
	// alertable rather than silently reported as zero. #3463: the descriptor
	// text names every read surface that increments this counter — including
	// the host-inbound kernel-nftables read — so an operator runbook built on
	// it does not misdiagnose a zone/policy/filter or host-inbound counter
	// failure as global-only.
	c.counterReadErrorsTotal = prometheus.NewDesc(
		"xpf_counter_read_errors_total",
		"Total counter read failures during metric scrapes (global, zone, "+
			"policy, and filter dataplane reads, plus kernel-nftables "+
			"host-inbound reads).",
		nil, nil,
	)
	c.sessionsCreatedTotal = prometheus.NewDesc(
		"xpf_sessions_created_total",
		"Total sessions created.",
		nil, nil,
	)
	c.sessionsClosedTotal = prometheus.NewDesc(
		"xpf_sessions_closed_total",
		"Total sessions closed.",
		nil, nil,
	)
	c.screenDropsTotal = prometheus.NewDesc(
		"xpf_screen_drops_total",
		"Total packets dropped by screen/IDS checks.",
		nil, nil,
	)
	// #3343: per-reason breakdown of screen/IDS drops. The aggregate
	// xpf_screen_drops_total cannot attribute a drop to a specific screen
	// check; this labeled series can (reason = syn-flood, port-scan,
	// session-limit, ...). Each reason maps to a dataplane.GlobalCtrScreen*
	// counter now populated by the userspace counter bridge (#3343).
	c.screenDropsByReasonTotal = prometheus.NewDesc(
		"xpf_screen_drops_by_reason_total",
		"Total packets dropped by screen/IDS checks, by reason.",
		[]string{"reason"}, nil,
	)
	// #5806: 1 per zone whose configured `screen ids-option` profile does NOT
	// resolve to a defined profile. Strict commit rejects a dangling reference,
	// but tolerant startup/recovery, HA config-sync from a schema-skewed peer,
	// and rolling-upgrade intervals all downgrade it to a warning — and the
	// dataplane then applies NONE of that zone's screen checks (LAND, fragment,
	// source-route, SYN/ICMP/UDP flood, scan/sweep, session-limit) while the
	// active config still claims a screen is attached.
	//
	// The current enforcement disposition rides in the HELP text, NOT in a label.
	// It is a global statement about the implementation — identical for every
	// zone — so a label would carry no information, and a prose label value would
	// hand us unbounded cardinality the day it starts to vary. The label set is
	// exactly {zone, profile}: the two things that actually differ per series.
	//
	// Config-derived (no dataplane dependency), emitted BEFORE the dataplane gate
	// in Collect. The series is present ONLY while a reference is unresolved
	// (absent = every configured screen resolves), so `max_over_time(...)` alerts
	// on any zone that was ever left unscreened.
	c.screenUnresolvedProfileZones = prometheus.NewDesc(
		"xpf_screen_unresolved_profile_zones",
		"1 while a security zone references a screen ids-option profile that is "+
			"not defined, labeled by zone and the referenced profile name. "+
			"Disposition: "+dpuserspace.ScreenUnresolvedDisposition+".",
		[]string{"zone", "profile"}, nil,
	)
	// #7059: a DISTINCT series, not a widening of the one above. That one's help
	// text says "not defined", and a zone in this state resolves to a profile
	// that IS defined — folding them would make a shipped series' documented
	// meaning false and silently change what existing alerts match.
	c.screenInertProfileZones = prometheus.NewDesc(
		"xpf_screen_inert_profile_zones",
		"1 while a security zone references a screen ids-option profile that IS "+
			"defined but enables no checks, so the dataplane publishes no snapshot "+
			"and enforces nothing for the zone, labeled by zone and profile name. "+
			"Unlike xpf_screen_unresolved_profile_zones this state passes STRICT "+
			"commit with no warning. "+
			"Disposition: "+dpuserspace.ScreenInertDisposition+".",
		[]string{"zone", "profile"}, nil,
	)
	c.policyDeniesTotal = prometheus.NewDesc(
		"xpf_policy_denies_total",
		"Total packets denied by policy.",
		nil, nil,
	)
	c.natAllocFailsTotal = prometheus.NewDesc(
		"xpf_nat_alloc_failures_total",
		"Total NAT port allocation failures.",
		nil, nil,
	)
	c.nat64XlateTotal = prometheus.NewDesc(
		"xpf_nat64_translations_total",
		"Total NAT64 (IPv6<->IPv4) packet translations.",
		nil, nil,
	)
}
