package api

import (
	"errors"
	"net"
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/routing"
)

// readHostInboundDenyCounters is the kernel nft host-inbound deny-counter source,
// a package var so the collector's degraded-boot behavior is unit-testable
// without a live kernel/netlink (#3361).
var readHostInboundDenyCounters = xnft.ReadHostInboundDenyCounters

// readHostInboundJunosHostDenyCounters is the kernel nft `to-zone junos-host`
// DENY drop-counter source (#4146), a package var so the collector's degraded-
// boot behavior is unit-testable without a live kernel/netlink, mirroring
// readHostInboundDenyCounters (the junos-host counters live in the same
// `inet xpf_hostinbound` table, separated by object-name prefix).
var readHostInboundJunosHostDenyCounters = xnft.ReadHostInboundJunosHostDenyCounters

// readLo0Counters is the kernel nft lo0 input-filter counter source, a package
// var so the collector's behavior is unit-testable without a live kernel/netlink
// (#4422), mirroring readHostInboundDenyCounters.
var readLo0Counters = xnft.ReadLo0Counters

// readHostInboundAcceptCounters is the kernel nft host-inbound ICMP-error / ND
// ACCEPT-counter source (#4759), a package var so the collector's behavior is
// unit-testable without a live kernel/netlink, mirroring
// readHostInboundDenyCounters (the accept counters live in the same
// `inet xpf_hostinbound` table as the deny counters, separated by object-name
// prefix).
var readHostInboundAcceptCounters = xnft.ReadHostInboundAcceptCounters

// collectHostInboundKernelDenies scrapes the per-zone/family named DROP counters
// from the kernel nftables host-inbound chain (#3361) and emits them as
// xpf_host_inbound_kernel_denies_total. This is the PRIMARY host-inbound
// enforcement path (host-bound traffic is shunted to the kernel before
// userspace-dp sees it), and is distinct from the userspace-dp
// xpf_host_inbound_denies_total path (#3326) — they are not double counts.
//
// The nft `inet xpf_hostinbound` chain is installed by the daemon INDEPENDENT of
// dataplane load state and keeps dropping control-plane traffic in a config-only
// / degraded boot, so Collect calls this BEFORE the dataplane gate — otherwise
// the series would vanish in exactly the degraded boot this metric exists to
// observe. ReadHostInboundDenyCounters reads nft via netlink and has no
// dataplane dependency.
//
// On a read failure the series is SKIPPED (no misleading 0) and
// xpf_counter_read_errors_total is bumped, matching the #3345 contract: a missing
// sample is distinguishable from a real zero. (The error-counter SAMPLE is
// emitted last in Collect by emitCounterReadErrors (#3462); the bump here
// accumulates on the collector and is reflected in the same scrape's emitted
// value when the dataplane is loaded.)
//
// #5719: a COUNTERLESS table gets the same treatment as a read failure. The
// #5644 cold-boot fail-closed fence installs the table with catch-all DROPs and
// deliberately NO named counters, so the kernel can be actively dropping
// host-bound traffic with nothing to scrape. There is no series to emit in that
// state either way; bumping xpf_counter_read_errors_total is what keeps this
// surface consistent with the REST host_inbound_kernel_denies_unavailable marker
// (stats.go), so an operator alerting on either one sees the fence. A table that
// is merely ABSENT keeps the silent, error-free skip: no enforcement really is
// no denies. See xnft.HostInboundTableCounterless for why a real generation
// (which always declares the #4759 accept counters) can never land here.
func (c *xpfCollector) collectHostInboundKernelDenies(ch chan<- prometheus.Metric) {
	counts, state, err := readHostInboundDenyCounters()
	if err != nil {
		c.counterReadErrors.Add(1)
		return
	}
	if state == xnft.HostInboundTableCounterless {
		c.counterReadErrors.Add(1)
		return
	}
	for _, ctr := range counts {
		ch <- prometheus.MustNewConstMetric(c.hostInboundKernelDenies,
			prometheus.CounterValue, float64(ctr.Packets), ctr.Zone, ctr.Family)
	}
}

// collectHostInboundJunosHostDenies scrapes the per-scope/family named DROP
// counters from the kernel nftables `to-zone junos-host` DENY rules (#4146) and
// emits them as xpf_host_inbound_junos_host_denies_total. These are the fine
// per-source/per-application host-inbound denies enforced on the DIRECT
// host-bound path — DISTINCT from the coarse xpf_host_inbound_kernel_denies_total
// (collectHostInboundKernelDenies) and the userspace-dp
// xpf_host_inbound_denies_total path, so the three do not double-count.
//
// The nft chain is installed by the daemon INDEPENDENT of dataplane load state
// and keeps dropping in a config-only / degraded boot, so Collect calls this
// BEFORE the dataplane gate, matching collectHostInboundKernelDenies. On a read
// failure the series is SKIPPED (no misleading 0) and
// xpf_counter_read_errors_total is bumped (#3345 missing-sample contract).
func (c *xpfCollector) collectHostInboundJunosHostDenies(ch chan<- prometheus.Metric) {
	counts, err := readHostInboundJunosHostDenyCounters()
	if err != nil {
		c.counterReadErrors.Add(1)
		return
	}
	for _, ctr := range counts {
		ch <- prometheus.MustNewConstMetric(c.hostInboundJunosHostDenies,
			prometheus.CounterValue, float64(ctr.Packets), ctr.Scope, ctr.Family)
	}
}

// collectLo0Counters scrapes the per-`then count` named counters from the kernel
// nftables lo0 input-filter chain (`inet xpf_lo0`, #4422) and emits them as
// xpf_lo0_counter_hits_total. lo0 host-inbound traffic is enforced by the KERNEL
// nft chain, so these counts are DISTINCT from the userspace-dp fast-path
// xpf_filter_hits_total (they are not double counts).
//
// The lo0 table is installed by the daemon INDEPENDENT of dataplane load state,
// so Collect calls this BEFORE the dataplane gate — the counters keep advancing
// in a config-only / degraded boot. ReadLo0Counters reads nft via netlink and has
// no dataplane dependency.
//
// On a read failure the series is SKIPPED (no misleading 0) and
// xpf_counter_read_errors_total is bumped, matching collectHostInboundKernelDenies
// and the #3345 missing-sample contract.
func (c *xpfCollector) collectLo0Counters(ch chan<- prometheus.Metric) {
	counts, err := readLo0Counters()
	if err != nil {
		c.counterReadErrors.Add(1)
		return
	}
	for _, ctr := range counts {
		ch <- prometheus.MustNewConstMetric(c.lo0CounterHits,
			prometheus.CounterValue, float64(ctr.Packets), ctr.Counter)
	}
}

// collectHostInboundICMPNDAccepts scrapes the GLOBAL ICMP-error / ND accept
// counters from the kernel nftables host-inbound chain (`inet xpf_hostinbound`,
// #4759) and emits them as xpf_host_inbound_icmp_nd_accept_total, labeled by
// type-class (icmp6_nd, icmp6_error, icmp4_error). These control-message accepts
// are admitted regardless of any per-zone host-inbound service set (so
// enforcement never black-holes core L3 operation); before #4759 they were
// UNCOUNTED, giving no per-type visibility into how many ICMP-error / ND packets
// the host-inbound path admits. The counts are AGGREGATE (the rules are global,
// not per-zone) — a per-zone breakdown would need per-zone rule splitting.
//
// The nft chain is installed by the daemon INDEPENDENT of dataplane load state
// and keeps counting in a config-only / degraded boot, so Collect calls this
// BEFORE the dataplane gate, matching collectHostInboundKernelDenies.
// ReadHostInboundAcceptCounters reads nft via netlink and has no dataplane
// dependency.
//
// On a read failure the series is SKIPPED (no misleading 0) and
// xpf_counter_read_errors_total is bumped, matching collectHostInboundKernelDenies
// and the #3345 missing-sample contract.
func (c *xpfCollector) collectHostInboundICMPNDAccepts(ch chan<- prometheus.Metric) {
	counts, err := readHostInboundAcceptCounters()
	if err != nil {
		c.counterReadErrors.Add(1)
		return
	}
	for _, ctr := range counts {
		ch <- prometheus.MustNewConstMetric(c.hostInboundICMPNDAccept,
			prometheus.CounterValue, float64(ctr.Packets), ctr.Type)
	}
}

// collectPBRStatus emits the policy-based-routing (filter-based-forwarding)
// build-health gauges xpf_pbr_rules_installed and xpf_pbr_degraded_terms (#4422).
// routing.PBRBuildStats is a pure function of the active config (no netlink), so
// this is a control-plane signal emitted BEFORE the dataplane gate, matching the
// config-derived host-inbound addressless collectors. Both gauges are emitted
// unconditionally (0 when there is no active config or no FBF term) so a
// zero-degradation state is a present sample distinct from "collector absent" —
// the alerting hook is xpf_pbr_degraded_terms > 0.
func (c *xpfCollector) collectPBRStatus(ch chan<- prometheus.Metric) {
	var cfg *config.Config
	if c.srv != nil && c.srv.store != nil {
		cfg = c.srv.store.ActiveConfig()
	}
	installed, degraded := routing.PBRBuildStats(cfg)
	ch <- prometheus.MustNewConstMetric(c.pbrRulesInstalled,
		prometheus.GaugeValue, float64(installed))
	ch <- prometheus.MustNewConstMetric(c.pbrDegradedTerms,
		prometheus.GaugeValue, float64(degraded))
}

// collectScreenUnresolvedProfileZones emits xpf_screen_unresolved_profile_zones
// (#5806): a 1 per {zone, profile} whose configured screen ids-option reference
// does not resolve to a defined profile, so the dataplane enforces none of that
// zone's screen checks while the active config says a screen is attached.
//
// Reachable via tolerant startup/recovery of an older or externally modified
// active.json, HA config-sync from a schema-skewed peer, and rolling-upgrade
// intervals — strict commit rejects the dangling reference, those paths only
// warn. Before this, a rate-limited runtime WARN was the ONLY signal, which a
// failover-noise window can swallow.
//
// The SSOT is dpuserspace.ScreenMissingProfileRefs — the SAME builder whose
// output is published to the helper as ConfigSnapshot.ScreenMissingProfiles and
// drives the dataplane WARN. Going through it is the contract, not a shortcut,
// and the guarantee it buys is this, stated with its condition (#6839 round 2):
// WHENEVER a snapshot has been published for the current active config, that
// snapshot's ScreenMissingProfiles and this metric are the same function of the
// same input, so this metric cannot name a different set than the dataplane was
// told about. "The dataplane" is the Rust helper, and that identity is only
// Go-struct to Go-struct: struct → wire → decoder is a SECOND hop, not part of
// this argument. It is bound separately rather than assumed —
// dpuserspace.TestScreenMissingProfilesPublishedToSnapshot
// (pkg/dataplane/userspace/screens_ssot_source_5806_test.go) marshals the
// snapshot and pins the wire key `screen_missing_profile_zones` with its
// `zone`/`profile` elements, the names the Rust decoder reads.
// The unqualified form — "impossible to report a different set" —
// is false in the config-only / degraded boot this collector exists to survive:
// there is no published snapshot at all then (this PR's own fixture compiles a
// config with a nil dataplane), so there is no told-about set to agree with, and
// what the metric reports is the set the dataplane WOULD be told on the next
// publish. That is the useful reading, but it is a different claim, and only the
// conditional one is provable.
//
// The enforcement disposition is carried in the descriptor's HELP text rather
// than as a label — it is identical for every series, so a label would add
// cardinality risk without information.
//
// Config-derived (no dataplane dependency), so Collect calls this BEFORE the
// dataplane gate.
func (c *xpfCollector) collectScreenUnresolvedProfileZones(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.store == nil {
		return
	}
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	for _, r := range dpuserspace.ScreenMissingProfileRefs(cfg) {
		ch <- prometheus.MustNewConstMetric(c.screenUnresolvedProfileZones,
			prometheus.GaugeValue, 1, r.Zone, r.Profile)
	}
}

// collectScreenInertProfileZones emits xpf_screen_inert_profile_zones (#7059):
// a 1 per {zone, profile} whose screen reference RESOLVES to a defined profile
// that enables no checks, so buildScreenSnapshots publishes nothing for the zone
// and the dataplane enforces none of its screen checks.
//
// This is the third state. Before #7059 it was reported by no surface at all —
// not this metric (the zone resolves, so it is absent from the unresolved set),
// not the status block, not the dataplane's runtime WARN. An operator saw a
// screened zone. It is also strictly MORE reachable than the unresolved case
// that already had a series: `set security screen ids-option p
// alarm-without-drop` with nothing else passes strict commit with zero
// warnings, whereas a dangling reference is strict-rejected and only reachable
// through the tolerant paths.
//
// The SSOT is dpuserspace.ScreenInertProfileRefs, which asks the real snapshot
// builder what it published rather than re-deriving the emit gate, so this
// series cannot disagree with what the dataplane will enforce.
//
// Config-derived (no dataplane dependency), so Collect calls this BEFORE the
// dataplane gate.
func (c *xpfCollector) collectScreenInertProfileZones(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.store == nil {
		return
	}
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	for _, r := range dpuserspace.ScreenInertProfileRefs(cfg) {
		ch <- prometheus.MustNewConstMetric(c.screenInertProfileZones,
			prometheus.GaugeValue, 1, r.Zone, r.Profile)
	}
}

// collectHostInboundAddresslessZones emits xpf_host_inbound_addressless_zones
// (#3698): a 1 per configured host-inbound-enforcing zone currently in the
// transient fail-open admit window — it has a non-lifeline interface but no
// resolvable address yet, so BuildZoneHostInboundViews yields an empty address
// set and applyHostInboundFilter emits no deny for it. The series is present
// only for zones IN the window (absent = enforced), matching the deny-counter
// contract where a missing sample is meaningful. Config-derived (no dataplane
// dependency), so Collect calls this BEFORE the dataplane gate. The SSOT for the
// window is dpuserspace.AddresslessEnforcingZones, the same builder that drives
// the daemon's state-transition warning log, so the metric and the log agree.
//
// KEEP THIS COMMENT ADJACENT TO ITS FUNC. #6839 round 2: the #5806 collector was
// inserted between this block and this declaration, so `go doc` reported
// collectScreenUnresolvedProfileZones as emitting xpf_host_inbound_addressless_zones
// and left this one undocumented. Inserting a new declaration immediately above
// an existing one is the natural place to put it, and it transfers the doc
// comment silently — no build, vet, or test can see it.
func (c *xpfCollector) collectHostInboundAddresslessZones(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.store == nil {
		return
	}
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	for _, z := range dpuserspace.AddresslessEnforcingZones(cfg) {
		ch <- prometheus.MustNewConstMetric(c.hostInboundAddresslessZones,
			prometheus.GaugeValue, 1, z.Zone)
	}
}

// collectHostInboundAddresslessInterfaces emits
// xpf_host_inbound_addressless_interfaces (#3710): a 1 per {zone, interface-unit,
// family} in the transient host-inbound fail-open admit window at
// per-interface/per-family granularity — a non-lifeline unit with a DHCP/DHCPv6
// client configured for the family but no resolved address in it yet. This is the
// refinement of collectHostInboundAddresslessZones above: the zone-level series
// goes silent for a MIXED zone the moment any interface resolves any address,
// hiding a DHCP-pending unit beside an addressed sibling (or the v6 side of a
// dual-stack edge whose v6 lease lands after v4). Config-derived (no dataplane
// dependency), so Collect calls this BEFORE the dataplane gate. The SSOT is
// dpuserspace.AddresslessEnforcingInterfaces, the same builder the daemon logs
// from, so the metric and the log agree.
func (c *xpfCollector) collectHostInboundAddresslessInterfaces(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.store == nil {
		return
	}
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	for _, i := range dpuserspace.AddresslessEnforcingInterfaces(cfg) {
		ch <- prometheus.MustNewConstMetric(c.hostInboundAddresslessIface,
			prometheus.GaugeValue, 1, i.Zone, i.Interface, i.Family, i.Reason)
	}
}

// collectHostInboundAmbiguousAddresses emits xpf_host_inbound_ambiguous_addresses
// (#3718 Option B): a 1 per firewall-local address that is
// host-inbound-reachable from more than one security zone with DIFFERING
// host-inbound service/protocol sets. The kernel host-inbound chain matches
// destination address only (no ingress predicate) over a single global input
// chain, so the admission verdict for such an address is order-dependent (the
// earlier-sorting zone wins) and can disagree with the ingress-scoped
// userspace-dp path. The strict commit gate
// (config.validateDuplicateHostLocalAddressStrict) rejects this; a tolerant /
// peer-synced load (#1960) can slip one through, and unlike the addressless
// window it is NOT self-healing — so this series stays present until the config
// is fixed. Config-derived (no dataplane dependency), so Collect calls this
// BEFORE the dataplane gate, matching the addressless-zone signal above. The
// SSOT is dpuserspace.AmbiguousHostInboundAddresses, the same builder the daemon
// logs from, so the metric and the log agree.
func (c *xpfCollector) collectHostInboundAmbiguousAddresses(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.store == nil {
		return
	}
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	for _, a := range dpuserspace.AmbiguousHostInboundAddresses(cfg) {
		ch <- prometheus.MustNewConstMetric(c.hostInboundAmbiguousAddrs,
			prometheus.GaugeValue, 1, a.Address, a.Family)
	}
}

func (c *xpfCollector) collectGlobalCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	// #3345: on a counter-read failure, SKIP emitting the sample instead of
	// reporting a misleading 0, and bump xpf_counter_read_errors_total. A
	// missing sample is distinguishable from a 0 sample; a clean zero would
	// make a degraded counter bridge indistinguishable from "no events".
	emit := func(desc *prometheus.Desc, idx uint32, labels ...string) {
		v, err := dp.ReadGlobalCounter(idx)
		if err != nil {
			c.counterReadErrors.Add(1)
			return
		}
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(v), labels...)
	}

	emit(c.packetsTotal, dataplane.GlobalCtrRxPackets, "rx")
	emit(c.packetsTotal, dataplane.GlobalCtrTxPackets, "tx")
	emit(c.dropsTotal, dataplane.GlobalCtrDrops)
	emit(c.sessionsCreatedTotal, dataplane.GlobalCtrSessionsNew)
	emit(c.sessionsClosedTotal, dataplane.GlobalCtrSessionsClosed)
	emit(c.screenDropsTotal, dataplane.GlobalCtrScreenDrops)
	// #3343: per-reason screen-drop breakdown. Emit one labeled series per
	// reason in the shared table; a per-reason read failure SKIPS that series
	// (and bumps counterReadErrors) under the same #3345 contract as `emit`.
	for i := range dataplane.ScreenReasonCounters {
		rc := &dataplane.ScreenReasonCounters[i]
		emit(c.screenDropsByReasonTotal, rc.Index, rc.Reason)
	}
	emit(c.policyDeniesTotal, dataplane.GlobalCtrPolicyDeny)
	emit(c.natAllocFailsTotal, dataplane.GlobalCtrNATAllocFail)
	emit(c.nat64XlateTotal, dataplane.GlobalCtrNAT64Xlate)
	emit(c.hostInboundDeny, dataplane.GlobalCtrHostInboundDeny)
	emit(c.tcEgressPacketsTotal, dataplane.GlobalCtrTCEgressPackets)

	// SYN cookie counters
	emit(c.syncookieTotal, dataplane.GlobalCtrSyncookieSent, "sent")
	emit(c.syncookieTotal, dataplane.GlobalCtrSyncookieValid, "valid")
	emit(c.syncookieTotal, dataplane.GlobalCtrSyncookieInvalid, "invalid")
	emit(c.syncookieTotal, dataplane.GlobalCtrSyncookieBypass, "bypass")

	// Flow cache counters (IPv4 + IPv6)
	emit(c.flowCacheTotal, dataplane.GlobalCtrFlowCacheHit, "hit")
	emit(c.flowCacheTotal, dataplane.GlobalCtrFlowCacheMiss, "miss")
	emit(c.flowCacheTotal, dataplane.GlobalCtrFlowCacheFlush, "flush")
	emit(c.flowCacheTotal, dataplane.GlobalCtrFlowCacheInvalidate, "invalidate")
}

// emitCounterReadErrors emits the xpf_counter_read_errors_total scrape-error
// sample. #3345: always emitted (0 when healthy) so the signal is present for
// alerting whether or not any read failed. #3462: this MUST run AFTER every
// sub-collector that can bump counterReadErrors (collectHostInboundKernelDenies,
// collectGlobalCounters, collectPolicyCounters,
// collectFilterCounters; #3643 dropped the per-zone bumper) so a policy/filter
// read that fails in THIS scrape is reflected in THIS scrape's value, not lagged
// by one scrape (which it was when the sample was emitted from
// collectGlobalCounters before those collectors ran). #5045: Collect establishes
// this as a `defer` at the TOP of the method, so it runs at function exit — on
// EVERY return path (including the unloaded-dataplane early return, where the
// pre-gate host-inbound/lo0 collectors can have bumped counterReadErrors) —
// keeping the omit-plus-error contract intact even in a config-only / degraded
// boot. It reads only the atomic counter, so it is safe to call exactly once at
// the end regardless of dataplane-loaded state.
func (c *xpfCollector) emitCounterReadErrors(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.counterReadErrorsTotal, prometheus.CounterValue,
		float64(c.counterReadErrors.Load()))
}

// emitInterfaceCounterReadErrors emits the xpf_interface_counter_read_errors_total
// scrape-error sample. #3464: always emitted (0 when healthy) so the signal is
// present for alerting whether or not any interface read failed. Collect calls
// it AFTER collectInterfaceCounters (the only bumper), so a failure this scrape
// is reflected in this scrape's value rather than lagging one scrape behind.
// Kept separate from emitCounterReadErrors because interface counters are out
// of the #3345 security-counter contract.
func (c *xpfCollector) emitInterfaceCounterReadErrors(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.interfaceCounterReadErrorsTotal, prometheus.CounterValue,
		float64(c.interfaceCounterReadErrors.Load()))
}

func (c *xpfCollector) collectInterfaceCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	for ifName := range allInterfaceNames(cfg) {
		// Translate Junos config name to Linux kernel ifname (#1565).
		iface, err := net.InterfaceByName(cfg.ResolveKernelIfName(ifName))
		if err != nil {
			continue
		}
		ctrs, err := dp.ReadInterfaceCounters(iface.Index)
		if err != nil {
			// #3464: a per-interface counter-read failure SKIPS this
			// interface's samples (no misleading 0) and bumps
			// xpf_interface_counter_read_errors_total — the interface-counter
			// analogue of the #3345/#3408 security-counter contract (skip, do
			// not emit a 0). The interface error metric is intentionally
			// SEPARATE from xpf_counter_read_errors_total (interface counters
			// are out of the security-counter contract; #3464).
			c.interfaceCounterReadErrors.Add(1)
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.ifacePacketsTotal, prometheus.CounterValue,
			float64(ctrs.RxPackets), ifName, "rx")
		ch <- prometheus.MustNewConstMetric(c.ifacePacketsTotal, prometheus.CounterValue,
			float64(ctrs.TxPackets), ifName, "tx")
		ch <- prometheus.MustNewConstMetric(c.ifaceBytesTotal, prometheus.CounterValue,
			float64(ctrs.RxBytes), ifName, "rx")
		ch <- prometheus.MustNewConstMetric(c.ifaceBytesTotal, prometheus.CounterValue,
			float64(ctrs.TxBytes), ifName, "tx")
	}
}

// collectZoneCounters emits the per-zone traffic-volume family
// (xpf_zone_packets_total / xpf_zone_bytes_total) plus the
// xpf_zone_counters_unpopulated_zones gauge.
//
// #3643 REMOVED this collector, for a reason that no longer holds and a
// conclusion that did. The reason: per-zone counters had no writer in the
// userspace era (the eBPF writers were deleted in #1476), so the family was
// permanently dead. That is now FALSE — #3651 shipped the populate path end to
// end (per-zone accounting on the Rust forward path in
// userspace-dp/src/afxdp/zone_counters.rs -> ProcessStatus.ZoneTrafficCounters
// -> syncBPFCountersLocked -> Manager.ReplaceZoneCounterOffsets), and
// `show security zones` and REST /security/zones have been reporting live
// per-zone volume since. Only the Prometheus surface was left behind, which is
// backwards: it is the one surface an operator actually alerts on. #3651
// restores it.
//
// The conclusion that DID hold, and the constraint on this code: the old
// collector read a DENSE MaxZones*2 per-CPU BPF array indexed by zone id.
// Stable-hash zone ids live in [1,65533] (config.StableZoneID, #3075) and
// MaxZones is 64, so essentially every real zone OOB'd the bounded Lookup and
// the collector's err != nil branch bumped xpf_counter_read_errors_total once
// per zone PER SCRAPE — a permanent false alert on the #3345 read-error signal,
// which is why dropping the family was the right call at the time.
//
// This collector cannot reintroduce that, structurally: its ONLY read is
// dp.ReadZoneCounters, which since #3643 keys a Go-side SPARSE
// map[uint16][2]CounterValue offset map and never indexes a dense array by
// position (pkg/dataplane/maps_counters.go). A large id is an ordinary map miss,
// not an out-of-bounds access. It is also not treated as an error — see below.
//
// Three-way read disposition:
//
//   - ErrCounterNotPopulated -> OMIT all four samples, count the zone into
//     xpf_zone_counters_unpopulated_zones, and do NOT bump counterReadErrors.
//     Unpopulated is a legitimate steady state, not a failure; routing it to the
//     error counter is exactly the #3643 false alert. It must stay non-erroring
//     even though it is now the rarer case.
//   - Any other error -> OMIT the samples and BUMP counterReadErrors. That is a
//     real degraded read, and the #3345/#3408 skip-and-bump contract applies:
//     never publish a 0 to stand in for a failed read.
//   - Success -> emit ingress/egress packets and bytes.
//
// Why omit rather than publish 0 for the unpopulated case: the helper's status
// snapshot is SPARSE and drops all-zero rows (ZoneCounterStore::snapshot), so
// ErrCounterNotPopulated conflates a pre-#3651 helper, a zone past the helper's
// 63 assignable hot-path slots whose traffic really is uncounted, and a merely
// idle zone. A 0 sample would be right only for the last and would silently
// understate the first two as "no traffic" — an authoritative zero over an
// unknown. The gauge makes the omission explicit instead.
func (c *xpfCollector) collectZoneCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	// The gauge is emitted on EVERY path through this function (0 when there is
	// nothing to report), so `> 0` is alertable and its absence means the scrape
	// did not run rather than "all zones healthy".
	unpopulated := 0
	defer func() {
		ch <- prometheus.MustNewConstMetric(c.zoneCountersUnpopulatedZones,
			prometheus.GaugeValue, float64(unpopulated))
	}()

	// #6843 R1: this runs ABOVE the dataplane-loaded gate. The guard below is
	// belt-and-braces, NOT a nil-safety requirement: Collect() already
	// dereferences c.srv unconditionally (metrics.go, c.srv.configPersistDegradedFn)
	// long before either position, so a nil c.srv panics regardless and the
	// below-gate position never actually ruled anything out. What the guard does
	// buy is the direct-call test path, where a collector method is invoked
	// without going through Collect().
	//
	// Counted, not pattern-matched -- and the count is NINE pre-gate collectors,
	// which partition into three sets, not two:
	//   - touch c.srv/c.srv.store AND guard: collectPBRStatus,
	//     collectHostInboundAddresslessZones, collectHostInboundAddresslessInterfaces,
	//     collectHostInboundAmbiguousAddresses.
	//   - touch NEITHER field, so need no guard: collectLo0Counters and the
	//     collectHostInbound{KernelDenies,JunosHostDenies,ICMPNDAccepts} readers.
	//   - touches c.srv and does NOT guard: collectFlowExportMetrics
	//     (metrics_system.go, c.srv.flowCollectorHealthFn). It is safe for the
	//     reason above, not because it was overlooked.
	// That third set is why "the collectHostInbound* family" would have been a
	// pattern-match rather than a check: an earlier revision of this comment
	// enumerated eight of the nine and its two-way split read as exhaustive.
	var cfg *config.Config
	if c.srv != nil && c.srv.store != nil {
		cfg = c.srv.store.ActiveConfig()
	}
	if cfg == nil {
		return
	}
	// #6843 R1: this collector runs ABOVE the dataplane-loaded gate, so dp may
	// be nil or unloaded on a degraded / config-only boot. That is not an error
	// and not an empty result: every configured zone is genuinely "not known",
	// which is exactly what the gauge reports. Volume samples are omitted (there
	// is nothing to read) and no read error is recorded — an unloaded dataplane
	// is a state, not a failed read.
	loaded := dp != nil && dp.IsLoaded()
	var cr *dataplane.ApplyResult
	if loaded {
		cr = dataplane.LastApplyResultOf(dp)
	}

	// Iterate the CONFIGURED zone set (not cr.ZoneIDs) with the same nil-zone
	// skip the REST handler uses (#3493 tolerant/HA-sync configs can carry a nil
	// zone value), so this gauge counts exactly the zones REST reports
	// per_zone_counters_available:false for. Pinned by
	// TestZoneUnpopulatedGaugeMatchesRESTAvailability — the two surfaces must
	// not drift.
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		// No loaded dataplane, no apply result, or a configured zone the last
		// apply did not assign an id to: nothing has been published for it,
		// which is the unpopulated state, not an error. REST leaves
		// PerZoneCountersAvailable false here for the same reason.
		if !loaded || cr == nil {
			unpopulated++
			continue
		}
		zoneID, ok := cr.ZoneIDs[zoneName]
		if !ok {
			unpopulated++
			continue
		}

		ingress, errIn := dp.ReadZoneCounters(zoneID, 0)
		egress, errOut := dp.ReadZoneCounters(zoneID, 1)
		switch {
		case errors.Is(errIn, dataplane.ErrCounterNotPopulated) ||
			errors.Is(errOut, dataplane.ErrCounterNotPopulated):
			unpopulated++
			continue
		case errIn != nil || errOut != nil:
			c.counterReadErrors.Add(1)
			continue
		}

		ch <- prometheus.MustNewConstMetric(c.zonePacketsTotal, prometheus.CounterValue,
			float64(ingress.Packets), zoneName, "ingress")
		ch <- prometheus.MustNewConstMetric(c.zonePacketsTotal, prometheus.CounterValue,
			float64(egress.Packets), zoneName, "egress")
		ch <- prometheus.MustNewConstMetric(c.zoneBytesTotal, prometheus.CounterValue,
			float64(ingress.Bytes), zoneName, "ingress")
		ch <- prometheus.MustNewConstMetric(c.zoneBytesTotal, prometheus.CounterValue,
			float64(egress.Bytes), zoneName, "egress")
	}
}

func (c *xpfCollector) collectPolicyCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	// #7016: emitted on EVERY path through this function (0 when there is
	// nothing to report), so `> 0` is alertable and its absence means the
	// collector did not run. It mirrors the per-zone
	// xpf_zone_counters_unpopulated_zones disposition: an unpublished per-rule
	// counter OMITS the sample and counts here, and does NOT bump
	// counterReadErrors.
	//
	// Scope note: unlike the zone gauge (#6843 R1), this one is NOT hoisted
	// above the dataplane-loaded gate -- Collect calls collectPolicyCounters
	// only on the loaded path, so a degraded / config-only boot emits no policy
	// counter family at all. That is pre-existing and deliberately unchanged
	// here; the REST inventory's hit_counters_unavailable (#5580) is the signal
	// for the unloaded state.
	unpublished := 0
	defer func() {
		ch <- prometheus.MustNewConstMetric(c.policyCountersUnpublishedRules,
			prometheus.GaugeValue, float64(unpublished))
	}()

	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// Honor `set security policy-stats system-wide enable` (#2008
	// M4). Junos collects per-policy hit counters only when policy-stats is
	// enabled system-wide; without the knob the firewall does not maintain
	// them. Mirror that: when PolicyStatsEnabled is false (the default), skip
	// per-policy counter collection so the stored-but-unenforced divergence
	// is closed. #3074: a policy with an explicit `then count` modifier
	// (`rule.Count`) opts into per-policy counting independent of the
	// system-wide knob (Junos per-policy `count`), so emit its counter even
	// when the global knob is off. The aggregate `policy_denies_total`
	// counter is emitted separately (collectGlobalCounters) and is
	// unaffected.
	statsEnabled := cfg.Security.PolicyStatsEnabled

	// #3965: read the whole policy set from ONE snapshot instead of calling
	// ReadPolicyCounters once per policy. The per-policy read rebuilt the
	// ruleID->counter index and rescanned the config under the dataplane's
	// policy mutex on EVERY call, so a scrape of P policies was O(P*(P+C)) with
	// the mutex held the entire time — starving commit/apply. NewPolicyCounter
	// Reader builds the index once (O(P+C), one brief lock) when the dataplane
	// provides the bulk snapshot, and falls back to the per-policy read
	// otherwise. A policy the helper has not published yields
	// ErrPolicyCounterUnpublished; the sample is skipped for it exactly as for a
	// failed read (#3345: never a 0 standing in for an unknown), but it counts
	// into xpf_policy_counters_unpublished_rules instead of bumping
	// counterReadErrors -- unpublished is a no-data window, not a failure
	// (#7016). A genuine read failure keeps the #3345/#3408 skip-and-bump.
	readPolicy := dpuserspace.NewPolicyCounterReader(dp, cfg, dp.ReadPolicyCounters)

	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		// #3476: the compile path normalizes nil entries out, but the
		// tolerant / HA-sync config path (#3474) can leave a nil zone-pair
		// set or rule that the runtime walker skips. Mirror that here so a
		// Prometheus scrape does not crash on zpp.FromZone / rule.Count.
		if zpp == nil {
			policySetID++
			continue
		}
		fromZone := zpp.FromZone
		toZone := zpp.ToZone
		for i, rule := range zpp.Policies {
			if rule == nil {
				continue
			}
			if !statsEnabled && !rule.Count {
				continue
			}
			policyID := policyCounterID(policySetID, i)
			ctrs, err := readPolicy(policyID)
			if err != nil {
				// #7016: unpublished is a no-data window, not a degraded read.
				// Skip the sample either way (#3345: never a 0 standing in for
				// an unknown), but bump the ERROR counter only for a genuine
				// failure -- routing the warm-up window there is exactly the
				// #3643 false alert.
				if errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished) {
					unpublished++
				} else {
					c.counterReadErrors.Add(1)
				}
				continue
			}
			ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
				float64(ctrs.Packets), fromZone, toZone, rule.Name)
		}
		policySetID++
	}

	for i, rule := range cfg.Security.GlobalPolicies {
		if rule == nil {
			continue
		}
		if !statsEnabled && !rule.Count {
			continue
		}
		policyID := policyCounterID(policySetID, i)
		ctrs, err := readPolicy(policyID)
		if err != nil {
			// #7016: see the zone-pair loop above.
			if errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished) {
				unpublished++
			} else {
				c.counterReadErrors.Add(1)
			}
			continue
		}
		// #3286: a scoped global policy (#3148 `match from-zone`/`to-zone`)
		// narrows itself to a zone pair. Prometheus is the canonical
		// counter-validation surface, so the per-policy hit metric must
		// carry the real scope on its from_zone/to_zone labels instead of
		// the all-zones "*"/"*" — otherwise scoped-global counters are
		// indistinguishable from an all-zones global. An unscoped global
		// keeps from_zone="*"/to_zone="*" (no regression). The rule label
		// is unchanged.
		// #4626: a scoped global's scope is a zone SET; label it via the
		// shared SSOT (unscoped → "*").
		fromZone := config.ScopeLabelOr(rule.Match.FromZones, "*")
		toZone := config.ScopeLabelOr(rule.Match.ToZones, "*")
		ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
			float64(ctrs.Packets), fromZone, toZone, rule.Name)
	}

	// #3363: emit the IMPLICIT default-policy hit counter (read via the
	// reserved DefaultPolicySentinelID handle) as its own time series, labeled
	// from_zone="-"/to_zone="-"/policy=dataplane.DefaultPolicyName so an
	// operator can alert on default-deny rate — the security-critical catch-all
	// that was previously uncounted. Gated on policy-stats like the per-rule
	// metrics above so all surfaces agree.
	if statsEnabled {
		ctrs, err := readPolicy(dataplane.DefaultPolicySentinelID)
		switch {
		case err == nil:
			ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
				float64(ctrs.Packets), "-", "-", dataplane.DefaultPolicyName)
		case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
			// #7016: see the zone-pair loop above.
			unpublished++
		default:
			c.counterReadErrors.Add(1)
		}
	}
}

func (c *xpfCollector) collectFilterCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane, userspaceStatus *dpuserspace.ProcessStatus) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// #3461: merge the userspace helper-published per-term hit counters
	// (filter_term_counters) into xpf_filter_hits_total, exactly as the CLI
	// (`show firewall filter`) and gRPC text paths do via
	// BuildFirewallFilterTermCounterIndex. The userspace-dp runtime publishes
	// filter hits HERE, not in the retired eBPF map, so without this merge the
	// canonical metrics path reports 0/stale while the text commands show real
	// hits. The userspace merge is independent of the eBPF apply result, so it
	// must NOT be gated on cr/FilterIDs below.
	//
	// #5317: the ProcessStatus is fetched ONCE per scrape by Collect (via
	// fetchUserspaceStatus) and shared with collectUserspaceStatus, so this no
	// longer issues its own control-socket Status() round trip. A nil pointer —
	// the helper exposes no Status() surface or the single round trip failed —
	// yields an empty term index from BuildFirewallFilterTermCounterIndex, so the
	// userspace merge is a no-op and the map path is unaffected, exactly as the
	// prior per-collector fetch behaved on a missing/failed status.
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)

	// The retired-eBPF/map counter path is gated on a compile result carrying
	// filter IDs; it may be absent (a pure userspace dataplane) without
	// suppressing the userspace merge above.
	cr := dataplane.LastApplyResultOf(dp)

	emitFilters := func(family string, filters map[string]*config.FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]

			// Resolve the map-counter span for this filter, if the compile
			// result carries it.
			var ruleOffset uint32
			var hasMap bool
			if cr != nil && cr.FilterIDs != nil {
				if fid, ok := cr.FilterIDs[family+":"+name]; ok {
					if fcfg, err := dp.ReadFilterConfig(fid); err == nil {
						ruleOffset = fcfg.RuleStart
						hasMap = true
					} else {
						// Skip the map path for this filter, but still surface
						// any userspace-published term counters below.
						c.counterReadErrors.Add(1)
					}
				}
			}

			for _, term := range filter.Terms {
				// #3459: the per-term counter-slot stride is the shared SSOT
				// config.FilterTermExpansionCount (full src×dst×dstPort×
				// srcPort cross-product, with prefix-list prefixes folded into
				// src/dst) — NOT the old nSrc*nDst that ignored ports and
				// prefix-lists and drifted later terms onto a neighbouring
				// term's slots, mis-attributing the hit.
				numRules := config.FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists)
				var totalPkts uint64
				mapFailed := false
				if hasMap {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
						} else {
							c.counterReadErrors.Add(1)
							mapFailed = true
						}
					}
					// Advance the offset regardless so later terms stay aligned.
					ruleOffset += numRules
				}

				userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
					Family: family, FilterName: name, TermName: term.Name,
				}]
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
				}

				// #3408: on a map read failure with NO userspace signal, SKIP
				// this term's sample (a missing sample, not a stale/partial 0)
				// — matching the zone/policy collectors — and rely on the
				// bumped counterReadErrors. A userspace-published counter is a
				// real signal, so still emit when one is present (#3461).
				if mapFailed && !userspaceOk {
					continue
				}
				if hasMap || userspaceOk {
					ch <- prometheus.MustNewConstMetric(c.filterHitsTotal, prometheus.CounterValue,
						float64(totalPkts), name, family, term.Name)
				}
			}
		}
	}

	emitFilters("inet", cfg.Firewall.FiltersInet)
	emitFilters("inet6", cfg.Firewall.FiltersInet6)
}
