package api

import "github.com/prometheus/client_golang/prometheus"

// #3651: per-security-zone traffic-volume descriptors, restored after the
// #3643 HIDE.
//
// History, because it is the constraint on this collector. #3643 DROPPED
// xpf_zone_packets_total / xpf_zone_bytes_total for two reasons: nothing
// populated per-zone counters in the userspace era (the eBPF writers went away
// in #1476), and — the load-bearing one — the read indexed a DENSE MaxZones*2
// per-CPU BPF array by a stable-hash zone id. Stable ids are in [1,65533]
// (config.StableZoneID, #3075) while MaxZones is 64, so essentially every real
// zone OOB'd the bounded Lookup, and the collector's err != nil branch bumped
// xpf_counter_read_errors_total once per zone per scrape: a permanent FALSE
// read-error alert on the #3345 signal.
//
// Both halves are now fixed. #3643 re-keyed Manager.ReadZoneCounters onto a
// Go-side SPARSE offset map (map[uint16][2]CounterValue) that is never indexed
// by position, so a large id cannot OOB anything; #3651 shipped the populate
// path (Rust per-zone accounting -> ProcessStatus.ZoneTrafficCounters ->
// ReplaceZoneCounterOffsets). The metrics come back sourced from that map — see
// collectZoneCounters in metrics_counters.go for the read contract.
func (c *xpfCollector) initZoneDescriptors() {
	// Label set is unchanged from the pre-#3643 metric ({zone, direction},
	// direction in {ingress, egress}) so dashboards and recording rules
	// written against the original family keep working across the gap.
	c.zonePacketsTotal = prometheus.NewDesc(
		"xpf_zone_packets_total",
		"Total packets per zone. Omitted for a zone whose per-zone counters "+
			"are not populated -- see xpf_zone_counters_unpopulated_zones; an "+
			"absent sample means \"not known\", never \"zero traffic\".",
		[]string{"zone", "direction"}, nil,
	)
	c.zoneBytesTotal = prometheus.NewDesc(
		"xpf_zone_bytes_total",
		"Total bytes per zone. Omitted for a zone whose per-zone counters "+
			"are not populated -- see xpf_zone_counters_unpopulated_zones; an "+
			"absent sample means \"not known\", never \"zero traffic\".",
		[]string{"zone", "direction"}, nil,
	)
	// #3651: the explicit "not yet known" signal, and the reason the collector
	// can omit samples without the omission being ambiguous.
	//
	// A zone is counted here for SIX distinct reasons, and they are
	// indistinguishable from the Go side. Six CAUSES, reached through THREE
	// increment branches in the collector — the two counts are different
	// quantities and neither substitutes for the other.
	//
	// Three come from dataplane.ErrCounterNotPopulated, because the helper's
	// snapshot is sparse and drops all-zero rows (ZoneCounterStore::snapshot,
	// userspace-dp/src/afxdp/zone_counters.rs): (a) a pre-#3651 helper that
	// publishes no per-zone block at all, (b) a zone past the helper's 63
	// assignable hot-path slots, whose traffic genuinely goes uncounted
	// (the helper stops publishing its row -- see below), and (c) a zone that
	// is simply idle.
	//
	// #6843 R1 added a FOURTH, and the round-5 gate found two MORE that this
	// collector's own pre-read branches produce (metrics_counters.go):
	//
	//   (d) NO LOADED DATAPLANE. This collector runs ABOVE the
	//       dataplane-loaded gate precisely so the gauge survives a degraded /
	//       config-only boot — but that availability CHANGED WHAT THE GAUGE
	//       MEANS. Before the hoist (a)-(c) were exhaustive; now the gauge
	//       reads N (every configured zone) when the dataplane failed to arm,
	//       which is a different operational situation from N idle zones.
	//   (e) LOADED BUT NO APPLY RESULT YET. `m.loaded` is set by
	//       LoadUserspaceShim (dataplane/loader.go) while `lastApply` is set
	//       only by recordApplyResult (dataplane/apply.go) — so between shim
	//       load and the first apply, and PERMANENTLY if that first apply
	//       fails, IsLoaded() is true and LastApplyResult() is nil.
	//   (f) ZONE IN THE ACTIVE CONFIG BUT NOT IN THE APPLY RESULT.
	//       assignZoneIDs is total over the config BEING APPLIED, but this
	//       collector reads store.ActiveConfig(), and commitAndApply promotes
	//       the store BEFORE the apply (daemon/daemon_apply_commit.go). A
	//       commit that adds a zone and then fails its dataplane apply leaves
	//       the store with N+1 zones and cr.ZoneIDs with N.
	//
	// (e) and (f) matter because they are the causes an operator is LEAST
	// likely to guess: the helper is current, the zone count is nowhere near
	// the slot capacity, the zone carries traffic, and the dataplane IS loaded
	// — so every one of (a)-(d) reads as inapplicable. They differ in the
	// MAGNITUDE they produce, which is itself a triage hint: (f) fires per
	// missing zone, so one newly-added zone whose apply failed reads 1, while
	// (e) fires for EVERY configured zone, so it reads N. Under-enumerating
	// either reproduces exactly the mis-triage (d) was added to prevent.
	//
	// There is no xpf_dataplane_loaded series to disambiguate against, so (d)
	// must be named in the HELP or an operator paging on `> 0` triages toward
	// causes none of which is true. Availability and meaning are not
	// separable for a gauge whose HELP enumerates its causes — and that is
	// why this block states no count of the causes it does not list: an
	// enumeration that claims to be exhaustive has to actually be, and the
	// number is the part that rots first.
	//
	// #6843: the earlier wording here said build "never registers the zone with
	// the store". That holds only for a zone that was ALWAYS overflowed. The
	// store is carried forward across applies and retains still-configured
	// zones, so a zone that accumulated traffic and LATER lost its slot keeps
	// its totals -- which is why the helper filters published rows by live slot
	// assignment and the Go side replaces (not merges) the offset map.
	//
	// Publishing 0 would be correct only for (c) and would silently understate
	// (a) and (b) as "no traffic" — an authoritative zero over an unknown,
	// which is worse than no sample at all. So the sample is OMITTED and this
	// gauge carries the count instead. It is ALWAYS emitted (0 when every
	// configured zone is reporting), so `> 0` is directly alertable and the
	// signal cannot be confused with a scrape that failed to run.
	//
	// This is deliberately NOT an error: unpopulated is a legitimate steady
	// state, so it must never touch xpf_counter_read_errors_total. Routing it
	// there is precisely the per-zone false alert #3643 removed the family to
	// stop. A genuine read failure still bumps that counter — see
	// collectZoneCounters.
	//
	// The counted set is exactly the set of zones REST reports
	// per_zone_counters_available:false for (pkg/api/security.go zonesHandler),
	// so the two surfaces cannot drift apart silently; the coherence is pinned
	// by TestZoneUnpopulatedGaugeMatchesRESTAvailability.
	// #6845: the one bit that disambiguates xpf_zone_counters_unpopulated_zones.
	//
	// That gauge is three-way ambiguous BY CONSTRUCTION — a zone reads
	// unpopulated when the helper predates the per-zone populate path (#3651),
	// when the zone OVERFLOWED the helper's 63-slot capacity so its traffic is
	// genuinely being missed, or when the zone is simply idle and nothing is
	// wrong at all. The first and third need no action; the second is an
	// operational problem, and the bit separating them was already on the wire
	// (ProcessStatus.ZoneCounterOverflowActive, from
	// userspace-dp/src/afxdp/zone_counters.rs) and thrown away by every Go
	// surface.
	//
	// ABSENCE and 0 mean different things here, deliberately, and differently
	// from the sibling gauge above. That one is CONFIG-derived and is emitted
	// above the dataplane gate, so it reads the full configured zone count in a
	// degraded boot. This one is a property of the RUNNING helper's slot table:
	// with no helper there is no slot table and no overflow to report, so it is
	// emitted only on a scrape that actually read a status. Absent = "no helper
	// to ask"; 0 = "the helper reported no overflow". A hardcoded 0 in the
	// no-helper case would be a false all-clear.
	//
	// Not an error, and it must never touch xpf_counter_read_errors_total: an
	// overflowed zone degrades to "not known" on every read surface rather than
	// publishing a false zero, so nothing is misreported. What overflow costs is
	// the ABILITY TO TELL WHY, which is what this gauge restores.
	c.zoneCountersOverflowActive = prometheus.NewDesc(
		"xpf_zone_counters_overflow_active",
		"1 while the userspace helper's per-zone hot-path counter slot table has "+
			"overflowed, so some configured security zones are not counted at "+
			"all and their traffic volume is silently missing. The helper has "+
			"63 assignable slots (slot 0 reserved of 64) and assigns them in "+
			"sorted zone-id order, so zones past that capacity are never "+
			"registered and read as unpopulated. Use with "+
			"xpf_zone_counters_unpopulated_zones: that gauge cannot say WHY a "+
			"zone is unpopulated (pre-#3651 helper, overflow, or simply idle), "+
			"and this one distinguishes the case that needs action. Emitted only "+
			"when a helper status was read this scrape -- its absence means "+
			"there was no helper to ask, not that there is no overflow.",
		nil, nil,
	)
	c.floodCounterOverflowActive = prometheus.NewDesc(
		"xpf_userspace_flood_counter_overflow_active",
		"1 while the userspace helper's per-zone screen flood-counter slot "+
			"table has overflowed; emitted only when a helper status was read.",
		nil, nil,
	)
	c.zoneFloodDropsTotal = prometheus.NewDesc(
		"xpf_userspace_zone_flood_drops_total",
		"Cumulative userspace screen flood drops attributed to a security "+
			"zone, by flood type (syn_flood, icmp_flood, or udp_flood).",
		[]string{"zone", "flood_type"}, nil,
	)
	c.zoneCountersUnpopulatedZones = prometheus.NewDesc(
		"xpf_zone_counters_unpopulated_zones",
		"Number of configured security zones whose per-zone traffic counters "+
			"are not populated this scrape, so no xpf_zone_packets_total / "+
			"xpf_zone_bytes_total samples were emitted for them. Not an error: "+
			"a zone is counted here when the dataplane has published no volume "+
			"for it: the helper predates the per-zone populate path, the zone "+
			"exceeded the helper's hot-path slot capacity, the zone is idle, "+
			"there is no loaded dataplane at all (degraded / config-only "+
			"boot -- this gauge is emitted above the dataplane gate, so it "+
			"reads the full configured zone count in that state), the dataplane "+
			"is loaded but has no apply result yet (shim loaded, first apply "+
			"pending or failed), OR the zone is in the active config but absent "+
			"from the last apply result (the config store is promoted before the "+
			"dataplane apply, so a commit whose apply failed leaves a newly "+
			"added zone counted here). Matches the "+
			"zones REST reports per_zone_counters_available false for. Genuine "+
			"read failures bump xpf_counter_read_errors_total instead "+
			"(#3651, #6843).",
		nil, nil,
	)
}
