package frr

// Junos route preferences (#16620, R3-A10-04). The operator's input
// language is Junos: a static `preference N` is written against Junos's
// protocol scale (static 5, OSPF internal 10, IS-IS L1 15 / L2 18,
// RIP 100, OSPF external 150, BGP 170). Static preferences normally
// render VERBATIM as FRR static distances; protocols with a distance knob
// are pinned to their Junos value instead:
//
//	preference 12  loses to OSPF internal (10), beats OSPF external (150)
//	preference 180 loses to BGP (170)
//
// FRR syntax (stable/10.6, the deployed line):
//   - OSPFv2: `distance ospf {intra-area|inter-area|external} (1-255)`
//     under `router ospf` — braces mean AT LEAST ONE clause; the
//     combined `intra-area 10 inter-area 10 external 150` form is
//     exactly what ospfd's own config writer emits.
//   - OSPFv3: `distance ospf6 {intra-area|inter-area|external} (1-255)`
//     under `router ospf6`, same brace grammar.
//   - BGP: `distance bgp (1-255) (1-255) (1-255)` under `router bgp`,
//     arguments external, internal, local.
//   - RIP: `distance (1-255)` under `router rip`.
//
// IS-IS has NO distance knob in FRR stable/10.6: zebra applies fixed 115,
// while Junos assigns IS-IS 15 (L1) / 18 (L2), ahead of RIP 100. #17735
// therefore rejects same-table active RIP+IS-IS and static preferences
// 15..114 with IS-IS at strict commit; tolerant rendering withholds RIP or
// the conflicting static rather than silently changing the Junos winner.
// The helper FIB uses Junos-scale preferences and conservatively assigns an
// imported IS-IS route 15 because kernel protocol metadata has no level.
// See the #16620 arbitration test for all static preferences and the
// #17735 independent RIP-vs-IS-IS expected-value regression.
const (
	junosPreferenceOSPFInternal = 10
	junosPreferenceISISLevel1   = 15
	junosPreferenceISISLevel2   = 18
	junosPreferenceRIP          = 100
	junosPreferenceOSPFExternal = 150
	junosPreferenceBGP          = 170

	// frrISISFixedDistance is zebra's built-in IS-IS distance in FRR.
	// It cannot be configured (see above); it is named here so the
	// arbitration table in the tests and the helper-FIB comparison in
	// pkg/dataplane/userspace share one spelling of the limitation.
	frrISISFixedDistance = 115
)

// junosOSPFDistanceLine is the OSPFv2 stanza line pinning OSPF to the
// Junos scale: internal (intra- and inter-area) 10, external 150.
const junosOSPFDistanceLine = " distance ospf intra-area 10 inter-area 10 external 150\n"

// junosOSPF6DistanceLine is the OSPFv3 twin (`distance ospf6 ...`).
const junosOSPF6DistanceLine = " distance ospf6 intra-area 10 inter-area 10 external 150\n"

// junosBGPDistanceLine pins eBGP, iBGP and local BGP routes all to the
// Junos BGP preference 170. Junos has a single BGP preference (170)
// regardless of peer type, so all three FRR arguments are 170 — in
// particular iBGP must NOT keep FRR's 200, which is what let a
// preference-180 floating static beat the iBGP route it backed up.
const junosBGPDistanceLine = " distance bgp 170 170 170\n"

// junosRIPDistanceLine pins RIP to the Junos RIP preference 100.
const junosRIPDistanceLine = " distance 100\n"

// JunosProtocolDistance returns the Junos-scale preference used by the
// helper FIB to arbitrate an imported kernel-selected route against
// configured routes. For IS-IS, rtnetlink identifies only "isis", not its
// L1/L2 level; return Junos's more-preferred L1 value (15) conservatively,
// rather than FRR's fixed 115, which would let a floating static shadow an
// IS-IS route that Junos prefers. The FRR renderer still uses its real fixed
// IS-IS distance; configs whose ordering cannot be represented there fail
// closed at commit and on tolerant rendering (#17735).
func JunosProtocolDistance(protocol string) (distance int, ok bool) {
	switch protocol {
	case "ospf", "ospf6":
		// Internal and external differ (10 vs 150); callers comparing a
		// static against "OSPF" without a route-type qualifier get the
		// conservative (best/internal) value the acceptance cases use.
		return junosPreferenceOSPFInternal, true
	case "isis":
		return junosPreferenceISISLevel1, true
	case "rip":
		return junosPreferenceRIP, true
	case "bgp":
		return junosPreferenceBGP, true
	default:
		return 0, false
	}
}

// junosISISPreference returns the Junos IS-IS preference for a
// canonical IS-IS level: 15 for level-1, 18 for level-2 / level-1-2.
func junosISISPreference(level string) int {
	if level == "level-1" {
		return junosPreferenceISISLevel1
	}
	return junosPreferenceISISLevel2
}
