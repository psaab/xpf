package frr

// Junos route preferences (#16620, R3-A10-04). The operator's input
// language is Junos: a static `preference N` is written against Junos's
// protocol scale (static 5, OSPF internal 10, IS-IS L1 15 / L2 18,
// RIP 100, OSPF external 150, BGP 170). Static preferences therefore
// keep rendering VERBATIM as the FRR static distance — already on the
// Junos scale — and every dynamic protocol that has an FRR distance
// knob is pinned to its Junos value instead. Pinning the protocols
// (rather than translating statics onto FRR's scale) preserves the
// operator's integer exactly and makes every Junos ordering hold in
// zebra:
//
//	preference 12  loses to OSPF internal (10), beats OSPF external (150)
//	preference 180 loses to BGP (170)
//	preference 12  loses to IS-IS (15/18) and RIP (100)
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
// IS-IS has NO distance knob in FRR (stable/10.6 isisd/yang expose no
// administrative-distance command; isisd sends no ZAPI distance, so
// zebra applies its built-in 115). Junos IS-IS is 15 (L1) / 18 (L2):
// both sit between OSPF internal (10) and RIP (100), exactly where
// FRR's fixed 115 does NOT sit — 115 is worse than RIP's Junos 100.
// The IS-IS↔RIP window is therefore NOT fully reproduced: a static at
// preference 110..115 still orders differently against IS-IS than on
// Junos. Every other Junos window IS reproduced, including both
// acceptance cases (12 vs OSPF internal, 180 vs BGP). See
// protocol_distance_16620_test.go for the table-driven arbitration
// proof over the whole 1..254 static range.
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

// JunosProtocolDistance returns the effective administrative distance
// the named dynamic protocol carries in the managed section after
// #16620, for comparison against a Junos-scale static preference.
// protocol is the kernel/rtnetlink spelling used by the FIB import
// ("bgp", "ospf", "ospf6", "isis", "rip"). For IS-IS it returns FRR's
// fixed 115 (no knob exists — see the file comment). ok is false for
// protocols with no Junos preference in this table.
func JunosProtocolDistance(protocol string) (distance int, ok bool) {
	switch protocol {
	case "ospf", "ospf6":
		// Internal and external differ (10 vs 150); callers comparing a
		// static against "OSPF" without a route-type qualifier get the
		// conservative (best/internal) value the acceptance cases use.
		return junosPreferenceOSPFInternal, true
	case "isis":
		return frrISISFixedDistance, true
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
