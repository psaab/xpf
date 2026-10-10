package config

// Deep duplicate-block detection — #8704.
//
// namedDupRules reaches `<stanza> { [<inner> {] <keyword> <name> { … } [}] }`:
// two container levels, neither of them a named instance. Six containers that
// LOSE configuration to a repeated block sit deeper than that and were
// therefore reported by nothing — not at commit, not on the tolerant path.
//
// The gap is structural rather than an oversight in the table. #8436's
// conservation census records these containers as not-conserved and lists them
// as accepted exceptions, and its binding is "conserved, refused, or LISTED".
// It is not "conserved, refused, or REPORTED", so a listed exception is
// permitted to be silent — and six of the nine were. An exception mechanism
// that does not require the exception to be visible turns a guard into a
// registration desk: every future silent site is compliant by construction.
//
// The worst of the six, and the reason this is not a diagnostics nit:
//
//	security { ipsec { vpn v1 {
//	    traffic-selector ts1 { local-ip  10.0.0.0/24; }
//	    traffic-selector ts1 { remote-ip 10.1.0.0/24; }
//	} } }
//	  -> local-ip "", remote-ip 10.1.0.0/24, STRICT COMMIT ACCEPTED, zero warnings
//
// A traffic selector decides which traffic enters the tunnel. It renders into
// swanctl.conf with the local side missing, so the SA is negotiated against a
// selector the operator did not write — on the path we tell operators is
// authoritative.

// deepDupRule locates a named container by an explicit PATH, so a duplicate can
// be detected below a named-instance level that namedDupRule cannot express.
//
// Each element is a container KEYWORD. A named-instance level needs no special
// marker: `vpn v1` is a single node whose Keys are ["vpn","v1"], so
// FindChildren("vpn") already returns the instances and the path simply names
// the keyword. (An earlier draft carried a "*" element for these levels; it
// descended one level too far and matched nothing, and it is gone rather than
// left in unused.) The final element is the container whose repeated blocks are
// the defect.
type deepDupRule struct {
	path   []string
	kind   string
	effect dupContainerEffect
}

// deepDupRules is the registry. Each row's `effect` is MEASURED, not inferred:
// dupEffectStrict's own comment is right that a wrong effect here is a wrong
// diagnosis rather than a wording nit, because it sends the operator to delete
// the wrong block.
var deepDupRules = []deepDupRule{
	// Measured by authoring the two blocks in BOTH orders — the later block
	// wins either way, so this is last-writer-wins and not a per-field merge:
	//
	//	local  then remote  -> local="",            remote=10.1.0.0/24
	//	remote then local   -> local=10.0.0.0/24,   remote=""
	//
	// One order alone would not have distinguished last-wins from "the local
	// side is dropped".
	{
		path:   []string{"security", "ipsec", "vpn", "traffic-selector"},
		kind:   "ipsec vpn traffic-selector",
		effect: dupEffectLastWins,
	},

	// dupEffectSplitInstances for both, deduced rather than assumed: #8436
	// records each as NOT CONSERVED (so not a per-field merge), and authored in
	// BOTH orders neither equals the block carrying only the first leaf nor the
	// one carrying only the second (so neither first- nor last-wins). That
	// leaves each block contributing separately. For `bgp neighbor` — which is
	// NOT gated here, see below — the object count confirmed the same shape
	// directly: two neighbours for one peer address where the merged spelling
	// gives one.
	{
		path:   []string{"chassis", "device-map", "interface"},
		kind:   "chassis device-map interface",
		effect: dupEffectSplitInstances,
	},
	{
		path:   []string{"security", "flow", "traceoptions", "packet-filter"},
		kind:   "security flow traceoptions packet-filter",
		effect: dupEffectSplitInstances,
	},

	// #12308, found during #12184: typing the QNH metric leaf let the
	// synthetic probe use valid integer metrics, which showed the census's
	// QNH skip hiding a genuine reduction. The compiler appends one
	// NextHopEntry PER BLOCK (compiler_routing.go), so a repeated block for
	// the same gateway is not last-wins — it is a SPLIT, measured in BOTH
	// orders with interface in one block and preference in the other:
	//
	//	interface then preference  -> 2 next-hops: {iface, pref=5} {no-iface, pref=250}
	//	preference  then interface -> 2 next-hops: {no-iface, pref=250} {iface, pref=5}
	//	merged                      -> 1 next-hop:  {iface, pref=250}
	//	flat `set` (both orders)    -> 1 next-hop:  {iface, pref=250}
	//
	// The halves land in DIFFERENT failover tiers: the interface half
	// inherits the route preference (5) while the preference half carries
	// 250, so one authored floating backup becomes a primary-tier path plus
	// an interfaceless backup — a failover that fires at the wrong admin
	// distance. The flat spelling merges (SetPath collapses same-gateway
	// lines onto one node), so the gate fires only on the hierarchical
	// re-opening; two DISTINCT gateways stay two legitimate backups.
	// The rib-scoped route compiles through the same loop, so it splits the
	// same way and needs its own row.
	{
		path:   []string{"routing-options", "static", "route", "qualified-next-hop"},
		kind:   "static route qualified-next-hop",
		effect: dupEffectSplitInstances,
	},
	{
		path:   []string{"routing-options", "rib", "static", "route", "qualified-next-hop"},
		kind:   "rib static route qualified-next-hop",
		effect: dupEffectSplitInstances,
	},
}

// deepDupUnreportable records the not-conserved containers this gate does NOT
// report, each with the MEASURED reason reporting them would be wrong.
//
// This is deliberately not the allowlist #8704 was filed about. That one
// permitted an exception to be silent with no reason at all, which made every
// future silent site compliant by construction. An entry here has to say what
// breaks, and TestEveryNotConservedContainerIsReported8704 fails for any
// container that is neither reported nor listed here — so adding one is a
// visible act, not an omission.
//
// I tried to gate all six and the existing suite refuted two of them. That is
// the over-reach control working: the first draft of this file reported every
// not-conserved container, and two of those reports rejected or displaced
// correct behaviour.
var deepDupUnreportable = map[string]string{
	"protocols bgp group xpfname neighbor": "gating this REJECTS VALID CONFIG. Measured: it fails " +
		"TestSlotEscapeTable's control `set protocols bgp group G neighbor 10.0.2.2 import PS`, " +
		"because flat-set authoring produces sibling nodes at this depth and the gate reads them " +
		"as a repeated block. Reporting here would refuse configuration an operator can legally " +
		"write with `set`, which is the failure mode this whole area exists to avoid.",
	"system services dhcp-local-server group xpfname pool xpfname static-binding": "a specific, " +
		"BETTER diagnosis already exists. Measured: the generic duplicate message pre-empts the " +
		"duplicate-MAC rejection TestDHCPStaticBindingRejectsDuplicateMAC asserts, replacing " +
		"'this MAC is already bound' with 'this block is repeated'. The second is true and less " +
		"useful. Reporting here needs the specific gate to win, not a second message racing it.",
	"system services dhcpv6-local-server group xpfname pool xpfname static-binding": "same as the " +
		"dhcp-local-server row above — the specific duplicate-MAC diagnosis must not be displaced " +
		"by a generic one.",
}

// findDeepDupBlocks walks the registry and returns the duplicates it finds.
//
// Duplicates are scoped to the IMMEDIATE holder, not to the rule. Two different
// VPNs may each legitimately carry a `traffic-selector ts1`, and a rule-wide
// `seen` map would report that valid config as a duplicate — an over-reach that
// would reject working configurations. Measured: two vpns with the same
// selector name compile to two selectors, so they are distinct objects.
func findDeepDupBlocks(tree *ConfigTree) []dupBlock {
	if tree == nil {
		return nil
	}
	var out []dupBlock
	for _, rule := range deepDupRules {
		if len(rule.path) < 2 {
			continue
		}
		for _, child := range tree.Children {
			if child.Name() != rule.path[0] {
				continue
			}
			collectDeepDups(child, rule.path[1:], rule, &out)
		}
	}
	return out
}

func collectDeepDups(node *Node, rest []string, rule deepDupRule, out *[]dupBlock) {
	if node == nil || len(rest) == 0 {
		return
	}
	if len(rest) == 1 {
		// The holder is reached; detect duplicates AMONG ITS OWN children.
		seen := map[string]bool{}
		reported := map[string]bool{}
		for _, inst := range namedInstances(node.FindChildren(rest[0])) {
			if inst.name == "" {
				continue // empty-name reporting stays with the existing gate
			}
			if seen[inst.name] {
				if !reported[inst.name] {
					*out = append(*out, dupBlock{rule.kind, inst.name, rule.effect})
					reported[inst.name] = true
				}
				continue
			}
			seen[inst.name] = true
		}
		return
	}
	for _, c := range node.FindChildren(rest[0]) {
		collectDeepDups(c, rest[1:], rule, out)
	}
}
