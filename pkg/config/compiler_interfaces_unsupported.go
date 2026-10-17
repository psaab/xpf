package config

import (
	"fmt"
	"strings"
)

// compiler_interfaces_unsupported.go carries reject-at-commit gates for
// interface spellings that xpf parses but cannot honour. These unsupported
// stanzas are silent-drops on master: the parser accepts them, the compiler
// never reads them, and the userspace AF_XDP dataplane has no mechanism to
// enforce them. Admitting them on commit is a silent functional lie, so the
// strict path hard-rejects and the tolerant load / peer-sync path warns
// instead of failing closed (#1960).
//
//   - H9: `interfaces <if> unit <n> family inet|inet6 policer arp <name>`
//     — a per-logical-interface ARP policer. The dataplane has NO
//     per-interface policer enforcement (feature-gaps.md "Interface
//     Policer ... Missing"); the only policer enforcement is the
//     admitted firewall-filter path and the color-blind three-color
//     discard slice (pkg/dataplane/userspace/filters.go). A real
//     implementation is a net-new dataplane subsystem.
//   - H10: `interfaces <if> [unit <n>] mac <addr>` — a static MAC
//     override. xpf computes the RETH virtual MAC deterministically per
//     node and RETH (02:bf:72:CC:RR:(2*reth-index+node-id)) and Junos
//     treats the interface MAC as read-only, so a static override is both
//     unimplemented and divergent.
//   - #10293 / #12090: interface filter LISTS, uRPF, policer binds, unit-level
//     `filter`, and `simple-filter` are not consumed by an InterfaceUnit hook.
//     Only one-name `filter input|output` under family inet|inet6 is wired;
//     every other spelling would silently leave the interface unfiltered.
//   - #2354 / #5879: a QinQ / stacked-VLAN (802.1ad S-tag + 802.1Q C-tag)
//     inner tag. The AF_XDP shim's parse_l2 unwinds exactly ONE VLAN tag,
//     so a double-tagged frame keeps eth_proto=0x8100 → the dispatch `_`
//     arm XDP_PASSes it to the kernel forwarding path, never reaching the
//     userspace firewall. A committed inner tag is therefore a false
//     promise of firewalled stacked-VLAN transit. This detection now lives
//     in the #5879 canonical per-physical-interface gate
//     (validateQinQVLANStackAST, compiler_interfaces_qinq.go): it keys on
//     the AGGREGATE effective stack across every spelling
//     (`inner-vlan-id` AND `vlan-tags outer/inner`), statements split
//     across a unit, and BOTH cluster-node expansions — catching a
//     peer-only-group or `vlan-tags`-spelled inner tag the old single-
//     statement `inner-vlan-id` check here missed. Single 802.1Q tagging
//     via `vlan-id` (with or without `flexible-vlan-tagging`) stays fully
//     supported and CORRECT (#2346). The multi-layer QinQ feature build
//     stays plan-deferred pending operator demand.
//
// Why reject at commit (vs the warn-only M1 persist-groups-inheritance
// or the PR #659 import-compat warnings): M1 is a daemon-behaviour knob
// that is harmless as a no-op (the firewall posture is correct either
// way), so a warning is honest. H9/H10 are FALSE PROMISES about
// dataplane enforcement / interface identity — a committed `policer arp`
// claims ARP is rate-limited and a committed `mac` claims a specific
// hardware address, neither of which the running firewall delivers.
// The #10293/#12090 filter aliases are the same false promise: the configured
// security hook is silently absent unless the binding lands on the one typed
// InterfaceUnit field.
// Blocking the new operator edit at commit stops an operator deploying a
// config they believe enforces security/identity when it does not; the
// lenient load/peer-sync downgrade still lets an already-imported or
// peer-synced config (which an older binary silently accepted) boot.
//
// This is an AST pre-walk (not a SchemaValidate typed leaf) because
// SchemaValidate is opt-in per known leaf and returns nil for unknown
// keywords by design (schema_walk.go) — it cannot REJECT an unknown
// stanza. Every other reject-at-commit-for-unsupported gate
// (validateVRRPTrackInterfaceAST, validateTCPMSSRanges,
// validateNodesControlChars, validateTunnelEndpointIDCollisionAST) is an
// AST pre-walk in compileExpanded for the same reason. The walk runs on
// the group-expanded, inactive-pruned tree (compileConfigWithOpts /
// compileConfigForNodeWithOpts strip inactive subtrees and expand groups
// before compileExpanded), so an apply-groups-inherited stanza is caught
// and an `inactive:` stanza is ignored (#2008 H1 doctrine) for free.

// validateUnsupportedInterfaceStanzasAST walks the `interfaces` subtree
// of the group-expanded AST and rejects the H9/H10/#2354/#10293/#12090
// silent-drop stanzas.
//
// Strict path (commit / commit-check, lenient=false): the first offending
// stanza is a hard compile error, naming the exact interface/unit path.
//
// Lenient path (load / peer-sync, lenient=true): every offending stanza
// is returned as a warning and compilation continues. The stanza is NOT
// pruned — it is already a no-op (no compiler reads it), so leaving it in
// the cloned tree is harmless and the warning is the operator signal.
// This differs from validateVRRPTrackInterfaceAST, which must prune
// because its duplicates change which statement the compiler picks; here
// there is nothing to pick.
//
// Detection is scoped to the `interfaces` stanza so the firewall
// `policer <name>` definition and chassis `device-map interface ... mac`
// identity key (both legitimate uses of these keywords elsewhere) are
// never touched. The #12090 scan below rejects `filter` / `simple-filter`
// keyword heads outside the supported family hook, not same-spelled values.
func validateUnsupportedInterfaceStanzasAST(nodes []*Node, lenient bool) ([]string, error) {
	// #5744: union across EVERY top-level `interfaces` root, not just the first.
	// A hierarchical config can split its interfaces across two sibling
	// `interfaces { }` stanzas, and compileSections compiles them all — so an
	// unsupported / silently-dropped interface stanza living in a SECOND root
	// was skipped by the old first-root-only scan, the sibling gap PR #5741
	// closed for the interface-range / stable-ID gates. Flattening every
	// interfaces root's children into one per-interface pass is equivalent to
	// nesting a loop over the roots; each stanza is flagged independently.
	var ifaceChildren []*Node
	sawInterfaces := false
	for _, n := range nodes {
		if n.Name() == "interfaces" {
			sawInterfaces = true
			ifaceChildren = append(ifaceChildren, n.Children...)
		}
	}
	if !sawInterfaces {
		return nil, nil
	}

	var warnings []string
	emit := func(format string, args ...any) error {
		msg := fmt.Sprintf(format, args...)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}
	// #12090: the only supported filter keyword under interfaces is
	// `unit <n> family inet|inet6 filter input|output <name>`, which has a
	// typed InterfaceUnit hook. This scan recognizes keyword positions, not
	// arbitrary same-spelled values or authored filter names. All other
	// `filter` heads and all `simple-filter` heads have no reader under the
	// open-world subtree.
	// Walk every interface subtree so another placement cannot silently
	// expand the accepted population.
	for _, iface := range ifaceChildren {
		var walk func(*Node, []*Node, *schemaNode) error
		walk = func(n *Node, ancestors []*Node, parentSchema *schemaNode) error {
			if n == nil {
				return nil
			}
			// Apply statements own their value tail and apply-macro body.
			if isApplyStatementKeyword(n.Name()) {
				return nil
			}
			nodeSchema, identity := schemaNodeAndIdentity12090(parentSchema, n)
			if keyword := n.Name(); keyword == "simple-filter" ||
				(keyword == "filter" && !isInterfaceDirectFilterConsumerPath12090(ancestors, n)) {
				if err := emit(
					"interfaces %s: `%s` is not supported (xpf has no consumer "+
						"for this interface binding; remove it) (#12090)",
					iface.Name(), filterKeywordLabel12090(n)); err != nil {
					return err
				}
			}
			// Compact spellings put their first child keyword in Keys. Inspect
			// only schema-resolved nodes, family nodes, and AF leaves directly
			// under a bare family. Otherwise the apparent head may be a value
			// (for example `members filter` or `apply-macro filter`).
			if inspectPackedHead12090(n, nodeSchema, ancestors) && identity < len(n.Keys) {
				tail := n.Keys[identity:]
				for _, p := range filterKeywordPositions12090(nodeSchema, tail) {
					head := tail[p]
					consumer := p == 0 && head == "filter" &&
						(isInterfaceFilterConsumerPath12090(ancestors) ||
							isInterfacePackedFilterConsumer12090(ancestors, n))
					if head == "filter" && isInterfaceInstancePackedTailFilterConsumer12090(ancestors, n, tail, p) {
						consumer = true
					}
					if !consumer {
						if err := emit(
							"interfaces %s: `%s` is not supported (xpf has no consumer "+
								"for this interface binding; remove it) (#12090)",
							iface.Name(), packedFilterKeywordLabel12090(head, tail[p+1:])); err != nil {
							return err
						}
					}
				}
			}
			next := append(ancestors, n)
			for _, child := range n.Children {
				if err := walk(child, next, nodeSchema); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(iface, nil, schemaForPath("interfaces")); err != nil {
			return nil, err
		}
	}

	// Each direct child of `interfaces` is a physical/aggregate interface
	// instance (wildcard name slot).
	for _, iface := range ifaceChildren {
		ifName := iface.Name()
		if ifName == "" {
			continue
		}
		// #14436: expand a packed instance tail (`ge-0/0/0 bandwidth 1g
		// unit 0 family inet { ... }`) so the H9/H10/#10293 checks below
		// see the same unit children as the braced spelling; on the raw
		// node the unit is packed onto Keys and every check missed it.
		ifaceBody := packedBody(iface, interfaceSchema9792())
		if ifaceBody == nil {
			ifaceBody = iface
		}

		// H10: a static MAC override at the physical-interface scope.
		// The packed tail may not expand when `mac` itself leaves the
		// modelled grammar, so scan the raw Keys tail as well (#14436).
		for _, c := range ifaceBody.Children {
			if c.Name() == "mac" {
				if err := emit(
					"interfaces %s: static `mac` override is not supported "+
						"(the interface MAC is read-only; for cluster RETH it is "+
						"computed deterministically per node) — remove it (#2008 H10)",
					ifName); err != nil {
					return nil, err
				}
			}
		}
		if packedIfaceTailHasMac14436(iface.Keys) {
			if err := emit(
				"interfaces %s: static `mac` override is not supported "+
					"(the interface MAC is read-only; for cluster RETH it is "+
					"computed deterministically per node) — remove it (#2008 H10)",
				ifName); err != nil {
				return nil, err
			}
		}

		for _, unit := range ifaceBody.Children {
			if unit.Name() != "unit" {
				continue
			}
			unitID := unitIdentity(unit)

			// H10: a static MAC override at logical-unit scope has no
			// consumer anywhere under `unit`. It surfaces as a packed
			// tail on the unit node (no inline peer), a mid-tail leaf
			// nested under the preceding stanza (flat packed split),
			// or an ordinary braced child — one descendant rule covers
			// every spelling.
			if packedUnitTailHasMac(unit.Keys) || unitHasMACDescendant(unit) {
				if err := emit(
					"interfaces %s unit %s: static `mac` override is not "+
						"supported (the interface MAC is read-only; for cluster "+
						"RETH it is computed deterministically per node) — "+
						"remove it (#2008 H10)",
					ifName, unitID); err != nil {
					return nil, err
				}
			}

			// #2354 QinQ / stacked-VLAN detection MOVED to the #5879
			// canonical per-physical-interface gate
			// (validateQinQVLANStackAST, compiler_interfaces_qinq.go). That
			// gate keys on the AGGREGATE effective stack across every VLAN
			// spelling (`inner-vlan-id` AND `vlan-tags outer/inner`), split
			// statements, and BOTH cluster-node expansions — the single-
			// statement `inner-vlan-id` check that lived here could not see
			// a peer-only-group or `vlan-tags`-spelled inner tag. Nothing
			// QinQ is checked in this post-expansion single-node walk.

			// H9: a per-unit ARP policer under family inet / inet6.
			for _, fam := range unit.Children {
				if fam.Name() != "family" || !isInetFamily(fam) {
					continue
				}
				famName := familyAfterKeyword(fam)
				if hasARPPolicer(fam) {
					if err := emit(
						"interfaces %s unit %s family %s: `policer arp` is not "+
							"supported (xpf has no per-interface ARP policer; ARP "+
							"is not rate-limited per logical interface) — remove it "+
							"(#2008 H9)",
						ifName, unitID, famName); err != nil {
						return nil, err
					}
				}
				// #10293: interface filter LISTS, uRPF, and input/output
				// policer bindings are accepted by the parser but have no
				// InterfaceUnit field or dataplane consumer. A single-name
				// filter input/output binding remains supported; these
				// unbound siblings must fail closed rather than promise
				// enforcement and silently do nothing.
				for _, knob := range unsupportedInterfaceFilterKnobs(fam) {
					if err := emit(
						"interfaces %s unit %s family %s: `%s` is not "+
							"supported (xpf has no consumer for this interface "+
							"binding; remove it) (#10293)",
						ifName, unitID, famName, knob); err != nil {
						return nil, err
					}
				}
			}
			// #12656: compileInterfaces only consumes address families inet
			// and inet6. Policer bindings under mpls/any, and bindings packed
			// under an unrecognized family token, otherwise disappear.
			for _, family := range unit.Children {
				if family.Name() != "family" {
					continue
				}
				afs := []*Node{family}
				if len(family.Keys) < 2 {
					afs = family.Children
				}
				for _, af := range afs {
					if af == nil {
						continue
					}
					afName := af.Name()
					start := 1
					if af.Name() == "family" && len(af.Keys) > 1 {
						afName = af.Keys[1]
						start = 2
					}
					var bindings []string
					for i := start; i+1 < len(af.Keys); i++ {
						if af.Keys[i] == "policer" &&
							(af.Keys[i+1] == "input" || af.Keys[i+1] == "output") {
							bindings = append(bindings, "policer "+af.Keys[i+1])
						}
						if af.Keys[i] == "filter" && isFilterDirection12090(af.Keys[i+1]) {
							bindings = append(bindings, "filter "+af.Keys[i+1])
						}
					}
					for _, child := range af.Children {
						switch child.Name() {
						case "policer":
							for i := 1; i < len(child.Keys); i++ {
								if child.Keys[i] == "input" || child.Keys[i] == "output" {
									bindings = append(bindings, "policer "+child.Keys[i])
								}
							}
							for _, leaf := range child.Children {
								if leaf.Name() == "input" || leaf.Name() == "output" {
									bindings = append(bindings, "policer "+leaf.Name())
								}
							}
						case "filter":
							for i := 1; i < len(child.Keys); i++ {
								if isFilterDirection12090(child.Keys[i]) {
									bindings = append(bindings, "filter "+child.Keys[i])
								}
							}
							// Braced filter leaves are diagnosed by the
							// #12090 keyword walk; avoid a duplicate warning.
							// Packed directions above remain in this check.

						}
					}
					if !isInterfaceFamilyAF12090(afName) {
						for _, binding := range bindings {
							if err := emit(
								"interfaces %s unit %s family %s: `%s` is not supported "+
									"(xpf has no consumer for this interface binding; remove it) (#12656)",
								ifName, unitID, afName, binding); err != nil {
								return nil, err
							}
						}
						continue
					}
					if afName == "mpls" || afName == "any" {
						for _, binding := range bindings {
							if strings.HasPrefix(binding, "policer ") {
								if err := emit(
									"interfaces %s unit %s family %s: `%s` is not supported "+
										"(xpf has no consumer for this interface binding; remove it) (#12656)",
									ifName, unitID, afName, binding); err != nil {
									return nil, err
								}
							}
						}
					}
				}
			}
		}
	}
	return warnings, nil
}

// validateMemberlessInterfaceRangeFilters12090 checks range shared paths that
// would be discarded by expandInterfaceRanges when a range has no members.
// The ordinary interface walk sees member configurations after expansion.
func validateMemberlessInterfaceRangeFilters12090(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	emit := func(rangeName, label string) error {
		msg := fmt.Sprintf(
			"interfaces interface-range %s: `%s` is not supported "+
				"(xpf has no consumer for this interface binding; remove it) (#12090)",
			rangeName, label)
		if !lenient {
			return fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
		return nil
	}
	for _, root := range nodes {
		if root == nil || root.Name() != "interfaces" {
			continue
		}
		for _, rangeNode := range root.Children {
			if rangeNode == nil || rangeNode.Name() != "interface-range" {
				continue
			}
			var ranges []interfaceRangeDef
			if len(rangeNode.Keys) >= 2 {
				rd, _ := parseHierInterfaceRange(rangeNode)
				if rd != nil {
					ranges = append(ranges, *rd)
				}
			} else {
				ranges, _ = parseFlatInterfaceRanges(rangeNode)
			}
			for _, rd := range ranges {
				if len(rd.members) != 0 {
					continue
				}
				for _, path := range rd.shared {
					pathSchema := schemaForPath("interfaces", "x")
					for _, p := range filterKeywordPositions12090(pathSchema, path) {
						keyword := path[p]
						if keyword != "filter" || !isInterfaceFilterConsumerTokens12090(path, p) {
							if err := emit(rd.name,
								packedFilterKeywordLabel12090(keyword, path[p+1:])); err != nil {
								return nil, err
							}
						}
					}
				}
			}
		}
	}
	return warnings, nil
}

// filterKeywordPositions12090 walks a packed token tail with schema guidance
// and returns the position of every `filter`/`simple-filter` keyword head.
// Apply statements and `vlan members` own their remaining tail; compound
// family names and unknown keywords are skipped without emitting.
func filterKeywordPositions12090(schema *schemaNode, path []string) []int {
	var hits []int
	pathSchema := schema
	for i := 0; i < len(path); {
		keyword := path[i]
		if isApplyStatementKeyword(keyword) {
			break
		}
		if keyword == "filter" || keyword == "simple-filter" {
			hits = append(hits, i)
			i++
			if i+1 < len(path) && isFilterDirection12090(path[i]) {
				i += 2
			}
			continue
		}
		if keyword == "vlan" && i+1 < len(path) && path[i+1] == "members" {
			break
		}
		child := schemaChildFor(pathSchema, keyword)
		if child == nil {
			if keyword == "family" && i+1 < len(path) {
				i += 2
				pathSchema = nil
				continue
			}
			i++
			pathSchema = nil
			continue
		}
		identity := 1 + child.args
		if child.compoundKey && i+identity < len(path) {
			family := path[i+identity]
			identity++
			if sub, ok := child.children[family]; ok {
				child = sub
			} else {
				child = nil
			}
		}
		if i+identity > len(path) {
			break
		}
		i += identity
		pathSchema = child
	}
	return hits
}

// Filter's only interface consumer has the token shape
// `unit <n> family inet|inet6 filter input|output <name>`.
// The index check keeps similarly named values in other paths out.
func isInterfaceFilterConsumerTokens12090(path []string, keyword int) bool {
	return keyword == 4 && len(path) > 6 &&
		path[0] == "unit" && path[2] == "family" &&
		(path[3] == "inet" || path[3] == "inet6") &&
		path[keyword] == "filter" && isFilterDirection12090(path[keyword+1])
}

// isInterfaceFilterConsumerPath12090 reports whether a `filter` keyword is
// directly below the only interface path with a typed hook. The compiler
// consumes both compound `family inet` and split `family { inet { ... } }`.
func isInterfaceFilterConsumerPath12090(ancestors []*Node) bool {
	familyIndex, ok := interfaceUnitFamilyAncestorIndex12090(ancestors)
	if !ok {
		return false
	}
	family := ancestors[familyIndex]
	if len(ancestors) == familyIndex+1 {
		return isInetFamily(family)
	}
	return len(ancestors) == familyIndex+2 && len(family.Keys) == 1 &&
		(ancestors[familyIndex+1].Name() == "inet" || ancestors[familyIndex+1].Name() == "inet6")
}

// isInterfaceDirectFilterConsumerPath12090 limits the direct-name exemption
// beneath a braced unit identity to braced filter-child spellings. The
// compiler also consumes #12093 scalar block values such as `input { f; }`,
// but not packed `filter input f;`.
func isInterfaceDirectFilterConsumerPath12090(ancestors []*Node, filter *Node) bool {
	// #14435/#14629: filter child directly under a packed unit node whose
	// Keys tail carries the packed family segment BEFORE any unit-level
	// filter hit — packedBody in compileInterfaces consumes it as the
	// family filter. A filter spelled BEFORE that segment is a unit-level
	// binding packedBody never reaches as a family filter, so it must not
	// inherit this exemption.
	if len(ancestors) == 2 && ancestors[1] != nil && ancestors[1].Name() == "unit" &&
		unitPackedTailHasFamilyBeforeFilter14435(ancestors[1]) &&
		isInterfaceBracedFilterConsumer12090(filter) {
		return true
	}
	if isInterfacePackedInstanceFilterConsumer12090(ancestors, filter) {
		return true
	}
	if !isInterfaceFilterConsumerPath12090(ancestors) {
		return false
	}
	familyIndex, ok := interfaceUnitFamilyAncestorIndex12090(ancestors)
	return ok && (familyIndex != 3 || isInterfaceBracedFilterConsumer12090(filter))
}

// isInterfacePackedInstanceFilterConsumer12090 reports whether filter is
// the braced `filter { input|output <name>; }` body of an interface
// instance whose `unit <n> family inet|inet6` path is packed onto the
// instance node's own Keys (#14436). packedBody expands that tail into
// the same unit/family chain the braced spelling produces and appends
// the original Children under it, so the filter node itself (pointer
// identity) appears under unit -> family in the expanded tree.
func isInterfacePackedInstanceFilterConsumer12090(ancestors []*Node, filter *Node) bool {
	if len(ancestors) == 0 || filter == nil || !isInterfaceBracedFilterConsumer12090(filter) {
		return false
	}
	iface := ancestors[0]
	if iface == nil || len(iface.Keys) < 2 {
		return false
	}
	expanded := packedBody(iface, interfaceSchema9792())
	if expanded == iface {
		return false
	}
	var found bool
	var walk func(n *Node, underUnit, underInetFamily bool)
	walk = func(n *Node, underUnit, underInetFamily bool) {
		if n == nil || found {
			return
		}
		if n == filter {
			found = underUnit && underInetFamily
			return
		}
		for _, c := range n.Children {
			u, f := underUnit, underInetFamily
			switch c.Name() {
			case "unit":
				u = true
			case "family":
				if len(c.Keys) == 1 {
					// Split form `family { inet { ... } }`: defer the AF
					// decision to the inet/inet6 child below.
					f = underInetFamily
				} else {
					f = underUnit && isInetFamily(c)
				}
			case "inet", "inet6":
				if underUnit {
					f = true
				}
			}
			walk(c, u, f)
		}
	}
	walk(expanded, false, false)
	return found
}

// isInterfaceInstancePackedTailFilterConsumer12090 reports whether a
// `filter` keyword at tail[p] of an interface instance node completes a
// packed `unit <n> family inet|inet6 filter input|output` run on that
// node's own Keys (#14436) — the token form of the shape above.
func isInterfaceInstancePackedTailFilterConsumer12090(ancestors []*Node, n *Node, tail []string, p int) bool {
	if len(ancestors) != 0 || n == nil || p < 0 || p >= len(tail) || tail[p] != "filter" {
		return false
	}
	if p+1 >= len(tail) || (tail[p+1] != "input" && tail[p+1] != "output") {
		return false
	}
	// Rebuild the effective token path up to the filter keyword by
	// consuming each preceding statement through the schema levels it
	// opens, deepest-first — the same walk packedBodyChildren performs.
	// Argument values are never mistaken for keywords.
	levels := []*schemaNode{interfaceSchema9792()}
	var path []string
	for i := 0; i < p; {
		at := -1
		var child *schemaNode
		for j := len(levels) - 1; j >= 0; j-- {
			if cs := schemaChildFor(levels[j], tail[i]); cs != nil {
				at, child = j, cs
				break
			}
		}
		if child == nil {
			return false
		}
		consumed, refined := consumeNodeKeys(tail[i:p], child)
		if consumed <= 0 || i+consumed > p {
			return false
		}
		path = append(path, tail[i:i+consumed]...)
		levels = append(levels[:at+1], refined)
		i += consumed
	}
	// path must end `unit <n> family inet|inet6`.
	if len(path) < 4 {
		return false
	}
	tailPath := path[len(path)-4:]
	return tailPath[0] == "unit" && tailPath[2] == "family" &&
		(tailPath[3] == "inet" || tailPath[3] == "inet6")
}

// isInterfaceBracedFilterConsumer12090 accepts the filter-child shapes that
// compileInterfaces reads. Master #12093 defines `input { f; }` as a scalar
// block value, and compileInterfaces iterates repeated directions in order,
// making the last binding effective.
func isInterfaceBracedFilterConsumer12090(filter *Node) bool {
	if filter == nil || len(filter.Keys) != 1 || len(filter.Children) == 0 {
		return false
	}
	for _, child := range filter.Children {
		if child == nil {
			return false
		}
		switch child.Name() {
		case "input", "output":
		default:
			return false
		}
		switch len(child.Keys) {
		case 1:
			if _, ok := singleBlockValue(child); !ok {
				return false
			}
		case 2:
			if child.Keys[1] == "" || len(child.Children) != 0 || !child.IsLeaf {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// interfaceUnitFamilyAncestorIndex12090 locates the family in the supported
// unit path, accounting for a braced unit-identity node between `unit` and
// `family`.
func interfaceUnitFamilyAncestorIndex12090(ancestors []*Node) (int, bool) {
	if len(ancestors) < 3 || ancestors[1] == nil || ancestors[1].Name() != "unit" || ancestors[2] == nil {
		return 0, false
	}
	if ancestors[2].Name() == "family" {
		return 2, true
	}
	if len(ancestors) >= 4 && isBracedUnitIdentityNode12090(ancestors[2]) &&
		ancestors[3] != nil && ancestors[3].Name() == "family" {
		return 3, true
	}
	return 0, false
}

func isBracedUnitIdentityNode12090(n *Node) bool {
	return n != nil && len(n.Keys) == 1 && n.Name() != "family"
}

// schemaNodeAndIdentity12090 resolves a node's schema and the number of its
// identity keys, including the second key of compound `family` nodes.
func schemaNodeAndIdentity12090(parent *schemaNode, n *Node) (*schemaNode, int) {
	identity := 1
	if n == nil {
		return nil, identity
	}
	nodeSchema := schemaChildFor(parent, n.Name())
	if nodeSchema == nil {
		if n.Name() == "family" && len(n.Keys) > 1 {
			return nil, 2
		}
		// In block form, an args-bearing container stores its braced
		// identity as a child node. Keep the container schema for the
		// identity node's body, while its own keys still begin with the
		// identity tokens. This lets packed-head inspection reach tails
		// beneath `unit { 0 ... }`, sampling `instance { s ... }`, and
		// relay `group { lan ... }` without treating args:0 value slots
		// (such as `members filter`) as keyword positions.
		if parent != nil && parent.args > 0 && parent.children != nil {
			return parent, parent.args
		}
		return nil, identity
	}
	identity += nodeSchema.args
	if nodeSchema.compoundKey && len(n.Keys) > identity {
		family := n.Keys[identity]
		identity++
		if child, ok := nodeSchema.children[family]; ok {
			nodeSchema = child
		}
	}
	return nodeSchema, identity
}

// inspectPackedHead12090 limits packed-tail scanning to keyword positions.
// Schema-resolved nodes have an unambiguous head; the explicit family cases
// retain coverage for legacy ASTs with a bare family and an unmodelled AF child.
func inspectPackedHead12090(n *Node, nodeSchema *schemaNode, ancestors []*Node) bool {
	if n == nil || isApplyStatementKeyword(n.Name()) {
		return false
	}
	if nodeSchema != nil || n.Name() == "family" {
		return true
	}
	if len(ancestors) == 0 {
		return false
	}
	parent := ancestors[len(ancestors)-1]
	return parent.Name() == "family" && len(parent.Keys) == 1 &&
		isInterfaceFamilyAF12090(n.Name())
}

// isInterfaceFamilyAF12090 names the AF tokens that a bare `family` parent
// can carry as a packed child. `any` is the all-families filter AF that
// flat-set `family any filter ...` lands as (#12522).
func isInterfaceFamilyAF12090(name string) bool {
	switch name {
	case "inet", "inet6", "inet-vpn", "inet6-vpn",
		"iso", "mpls", "ccc", "tcc", "bridge", "vpls",
		"ethernet-switching", "evpn", "any":
		return true
	default:
		return false
	}
}

func isInterfacePackedFilterConsumer12090(ancestors []*Node, n *Node) bool {
	if n == nil {
		return false
	}
	// Keep the packed-tail exemption restricted to its existing AST shapes.
	// A packed tail beneath a braced unit identity does not populate the
	// InterfaceUnit filter hook; only the braced filter-child path is a consumer.
	if n.Name() == "family" && isInetFamily(n) {
		return len(ancestors) == 2 && ancestors[1] != nil && ancestors[1].Name() == "unit"
	}
	// #14435: `unit 0 point-to-point family inet { filter { ... } }` and
	// the `tunnel ...`-first form pack point-to-point/tunnel + family onto
	// the unit node itself; the filter arrives as a real child of that
	// packed unit node (the family body). packedBody in compileInterfaces
	// now consumes it, so the gate must not reject it as unbound.
	if n.Name() == "unit" && len(ancestors) == 1 {
		return unitPackedTailHasFamilyBeforeFilter14435(n)
	}
	familyIndex, ok := interfaceUnitFamilyAncestorIndex12090(ancestors)
	return ok && familyIndex == 2 && len(ancestors) == familyIndex+1 &&
		len(ancestors[familyIndex].Keys) == 1 &&
		(n.Name() == "inet" || n.Name() == "inet6")
}

// unitPackedTailHasFamilyBeforeFilter14435 reports whether a packed unit
// node carries `... family inet|inet6` in its Keys tail BEFORE any
// unit-level `filter`/`simple-filter` keyword hit in that same tail (the
// #14435 shape), in which case a `filter` keyword hit in the tail is —
// after packedBody expansion in the compiler — the consumed family filter,
// not an unbound unit-level filter.
//
// #14629: the previous check accepted `family inet|inet6` ANYWHERE in the
// tail, so `unit 0 filter input DISCARD-BAD family inet { ... }` (filter
// FIRST, family later) exempted the unit-level filter from the #12090
// gate while packedBody expanded only the trailing family segment — the
// filter, the addresses and the family itself were all dropped and the
// unit strict-committed empty: accepted-but-dropped, fail-open.
//
// The walk mirrors packedBodyChildren/filterKeywordPositions12090: it
// consumes each statement by the unit schema's own arity (so a VALUE that
// merely spells `family`, `filter` or `inet` — e.g. `description family`
// or a tunnel endpoint — is never mistaken for a keyword), keeps the
// open-levels stack packedBodyChildren keeps (so `family` after a
// `tunnel …` run still resolves at the unit level), and stops at the
// first token outside the modelled grammar (do-not-guess, same posture
// as packedBodyChildren) or at a unit-level filter hit that precedes the
// family segment. A family segment that appears only AFTER such a hit
// does not retroactively consume it.
func unitPackedTailHasFamilyBeforeFilter14435(n *Node) bool {
	if n == nil || n.Name() != "unit" {
		return false
	}
	schema := schemaForPath("interfaces", "x", "unit")
	if schema == nil {
		return false
	}
	consumed, _ := consumeNodeKeys(n.Keys, schema)
	tail := n.Keys[consumed:]
	quoted := func(idx int) bool {
		return len(n.KeysQuoted) == len(n.Keys) && consumed+idx >= 0 && consumed+idx < len(n.KeysQuoted) && n.KeysQuoted[consumed+idx]
	}
	// Open levels, deepest last — the same stack packedBodyChildren
	// keeps. A statement after `tunnel` (`source … destination …`) is
	// declared by the tunnel level, not by `unit`; a single `pathSchema`
	// that refined straight to `tunnel` would never resolve the unit-level
	// `family` that follows it. Each token is owned by the DEEPEST open
	// level declaring it, and the stack is truncated back to that level:
	// siblings after a container therefore return to the container that
	// declares them. The #14629 ordering question is decided at the
	// unit level (stack depth 0): `family inet|inet6` there opens the
	// consumed segment; `filter`/`simple-filter` there precedes it and
	// blocks the exemption. The same keywords INSIDE an opened level
	// (a tunnel argument spelled `family`, a description value, …) were
	// already consumed by arity, so they never reach this switch.
	levels := []*schemaNode{schema}
	for i := 0; i < len(tail); {
		keyword := tail[i]
		if quoted(i) {
			// A quoted token is a value, never a keyword (same provenance
			// rule packedBodyChildren honours). Its arity is unknowable
			// here, so stop rather than guess (fail-closed for the
			// exemption: the #12090 gate still rejects the filter).
			return false
		}
		at := -1
		var child *schemaNode
		for lvl := len(levels) - 1; lvl >= 0; lvl-- {
			if cs := schemaChildFor(levels[lvl], keyword); cs != nil {
				at, child = lvl, cs
				break
			}
		}
		if child == nil {
			return false
		}
		if at == 0 && keyword == "family" && i+1 < len(tail) && !quoted(i+1) &&
			(tail[i+1] == "inet" || tail[i+1] == "inet6") {
			return true
		}
		if at == 0 && (keyword == "filter" || keyword == "simple-filter") {
			return false
		}
		if isApplyStatementKeyword(keyword) {
			return false
		}
		identity := 1 + child.args
		refined := child
		if child.compoundKey && i+identity < len(tail) {
			fam := tail[i+identity]
			identity++
			if sub, ok := child.children[fam]; ok {
				refined = sub
			} else {
				refined = nil
			}
		}
		if i+identity > len(tail) {
			return false
		}
		levels = append(levels[:at+1], refined)
		i += identity
	}
	return false
}

// filterKeywordLabel12090 names a filter keyword and direction without
// including authored filter names, which are operator-controlled values.
func filterKeywordLabel12090(n *Node) string {
	keyword := n.Name()
	if len(n.Keys) >= 2 && isFilterDirection12090(n.Keys[1]) {
		return keyword + " " + n.Keys[1]
	}
	for _, child := range n.Children {
		if isFilterDirection12090(child.Name()) {
			return keyword + " " + child.Name()
		}
	}
	return keyword
}

func isFilterDirection12090(token string) bool {
	switch token {
	case "input", "output", "input-list", "output-list":
		return true
	default:
		return false
	}
}

// packedFilterKeywordLabel12090 reports a packed keyword and direction without
// including authored filter names, which are operator-controlled values.
func packedFilterKeywordLabel12090(keyword string, rest []string) string {
	if len(rest) > 0 && isFilterDirection12090(rest[0]) {
		return keyword + " " + rest[0]
	}
	return keyword
}

// unsupportedInterfaceFilterKnobs returns the exact interface family-level
// children that compileInterfaces does not consume. It handles both AST
// shapes: flat-set statements keep the tail in Keys, while hierarchical
// statements put the leaf under the filter/policer container.
func unsupportedInterfaceFilterKnobs(fam *Node) []string {
	if fam == nil {
		return nil
	}
	var knobs []string
	add := func(knob string) {
		for _, existing := range knobs {
			if existing == knob {
				return
			}
		}
		knobs = append(knobs, knob)
	}
	for _, c := range fam.Children {
		switch c.Name() {
		case "rpf-check":
			add("rpf-check")
		case "filter":
			for i, key := range c.Keys[1:] {
				switch key {
				case "input-list", "output-list":
					add("filter " + key)
				case "input", "output":
					// A packed filter child with more than one AUTHORED
					// value for this direction leaves every value after
					// nodeVal's first one unenforced. Direction keywords
					// are statement boundaries, not values: a two-direction
					// run (input F-IN output F-OUT) is two single-value
					// statements, so a trailing direction bounds this
					// direction to one value. (#14431)
					if len(c.Keys[1:]) > i+2 && !isFilterDirection12090(c.Keys[i+3]) {
						add("filter " + key)
					}
				}
			}
			for _, leaf := range c.Children {
				switch leaf.Name() {
				case "input-list", "output-list":
					add("filter " + leaf.Name())
				case "input", "output":
					// Count every authored value across the parser's
					// bracket, block, and packed-child shapes. nodeVal
					// consumes only the first.
					values := len(leaf.Keys) - 1
					for _, child := range leaf.Children {
						values += len(child.Keys)
					}
					if values > 1 {
						add("filter " + leaf.Name())
					}
				}
			}
		case "policer":
			for _, key := range c.Keys[1:] {
				if key == "input" || key == "output" {
					add("policer " + key)
				}
			}
			for _, leaf := range c.Children {
				if leaf.Name() == "input" || leaf.Name() == "output" {
					add("policer " + leaf.Name())
				}
			}
		}
	}
	return knobs
}

// unitIdentity returns the unit number token for an error message. The
// `unit <n>` node packs the number as Keys[1] in both AST shapes
// (flat-set `set ... unit 0 ...` and hierarchical `unit 0 { ... }`).
func unitIdentity(unit *Node) string {
	if len(unit.Keys) >= 2 {
		return unit.Keys[1]
	}
	return "?"
}

// isInetFamily reports whether a `family` node is the inet or inet6
// family. The family token is Keys[1] in both shapes (flat-set packs
// `family inet` into one node's Keys; hierarchical `family inet { ... }`
// is the compoundKey shape with the same Keys layout).
func isInetFamily(fam *Node) bool {
	name := familyAfterKeyword(fam)
	return name == "inet" || name == "inet6"
}

// familyAfterKeyword returns the family-name token (Keys[1]) of a
// `family <name>` node, or "" if absent.
func familyAfterKeyword(fam *Node) string {
	if len(fam.Keys) >= 2 {
		return fam.Keys[1]
	}
	return ""
}

// hasARPPolicer reports whether a `family inet|inet6` node carries a
// `policer arp` statement in either AST shape:
//
//   - flat-set: a single child node Keys=["policer","arp",<name>...]
//   - hierarchical: a `policer` child node containing an `arp` child.
func hasARPPolicer(fam *Node) bool {
	for _, c := range fam.Children {
		if len(c.Keys) == 0 || c.Keys[0] != "policer" {
			continue
		}
		// Flat-set: policer arp <name> packed into this node's Keys.
		if len(c.Keys) >= 2 && c.Keys[1] == "arp" {
			return true
		}
		// Hierarchical: policer { arp <name>; }.
		for _, pc := range c.Children {
			if pc.Name() == "arp" {
				return true
			}
		}
	}
	return false
}

// packedUnitTailHasMac walks a packed unit tail (`unit <n> [stanza
// <args> ...]`) with the unit schema and reports a `mac` keyword at a
// stanza position. Argument values are skipped by arity, so a value
// that merely spells "mac" (e.g. `description mac`) is not a hit;
// unknown keywords advance one token (their arity is unknowable, the
// same posture as filterKeywordPositions12090).
// packedIfaceTailHasMac14436 is packedUnitTailHasMac for the interface
// instance node (`<if> [leaf <args> ...]`): it walks Keys[1:] through
// the interface schema levels (deepest-first, as packedBodyChildren
// does) and reports a `mac` keyword at a statement position.
func packedIfaceTailHasMac14436(keys []string) bool {
	if len(keys) < 3 {
		return false
	}
	levels := []*schemaNode{interfaceSchema9792()}
	for i := 1; i < len(keys); {
		keyword := keys[i]
		if isApplyStatementKeyword(keyword) {
			return false
		}
		if keyword == "mac" {
			return true
		}
		at := -1
		var child *schemaNode
		for j := len(levels) - 1; j >= 0; j-- {
			if cs := schemaChildFor(levels[j], keyword); cs != nil {
				at, child = j, cs
				break
			}
		}
		if child == nil {
			i++
			continue
		}
		consumed, refined := consumeNodeKeys(keys[i:], child)
		if consumed <= 0 {
			i++
			continue
		}
		levels = append(levels[:at+1], refined)
		i += consumed
	}
	return false
}

func packedUnitTailHasMac(keys []string) bool {
	if len(keys) < 4 {
		return false
	}
	unitSchema := schemaInterfaces.wildcard.children["unit"]
	for i := 2; i < len(keys); {
		keyword := keys[i]
		if isApplyStatementKeyword(keyword) {
			return false
		}
		if keyword == "mac" {
			return true
		}
		child := unitSchema.children[keyword]
		if child == nil {
			i++
			continue
		}
		i += 1 + child.args
	}
	return false
}

// unitHasMACDescendant reports whether any node under a unit is named
// `mac`. No legitimate unit subtree contains one: family/address leaves
// carry no mac stanza, and a value spelling "mac" is never a node name.
func unitHasMACDescendant(unit *Node) bool {
	for _, c := range unit.Children {
		if c.Name() == "mac" || unitHasMACDescendant(c) {
			return true
		}
	}
	return false
}
