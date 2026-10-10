package config

import "fmt"

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
//     node (programRethMAC, 02:bf:72:CC:RR:NN) and Junos treats the
//     interface MAC as read-only, so a static override is both
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
				(keyword == "filter" && !isInterfaceFilterConsumerPath12090(ancestors)) {
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
			if inspectPackedHead12090(n, nodeSchema, ancestors) {
				if head, rest, ok := packedHead12090(n, identity); ok &&
					(head == "filter" || head == "simple-filter") {
					consumer := head == "filter" &&
						(isInterfaceFilterConsumerPath12090(ancestors) ||
							isInterfacePackedFilterConsumer12090(ancestors, n))
					if !consumer {
						if err := emit(
							"interfaces %s: `%s` is not supported (xpf has no consumer "+
								"for this interface binding; remove it) (#12090)",
							iface.Name(), packedFilterKeywordLabel12090(head, rest)); err != nil {
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

		// H10: a static MAC override at the physical-interface scope.
		for _, c := range iface.Children {
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

		for _, unit := range iface.Children {
			if unit.Name() != "unit" {
				continue
			}
			unitID := unitIdentity(unit)

			// H10: a static MAC override at the logical-unit scope.
			for _, c := range unit.Children {
				if c.Name() == "mac" {
					if err := emit(
						"interfaces %s unit %s: static `mac` override is not "+
							"supported (the interface MAC is read-only; for cluster "+
							"RETH it is computed deterministically per node) — "+
							"remove it (#2008 H10)",
						ifName, unitID); err != nil {
						return nil, err
					}
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
					for i := 0; i < len(path); {
						keyword := path[i]
						// Apply statements own the remaining path tail, so
						// their values cannot be filter keyword heads.
						if isApplyStatementKeyword(keyword) {
							break
						}
						if keyword == "filter" || keyword == "simple-filter" {
							if keyword != "filter" || !isInterfaceFilterConsumerTokens12090(path, i) {
								if err := emit(rd.name,
									packedFilterKeywordLabel12090(keyword, path[i+1:])); err != nil {
									return nil, err
								}
							}
							i++
							if i+1 < len(path) && isFilterDirection12090(path[i]) {
								i += 2 // direction and authored filter name
							}
							continue
						}
						// The Ethernet-switching VLAN list is open-world in
						// this schema, but `members` owns the remaining values.
						if keyword == "vlan" && i+1 < len(path) && path[i+1] == "members" {
							break
						}
						child := schemaChildFor(pathSchema, keyword)
						if child == nil {
							if keyword == "family" && i+1 < len(path) {
								i += 2 // compound family name is part of its identity
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
				}
			}
		}
	}
	return warnings, nil
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

func isInterfaceFamilyAF12090(name string) bool {
	switch name {
	case "inet", "inet6", "inet-vpn", "inet6-vpn",
		"iso", "mpls", "ccc", "tcc", "bridge", "vpls",
		"ethernet-switching", "evpn":
		return true
	default:
		return false
	}
}

func packedHead12090(n *Node, identity int) (head string, rest []string, ok bool) {
	if n == nil || identity < 0 || identity >= len(n.Keys) {
		return "", nil, false
	}
	return n.Keys[identity], n.Keys[identity+1:], true
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
	familyIndex, ok := interfaceUnitFamilyAncestorIndex12090(ancestors)
	return ok && familyIndex == 2 && len(ancestors) == familyIndex+1 &&
		len(ancestors[familyIndex].Keys) == 1 &&
		(n.Name() == "inet" || n.Name() == "inet6")
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
					// A packed filter child with more than one value
					// leaves every value after nodeVal's first one
					// unenforced.
					if len(c.Keys[1:]) > i+2 {
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
