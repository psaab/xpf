package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// compiler_interfaces_vlan_tagging.go carries the #14574 vlan-id-without-
// tagging gate and its #15034 sibling: a non-zero unit with no VLAN tag
// on an untagged parent.
//
// Background: a unit carrying `vlan-id N` (N > 0) asks for an 802.1Q
// sub-interface `<parent>.N`. That device only exists when the parent
// enables tagging (`vlan-tagging`, or `flexible-vlan-tagging` for the
// single-tag flexible-services shape). Without either flag the two
// writers disagreed:
//
//   - the networkd model (buildInterfaceNetworkdModels) branches on
//     VlanTagging and, without it, collects every unit's addresses onto
//     the untagged parent — the address answers on the untagged wire;
//   - the zone/dataplane path (resolveInterfaceRef) returns unit.VlanID
//     with no tagging test and ensureVLANSubInterface creates
//     `<parent>.N` — the dataplane holds a tagged connected prefix.
//
// So one commit produced an address on both wires with no diagnostic.
//
// Doctrine mirrors #5879/#6178/#1960 exactly: strict (commit /
// commit-check) hard-rejects, naming the interface and unit; lenient
// (tolerant load / peer-sync) downgrades to a warning so an
// already-persisted config still boots. The gate runs PRE-expansion and
// evaluates the effective view for EVERY cluster node (node0 AND node1
// `${node}`/apply-groups expansions) so a vlan-id staged under a
// peer-only group, or tagging supplied only in a peer view, is judged
// on the aggregate view and the verdict is HA-symmetric.
//
// The check is semantic, not string-based: it parses the vlan-id /
// outer-tag values and only fires for a positive tag. `vlan-id 0` is
// the untagged sentinel (see schema_interfaces.go) and stays legal
// without tagging, as does `vlan-tags outer 0`.
//
// #15034 (residual of #14574, whose predicate keyed on a positive tag
// only): a unit with NUMBER > 0, no positive tag and a parent without
// tagging is the mirror-image split. ResolveKernelIfName and
// snapshotLinuxName derive `kernelBase.<unit.Number>` for it — a
// device nothing creates — while buildInterfaceNetworkdModels folds
// every unit's addresses onto the untagged parent. The address lands
// on the parent (unit 0's zone) while the unit's own zone and input
// filter bind to the never-created `.<unit>` device, so the filter is
// never installed. Junos rejects a non-zero untagged unit on an
// untagged parent for the same reason; the gate below strict-rejects
// it (lenient warns, #1960). Exemptions are exactly the shapes whose
// device is created by another owner: a unit or interface `tunnel`
// stanza (per-unit tunnel device, or the interface tunnel / WireGuard
// device the unit shares), a secure-tunnel name (`st<N>`, whose unit
// device is the xfrmi), a loopback name (`lo<N>`, Junos multi-unit
// loopback), and `irb` (bridge-domain routing-interface). A `reth<N>`
// unit is NOT exempt: it resolves onto the member's `.<unit>` device,
// which only tagging creates, so an untagged non-zero reth unit splits
// the same way.
// vlanIDTaggingFinding records one (interface, unit) that carries a
// positive VLAN tag while its parent enables neither tagging mode, or
// (#15034) a non-zero unit number with no positive tag on such a
// parent. Exactly one of stmts / untaggedUnit is set.
type vlanIDTaggingFinding struct {
	iface        string
	unit         string
	stmts        []string // rendered tag statements contributing the positive tag
	dev          string   // authored device name (LinuxIfName(iface).vid) the dataplane creates
	untaggedUnit bool     // #15034: no positive tag; dev is the unit-number device
}

func (f vlanIDTaggingFinding) message() string {
	if f.untaggedUnit {
		return fmt.Sprintf("interfaces %s unit %s: non-zero unit without `vlan-id` on an untagged interface — "+
			"unit %s carries no positive vlan-id/vlan-tags tag and interface %s enables neither "+
			"`vlan-tagging` nor `flexible-vlan-tagging`, so the networkd writer would place the unit's "+
			"addresses on the untagged parent %s while the zone/dataplane writers bind the unit's zone "+
			"and filters to %s, a device nothing creates: the unit's filter is never installed and its "+
			"subnet is attributed to the parent unit's zone. Add `vlan-tagging` with a `vlan-id` to "+
			"unit %s, renumber it to unit 0, or remove the unit (#15034)",
			f.iface, f.unit, f.unit, f.iface, f.iface, f.dev, f.unit)
	}
	return fmt.Sprintf("interfaces %s unit %s: `vlan-id` without `vlan-tagging` — unit carries `%s` "+
		"but interface %s enables neither `vlan-tagging` nor `flexible-vlan-tagging`; "+
		"the networkd writer would place the unit's addresses on the untagged parent %s "+
		"while the dataplane writer creates tagged sub-interface %s.%s (device %s), so the address "+
		"would answer on both wires with a duplicate connected prefix. "+
		"Add `vlan-tagging` (or `flexible-vlan-tagging`) to interfaces %s, or remove the vlan-id (#14574)",
		f.iface, f.unit, strings.Join(f.stmts, "`, `"), f.iface, f.iface, f.iface, f.unit, f.dev, f.iface)
}

// ifaceTaggingEnabled reports whether an interface node enables either
// tagging mode in either AST shape (flag leaf, or packed onto the
// interface node's own Keys).
func ifaceTaggingEnabled(iface *Node) bool {
	for _, k := range iface.Keys[1:] {
		if k == "vlan-tagging" || k == "flexible-vlan-tagging" {
			return true
		}
	}
	return iface.FindChild("vlan-tagging") != nil || iface.FindChild("flexible-vlan-tagging") != nil
}

// positiveTagStmts returns the rendered statements under a unit that
// assign a positive (tagged) VLAN id: `vlan-id N` with N > 0, or a
// `vlan-tags` statement carrying an `outer N` with N > 0. Malformed
// values contribute nothing — the schema/numeric gates own those.
func positiveTagStmts(unit *Node) []string {
	var stmts []string
	for _, c := range unit.Children {
		if len(c.Keys) == 0 {
			continue
		}
		switch c.Keys[0] {
		case "vlan-id":
			if len(c.Keys) >= 2 && parsePositiveVID(c.Keys[1]) {
				stmts = append(stmts, renderVLANStmt(c))
			}
		case "vlan-tags":
			if vlanTagsOuterPositive(c) {
				stmts = append(stmts, renderVLANStmt(c))
			}
		}
	}
	return stmts
}

func parsePositiveVID(tok string) bool {
	n := 0
	if tok == "" {
		return false
	}
	for _, r := range tok {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
		if n > 4094 {
			return false
		}
	}
	return n > 0
}

// vlanTagsOuterPositive reports whether a `vlan-tags` node carries an
// `outer N` with N > 0, in either AST shape (packed Keys or nested
// children).
func vlanTagsOuterPositive(n *Node) bool {
	for i, k := range n.Keys {
		if k == "outer" && i+1 < len(n.Keys) && parsePositiveVID(n.Keys[i+1]) {
			return true
		}
	}
	for _, c := range n.Children {
		if len(c.Keys) >= 2 && c.Keys[0] == "outer" && parsePositiveVID(c.Keys[1]) {
			return true
		}
		// Hierarchical `vlan-tags { outer { 100; } }` nests one deeper.
		for _, g := range c.Children {
			if len(g.Keys) >= 1 && c.Name() == "outer" && parsePositiveVID(g.Keys[0]) {
				return true
			}
		}
	}
	return false
}

// authoredVlanDevice renders the kernel device the dataplane writer
// creates for a unit's positive tag: LinuxIfName(iface) + "." + vid.
// Returns "" when no positive tag value can be parsed (the finding's
// other fields still name the unit for the operator).
func authoredVlanDevice(ifName string, unit *Node) string {
	for _, c := range unit.Children {
		if len(c.Keys) >= 2 && c.Keys[0] == "vlan-id" && parsePositiveVID(c.Keys[1]) {
			return fmt.Sprintf("%s.%s", LinuxIfName(ifName), c.Keys[1])
		}
		if len(c.Keys) >= 1 && c.Keys[0] == "vlan-tags" {
			for i, k := range c.Keys {
				if k == "outer" && i+1 < len(c.Keys) && parsePositiveVID(c.Keys[i+1]) {
					return fmt.Sprintf("%s.%s", LinuxIfName(ifName), c.Keys[i+1])
				}
			}
			for _, ch := range c.Children {
				if len(ch.Keys) >= 2 && ch.Keys[0] == "outer" && parsePositiveVID(ch.Keys[1]) {
					return fmt.Sprintf("%s.%s", LinuxIfName(ifName), ch.Keys[1])
				}
			}
		}
	}
	return ""
}

// untaggedNonzeroUnit15034 reports whether a unit on an untagged parent
// is the #15034 shape: unit number > 0, no positive tag (the caller has
// already established that), and no other device owner. The tunnel test
// is AST-level (a `tunnel` child on the unit or its parent), mirroring
// how compileInterfaces creates unit.Tunnel / shares the interface
// tunnel device; the name tests reuse the canonical class predicates
// so a name no resolver treats as tunnel/loopback is not exempted.
func untaggedNonzeroUnit15034(ifName string, iface, unit *Node, unitName string) bool {
	n, err := strconv.Atoi(unitName)
	if err != nil || n <= 0 {
		return false
	}
	if ifName == "irb" || IsLoopbackIfName(ifName) || IsSecureTunnelIfName(ifName) {
		return false
	}
	if len(iface.FindChildren("tunnel")) > 0 || len(unit.FindChildren("tunnel")) > 0 {
		return false
	}
	// A packed `unit N tunnel ...` tail parses as a tunnel child too
	// (packedBody consumers rely on it); the braced child test above is
	// the same node set compileInterfaces reads.
	return true
}

func collectVlanIDTaggingFromInterfacesNode(ifacesNode *Node, out map[string]vlanIDTaggingFinding) {
	if ifacesNode == nil {
		return
	}
	for _, iface := range ifacesNode.Children {
		ifName := iface.Name()
		if ifName == "" || ifaceTaggingEnabled(iface) {
			continue
		}
		// A declared dotted name (`p.0`, `ge-0/0/5.0`) is an authored
		// interface in its own right (#8994/#9821), not a physical
		// parent: its units' vlan devices derive from the dotted base
		// itself and the #9821 dotted-sibling shapes rely on that. The
		// two-writer disagreement this gate targets is the plain
		// physical/reth parent, so dotted bases are out of scope.
		if strings.Contains(ifName, ".") {
			continue
		}
		for _, unitInst := range namedInstances(iface.FindChildren("unit")) {
			stmts := positiveTagStmts(unitInst.node)
			key := ifName + "\x00" + unitInst.name
			if len(stmts) == 0 {
				// #15034: no positive tag — a non-zero unit number on
				// this untagged parent derives a `.<unit>` device
				// nothing creates. A unit already reported under a
				// tag finding (other node view) keeps that finding.
				if _, seen := out[key]; seen {
					continue
				}
				if !untaggedNonzeroUnit15034(ifName, iface, unitInst.node, unitInst.name) {
					continue
				}
				out[key] = vlanIDTaggingFinding{
					iface: ifName, unit: unitInst.name, untaggedUnit: true,
					dev: fmt.Sprintf("%s.%s", LinuxIfName(ifName), unitInst.name),
				}
				continue
			}
			// Authored device the dataplane writer creates: the
			// linux name plus the tag value, e.g. ge-0-0-0.100.
			dev := authoredVlanDevice(ifName, unitInst.node)
			finding, seen := out[key]
			if !seen {
				out[key] = vlanIDTaggingFinding{iface: ifName, unit: unitInst.name, stmts: stmts, dev: dev}
				continue
			}
			if finding.untaggedUnit {
				// The other node view carries the tag: the #14574
				// finding is the precise one for the union.
				finding.untaggedUnit = false
				finding.dev = dev
			}
			finding.stmts = append(finding.stmts, stmts...)
			out[key] = finding
		}
	}
}

func collectVlanIDTaggingFindingsForNode(tree *ConfigTree, nodeID int, out map[string]vlanIDTaggingFinding) bool {
	clone := tree.Clone()
	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := clone.ExpandGroupsWithVars(vars); err != nil {
		return false
	}
	_, _ = expandInterfaceRanges(clone)
	for _, ifaces := range clone.FindChildren("interfaces") {
		collectVlanIDTaggingFromInterfacesNode(ifaces, out)
	}
	return true
}

// validateVlanIDTaggingAST is the #14574 gate, extended by #15034 to
// the untagged non-zero unit. See file header.
func validateVlanIDTaggingAST(tree *ConfigTree, lenient bool) ([]string, error) {
	findings := make(map[string]vlanIDTaggingFinding)
	expandedAny := collectVlanIDTaggingFindingsForNode(tree, 0, findings)
	expandedAny = collectVlanIDTaggingFindingsForNode(tree, 1, findings) || expandedAny
	if !expandedAny {
		for _, ifaces := range tree.FindChildren("interfaces") {
			collectVlanIDTaggingFromInterfacesNode(ifaces, findings)
		}
	}
	if len(findings) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(findings))
	for k := range findings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var warnings []string
	for _, k := range keys {
		msg := findings[k].message()
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
	}
	return warnings, nil
}
