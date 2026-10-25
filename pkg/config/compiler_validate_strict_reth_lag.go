package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateRethMultiChildAST rejects a reth that names more than one
// local child per cluster node (#16586).
//
// Junos models two or more child interfaces per node on one reth as a
// reth LAG (up to 8 per node): if one link in the primary aggregate
// fails, its traffic load is taken up by the remaining links. xpf
// implements no reth LAG. RethToPhysical keeps ONE member per reth
// (best slot score, then the lexically-first name), and the dataplane
// gives every member with a RedundantParent the reth's effective
// config plus a 169.254.<rg>.<node+1>/32 link-local
// (pkg/dataplane/compiler_iface.go). Before this gate the extra
// children therefore came up managed UP with a duplicate 169.254
// source, no security zone and their physical MAC, while the VIP,
// virtual MAC and zone landed only on the lexically-first child —
// the configured intra-node redundancy and bandwidth were silently
// lost, contrary to the accepted-only doctrine (#2078/#4231/#5804,
// applied to ae in #6544).
//
// Locality is the FPC slot, exactly as RethToPhysical scores it:
// slot 0 is node 0, slot 7 is node 1 (SlotToNodeID), any other parsed
// slot keeps its own node bucket, and an unparseable name (slot -1)
// forms a single unknown bucket. The canonical cluster spelling —
// one ge-0/... child and one ge-7/... child of the same reth — is
// one child per node and is NOT flagged. Names that canonicalise to
// the same kernel device (ge-0/0/1 and its dash spelling ge-0-0-1)
// are ONE child, not two: they name the same port, and the
// ifname-collision gate (#7795) owns that pair.
//
// The gate runs on the PRE-expansion tree and unions three views —
// the authored top level plus every groups block, and the node0 /
// node1 group expansions — so both cluster nodes accept or reject
// identically even when the children are declared only inside
// per-node groups (the #1873/#1914 union pattern). Strict on commit /
// commit-check (hard reject, naming the reth, the node and the
// ignored children); downgraded to a warning on the tolerant load /
// peer-sync paths via opts.lenientRethMultiChild (#1960 no-brick),
// where RethToPhysical's single binding remains the bound.
func validateRethMultiChildAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	// members[parent][node][canonical device] = authored name shown in
	// the diagnostic (the first spelling seen, deterministically the
	// slash spelling when both are authored, as views run in order).
	members := make(map[string]map[int]map[string]string)
	add := func(name, parent string) {
		if name == "" || parent == "" {
			return
		}
		// A dotted name (ge-0/0/1.100) is a unit alias of its base
		// port (#6722 case C), not a second child link.
		if base, _, dotted := SplitIfaceRef(name); dotted {
			name = base
		}
		if strings.HasPrefix(name, "reth") {
			// A reth naming a redundant parent is #6722's clause, not
			// a child link; counting it here would double-diagnose.
			return
		}
		byNode, ok := members[parent]
		if !ok {
			byNode = make(map[int]map[string]string)
			members[parent] = byNode
		}
		node := -1
		if slot := InterfaceSlot(name); slot >= 0 {
			node = SlotToNodeID(slot)
		}
		// One bucket per canonical device so slash/dash spellings of
		// the same port count once; the authored name is what the
		// operator wrote and what the diagnostic must name.
		dev := LinuxIfName(name)
		set, ok := byNode[node]
		if !ok {
			set = make(map[string]string)
			byNode[node] = set
		}
		if _, ok := set[dev]; !ok {
			set[dev] = name
		}
	}
	collect := func(view *ConfigTree) {
		for _, ifaces := range view.FindChildren("interfaces") {
			collectRethMembersAST(ifaces, add)
		}
	}
	// View 1: pre-expansion union (top level + every groups block).
	collect(tree)
	for _, child := range tree.Children {
		if child == nil || child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			if group == nil {
				continue
			}
			for _, ifaces := range group.FindChildren("interfaces") {
				collectRethMembersAST(ifaces, add)
			}
		}
	}
	// Views 2/3: node0 / node1 expansions, so children supplied only
	// by an applied per-node group (or an interface-range / wildcard
	// group) are seen even if view 1 missed their concrete names.
	// Expansion failure contributes nothing (best-effort, #1914).
	for _, nodeID := range []int{0, 1} {
		view := tree.Clone()
		vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
		if err := view.ExpandGroupsWithVarsTagged(vars); err != nil {
			continue
		}
		collectExpandedRethMembers(view, add)
	}

	parents := make([]string, 0, len(members))
	for parent := range members {
		parents = append(parents, parent)
	}
	sort.Strings(parents)
	var warnings []string
	for _, parent := range parents {
		nodes := make([]int, 0, len(members[parent]))
		for node := range members[parent] {
			nodes = append(nodes, node)
		}
		sort.Ints(nodes)
		for _, node := range nodes {
			set := members[parent][node]
			if len(set) < 2 {
				continue
			}
			children := make([]string, 0, len(set))
			for _, authored := range set {
				children = append(children, authored)
			}
			sort.Strings(children)
			kept := children[0]
			ignored := children[1:]
			nodeLabel := fmt.Sprintf("node %d", node)
			if node < 0 {
				nodeLabel = "the node whose FPC slot cannot be determined from the interface name"
			}
			msg := fmt.Sprintf(
				"redundant-ethernet interface %q has %d local children on %s (%s); "+
					"xpf does not implement reth LAG (Junos allows two or more child "+
					"interfaces per node on one reth, up to 8, with the remaining links "+
					"taking over a failed link's load) — only %q is bound as the member "+
					"of %q and carries its addresses, virtual MAC and security zone, "+
					"while %s would come up zoneless with a duplicate 169.254 "+
					"link-local address and its physical MAC and would carry no traffic "+
					"for %q. Keep one child per node on %q, or move the extra children "+
					"to another reth (#16586)",
				parent, len(children), nodeLabel, strings.Join(children, ", "),
				kept, parent,
				strings.Join(ignored, ", "), parent, parent)
			if !lenient {
				return nil, fmt.Errorf("%s", msg)
			}
			warnings = append(warnings,
				"reth LAG (downgraded to warning on tolerant path): "+msg)
		}
	}
	return warnings, nil
}

func collectRethMembersAST(ifaces *Node, add func(name, parent string)) {
	if ifaces == nil {
		return
	}
	for _, child := range ifaces.Children {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		name := child.Keys[0]
		if strings.ContainsAny(name, "<>*") {
			continue
		}
		body := packedBody(expandResolvingRun9792(child, interfaceSchema9792()), interfaceSchema9792())
		goNode := body.FindChild("gigether-options")
		if goNode == nil {
			continue
		}
		goNode = expandResolvingRun9792(goNode, gigetherOptionsSchema9792())
		rp := goNode.FindChild("redundant-parent")
		if rp == nil {
			continue
		}
		if parent := nodeVal(rp); parent != "" {
			add(name, parent)
		}
	}
}

// collectExpandedRethMembers compiles the expanded view's interfaces
// leniently and collects redundant-parent members from the typed
// result, so packed spellings the AST walk cannot resolve still
// count. A compile error contributes nothing (best-effort union).
func collectExpandedRethMembers(view *ConfigTree, add func(name, parent string)) {
	ifacesNodes := view.FindChildren("interfaces")
	if len(ifacesNodes) == 0 {
		return
	}
	ifaces := InterfacesConfig{Interfaces: make(map[string]*InterfaceConfig)}
	for _, ifacesNode := range ifacesNodes {
		if err := compileInterfaces(ifacesNode, &ifaces, compileOpts{lenientNonNumericUnit: true}, nil); err != nil {
			return
		}
	}
	names := make([]string, 0, len(ifaces.Interfaces))
	for name := range ifaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if ifc := ifaces.Interfaces[name]; ifc != nil && ifc.RedundantParent != "" {
			add(name, ifc.RedundantParent)
		}
	}
}
