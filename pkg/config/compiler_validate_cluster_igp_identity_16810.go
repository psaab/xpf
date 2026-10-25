package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateClusterIGPIdentityStrict rejects a non-node-specific IGP
// identity that would be originated by both cluster nodes at once
// during an active/active RG split (#16810).
//
// One config is synced to both nodes. `routing-options router-id X`
// (or an explicit `protocols ospf router-id X` / `ospf3 router-id X`)
// compiles to the same OSPF/OSPFv3 RouterID on both nodes, and a
// shared IS-IS NET does the same for IS-IS. The daemon's per-RG HA
// filter (#11415) then keeps each node's owned RETH interfaces, so
// during a split (RG1 on node0, RG2 on node1) both ospfd/ospf6d/
// isisd processes originate router-LSAs / LSPs under ONE identity.
// RFC 2328 §1.2 requires the Router ID to uniquely identify a router
// within the AS: neighbours keep only the newest self-originated
// LSA, the other node's RETH prefixes vanish area-wide, and the
// surviving prefixes are ECMP'd to both nodes — including the node
// that does not own them.
//
// The gate fires only when the split is actually reachable from the
// compiled config:
//
//   - the config is a cluster config (Chassis.Cluster != nil);
//   - a protocol carries a non-empty identity (after
//     resolveRoutingOptionsRouterID inheritance, so an inherited
//     routing-options router-id counts exactly like an explicit
//     protocol router-id); and
//   - that protocol's ENABLED interfaces, after resolving each
//     interface to its RETH redundancy group, span more than one
//     DISTINCT data RG (>0). Interfaces with no RETH owner —
//     node-local ge/xe/lo, or interfaces attributable only via a
//     routing instance's interface list — are RG-unscoped and do
//     not count: they follow RG0 (see daemon's inactiveInterface),
//     so they cannot by themselves put both nodes into the IGP.
//     Disabled protocols and disabled interfaces render nothing
//     and do not count either.
//
// A node-specific identity is the Junos escape: `groups { node0 {
// protocols { ospf { router-id … } } } node1 { … } }` with
// `apply-groups "${node}"`. That idiom only materialises distinct
// values in the per-node compiles (CompileConfigForNode), while the
// generic compile resolves ${node} with the node0 fallback and sees
// just one value. The commit pipeline's peer gate
// (compileTreeStrict → CompileConfigForNode for the peer) runs this
// same gate on the peer's view, so a config that is distinct on
// each node still commits cleanly there — see
// igpIdentityNodeViewsDistinct16810, which the AST-level pre-check
// uses to keep the generic compile from rejecting the idiom before
// the per-node views are ever compiled.
//
// Strict on commit / commit-check (hard reject naming the protocol,
// identity, and the RGs involved, with the ${node} remedy); tolerant
// load / peer-sync downgrade to a warning via
// opts.lenientClusterIGPIdentity16810 (#1960 no-brick), where the
// daemon's single-participant render belt keeps the leniently
// loaded duplicate inert (only the lowest-numbered active data RG
// participates; see pkg/daemon filterProtocols).
func validateClusterIGPIdentityStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	scopes := igpIdentityScopes16810(cfg)
	for _, sc := range scopes {
		if sc.identity == "" {
			continue
		}
		rgs := sc.rgs
		if len(rgs) < 2 {
			continue
		}
		return fmt.Errorf("%s: cluster IGP identity %q is shared by both cluster nodes "+
			"while %s interfaces span redundancy groups %s — in an active/active split "+
			"both nodes originate LSAs under router-id/NET %q, so neighbours keep only "+
			"one node's prefixes and ECMP the rest to a node that does not own them "+
			"(RFC 2328 §1.2 requires a unique router-id per router). Configure a "+
			"node-specific identity via groups node0/node1 with apply-groups \"${node}\", "+
			"or confine %s to RETHs of a single redundancy group (#16810)",
			sc.scopeLabel, sc.identity, sc.protoLabel, formatRGList16810(rgs), sc.identity, sc.protoLabel)
	}
	return nil
}

// igpIdentityTreeHasNodeVarIGP16810 reports whether the PRE-
// EXPANSION tree carries a `groups node0` or `groups node1` body
// that sets an OSPF/OSPFv3 router-id or IS-IS NET under protocols
// (global or routing-instance scope), while an apply-groups
// "${node}" reference exists. Leaves outside a node group are
// shared by construction, so only node-group bodies can make the
// per-node identities distinct. This cheap AST probe gates the
// (relatively expensive) both-node-views comparison in
// igpIdentityNodeViewsDistinct16810.
func igpIdentityTreeHasNodeVarIGP16810(tree *ConfigTree) bool {
	if tree == nil {
		return false
	}
	if !treeHasNodeVarApplyGroups15031(tree.Children) {
		return false
	}
	for _, child := range tree.Children {
		if child == nil || child.Name() != "groups" {
			continue
		}
		for _, group := range child.Children {
			if group == nil || len(group.Keys) == 0 {
				continue
			}
			if group.Keys[0] != "node0" && group.Keys[0] != "node1" {
				continue
			}
			if nodeGroupHasIGPIdentity16810(group) {
				return true
			}
		}
	}
	return false
}

// nodeHasIGPIdentity16810 reports whether a node-group body sets an
// IGP identity leaf anywhere under a protocols subtree (including
// routing-instances protocols, whose AST nests the same way).
func nodeHasIGPIdentity16810(n *Node) bool {
	if n == nil {
		return false
	}
	if n.Name() == "router-id" || n.Name() == "net" {
		// Only count it under a protocols ancestor is guaranteed by
		// the caller descending through protocols subtrees; the walk
		// below enforces that by starting at protocols children.
		return true
	}
	for _, c := range n.Children {
		if nodeHasIGPIdentity16810(c) {
			return true
		}
	}
	return false
}

func nodeGroupHasIGPIdentity16810(group *Node) bool {
	for _, child := range group.Children {
		if child == nil {
			continue
		}
		if child.Name() == "protocols" && nodeHasIGPIdentity16810(child) {
			return true
		}
		if child.Name() == "routing-instances" && nodeHasIGPIdentity16810(child) {
			return true
		}
	}
	return false
}

// igpIdentityNodeViewsDistinct16810 reports whether the two per-node
// views of the PRE-EXPANSION tree carry distinct identities for
// every protocol scope that can span data RGs. It full-compiles
// (leniently, which still records the same identities) node0 and
// node1 via compileTree, so packed spellings, group nesting and
// routing-options inheritance all resolve exactly as the real
// per-node compiles do.
//
// A scope is excused when the two views' identities differ (both
// non-empty). A scope that spans in one view but is absent/empty in
// the other is NOT excused by that scope alone — the missing view
// would auto-derive, but this helper only excuses the explicit
// distinct-identity idiom.
//
// Returns false when the tree has no node-group IGP identity (fast
// path for ordinary strict rejects), either view fails to compile,
// or every spanning scope is not distinctly identified per node.
func igpIdentityNodeViewsDistinct16810(tree *ConfigTree) bool {
	if !igpIdentityTreeHasNodeVarIGP16810(tree) {
		return false
	}
	views := make([]*Config, 2)
	for nodeID := 0; nodeID <= 1; nodeID++ {
		id := nodeID
		cfg, err := compileTree(tree.Clone(), lenientCompileOpts(), &id)
		if err != nil || cfg == nil || cfg.Chassis.Cluster == nil {
			return false
		}
		views[nodeID] = cfg
	}
	// Collect every scope that spans >=2 data RGs in EITHER view
	// (or carries an identity in either view): it must be distinct.
	keys := map[string]bool{}
	for _, view := range views {
		for _, sc := range igpIdentityScopes16810(view) {
			if len(sc.rgs) >= 2 || sc.identity != "" {
				keys[sc.key] = true
			}
		}
	}
	excused := false
	for key := range keys {
		var ids [2]string
		var spans [2]bool
		for n, view := range views {
			for _, sc := range igpIdentityScopes16810(view) {
				if sc.key == key {
					ids[n] = sc.identity
					spans[n] = len(sc.rgs) >= 2
				}
			}
		}
		if !spans[0] && !spans[1] {
			continue
		}
		if ids[0] == "" || ids[1] == "" || ids[0] == ids[1] {
			return false
		}
		excused = true
	}
	return excused
}

type igpIdentityScope16810 struct {
	key        string // stable scope identity (protocol + instance)
	scopeLabel string // human prefix for diagnostics, "" for global
	protoLabel string // e.g. "protocols ospf"
	identity   string
	rgs        []int // distinct data RGs (>0), sorted
}

// igpIdentityScopes16810 enumerates every OSPF/OSPFv3/IS-IS scope in
// cfg (global protocols plus each routing instance) with its
// identity and the distinct RETH data RGs its enabled interfaces
// resolve to.
func igpIdentityScopes16810(cfg *Config) []igpIdentityScope16810 {
	owners := cfg.RethRGOwners()
	rgOf := func(name string) (int, bool) {
		if rg, ok := owners[name]; ok {
			return rg, true
		}
		if base, _, dotted := SplitIfaceRef(name); dotted {
			if rg, ok := owners[base]; ok {
				return rg, true
			}
		}
		return 0, false
	}
	distinctDataRGs := func(names []string) []int {
		set := map[int]bool{}
		for _, n := range names {
			if rg, ok := rgOf(n); ok && rg > 0 {
				set[rg] = true
			}
		}
		out := make([]int, 0, len(set))
		for rg := range set {
			out = append(out, rg)
		}
		sort.Ints(out)
		return out
	}

	var scopes []igpIdentityScope16810
	add := func(key, scopeLabel string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, isis *ISISConfig) {
		prefix := ""
		if scopeLabel != "" {
			prefix = scopeLabel + " "
		}
		if ospf != nil && !ospf.Disable {
			var names []string
			for _, area := range ospf.Areas {
				if area == nil {
					continue
				}
				for _, iface := range area.Interfaces {
					if iface != nil && !iface.Disable {
						names = append(names, iface.Name)
					}
				}
			}
			scopes = append(scopes, igpIdentityScope16810{
				key: key + "/ospf", scopeLabel: prefix + "protocols ospf",
				protoLabel: "protocols ospf", identity: ospf.RouterID,
				rgs: distinctDataRGs(names),
			})
		}
		if ospfv3 != nil && !ospfv3.Disable {
			var names []string
			for _, area := range ospfv3.Areas {
				if area == nil {
					continue
				}
				for _, iface := range area.Interfaces {
					if iface != nil && !iface.Disable {
						names = append(names, iface.Name)
					}
				}
			}
			scopes = append(scopes, igpIdentityScope16810{
				key: key + "/ospf3", scopeLabel: prefix + "protocols ospf3",
				protoLabel: "protocols ospf3", identity: ospfv3.RouterID,
				rgs: distinctDataRGs(names),
			})
		}
		if isis != nil && !isis.Disable {
			var names []string
			for _, iface := range isis.Interfaces {
				if iface != nil && !iface.Disable {
					names = append(names, iface.Name)
				}
			}
			scopes = append(scopes, igpIdentityScope16810{
				key: key + "/isis", scopeLabel: prefix + "protocols isis",
				protoLabel: "protocols isis", identity: isis.NET,
				rgs: distinctDataRGs(names),
			})
		}
	}
	add("global", "", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.ISIS)
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		add("instance/"+ri.Name, fmt.Sprintf("routing-instance %s", ri.Name),
			ri.OSPF, ri.OSPFv3, ri.ISIS)
	}
	return scopes
}

func formatRGList16810(rgs []int) string {
	parts := make([]string, len(rgs))
	for i, rg := range rgs {
		parts[i] = fmt.Sprintf("RG%d", rg)
	}
	return strings.Join(parts, ", ")
}
