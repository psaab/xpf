package config

import "strconv"

// BGP NEIGHBOR NODE MERGE (#9192).
//
// `compileBGP` appended one `*BGPNeighbor` per AST NODE, and one authored
// neighbor is not always one node. `SetPath` does not reuse a node it has
// already marked `IsLeaf`, so a bare declaration followed by a sub-leaf becomes
// two siblings — ordinary flat-set authoring, and the shape this package's own
// slot-escape fixtures use:
//
//	set protocols bgp group G neighbor 10.0.2.2
//	set protocols bgp group G neighbor 10.0.2.2 import PS
//	  -> [neighbor 10.0.2.2]
//	     [neighbor 10.0.2.2] > [import PS]
//	  -> neighbors=2   [0] import=[]   [1] import=[PS]
//
// The rendered FRR output was REDUNDANT rather than wrong — a repeated
// `remote-as` is accepted, and the `activate` / route-map lines only the second
// entry carried were still emitted — which is why nothing caught it, and it is
// not why this is worth fixing.
//
// The duplication is invisible in the typed config's contract, so ANYTHING
// reasoning over `BGP.Neighbors` as a set of peers is wrong by construction and
// each new consumer has to rediscover it. Two already did, while #9007 was being
// fixed: a duplicate-address check keyed on `Address` alone reported a peer as
// "configured in more than one group (G and G)" — the same group twice — and
// false-rejected a legitimate config; and a first-wins dedup at the renderer's
// `validNeighbors` silently dropped the policy-bearing entry along with its
// `activate` and `route-map … in` lines. Both were caught by existing cells and
// reverted, and `pkg/frr/README.md` records the second so the next person
// reaching for that layer finds the reason first.
//
// THE THREE BOUNDARIES, each measured and each pinned by a cell in
// bgp_neighbor_node_merge_9192_test.go:
//
//   - Two DISTINCT addresses never fold: they do not share the key.
//   - The CROSS-GROUP case never folds. Two groups naming one address with
//     divergent `peer-as`, timers and authentication keys is #9007's genuinely
//     ambiguous shape, resolved by render order and rejected at commit by PR
//     #9191. The key is the PAIR precisely so that folding here cannot silently
//     resolve an ambiguity the operator is meant to be told about.
//   - Two `group G` BLOCKS naming one address DO share the key. That config is
//     rejected at strict commit by the #5180 duplicate-block gate, so the
//     behaviour is reachable only on the lenient boot / HA-sync path. There the
//     merged neighbor keeps the FIRST block's group-level defaults and unions
//     both blocks' per-neighbor statements, instead of two entries whose group
//     defaults disagree and which the renderer emits BOTH of.
//
// Group defaults are applied on CREATE only. Re-applying them for a later node
// would wipe the per-neighbor overrides an earlier node set, which is the drop
// this merge exists to prevent — measured: with the props-then-bare ordering the
// description survives.
//
// `neighborOwnExport` / `neighborOwnImport` — the #5277 most-specific-LEVEL-wins
// flags — moved from per-NODE locals to per-NEIGHBOR state for the same reason.
// They were correct while one node meant one neighbor; with several nodes per
// neighbor a per-node flag makes the SECOND node's first `export` wipe the FIRST
// node's own list, turning the union back into a last-node-wins drop, silently.

// findBGPNeighbor9192 returns the already-compiled neighbor for
// (group, address) within one BGP instance, or nil.
func findBGPNeighbor9192(neighbors []*BGPNeighbor, group, addr string) *BGPNeighbor {
	for _, n := range neighbors {
		if n != nil && n.GroupName == group && n.Address == addr {
			return n
		}
	}
	return nil
}

// applyBGPNeighborProps9192 applies ONE neighbor AST node's own statements onto
// an already-constructed *BGPNeighbor.
//
// Split out of compileProtocols in #9192, and the split is the change rather
// than tidying alongside it: this loop used to run exactly once per neighbor,
// because the caller created a fresh struct per AST node. It now runs once per
// NODE onto a SHARED neighbor, so `ownExport` / `ownImport` are pointers into
// the caller's per-NEIGHBOR state instead of locals — the #5277
// most-specific-LEVEL-wins flags have to survive from one node to the next or
// the second node's first `export` wipes the first node's own list.
func applyBGPNeighborProps9192(neighbor *BGPNeighbor, child *Node, ownExport, ownImport *bool) {
	for _, prop := range expandResolvingRuns9792(child.Children, bgpNeighborSchema9792()) { // #9792: expand a lenient-path packed run (#9235).
		switch prop.Name() {
		case "description":
			neighbor.Description = nodeVal(prop)
		case "multihop":
			if v := nodeVal(prop); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					neighbor.MultihopTTL = n
				}
			}
		case "peer-as":
			if v := nodeVal(prop); v != "" {
				// #4713: no silent uint32 wrap — leave the
				// inherited group peer-as in place on a
				// negative/oversized override (inert on
				// lenient load; the renderer skips a
				// remote-as-0 neighbor).
				if n, ok := parseASNumber(v); ok {
					neighbor.PeerAS = n
				}
			}
		case "local-as":
			if v := nodeVal(prop); v != "" {
				if n, ok := parseASNumber(v); ok {
					neighbor.LocalAS = n
				}
			}
		case "local-address":
			neighbor.LocalAddress = nodeVal(prop)
		case "hold-time":
			if v := nodeVal(prop); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					neighbor.HoldTime = n
				}
			}
		case "passive":
			neighbor.Passive = true
		case "authentication-key":
			neighbor.AuthPassword = Secret(nodeVal(prop))
		case "route-reflector-client":
			neighbor.RouteReflectorClient = true
		case "default-originate":
			neighbor.DefaultOriginate = true
		case "bfd-liveness-detection":
			neighbor.BFD = true
			for _, bc := range prop.Children {
				switch bc.Name() {
				case "minimum-interval":
					if v := nodeVal(bc); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							neighbor.BFDInterval = n
						}
					}
				case "multiplier":
					if v := nodeVal(bc); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							neighbor.BFDMultiplier = n
						}
					}
				}
			}
		case "loops":
			if v := nodeVal(prop); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					neighbor.AllowASIn = n
				}
			}
		case "remove-private":
			neighbor.RemovePrivateAS = true
		case "export":
			// Per-neighbor export override (#2490 made
			// the per-neighbor slot parseable; group-level
			// export is already inherited above). The
			// neighbor's OWN export REPLACES the inherited
			// group export (Junos most-specific-LEVEL-wins,
			// #5277): the first own entry drops the inherited
			// group list, then this and any further
			// neighbor-level entries accumulate as the
			// neighbor's ordered chain. Pre-#5277 this
			// APPENDED to the group list and the renderer
			// kept only the last (lastNonEmpty), which both
			// dropped a multi-policy neighbor chain AND kept
			// the wrong policy when the neighbor overrode a
			// group export.
			//
			// Multi-value leaf (#2702): a bracket-list
			// `export [ p1 p2 ]` collapses every policy onto
			// prop.Keys[1:] (flat-set) or onto child nodes
			// (hierarchical). The old nodeVal-first read
			// returned Keys[1] and dropped all but the first
			// policy; firewallMatchValues accumulates both
			// AST shapes.
			if !*ownExport {
				neighbor.Export = nil
				*ownExport = true
			}
			neighbor.Export = append(neighbor.Export, firewallMatchValues(prop)...)
		case "import":
			// Per-neighbor import override (#2490/#5277):
			// the neighbor's OWN import REPLACES the
			// inherited group import (most-specific level
			// wins), symmetric to export above. Multi-value
			// (#2702) — accumulate every policy across both
			// AST shapes via firewallMatchValues.
			if !*ownImport {
				neighbor.Import = nil
				*ownImport = true
			}
			neighbor.Import = append(neighbor.Import, firewallMatchValues(prop)...)
		case "family":
			if len(prop.Keys) >= 2 {
				switch prop.Keys[1] {
				case "inet":
					neighbor.FamilyInet = true
					if pl := parsePrefixLimit(prop); pl > 0 {
						neighbor.PrefixLimitInet = pl
					}
				case "inet6":
					neighbor.FamilyInet6 = true
					if pl := parsePrefixLimit(prop); pl > 0 {
						neighbor.PrefixLimitInet6 = pl
					}
				}
			} else {
				for _, fc := range prop.Children {
					switch fc.Name() {
					case "inet":
						neighbor.FamilyInet = true
						if pl := parsePrefixLimit(fc); pl > 0 {
							neighbor.PrefixLimitInet = pl
						}
					case "inet6":
						neighbor.FamilyInet6 = true
						if pl := parsePrefixLimit(fc); pl > 0 {
							neighbor.PrefixLimitInet6 = pl
						}
					}
				}
			}
		}
	}
}
