package config

import (
	"fmt"
	"strconv"
)

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

// bgpNeighborBody14409 returns the statements of ONE neighbor node in the
// shape applyBGPNeighborProps9192's switch reads.
//
// A braced neighbor carries its statements as Children, and that is what
// this reader historically iterated — so a PACKED neighbor line
// (`neighbor 10.0.0.1 passive authentication-key K;`) arrived with
// Children == [] and installed nothing at all: no passive, no peer-as,
// and in particular no authentication-key, leaving the session to come
// up with no TCP-MD5 while `show configuration` still displayed the key
// (#14409). Rescue depended entirely on the #8662 normalizer fold, which
// never fires for unscoped heads (passive, route-reflector-client,
// default-originate, family, bfd-liveness-detection, remove-private)
// and is declined by #8880 whenever the following group-level sibling
// shares a keyword with the neighbor grammar (export, peer-as, ...).
//
// packedBodyChildren expands the packed tail schema-driven (the same
// reader the group loop and the OSPF interface loop use): with no tail
// it returns Children unchanged, and a tail that leaves the modelled
// grammar also returns Children unchanged rather than guessing. When a
// node carries both a tail and braced children, packedBodyChildren
// either attaches those children under the deepest packed node (where
// the grammar permits a body there) or, for a leaf terminal, returns
// the children unexpanded — either way no statement is read twice or
// dropped by this substitution.
func bgpNeighborBody14409(child *Node, schema *schemaNode) []*Node {
	if child == nil {
		return nil
	}
	body := packedBodyChildren(child, schema)
	// packedBodyChildren models `export`/`import` as multi leaves, so a
	// following packed statement can be fused into the value span in
	// EITHER of two shapes:
	//   - on the neighbor node's own Keys (`neighbor 10.0.0.1 export EP
	//     authentication-key K;`), where the expansion synthesizes one
	//     node carrying all four tokens; or
	//   - nested under the neighbor by the #8662 normalizer fold
	//     (`neighbor 10.0.0.1` > `export EP authentication-key K`), where
	//     the fused node arrives as a real child.
	// In both, firewallMatchValues would install the keyword and the
	// key as two extra policies while the key itself never arrives.
	// Between two statements of a packed run the split is unambiguous —
	// a bare, unbracketed neighbor-grammar keyword at a statement
	// position cannot be a policy-name value (a policy actually named
	// that way must be quoted, and bracketed lists are excluded below)
	// — so split fused multi leaves at such keywords. This is safe for
	// braced children too: a braced `export { EP; }` carries EP as a
	// child node, not in Keys, so it never matches the scan; the only
	// Keys-carrying shape is the fused one.
	body = splitFusedMultiLeaves14409(body, schema)
	return body
}

// splitFusedMultiLeaves14409 splits a synthesized multi-value leaf whose
// key span fused a following packed statement (see bgpNeighborBody14409).
func splitFusedMultiLeaves14409(body []*Node, schema *schemaNode) []*Node {
	if schema == nil {
		return body
	}
	for i, prop := range body {
		if prop == nil || len(prop.Keys) < 2 || len(prop.Children) > 0 {
			continue
		}
		head := resolveSchemaChild(schema, prop.Keys[0])
		if head == nil || !head.multi {
			continue
		}
		cut := -1
		for j := 1; j < len(prop.Keys); j++ {
			if prop.KeyBracketed(j) || prop.KeyQuoted(j) {
				continue
			}
			if resolveSchemaChild(schema, prop.Keys[j]) != nil {
				cut = j
				break
			}
		}
		if cut < 0 {
			continue
		}
		first := &Node{Keys: append([]string(nil), prop.Keys[:cut]...), InheritedFrom: prop.InheritedFrom}
		rest := &Node{Keys: append([]string(nil), prop.Keys[cut:]...), InheritedFrom: prop.InheritedFrom}
		if len(prop.KeysQuoted) == len(prop.Keys) {
			first.setKeysQuoted(append([]bool(nil), prop.KeysQuoted[:cut]...))
			rest.setKeysQuoted(append([]bool(nil), prop.KeysQuoted[cut:]...))
		}
		if len(prop.KeysBracketed) == len(prop.Keys) {
			first.setKeysBracketed(append([]bool(nil), prop.KeysBracketed[:cut]...))
			rest.setKeysBracketed(append([]bool(nil), prop.KeysBracketed[cut:]...))
		}
		// The tail after the cut is itself a packed run; expand it so a
		// chain (`export EP peer-as 65002 authentication-key K`) splits
		// fully rather than stranding everything after the first keyword.
		tail := packedBodyTail14409(rest, schema)
		out := append([]*Node(nil), body[:i]...)
		out = append(out, first)
		out = append(out, tail...)
		out = append(out, body[i+1:]...)
		// Re-scan: a tail node may itself be a fused multi leaf.
		return splitFusedMultiLeaves14409(out, schema)
	}
	return body
}

// packedBodyTail14409 expands one already-split packed statement node
// (Keys = [keyword, ...run]) into the sibling statements of the run it
// heads, by re-homing its keys under a synthetic neighbor identity and
// asking packedBodyChildren to walk them.
func packedBodyTail14409(rest *Node, schema *schemaNode) []*Node {
	wrapper := &Node{Keys: []string{"neighbor", "0.0.0.0"}, InheritedFrom: rest.InheritedFrom}
	wrapper.Keys = append(wrapper.Keys, rest.Keys...)
	if len(rest.KeysQuoted) == len(rest.Keys) {
		q := []bool{false, false}
		q = append(q, rest.KeysQuoted...)
		wrapper.setKeysQuoted(q)
	}
	if len(rest.KeysBracketed) == len(rest.Keys) {
		b := []bool{false, false}
		b = append(b, rest.KeysBracketed...)
		wrapper.setKeysBracketed(b)
	}
	body := packedBodyChildren(wrapper, schema)
	if len(body) == 0 {
		return []*Node{rest}
	}
	return body
}

func applyBGPNeighborProps9192(neighbor *BGPNeighbor, child *Node, ownExport, ownImport *bool, opts compileOpts, warnings *[]string, warningRecords *[]bgpSAFIWarning11815) error {
	for _, prop := range expandFlatRun(expandResolvingRuns9792(bgpNeighborBody14409(child, bgpNeighborSchema9792()), bgpNeighborSchema9792()), bgpNeighborSchema9792()) { // #9792: expand a lenient-path packed run (#9235); #14409: expand the neighbor's own packed tail (fused multi leaves are split inside bgpNeighborBody14409); expandFlatRun then splits any remaining packed run on a synthesized statement.
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
				n, err := strconv.Atoi(v)
				if err != nil || n == 0 {
					neighbor.AllowASIn = -1
				} else {
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
			applyNeighborFamily := func(familyNode *Node, afi string) error {
				scope := fmt.Sprintf("BGP neighbor %q family %s", neighbor.Address, afi)
				// An explicit per-neighbor inet on an IPv6-literal peer
				// cannot be rendered: xpf has no RFC 8950 extended-next-hop.
				// Without a guard, the IPv4 AF cannot receive its policies;
				// an inet-only peer can land in no AF while FRR's default
				// IPv4-unicast activation claims it without those policies.
				// Use FRRAddrFamily, the shared FRR address predicate (#9820),
				// so IPv4-mapped IPv6 literals classify consistently with
				// group inheritance and rendering.
				if afi == "inet" && FRRAddrFamily(neighbor.Address) == "v6" {
					msg := fmt.Sprintf(
						"%s: family inet on IPv6 peer %q requires RFC 8950 extended-next-hop support, "+
							"which xpf does not render; FRR's default ipv4-unicast can otherwise "+
							"activate this peer without its import/export policy (#12185)",
						scope, neighbor.Address)
					if !opts.lenientBGPCrossFamily12185 {
						return fmt.Errorf("%s", msg)
					}
					// Retain SAFI diagnostics on tolerant cross-family peers too.
					// This family remains inert, but unsupported SAFI evidence and
					// its merged-activation warning still belong to the compiler.
					_, unsupported, err := applyBGPFamilySAFI11815(familyNode, afi, scope, opts, warnings, warningRecords)
					if err != nil {
						return err
					}
					neighbor.UnsupportedInetSAFI = neighbor.UnsupportedInetSAFI || unsupported
					if !neighbor.CrossFamilyInet && warnings != nil {
						*warnings = append(*warnings, msg)
					}
					neighbor.CrossFamilyInet = true
					// A family inherited from a group is equally inert on this
					// peer; clear it so the renderer takes the explicit IPv4
					// deactivation arm instead of losing the peer in no AF.
					neighbor.FamilyInet = false
					return nil
				}
				unicast, unsupported, err := applyBGPFamilySAFI11815(familyNode, afi, scope, opts, warnings, warningRecords)
				if err != nil {
					return err
				}
				if afi == "inet" {
					neighbor.FamilyInet = neighbor.FamilyInet || unicast
					neighbor.UnsupportedInetSAFI = neighbor.UnsupportedInetSAFI || unsupported
					if unicast {
						return applyPrefixLimit11793(familyNode, &neighbor.PrefixLimitInet, false, scope, opts, warnings)
					}
					return nil
				}
				neighbor.FamilyInet6 = neighbor.FamilyInet6 || unicast
				neighbor.UnsupportedInet6SAFI = neighbor.UnsupportedInet6SAFI || unsupported
				if unicast {
					return applyPrefixLimit11793(familyNode, &neighbor.PrefixLimitInet6, false, scope, opts, warnings)
				}
				return nil
			}
			if len(prop.Keys) >= 2 {
				switch prop.Keys[1] {
				case "inet":
					if err := applyNeighborFamily(prop, "inet"); err != nil {
						return err
					}
				case "inet6":
					if err := applyNeighborFamily(prop, "inet6"); err != nil {
						return err
					}
				}
			} else {
				for _, fc := range prop.Children {
					switch fc.Name() {
					case "inet":
						if err := applyNeighborFamily(fc, "inet"); err != nil {
							return err
						}
					case "inet6":
						if err := applyNeighborFamily(fc, "inet6"); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}
