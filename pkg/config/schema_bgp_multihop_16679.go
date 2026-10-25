package config

import (
	"fmt"
	"strconv"
	"strings"
)

// #16679: BGP `multihop` was an xpf-only scalar `multihop <ttl>` leaf.
// Junos spells it as a presence container:
//
//	multihop;                     (eBGP multihop at the Junos default TTL 64)
//	multihop { ttl N; }           (explicit TTL, 1..255)
//	multihop no-nexthop-change;   (packed modifier, optionally with ttl)
//
// and the flat-set twin of the block spelling is `multihop ttl N`.
// Every one of those was rejected at commit ("missing value" / "not an
// integer") while `multihop 2` — a spelling Junos never emits — was the
// only form that committed.
//
// The schema models `multihop` as what Junos says it is: a typed leaf
// whose first token is the TTL and whose `ttl` / `no-nexthop-change`
// children are modifiers (schema_walk.go's typed-leaf modifier
// machinery, #9880), plus a nodeValidator (validateBGPMultihop16679)
// for the shapes that machinery cannot express:
//
//   - the bare presence form (`multihop;` / `set ... multihop`) carries
//     no value token at all;
//   - `no-nexthop-change` is REFUSED BY NAME until it is rendered. xpf
//     compiles eBGP peers through FRR `neighbor X ebgp-multihop <ttl>`,
//     which rewrites the next hop of routes received from an external
//     peer; Junos' `no-nexthop-change` asks for the opposite (retain the
//     received next hop), and FRR has no per-neighbor equivalent
//     (only the route-server-client construct implies it). Rendering
//     the TTL while dropping the flag would silently invert the
//     route-propagation behaviour the operator configured, so the
//     statement is refused wherever it appears — packed, blocked or
//     flat — on both the strict schema gate (this validator) and the
//     tolerant compile paths (warnBGPMultihop16679 below).
//
// Rendering: every accepted form lands in BGPNeighbor.MultihopTTL and
// renders the existing FRR line `neighbor X ebgp-multihop <ttl>`. The
// ttl-less forms resolve to the Junos default below.

// bgpMultihopDefaultTTL16679 is Junos' default maximum TTL for a
// multihop eBGP session when no `ttl` statement is given (Junos OS BGP
// multihop documentation: "The default TTL value is 64 for multihop
// EBGP sessions"). A bare `multihop;` therefore renders
// `ebgp-multihop 64`, matching what Junos would put on the wire.
const bgpMultihopDefaultTTL16679 = 64

// bgpMultihopSchema16679 builds the group- and neighbor-level `multihop`
// schema node. A fresh node per call site, mirroring the other
// per-level BGP leaves: the two sites must not share fate if one is
// ever specialised.
func bgpMultihopSchema16679() *schemaNode {
	return &schemaNode{
		desc: "Multihop eBGP session (bare = Junos default TTL 64; `multihop <ttl>` and `multihop { ttl N; }` pin the TTL)",
		args: 1,
		// The TTL slot: same range the scalar leaf enforced before
		// #16679 (Junos ttl range for multihop is 1..255).
		placeholder:   "<ttl>",
		valueType:     ValueInteger,
		valueDesc:     "Multihop TTL (1..255); omit for the Junos default 64",
		valueExamples: []string{"2", "64"},
		validator:     ValidateInteger(1, 255),
		nodeValidator: validateBGPMultihop16679,
		children: map[string]*schemaNode{
			// `multihop ttl N` / `multihop { ttl N; }`: the canonical
			// Junos spelling of the pinned TTL. The typed-leaf
			// machinery validates N against this node's validator.
			"ttl": {desc: "Multihop TTL (1..255)", args: 1, valueType: ValueInteger, placeholder: "<ttl>", validator: ValidateInteger(1, 255), children: nil},
			// Modelled ONLY so it is REFUSED by name (see header):
			// presence-only, so any value packed after it is an
			// unknown-modifier error, not a silently dropped token.
			"no-nexthop-change": {desc: "no-nexthop-change (not implemented by xpf; rejected at commit — see #16679)", children: nil},
		},
	}
}

// bgpMultihopRefusal16679 is the shared refusal text for
// `no-nexthop-change`, used by the schema validator and the tolerant
// compile-path warning so both name the same reason.
func bgpMultihopRefusal16679() string {
	return "multihop no-nexthop-change is not implemented by xpf: the rendered " +
		"`neighbor X ebgp-multihop <ttl>` rewrites the next hop of routes received " +
		"from the external peer, while no-nexthop-change asks to retain the received " +
		"next hop, and FRR has no per-neighbor equivalent. Remove the " +
		"no-nexthop-change statement (the multihop TTL itself is supported) (#16679)"
}

// validateBGPMultihop16679 is the nodeValidator for the `multihop`
// leaf. walkSchemaNode runs it on an exact schema-key match BEFORE
// the typed-leaf branch, so it owns the shapes that machinery cannot
// express:
//
//   - `multihop no-nexthop-change` in ANY position (packed first
//     token, packed tail, blocked child, flat-set child) refuses by
//     name. The typed-leaf machinery would otherwise either treat the
//     keyword as an unvalidated presence modifier or reject it as a
//     non-integer TTL without ever naming the actual problem.
//   - The bare presence form (`multihop;`, `set ... multihop`) is
//     accepted (see the bare early-return in walkSchemaNode); the
//     Junos default TTL is applied by the compiler extractor.
//   - The `ttl` modifier in EVERY spelling: packed (`multihop ttl
//     2`, hierarchical lexer), flat-set child (`multihop` ->
//     `ttl 2`, where SetPath grouped only `ttl` onto the child and
//     the walk would read `2` as an unmodeled grandchild), and
//     blocked (`multihop { ttl 2; }`). The typed-leaf modifier
//     machinery only validates the packed form, so the range/arity
//     check lives here for all three.
//   - A `ttl` child carrying no value (`multihop { ttl; }`) refuses
//     as a missing value instead of silently resolving to the bare
//     default in the compiler.
//
// The packed scalar form (`multihop 2`, including its 1..255 range)
// and unknown packed modifiers stay with the typed-leaf machinery.
func validateBGPMultihop16679(node *Node, _ *schemaNode) error {
	if node == nil {
		return nil
	}
	// Packed tokens: `multihop no-nexthop-change`,
	// `multihop 2 no-nexthop-change`, `multihop ttl 2 no-nexthop-change`.
	for _, tok := range node.Keys[1:] {
		if tok == "no-nexthop-change" {
			return fmt.Errorf("%s", bgpMultihopRefusal16679())
		}
	}
	// Flat-set packed shape: `multihop ttl` with the TTL as the sole
	// CHILD token (child Keys=["256"], or ["0","passive"] fused).
	// The child is a value, not a `ttl` child node, so the loop below
	// never sees it; range-check its first token here.
	if len(node.Keys) == 2 && node.Keys[1] == "ttl" && len(node.Children) > 0 {
		if c := node.Children[0]; c != nil && len(c.Keys) > 0 {
			if err := ValidateInteger(1, 255)(c.Keys[0]); err != nil {
				return fmt.Errorf("multihop ttl: invalid value %q: %v (#16679)", c.Keys[0], err)
			}
		}
	}
	// Blocked / flat-set children: `multihop { no-nexthop-change; }`,
	// `multihop { ttl 2; no-nexthop-change; }`, and the flat-set
	// child shape (child Keys=["ttl"], value as grandchild or packed).
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		if c.Keys[0] == "no-nexthop-change" {
			return fmt.Errorf("%s", bgpMultihopRefusal16679())
		}
		if c.Keys[0] != "ttl" {
			continue
		}
		// The ttl value rides Keys[1], a sole grandchild (flat-set),
		// or — brace-elided — deeper packed keys; nodeVal reads the
		// first two, the Keys fallback covers the third.
		v := nodeVal(c)
		if v == "" && len(c.Keys) >= 2 {
			v = c.Keys[1]
		}
		if v == "" {
			return fmt.Errorf("multihop ttl: missing value — `multihop { ttl <1..255>; }` requires a TTL, or author bare `multihop;` for the Junos default 64 (#16679)")
		}
		if err := ValidateInteger(1, 255)(v); err != nil {
			return fmt.Errorf("multihop ttl: invalid value %q: %v (#16679)", v, err)
		}
	}
	return nil
}

// bgpMultihopTTLOf16679 extracts the effective MultihopTTL from one
// authored `multihop` node, across every spelling the schema admits:
//
//	multihop 2                        -> 2   (packed TTL, legacy xpf form)
//	multihop ttl 2                    -> 2   (packed ttl modifier)
//	multihop { ttl 2; }               -> 2   (blocked ttl child; the
//	                                          hierarchical parser also
//	                                          packs `ttl 2` onto Keys)
//	multihop;  /  set ... multihop    -> bgpMultihopDefaultTTL16679
//
// It deliberately does NOT special-case `no-nexthop-change`: strict
// commit refuses that spelling (validateBGPMultihop16679), and on the
// tolerant path warnBGPMultihop16679 names it. If the keyword carries
// no TTL token at all ("multihop no-nexthop-change" alone), no TTL is
// invented for a session whose semantics xpf cannot render — the peer
// keeps its previous/directly-connected TTL (0 unless another multihop
// statement set one) and the warning says the statement was dropped.
// A TTL packed alongside the refused flag (`multihop 2
// no-nexthop-change`) is likewise not partially honoured: honouring
// the TTL while dropping the flag would render exactly the
// next-hop-rewriting behaviour the operator asked to disable.
func bgpMultihopTTLOf16679(node *Node) (ttl int, present bool) {
	if node == nil {
		return 0, false
	}
	keys := node.Keys
	// Refused spelling mixed into this node: not partially honoured.
	for _, tok := range keys[1:] {
		if tok == "no-nexthop-change" {
			return 0, false
		}
	}
	for _, c := range node.Children {
		if c != nil && len(c.Keys) > 0 && c.Keys[0] == "no-nexthop-change" {
			return 0, false
		}
	}
	// Packed scalar: `multihop 2` (hierarchical lexer / braced form).
	// SetPath's flat-set grouping instead packs the Junos modifier
	// spelling onto the same node as `multihop ttl` with the value as
	// a CHILD (see below), and packs a bare hierarchical
	// `multihop ttl 2` whole.
	if len(keys) >= 2 {
		if n, err := strconv.Atoi(keys[1]); err == nil {
			return n, true
		}
		// Packed ttl modifier: `multihop ttl 2`.
		if keys[1] == "ttl" {
			if len(keys) >= 3 {
				if n, err := strconv.Atoi(keys[2]); err == nil {
					return n, true
				}
				return 0, false
			}
			// Flat-set shape: value is the sole child token
			// (`multihop ttl` -> child ["2"], or ["3","passive"]
			// when a following statement fused onto the child).
			if len(node.Children) == 1 && len(node.Children[0].Keys) >= 1 {
				if n, err := strconv.Atoi(node.Children[0].Keys[0]); err == nil {
					return n, true
				}
			}
			return bgpMultihopDefaultTTL16679, true
		}
		// A non-numeric, non-ttl first token is schema-rejected garbage
		// on the strict path; on the tolerant path it carries no TTL.
		return 0, false
	}
	// Blocked children: `multihop { ttl 2; }` (child Keys=["ttl","2"]),
	// the brace-elided child shape (child Keys=["ttl"], grandchild
	// Keys=["2"]) — nodeVal covers both — and the flat-set child
	// shape whose value stayed packed on the child Keys.
	for _, c := range node.Children {
		if c == nil || len(c.Keys) == 0 {
			continue
		}
		if c.Keys[0] == "ttl" {
			v := nodeVal(c)
			if v == "" && len(c.Keys) >= 2 {
				v = c.Keys[1]
			}
			if v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					return n, true
				}
			}
			return bgpMultihopDefaultTTL16679, true
		}
	}
	// Bare presence form.
	return bgpMultihopDefaultTTL16679, true
}

// bgpGroupMultihop16679 resolves one group-level `multihop` child node
// to the group TTL it sets, keeping `prior` when the node carries the
// refused `no-nexthop-change` spelling (present=false from the
// extractor). It first normalises the flat-set child shape — SetPath
// groups `... group G multihop ttl 2` as multihop -> `ttl` -> `2`,
// where `ttl` is a CHILD of the multihop node rather than a packed
// key — into the packed form the extractor reads, without mutating
// the authored node.
func bgpGroupMultihop16679(child *Node, prior int) int {
	node := child
	if len(child.Keys) == 1 {
		for _, c := range child.Children {
			if c == nil || len(c.Keys) == 0 || c.Keys[0] != "ttl" {
				continue
			}
			v := nodeVal(c)
			if v == "" && len(c.Keys) >= 2 {
				v = c.Keys[1]
			}
			if v != "" {
				node = &Node{Keys: []string{"multihop", "ttl", v}}
			}
			break
		}
	}
	if ttl, ok := bgpMultihopTTLOf16679(node); ok {
		return ttl
	}
	return prior
}

// bgpMultihopNoNexthopChange16679 reports whether an authored
// `multihop` statement anywhere in the tree carries the refused
// `no-nexthop-change` modifier, in any spelling (packed token on the
// multihop node, blocked child, or flat-set child). Used by the
// tolerant-path warning; the strict path refuses via the schema
// nodeValidator instead.
func bgpMultihopHasNoNexthopChange16679(node *Node) bool {
	if node == nil || len(node.Keys) == 0 || node.Keys[0] != "multihop" {
		return false
	}
	for _, tok := range node.Keys[1:] {
		if tok == "no-nexthop-change" {
			return true
		}
	}
	for _, c := range node.Children {
		if c != nil && len(c.Keys) > 0 && c.Keys[0] == "no-nexthop-change" {
			return true
		}
	}
	return false
}

// warnBGPMultihop16679 returns a specific warning for each authored
// `multihop no-nexthop-change` under a `protocols bgp` subtree (default
// instance or routing instance), so the tolerant load / peer-sync path
// — and a direct CompileConfig without SchemaValidate — names the
// dropped statement instead of only the generic #10707 advisory. The
// scan is keyword-only: it never reads a TTL value.
func warnBGPMultihop16679(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var warnings []string
	seen := map[string]struct{}{}
	var walk func(nodes []*Node, path []string)
	walk = func(nodes []*Node, path []string) {
		for _, node := range nodes {
			if node == nil || len(node.Keys) == 0 {
				continue
			}
			inBGP := false
			for i, p := range path {
				if p == "bgp" && i > 0 && path[i-1] == "protocols" {
					inBGP = true
					break
				}
			}
			isBGPRoot := node.Keys[0] == "bgp" && len(path) > 0 && path[len(path)-1] == "protocols"
			if (inBGP || isBGPRoot) && bgpMultihopHasNoNexthopChange16679(node) {
				loc := append(append([]string(nil), path...), node.Keys[0])
				msg := fmt.Sprintf("%s: %s", strings.Join(loc, " "), bgpMultihopRefusal16679())
				if _, dup := seen[msg]; !dup {
					seen[msg] = struct{}{}
					warnings = append(warnings, msg)
				}
			}
			// A packed neighbour/group line can carry `multihop` (and
			// its refused modifier) as tail tokens of an ancestor node
			// rather than as a child node; scan those too, mirroring
			// warnBGPAuth16621's whole-Keys scan.
			if inBGP || isBGPRoot {
				for i, tok := range node.Keys {
					if tok != "multihop" || i+1 >= len(node.Keys) {
						continue
					}
					if node.Keys[i+1] != "no-nexthop-change" {
						continue
					}
					loc := append(append([]string(nil), path...), node.Keys[0])
					msg := fmt.Sprintf("%s: %s", strings.Join(loc, " "), bgpMultihopRefusal16679())
					if _, dup := seen[msg]; !dup {
						seen[msg] = struct{}{}
						warnings = append(warnings, msg)
					}
				}
			}
			walk(node.Children, append(append([]string(nil), path...), node.Keys[0]))
		}
	}
	walk(tree.Children, nil)
	return warnings
}
