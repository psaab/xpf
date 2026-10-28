package config

import "strconv"

// #17182 (R4-Q21-03): `bfd-liveness-detection` was five identical
// schema literals (OSPF, OSPFv3, BGP group, BGP neighbor, IS-IS in
// schema_routing.go) and five identical 17-line compiler readers
// (compiler_protocols.go x4, compiler_bgp_neighbor_merge_9192.go x1).
// TestEveryBFDSiteIsTyped9012 guarded only the numeric typing, so any
// other grammar change — e.g. accepting the packed spelling — had to
// be made five times in each layer. This file is the single source of
// truth for both layers:
//
//   - bfdLivenessSchema17182 builds the schema node; each call returns
//     FRESH pointers (a factory must not share fate between sites —
//     see bgpMultihopSchema16679's precedent), so
//     TestEveryBFDSiteIsTyped9012 still counts five sites.
//   - parseBFDLiveness17182 reads one authored `bfd-liveness-detection`
//     node across every spelling the schema admits (braced block and
//     flat-set children; packed tails are expanded by the callers via
//     packedBodyChildren/expandFlatRun before this is invoked, exactly
//     as the five former inline readers were reached) and returns the
//     (enabled, interval, multiplier) triplet the four model types
//     carry as BFD/BFDInterval/BFDMultiplier, PLUS a presence flag per
//     numeric leaf: callers merge field-wise through apply, so a node
//     naming only one leaf never wipes the value the target already
//     carries (BGP group->neighbor inheritance, find-or-create
//     fragment merging).
//
// The per-daemon FRR renderer arms are deliberately NOT consolidated:
// ospfd/isisd need a bare enable line before the profile, ospf6d emits
// `ipv6 ospf6 bfd [profile]` alone, and BGP has the multihop branch —
// per-daemon syntax, not copies (see the issue's adversarial analysis).

// bfdLivenessSchema17182 returns a fresh `bfd-liveness-detection`
// schema node. Bounds are FRR's own grammar (see
// bfd_damping_typed_9012_test.go): minimum-interval is (10-60000) ms,
// multiplier is (2-255).
func bfdLivenessSchema17182() *schemaNode {
	return &schemaNode{
		desc: "BFD liveness detection",
		children: map[string]*schemaNode{
			"minimum-interval": {desc: "Minimum interval (milliseconds)", args: 1, valueType: ValueInteger, placeholder: "<milliseconds>", validator: ValidateInteger(10, 60000), children: nil},
			"multiplier":       {desc: "Multiplier", args: 1, valueType: ValueInteger, placeholder: "<multiplier>", validator: ValidateInteger(2, 255), children: nil},
		},
	}
}

// bfdLiveness17182 is the compiled BFD triplet carried (as three
// fields) by OSPFInterface, OSPFv3Interface, ISISInterface and
// BGPNeighbor. The model types keep their flat fields for renderer
// compatibility; this struct is only the reader's return value.
//
// intervalSet/multiplierSet report per-field presence: the leaf was
// present AND parsed. They are what make the merge field-wise — the
// reader zero-starts its struct, so without them a caller assigning
// the triplet wholesale cannot tell "leaf absent/unparseable" from
// "leaf set to 0" and wipes the inherited/fragment value (Rev18229
// B1). An unparseable present leaf leaves its flag clear, so the
// tolerant path keeps the inherited value exactly as the former
// inline readers did.
type bfdLiveness17182 struct {
	enabled       bool
	interval      int
	multiplier    int
	intervalSet   bool
	multiplierSet bool
}

// apply merges b onto one target's flat BFD fields field-wise:
// presence of the node enables BFD, and each numeric field is
// assigned only when its leaf was actually present and parsed.
func (b bfdLiveness17182) apply(enabled *bool, interval, multiplier *int) {
	if !b.enabled {
		return
	}
	*enabled = true
	if b.intervalSet {
		*interval = b.interval
	}
	if b.multiplierSet {
		*multiplier = b.multiplier
	}
}

// parseBFDLiveness17182 reads one `bfd-liveness-detection` node.
//
// Callers pass the node as authored (braced children, or the flat-set
// shape ParseSetCommand+SetPath produces, which arrives as the same
// Children shape). Packed tails (`bfd-liveness-detection
// minimum-interval 300 multiplier 3` on an interface/group/neighbor
// line) are expanded by the callers' packedBodyChildren/expandFlatRun
// passes before the switch that dispatches here, so this reader sees
// the braced-equivalent shape at every site — the behaviour the five
// former inline copies had.
//
// enabled is true whenever the node is present (the statement itself
// enables BFD). A numeric leaf sets its value and presence flag only
// when present and parseable; unset or unparseable leaves the flag
// clear so apply keeps the target's existing value, matching the
// former readers: a non-numeric value leaves the field at its prior
// (inherited/fragment) value rather than failing the compile (the
// strict schema gate rejects it before compile; the tolerant path
// drops it).
func parseBFDLiveness17182(prop *Node) bfdLiveness17182 {
	if prop == nil {
		return bfdLiveness17182{}
	}
	out := bfdLiveness17182{enabled: true}
	for _, bc := range prop.Children {
		switch bc.Name() {
		case "minimum-interval":
			if v := nodeVal(bc); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					out.interval, out.intervalSet = n, true
				}
			}
		case "multiplier":
			if v := nodeVal(bc); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					out.multiplier, out.multiplierSet = n, true
				}
			}
		}
	}
	return out
}
