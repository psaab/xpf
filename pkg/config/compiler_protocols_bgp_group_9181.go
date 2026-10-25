package config

import "fmt"

// bgpGroupSchema9181 resolves `protocols bgp group <name>` so expandFlatRun can
// tell one of the group's leaves from a value token.
//
// In its own file for the same reason as the sibling #8939 helpers:
// compiler_protocols.go sits just under the 1500 LOC [WATCH] floor.
func bgpGroupSchema9181() *schemaNode {
	return refBGPGroup.resolve()
}

// ValidateBGPGroupType accepts only the two Junos BGP group types.
func ValidateBGPGroupType(raw string) error {
	switch raw {
	case "internal", "external":
		return nil
	default:
		return fmt.Errorf("invalid BGP group type %q (expected one of: external, internal)", raw)
	}
}

// Check the authored statement, not just compiled neighbors: a missing or
// invalid type must also be rejected in a group with no neighbors (#16567).
func validateBGPGroupTypeNode(node *Node) error {
	if err := ValidateBGPGroupType(nodeVal(node)); err != nil {
		return err
	}
	if len(node.Keys) == 2 && len(node.Children) == 0 {
		return nil
	}
	// The braced scalar spelling carries its value in a single child.
	if len(node.Keys) == 1 && len(node.Children) == 1 &&
		len(node.Children[0].Keys) == 1 && len(node.Children[0].Children) == 0 {
		return nil
	}
	return fmt.Errorf("BGP group type requires exactly one value (internal or external)")
}
