package config

// bgpGroupSchema9181 resolves `protocols bgp group <name>` so expandFlatRun can
// tell one of the group's leaves from a value token.
//
// In its own file for the same reason as the sibling #8939 helpers:
// compiler_protocols.go sits just under the 1500 LOC [WATCH] floor.
func bgpGroupSchema9181() *schemaNode {
	return refBGPGroup.resolve()
}
