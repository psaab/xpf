package config

// bgpLeafSchema8939 resolves `protocols bgp` so expandFlatRun can tell one of
// its leaves from a value token.
//
// In its own file for the same reason as the sibling #8939 helpers:
// compiler_protocols.go sits just under the 1500 LOC [WATCH] floor and an
// appended helper block is what crossed it in #9106.
func bgpLeafSchema8939() *schemaNode {
	return refBGP.resolve()
}
