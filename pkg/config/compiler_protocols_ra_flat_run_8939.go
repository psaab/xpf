package config

// raInterfaceSchema8939 resolves `protocols router-advertisement interface
// <name>` so expandFlatRun can tell one of its leaves from a value token.
//
// In its own file for the same reason as compiler_protocols_flat_run_8939.go:
// compiler_protocols.go sits just under the 1500 LOC [WATCH] floor, and an
// appended helper block is what pushed it over last time.
func raInterfaceSchema8939() *schemaNode {
	return refRAInterface.resolve()
}
