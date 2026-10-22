package config

// cosTrafficControlProfileSchema8939 resolves the
// `class-of-service traffic-control-profiles <name>` body so expandFlatRun knows
// which tokens on a packed node are siblings rather than values.
func cosTrafficControlProfileSchema8939() *schemaNode {
	return refCoSTCPInstance.resolve()
}
