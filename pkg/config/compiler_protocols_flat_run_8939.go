package config

// Schema resolvers for the #8939 flat-run walk in compiler_protocols.go.
//
// SPLIT OUT RATHER THAN EXEMPTED. Adding them inline took
// compiler_protocols.go from 1460 to 1504 LOC and crossed the 1500 [WATCH]
// floor. `docs/refactoring-audit-accepted.txt` exists for files that
// genuinely resist splitting; this is not one -- the block is a cohesive
// unit with no coupling to the compile loops beyond being called by them,
// so recording an exemption for a threshold MY OWN appended block crossed
// would be using a legitimate escape hatch to avoid tidying up after
// myself. A forced seam in a compiler file would be worse than a recorded
// decision; this seam is not forced.

// ripLeafSchema8939 / isisLeafSchema8939 / isisInterfaceSchema8939 resolve the
// containers whose leaf sets expandFlatRun needs in order to tell one of their
// leaves from a value token.
//
// WHY THESE THREE AND WHY THE SEVERITY IS NOT "A LOST SETTING". Alphabetically
// `authentication-key` precedes `authentication-type`, so a flat run keeps the
// KEY and drops the TYPE -- the one combination that leaves authentication
// switched ON and downgraded to cleartext, rather than switched off. Measured
// end to end through pkg/frr:
//
//	isis split   -> area-password md5 secret1   / domain-password md5 secret1
//	isis packed  -> area-password clear secret1 / domain-password clear secret1
//	rip  split   -> ip rip authentication mode md5
//	rip  packed  -> ip rip authentication mode text
func ripLeafSchema8939() *schemaNode {
	return refRIP.resolve()
}

func isisLeafSchema8939() *schemaNode {
	return refISIS.resolve()
}

func isisInterfaceSchema8939() *schemaNode {
	return refISISInterface.resolve()
}
