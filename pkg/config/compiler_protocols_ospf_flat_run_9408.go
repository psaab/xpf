package config

// ospfSchema9408 resolves `protocols ospf` so expandFlatRun can tell one of its
// leaves from a value token.
//
// In its own file for the same reason as compiler_protocols_ra_flat_run_8939.go
// and compiler_protocols_flat_run_8939.go: compiler_protocols.go sits just
// under the 1500 LOC [WATCH] floor.
//
// THE SHAPE. `set protocols ospf passive reference-bandwidth 1g` is ONE set
// command, and SetPath models only the FIRST link: `reference-bandwidth` nests
// UNDER `passive` rather than beside it, so a loop over direct children reads
// `passive` and silently drops the rest of the run. The same happens for
// `router-id X reference-bandwidth Y`, in either order. The strict commit walk
// ADMITS that spelling, so it is an operator-reachable configuration loss on a
// commit that reports success — and `show configuration` still renders what the
// operator typed.
//
// expandFlatRun is schema-gated in both directions: `area` declares children so
// its subtree is left whole, `export` is `multi` so its value list is never
// cut, and a token the container does not declare stays with the leaf it
// follows. compileProtocols reads the SAME expanded slice from BOTH its loops —
// an `area` link that arrived at the tail of a chain has been hoisted to the
// ospf level by the expansion, and reading it off the raw node would put the
// two loops on different views of one command.
//
// WHY THIS ARRIVED WITH #9408 rather than with #8939. The chain loss was
// already there — `set protocols ospf passive reference-bandwidth 1g` nests
// `reference-bandwidth` UNDER `passive`, so the direct-children loop in
// compileProtocols never saw it — but it was UNMEASURABLE, and the #8939
// census recorded it as `vacuous` rather than as a loss. `reference-bandwidth`
// was the only OSPF-level leaf whose loss the census could have observed, and
// it compiled to 0 in BOTH the packed and the split spelling because the
// pre-#9408 compiler discarded its strconv.Atoi error. Two equal-but-empty
// compiles prove nothing, which is exactly what the census's own observability
// control says.
//
// Typing the leaf made the value survive the split spelling, which turned the
// row from `vacuous` into a measured loser on the OPERATOR channel — the
// strict commit walk admits the packed spelling. Landing the typed leaf
// without this would have shipped a leaf whose first measurable behaviour is a
// silent drop.
func ospfSchema9408() *schemaNode {
	return resolveSchemaChild(resolveSchemaChild(setSchema, "protocols"), "ospf")
}

// ospf3Schema13531 resolves `protocols ospf3` for schema-gated flat-run
// expansion, so chained top-level leaves and areas are segmented alike.
func ospf3Schema13531() *schemaNode {
	return resolveSchemaChild(resolveSchemaChild(setSchema, "protocols"), "ospf3")
}

// applyOSPFReferenceBandwidth9408 stores `protocols ospf reference-bandwidth`
// as the FRR Mbps integer the renderer emits verbatim.
//
// BITS PER SECOND in, Mbps out, through ospfReferenceBandwidthMbps -- the same
// SSOT the schema validator calls, so the commit gate and the compiler cannot
// answer differently about one token.
//
// THE err != nil ARM FAILS SAFE ON PURPOSE, and is NOT redundant with that
// gate. ValidateOSPFReferenceBandwidth hard-rejects a bad value on the strict
// commit / commit-check path, but SchemaValidate violations are DOWNGRADED TO
// WARNINGS on the tolerant Store.Load / Store.SyncApply paths
// (configstore.compileTreeLenient), so a config persisted under the pre-#9408
// Mbps reading still arrives here. Leaving the field at 0 emits no auto-cost
// line and lets FRR apply its own 100 Mbps default; storing the unconverted
// token instead would put a number up to six orders of magnitude out of range
// into the managed section, where one line vtysh rejects can degrade the whole
// reload.
func applyOSPFReferenceBandwidth9408(ospf *OSPFConfig, child *Node) {
	v := nodeVal(child)
	if v == "" {
		return
	}
	if mbps, err := ospfReferenceBandwidthMbps(v); err == nil {
		ospf.ReferenceBandwidthMbps = mbps
	}
}
