package config

// THE #8939 LENIENT-PATH RESIDUE (#9235).
//
// #8939 drove the operator-typed flat-run losses to zero. What it left is a
// different population, and the CHANNEL is the whole finding rather than a
// caveat on it:
//
//	config.SchemaValidate            REJECTS the packed spelling at these
//	                                 containers, so an operator cannot type it
//	                                 into a running box.
//	config.CompileConfig             does NOT lose the value -- the strict
//	                                 pipeline never sees the tree, because the
//	                                 schema gate ran first and refused it.
//	config.CompileConfigLenient      LOSES it. This is the channel the defect
//	                                 lives on, and nothing else.
//	configstore.CheckText            REJECTS (it is compileTreeStrict).
//
// So these are `lenient-only` rows: reachable through `Store.Load` (boot from
// the persisted DB) and `Store.SyncApply` (HA config sync from the peer), which
// call `compileTreeLenient` and downgrade the same gate to a `slog.Warn` for the
// #1960 no-brick doctrine. A fidelity defect, not a security one -- but the
// reach is exactly where nobody is watching, and a warning on a booting
// firewall is not a channel anyone reads in time.
//
// THE ISSUE ASKED WHETHER THAT REACH IS REAL BEFORE ANY FIX: "how does a packed
// run get into a persisted tree at all, if commit rejects it?" It does not need
// a new measurement, because the tree already carries two SHIPPED migrations
// whose only reason to exist is that exact situation:
//
//	rewriteRetiredDataplaneType   (#1373/#1525, store_persist.go) -- "a node may
//	  boot with `system dataplane-type ebpf` persisted from before the
//	  retirement-strict validator landed".
//	SanitizeTreeControlChars      (#1798, store_persist.go) -- "a persisted
//	  free-text value carrying control characters committed before the strict
//	  commit-time gate landed".
//
// And `compileTreeLenient`'s own doc comment states both candidate mechanisms as
// design premises, not hypotheses: "a persisted config written by an older
// binary (pre-gate, or before a leaf's range was typed/tightened)" and "a config
// pushed from a possibly-un-upgraded cluster primary". A schema that declares a
// leaf today did not always declare it -- every container in this file got its
// declaration in some commit -- so a tree written before that commit carries the
// packed spelling and boots through the lenient path now. The rows are reachable.
//
// THE REMEDY IS hoistAndSplitRun8939, NOT expandFlatRun, AND THAT IS MEASURED
// RATHER THAN PREFERRED. `SetPath` builds a flat-set line as a NESTED CHAIN, one
// node per leaf, so the trailing statements are not on the container's children
// at all:
//
//	set security flow aging early-ageout 10 high-watermark 80 low-watermark 60
//	  [aging] > [early-ageout 10] > [high-watermark 80] > [low-watermark 60]
//
// `expandFlatRun` splits a packed run carried on ONE node's Keys and cannot see
// that chain; `hoistAndSplitRun8939` does both, and it carries the #9234
// ambiguity bound (a head legal in BOTH the container and the body it sits in is
// left where it was authored) that makes hoisting safe.

// expandRun9235 returns a shallow clone of n whose Children are the flat-run
// expansion of n's children against `container`.
//
// THE CLONE IS ONE OF TWO GUARDS ON THE SAME PROPERTY, AND THE FIRST VERSION OF
// THIS COMMENT CLAIMED IT WAS THE ONLY ONE. It said expanding in place "would
// rewrite the operator's authored spelling as a side effect of compiling it".
// Measured, it would not — on its own. `compileConfigWithOpts` (compiler.go)
// opens with `tree = tree.cloneForExpansion()`, a deep copy taken before any
// reader runs, so the tree the renderers and `show | display set` read is already
// out of reach. Removing EITHER guard survives the suite; removing BOTH reds
// TestFlatRunResidueCompileDoesNotTouchTheAuthoredTree9235, which carries the
// three-row matrix.
//
// The clone is KEPT, and the reason is scope rather than depth:
// `cloneForExpansion` is the TOTAL guarantee (every compiler reader) while this
// clone is the LOCAL one that keeps a caller outside the compile path honest —
// there is none today. So the two are redundant on today's fixtures and not
// redundant in what they cover, which is why neither is deleted and the
// individually-surviving mutations are recorded instead.
//
// It runs once per container read at compile time, never per packet.
func expandRun9235(n *Node, container *schemaNode) *Node {
	if n == nil || container == nil || len(n.Children) == 0 {
		return n
	}
	clone := *n
	clone.Children = hoistAndSplitRun8939(n.Children, container)
	return &clone
}

// expandRunChildren9235 is expandRun9235 for a caller that iterates children
// directly rather than calling FindChild on the node.
func expandRunChildren9235(children []*Node, container *schemaNode) []*Node {
	if container == nil || len(children) == 0 {
		return children
	}
	return hoistAndSplitRun8939(children, container)
}

// The resolvers below each resolve their container out of `setSchema` rather
// than rebuilding it, so the expansion is driven by the same declaration
// `SetPath` walked. A nil return disables the expansion at that site, which is
// why TestFlatRunResidueSchemasResolve9235 asserts every one is non-nil: a
// resolver that silently started returning nil would turn the fix off and no
// behavioural test would necessarily notice.

func policerIfExceedingSchema9235() *schemaNode {
	return resolveSchemaPath9235("firewall", "policer", "if-exceeding")
}

// #9882: the policer `then` containers, for the hoistAndSplitRun8939 reader
// below them. A one-line run (`then forwarding-class af11 loss-priority
// high;`, or the flat-set single command) nests or packs the later statements
// where a children-only walk keeps just the head; expanding the run at the
// reader makes every spelling read what the operator wrote. Covered by
// TestFlatRunResidueSchemasResolve9235 like every resolver here.
func policerThenSchema9882() *schemaNode {
	return resolveSchemaPath9235("firewall", "policer", "then")
}

func threeColorPolicerThenSchema9882() *schemaNode {
	return resolveSchemaPath9235("firewall", "three-color-policer", "then")
}

func raPrefixSchema9235() *schemaNode {
	return resolveSchemaPath9235("protocols", "router-advertisement", "interface", "prefix")
}

func staticQualifiedNextHopSchema9235() *schemaNode {
	return resolveSchemaPath9235("routing-options", "static", "route", "qualified-next-hop")
}

func schedulerSchema9235() *schemaNode {
	return resolveSchemaPath9235("schedulers", "scheduler")
}

func flowAgingSchema9235() *schemaNode {
	return resolveSchemaPath9235("security", "flow", "aging")
}

func securityLogSchema9235() *schemaNode {
	return resolveSchemaPath9235("security", "log")
}

func persistentNATSchema9235() *schemaNode {
	return resolveSchemaPath9235("security", "nat", "source", "pool", "persistent-nat")
}

func ipfixTemplateSchema9235() *schemaNode {
	return resolveSchemaPath9235("services", "flow-monitoring", "version-ipfix", "template")
}

func version9TemplateSchema9235() *schemaNode {
	return resolveSchemaPath9235("services", "flow-monitoring", "version9", "template")
}

func dataplaneCoalescenceSchema9235() *schemaNode {
	return resolveSchemaPath9235("system", "dataplane", "coalescence")
}

func dhcpStaticBindingSchema9235() *schemaNode {
	return resolveSchemaPath9235("system", "services", "dhcp-local-server", "group", "pool", "static-binding")
}

func systemServicesSSHSchema9235() *schemaNode {
	return resolveSchemaPath9235("system", "services", "ssh")
}

// resolveSchemaPath9235 walks `setSchema` by keyword. An `args:N` container IS
// the node its arguments are written after, so no wildcard step is needed for
// any container in this family -- measured, not assumed
// (TestFlatRunResidueSchemasResolve9235 pins the children each one declares).
func resolveSchemaPath9235(path ...string) *schemaNode {
	n := setSchema
	for _, k := range path {
		if n == nil {
			return nil
		}
		n = resolveSchemaChild(n, k)
	}
	return n
}
