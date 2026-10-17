package config

import "fmt"

// #14447 (DR20-H1): duplicate singleton scalar gate for
// `system services ssh root-login`.
//
// The SSH reader used FindChild (first sibling wins), so
// `root-login allow; root-login deny;` installed RootLogin="allow"
// (PermitRootLogin yes) and silently discarded the explicit deny.
// Junos/flat-set semantics are last-wins, and the codebase rejects
// conflicting duplicates for analogous scalars (#6714/#3366) instead
// of picking the permissive value.
//
// validateDuplicateRootLoginAST runs on the group-expanded,
// inactive-pruned tree from runPreWalkGates, so group-supplied values
// are counted exactly as the compiler pools them. It mirrors the
// reader's pooling: every `system` root, every `services` child
// (packed bodies via packedBodyChildren), every `ssh` child, with
// the same expandRun9235 the reader applies. Inherited (group)
// values participate in the pooled order; expansion may keep a
// group value beside an inline one as siblings, and both are real
// authored values the reader would pool.
//
// Strict: conflicting distinct values reject naming leaf, both
// values, and issue. Lenient: warn (same diagnostic) and the reader
// (now last-wins) keeps the last value, matching Junos.
// Identical repeats and single values pass unchanged.

func collectRootLoginValues14447(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var values []string
	for _, sysNode := range tree.Children {
		if sysNode == nil || sysNode.Name() != "system" {
			continue
		}
		systemChildren := expandResolvingRuns9792(sysNode.Children, systemSchema9792())
		var serviceChildren []*Node
		for _, child := range systemChildren {
			if child == nil || child.Name() != "services" {
				continue
			}
			serviceChildren = append(serviceChildren,
				packedBodyChildren(child, schemaForPath("system", "services"))...)
		}
		if len(serviceChildren) == 0 && len(sysNode.Keys) > 1 && sysNode.Keys[1] == "services" {
			for _, services := range packedBodyChildren(sysNode, systemSchema9792()) {
				if services.Name() == "services" {
					serviceChildren = append(serviceChildren,
						packedBodyChildren(services, schemaForPath("system", "services"))...)
				}
			}
		}
		for _, child := range serviceChildren {
			if child == nil || child.Name() != "ssh" {
				continue
			}
			expanded := expandRun9235(child, systemServicesSSHSchema9235())
			for _, rl := range expanded.FindChildren("root-login") {
				if len(rl.Keys) >= 2 && rl.Keys[1] != "" {
					values = append(values, rl.Keys[1])
				}
			}
		}
	}
	return values
}

func validateDuplicateRootLoginAST(tree *ConfigTree, lenient bool) ([]string, error) {
	values := collectRootLoginValues14447(tree)
	if len(values) < 2 {
		return nil, nil
	}
	first := values[0]
	for _, v := range values[1:] {
		if v == first {
			continue
		}
		diagnostic := fmt.Sprintf(
			"system services ssh: conflicting duplicate \"root-login\" values %q and %q: a single-valued leaf may be set only once with one value — the first value previously won silently, so \"allow\" followed by \"deny\" installed PermitRootLogin yes and discarded the explicit deny; author root-login once (#14447)",
			first, v)
		if !lenient {
			return nil, fmt.Errorf("%s", diagnostic)
		}
		return []string{diagnostic + "; tolerant compilation keeps the last value (last-wins)"}, nil
	}
	return nil, nil
}
