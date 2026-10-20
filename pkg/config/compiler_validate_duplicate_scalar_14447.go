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

// unpackSystemRootLogin15716 returns braced `system { services {
// ssh { root-login <val> } } }` synthesized from any packed spelling
// of the chain rooted at sysNode (header-packed system, packed
// services, packed ssh, packed root-login run). Already-braced
// children are returned unchanged by packedBodyChildren, so the
// result is the full pooled body in authored order.
func unpackSystemRootLogin15716(sysNode *Node) []string {
	if sysNode == nil {
		return nil
	}
	var out []string
	if len(sysNode.Keys) > 1 {
		for _, svc := range packedBodyChildren(sysNode, systemSchema9792()) {
			if svc.Name() != "services" {
				continue
			}
			out = append(out, unpackServicesRootLogin15716(svc)...)
		}
		if v, ok := headerPackedRootLogin15716(sysNode.Keys); ok {
			found := false
			for _, x := range out {
				if x == v {
					found = true
					break
				}
			}
			if !found {
				out = append([]string{v}, out...)
			}
		}
	}
	for _, child := range expandResolvingRuns9792(sysNode.Children, systemSchema9792()) {
		if child == nil || child.Name() != "services" {
			continue
		}
		for _, svcChild := range packedBodyChildren(child, schemaForPath("system", "services")) {
			out = append(out, unpackServicesChildRootLogin15716(svcChild)...)
		}
	}
	return out
}

func unpackServicesRootLogin15716(svc *Node) []string {
	var out []string
	for _, c := range packedBodyChildren(svc, schemaForPath("system", "services")) {
		out = append(out, unpackServicesChildRootLogin15716(c)...)
	}
	return out
}

func unpackServicesChildRootLogin15716(c *Node) []string {
	if c == nil || c.Name() != "ssh" {
		return nil
	}
	var out []string
	expanded := expandRun9235(c, systemServicesSSHSchema9235())
	for _, rl := range expanded.FindChildren("root-login") {
		if len(rl.Keys) >= 2 && rl.Keys[1] != "" {
			out = append(out, rl.Keys[1])
		}
	}
	// Packed ssh leaf: Keys=[ssh root-login <val> ...] with no children.
	if len(out) == 0 && len(c.Keys) >= 3 && c.Keys[1] == "root-login" && c.Keys[2] != "" {
		out = append(out, c.Keys[2])
		// Packed run: `ssh root-login allow root-login deny`
		for i := 3; i+1 < len(c.Keys); i++ {
			if c.Keys[i] == "root-login" && c.Keys[i+1] != "" {
				out = append(out, c.Keys[i+1])
			}
		}
	}
	return out
}

func collectRootLoginValues14447(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var values []string
	for _, sysNode := range tree.Children {
		if sysNode == nil || sysNode.Name() != "system" {
			continue
		}
		values = append(values, unpackSystemRootLogin15716(sysNode)...)
	}
	return values
}

// headerPackedRootLogin15716 extracts `root-login <val>` from a
// header-packed system node's Keys (`system services ssh root-login
// <val> ...`), or reports false.
func headerPackedRootLogin15716(keys []string) (string, bool) {
	if len(keys) >= 5 && keys[0] == "system" && keys[1] == "services" && keys[2] == "ssh" && keys[3] == "root-login" && keys[4] != "" {
		return keys[4], true
	}
	return "", false
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
