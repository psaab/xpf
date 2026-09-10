package config

// Issue 9023: a repeated named BLOCK silently discarded the earlier one.
//
//	snmp { trap-group tg1 { targets 10.0.0.1; }
//	       trap-group tg1 { version v1; } }
//	  -> targets LOST   (measured: 1 -> 0)
//
//	forwarding-options { sampling {
//	    instance i1 { input { rate 100; } }
//	    instance i1 { family inet { output { flow-server ...; } } } } }
//	  -> input rate LOST (measured: 100 -> 0)
//
// Junos merges repeated stanzas; the compiler's `m[name] = x` assignment made
// the last block win instead.
//
// WHY THIS MERGES ON BOTH PATHS, WHERE #8752 MERGES ONLY ON THE TOLERANT ONE.
// That fold is deliberately tolerant-only because the #3473 gate hard-rejects a
// duplicate policy name at commit, and merging first would destroy a diagnostic
// worth keeping. THERE IS NO SUCH GATE HERE -- `sampling instance` accepts a
// duplicate silently on the strict path, so there is no diagnostic to preserve,
// and the tolerant-only scoping that was right for policies would leave the
// operator-typed case unfixed.
//
// `snmp trap-group` looked like it had a gate and does not. It is rejected
// strictly, but for an unrelated reason: the zero-target check (#2990) runs
// per BLOCK, so the `version v1` block trips it on its own. The operator who
// wrote `targets 10.0.0.1` is told "no targets configured" -- a true statement
// about a block they did not intend to exist, describing a symptom of the
// duplication rather than the duplication. Merging first makes that gate see
// the group the operator actually described, so it stops firing on a config
// that is not missing its targets.
//
// The merge is announced, never silent: a config whose meaning changes deserves
// to say so even when the new meaning is the intended one.

// dupBlockMergeSites9023 is the (parent-container, repeated-keyword) list.
// Explicit rather than a predicate, so a container joins by a reviewed decision
// -- the same discipline compactNormalizeInScope settled on.
var dupBlockMergeSites9023 = []struct{ parent, keyword string }{
	{"snmp", "trap-group"},
	{"sampling", "instance"},

	// Issue 9209. These four became visible when #9024 taught the #8436 census
	// to build a NESTED fixture: each has only container children, so no
	// two-leaf fixture could be built, each left the population before any
	// verdict was formed, and the census reported "SILENT: 0" over a set that
	// excluded them. They are the same defect as the two above, at containers
	// that pass did not reach.
	//
	// EACH WAS CHECKED FOR AN EXISTING GATE BEFORE BEING ADDED, because
	// merging first destroys a diagnostic where one exists -- the reason #8752
	// folds only on the tolerant path:
	//
	//	firewall policer                        ACCEPTS the duplicate, silent
	//	protocols ospf area                     ACCEPTS the duplicate, silent
	//	system services dhcp-local-server group ACCEPTS the duplicate, silent
	//	security ipsec policy                   REJECTS -- but see below
	//
	// `security ipsec policy` is the `snmp trap-group` shape again, and it is
	// the reason this list is checked per site rather than in aggregate. The
	// gate that fires says `ipsec policy "p1" has no resolvable ipsec
	// proposals` -- a true statement about the SECOND block, which the operator
	// never intended to exist on its own, describing a symptom of the
	// duplication rather than the duplication. Merging first makes that gate
	// see the policy the operator actually described, so it stops firing on a
	// config that is not missing its proposals. No diagnostic is lost; a
	// misdirecting one is.
	{"firewall", "policer"},
	{"ospf", "area"},
	{"ipsec", "policy"},
	{"dhcp-local-server", "group"},
}

// mergeDuplicateBlocks9023 folds repeated named blocks into the first
// occurrence and returns a description of each merge performed.
func mergeDuplicateBlocks9023(tree *ConfigTree) []string {
	if tree == nil {
		return nil
	}
	var merged []string
	var walk func(n *Node, depth int)
	walk = func(n *Node, depth int) {
		if n == nil || depth > 6 {
			return
		}
		for _, site := range dupBlockMergeSites9023 {
			if n.Name() != site.parent {
				continue
			}
			names, _ := mergeInstancesUnder(n, site.keyword, askNone9571)
			for _, name := range names {
				merged = append(merged, site.parent+" "+site.keyword+" "+name)
			}
		}
		for _, ch := range n.Children {
			walk(ch, depth+1)
		}
	}
	for _, root := range tree.Children {
		walk(root, 0)
	}
	return merged
}
