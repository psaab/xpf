package config

import (
	"fmt"
	"sort"
)

// natRuleSubBlocks lists the NAT sub-blocks whose rule-sets carry named,
// ordered, first-match rules. Keep in sync with compileNAT
// (compiler_nat_source.go), which iterates exactly these sub-blocks and whose
// per-type compilers read `rule-set` -> `rule` with namedInstances. nat64 /
// natv6v4 / proxy-arp are intentionally excluded: they carry no name-derived
// first-match rule identity of this shape.
var natRuleSubBlocks = []string{"source", "destination", "static"}

// dupNATRule is one detected duplicate rule name within a single NAT rule-set.
type dupNATRule struct {
	natType string // "source" | "destination" | "static"
	ruleSet string // the rule-set that owns the duplicated rule
	rule    string // the duplicated rule name
}

// validateDuplicateNATRuleNamesAST rejects (strict) or warns (lenient) when the
// candidate authors the SAME rule name twice inside one NAT rule-set.
//
// A NAT rule-set is keyed by rule name and is an ordered first-match table, so
// the same name authored twice is a config error regardless of NAT type: both
// instances compile as separate first-match entries sharing one operational
// identity (the rule name). For source / destination / ordinary static NAT
// those are counted rows on the shared natType/ruleset/rule hit counter
// (pkg/dataplane/compiler_nat.go NATCounterKey); for a counter-less NPTv6 (RFC
// 6296) static rule they are two snapshots (buildNptv6Snapshots appends each,
// pkg/dataplane/userspace/nat_nptv6.go). The reason line is deliberately
// type-agnostic: it never claims a per-rule counter (an NPTv6 rule has none —
// compileStaticNAT skips rule.IsNPTv6 before assignNATCounterID) and does not
// assert runtime shadowing for disjoint prefixes. The #2241 overlap gate
// compares every emitted snapshot row and catches overlapping same-name
// entries too, but it does not reject disjoint prefix/zone pairs — the
// independent shared rule-name identity reason remains necessary.
//
// This is a DIFFERENT failure mode from #5180's last-writer-wins hierarchical
// blocks: duplicate NAT rules BOTH survive. Runs PRE-expansion on top-level
// `security` stanzas only, exactly like validateDuplicateNamedBlockAST (#5180):
// apply-groups DEEP-MERGES a rule of the same name rather than duplicating it, and
// a rule authored once via flat `set` reuses its rule node, so only hierarchical
// duplicates authored directly reach here. The seen-set is keyed by (natType,
// ruleSet, rule) and unioned across repeated `security` / `nat` /
// `source|destination|static` blocks — compileNAT (#3915) merges those repeats —
// so a rule name split across two `source {}` blocks is caught too. A quoted-empty
// rule name is recorded as an empty-name defect (#6455) rather than skipped; an
// empty rule-SET name is NOT reported here (the #6454 rule-set gate owns it, so
// the warning is not double-reported) — this gate skips an empty rule-set. Strict
// rejects on the operator commit / commit-check path; lenient (Load / peer-sync,
// #1960) warns and keeps the historical two-row behavior.
//
// A duplicate authored ENTIRELY inside an applied group body is not caught here
// — this gate is pre-expansion by design. It is caught by
// validateDuplicateNamesExpandedAST (dup_names_expanded_6455.go, #6455
// Finding 1), which re-runs THIS function on a group-expanded clone.
func validateDuplicateNATRuleNamesAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var dups []dupNATRule
	var emptyKinds []string
	seen := map[string]bool{}
	reported := map[string]bool{}
	emptyRuleReported := map[string]bool{}
	for _, top := range tree.Children {
		if top.Name() != "security" {
			continue
		}
		for _, nat := range top.FindChildren("nat") {
			for _, natType := range natRuleSubBlocks {
				for _, sub := range nat.FindChildren(natType) {
					for _, rsInst := range namedInstances(sub.FindChildren("rule-set")) {
						// An empty rule-set name is owned by the #6454 rule-set
						// gate; skip it here so the empty-name warning is not
						// double-reported (the #6455 lenient double-warning fix).
						if rsInst.name == "" {
							continue
						}
						for _, ruleInst := range namedInstances(rsInst.node.FindChildren("rule")) {
							if ruleInst.name == "" {
								ek := natType + "\x00" + rsInst.name
								if !emptyRuleReported[ek] {
									emptyKinds = append(emptyKinds, "NAT "+natType+" rule")
									emptyRuleReported[ek] = true
								}
								continue
							}
							key := natType + "\x00" + rsInst.name + "\x00" + ruleInst.name
							if seen[key] {
								if !reported[key] {
									dups = append(dups, dupNATRule{natType, rsInst.name, ruleInst.name})
									reported[key] = true
								}
							} else {
								seen[key] = true
							}
						}
					}
				}
			}
		}
	}

	if len(dups) == 0 && len(emptyKinds) == 0 {
		return nil, nil
	}
	// Deterministic order: natType, then rule-set, then rule.
	sort.Slice(dups, func(i, j int) bool {
		if dups[i].natType != dups[j].natType {
			return dups[i].natType < dups[j].natType
		}
		if dups[i].ruleSet != dups[j].ruleSet {
			return dups[i].ruleSet < dups[j].ruleSet
		}
		return dups[i].rule < dups[j].rule
	})
	sort.Strings(emptyKinds)

	if !lenient {
		// Duplicates keep first-error priority so the pre-#6455 messages are
		// unchanged when no empty name is present.
		if len(dups) > 0 {
			d := dups[0]
			return nil, fmt.Errorf("duplicate NAT %s rule %q in rule-set %q: a NAT "+
				"rule-set is keyed by rule name, so the same name authored twice "+
				"compiles both instances as separate first-match entries sharing one "+
				"operational identity — author the rule once (flat `set` merges "+
				"repeated statements automatically) (#5649)",
				d.natType, d.rule, d.ruleSet)
		}
		return nil, emptyNameError(emptyKinds[0])
	}

	warnings := make([]string, 0, len(dups)+len(emptyKinds))
	for _, d := range dups {
		warnings = append(warnings, fmt.Sprintf("duplicate NAT %s rule %q in "+
			"rule-set %q: the same name compiles both instances as separate "+
			"first-match entries sharing one operational identity — author it "+
			"once (#5649)", d.natType, d.rule, d.ruleSet))
	}
	for _, k := range emptyKinds {
		warnings = append(warnings, emptyNameWarning(k))
	}
	return warnings, nil
}
