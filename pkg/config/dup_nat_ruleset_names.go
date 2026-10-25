package config

import (
	"fmt"
	"sort"
)

// validateSourceNATDuplicateContextAST rejects (strict) or warns (lenient)
// when two DISTINCTLY-NAMED source-NAT rule-sets share the same normalised
// (from, to) context (#16607).
//
// Junos forbids this: "You cannot specify the same source and destination
// conditions for source NAT rule sets." xpf compiles each rule-set by
// appending its rules to one first-match snapshot (buildSourceNATSnapshots)
// after a stable sort by scope tier (#4161); equal contexts keep config
// order, so an early catch-all (for example `source-nat interface` matching
// any) silently shadows every rule of the later rule-set — including a
// `source-nat off` exemption that never acts as authored. Merged rules in
// ONE rule-set can express the exemption if ordered first; across two
// rule-sets the operator gets no signal.
//
// Normalisation mirrors the compiler: each side is the SET of (kind, value)
// scopes from collectNATScopes (which injects the {zone, ""} match-any
// default for an absent clause), so bracket lists compare as sets
// regardless of order (`[ trust dmz ]` == `[ dmz trust ]`, and a bracketed
// list equals repeated clauses), duplicate spellings of one value collapse,
// and a single authored rule-set carrying a list (#3096 Cartesian expansion)
// is ONE instance and never self-collides. Scope kinds compare verbatim:
// `from zone trust` and `from interface ge-0/0/0.0` are different contexts.
// Rule-set names are required to differ — a same-named pair is owned by the
// #6454 gate which runs first on the strict path and would otherwise double
// report. An empty (quoted) name is skipped here; #6454 owns it too.
//
// Like the #6454 gate this runs PRE-expansion on top-level `security`
// stanzas only; validateDuplicateNamesExpandedAST re-runs it on the
// group-expanded clone (#6455 Finding 1 mechanism) so a duplicate-context
// pair authored entirely inside an applied group is caught as well.
// Strict rejects on the commit / commit-check path naming BOTH rule-sets;
// lenient (Load / peer-sync, #1960) warns and keeps the historical
// concatenated behaviour.
func validateSourceNATDuplicateContextAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	type ctxPair struct {
		first, second string
		fromKey       string
		toKey         string
	}
	var pairs []ctxPair
	seen := map[string]string{} // ctxKey -> first rule-set name
	reported := map[string]bool{}
	for _, top := range tree.Children {
		if top.Name() != "security" {
			continue
		}
		for _, nat := range top.FindChildren("nat") {
			for _, sub := range nat.FindChildren("source") {
				for _, rsInst := range namedInstances(sub.FindChildren("rule-set")) {
					if rsInst.name == "" {
						continue
					}
					fromScopes, toScopes := collectNATScopes(rsInst.node, true, "source")
					key := scopeSetKey(fromScopes) + "\x00" + scopeSetKey(toScopes)
					first, ok := seen[key]
					if !ok {
						seen[key] = rsInst.name
						continue
					}
					if first == rsInst.name {
						// Same-name duplicate: #6454 owns it.
						continue
					}
					pairKey := key + "\x00" + first + "\x00" + rsInst.name
					if reported[pairKey] {
						continue
					}
					reported[pairKey] = true
					pairs = append(pairs, ctxPair{
						first: first, second: rsInst.name,
						fromKey: scopeSetKey(fromScopes), toKey: scopeSetKey(toScopes),
					})
				}
			}
		}
	}
	if len(pairs) == 0 {
		return nil, nil
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].first != pairs[j].first {
			return pairs[i].first < pairs[j].first
		}
		return pairs[i].second < pairs[j].second
	})
	format := func(p ctxPair) string {
		return fmt.Sprintf("source NAT rule-sets %q and %q have the same from/to "+
			"context (from [%s], to [%s]): Junos does not allow two source NAT "+
			"rule sets with the same source and destination conditions, and in "+
			"xpf the rule-sets are evaluated in definition order so the rules of "+
			"%q — including any `source-nat off` exemption — are unreachable "+
			"behind an earlier matching rule in %q; merge them into one "+
			"rule-set (#16607)", p.first, p.second, p.fromKey, p.toKey, p.second, p.first)
	}
	if !lenient {
		return nil, fmt.Errorf("%s", format(pairs[0]))
	}
	warnings := make([]string, 0, len(pairs))
	for _, p := range pairs {
		warnings = append(warnings, format(p))
	}
	return warnings, nil
}

// scopeSetKey renders a normalised scope set for comparison and display:
// duplicate (kind, value) tokens collapse and entries sort, so list order
// and repeated spellings never change the key. The empty value renders as
// the match-any wildcard marker.
func scopeSetKey(scopes []natMatchScope) string {
	uniq := make(map[string]bool, len(scopes))
	parts := make([]string, 0, len(scopes))
	for _, s := range scopes {
		v := s.value
		if v == "" {
			v = "<any>"
		}
		p := s.kind + " " + v
		if uniq[p] {
			continue
		}
		uniq[p] = true
		parts = append(parts, p)
	}
	sort.Strings(parts)
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// natRuleSetSubBlocks lists the NAT sub-blocks whose rule-SETS carry a named
// operational identity that must be unique within the sub-block's natType
// namespace. It EXTENDS natRuleSubBlocks (source / destination / static — the
// rule-NAME axis of #5649) with nat64: a nat64 rule-set carries prefix /
// source-pool and NO `rule` nodes (correctly excluded from the #5649 rule-name
// gate), but its NAME is still the operational identity, so a duplicated nat64
// rule-set name is its own fail-open worth catching (#6454). natv6v4 /
// proxy-arp are excluded: neither is a named first-match rule-set.
var natRuleSetSubBlocks = []string{"source", "destination", "static", "nat64"}

// dupNATRuleSet is one detected duplicate rule-set name within one NAT type.
type dupNATRuleSet struct {
	natType string // "source" | "destination" | "static" | "nat64"
	ruleSet string // the duplicated rule-set name
}

// validateDuplicateNATRuleSetNamesAST rejects (strict) or warns (lenient) when
// the candidate authors the SAME rule-set name twice within one NAT type. This
// is the #5649 (C181-M18) duplicate-NAT-rule-name defect one level up — the
// rule-SET axis (#6454).
//
// A NAT rule-set name is its operational identity: the from/to scope binding
// and the CLI show key. The name is UNIQUE per nat type but reusable ACROSS nat
// types — Junos gives source / destination / static / nat64 independent name
// spaces (NATCounterKey in pkg/dataplane/compiler_nat.go is natType-prefixed for
// the counted types), so the same rule-set name in two DIFFERENT nat types is a
// distinct identity and legitimate; only the same name WITHIN one nat type
// collides. Two same-named rule-sets do NOT reduce to last-writer-wins like a
// #5180 hierarchical block — they BOTH survive: compileNATSource /
// compileNATDestination / compileNATStatic / compileNAT64 each APPEND the
// rule-set (sec.NAT.Source / Destination.RuleSets / Static / NAT64), never
// merging by name, so both compile as separate first-match tables sharing one
// name. The operator authored what they read as one rule-set; it compiles to
// two, evaluated in sequence. The CLI named-rule-set show lookup (e.g.
// showNATSourceRuleSet in pkg/cli/cli_show_nat.go) returns on the FIRST name
// match, so the second same-named rule-set — and its rules — is invisible on
// that surface and the operator cannot disambiguate the two.
//
// This is NOT a per-rule counter merge: NATCounterKey INCLUDES the rule name, so
// the disjoint rules this gate uniquely catches (rule R1 in the first RS, rule
// R2 in the second) get DISTINCT counter keys and never share a hit counter — a
// SAME rule name in both rule-sets is caught first by the #5649 rule-NAME gate.
// The genuine, type-independent defect is the shared rule-set NAME identity, so
// the diagnostic is deliberately type-agnostic and never claims a per-rule
// counter (a nat64 rule-set is counter-less anyway).
//
// Runs PRE-expansion on top-level `security` stanzas only, exactly like
// validateDuplicateNATRuleNamesAST (#5649) and validateDuplicateNamedBlockAST
// (#5180): apply-groups DEEP-MERGES a same-named rule-set rather than duplicating
// it, and a rule-set authored once via flat `set` reuses its rule-set node
// (tree.SetPath merges), so only a directly-authored hierarchical duplicate
// reaches here. The seen-set is keyed by (natType, ruleSet) and unioned across
// repeated `security` / `nat` / sub-block stanzas — compileNAT (#3915) merges
// those repeats — so a rule-set name split across two `source {}` blocks is caught
// too. A quoted-empty rule-set name is recorded as an empty-name defect (#6455)
// rather than skipped — this gate OWNS the empty rule-set name (the #5649
// rule-name gate skips an empty rule-set so the warning is not double-reported).
// Crucially the dedup is at the AST rule-set-INSTANCE level, NOT the compiled
// level: a single authored rule-set carrying a bracket list of from/to scopes
// (#3096) Cartesian-expands into MULTIPLE same-named NATRuleSet objects downstream
// — that legitimate expansion is one AST instance and is NOT flagged. Strict
// rejects on the operator commit / commit-check path; lenient (Load / peer-sync,
// #1960) warns and keeps the historical two-table behavior.
//
// A duplicate authored ENTIRELY inside an applied group body is NOT caught here —
// this gate is pre-expansion by design; it is caught by
// validateDuplicateNamesExpandedAST (dup_names_expanded_6455.go, #6455
// Finding 1), which re-runs THIS function on a group-expanded clone.
func validateDuplicateNATRuleSetNamesAST(tree *ConfigTree, lenient bool) ([]string, error) {
	if tree == nil {
		return nil, nil
	}
	var dups []dupNATRuleSet
	var emptyKinds []string
	seen := map[string]bool{}
	reported := map[string]bool{}
	emptyReported := map[string]bool{}
	for _, top := range tree.Children {
		if top.Name() != "security" {
			continue
		}
		for _, nat := range top.FindChildren("nat") {
			for _, natType := range natRuleSetSubBlocks {
				for _, sub := range nat.FindChildren(natType) {
					for _, rsInst := range namedInstances(sub.FindChildren("rule-set")) {
						if rsInst.name == "" {
							if !emptyReported[natType] {
								emptyKinds = append(emptyKinds, "NAT "+natType+" rule-set")
								emptyReported[natType] = true
							}
							continue
						}
						key := natType + "\x00" + rsInst.name
						if seen[key] {
							if !reported[key] {
								dups = append(dups, dupNATRuleSet{natType, rsInst.name})
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

	if len(dups) == 0 && len(emptyKinds) == 0 {
		return nil, nil
	}
	// Deterministic order: natType, then rule-set.
	sort.Slice(dups, func(i, j int) bool {
		if dups[i].natType != dups[j].natType {
			return dups[i].natType < dups[j].natType
		}
		return dups[i].ruleSet < dups[j].ruleSet
	})
	sort.Strings(emptyKinds)

	if !lenient {
		// Duplicates keep first-error priority so the pre-#6455 messages are
		// unchanged when no empty name is present; an empty-name-only config
		// surfaces the empty-name error.
		if len(dups) > 0 {
			d := dups[0]
			return nil, fmt.Errorf("duplicate NAT %s rule-set %q: a NAT rule-set name "+
				"is its operational identity, so the same name authored twice compiles "+
				"both instances as separate first-match rule-sets sharing one identity "+
				"— operator show surfaces cannot disambiguate them; author the "+
				"rule-set once (flat `set` merges repeated statements automatically) "+
				"(#6454)", d.natType, d.ruleSet)
		}
		return nil, emptyNameError(emptyKinds[0])
	}

	warnings := make([]string, 0, len(dups)+len(emptyKinds))
	for _, d := range dups {
		warnings = append(warnings, fmt.Sprintf("duplicate NAT %s rule-set %q: the "+
			"same name compiles both instances as separate rule-sets sharing one "+
			"operational identity — author it once (#6454)", d.natType, d.ruleSet))
	}
	for _, k := range emptyKinds {
		warnings = append(warnings, emptyNameWarning(k))
	}
	return warnings, nil
}
