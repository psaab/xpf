package config

import "fmt"

// NAT rule match-set emptiness — #8430.
//
// A NAT rule whose `match` block contributes NO constraint compiles to an
// empty match set, and the dataplane reads an empty set as UNCONSTRAINED:
//
//	nets_match_v4:  if !constrained { return true }
//	source_constrained = !snap.source_addresses.is_empty()
//
// So an unconstrained source-NAT rule translates EVERY source, not none. Two
// authoring mistakes land there, and both used to commit clean:
//
//   - an unknown or misspelled leaf (`soruce-address`) — the match switches in
//     compiler_nat_{source,static,destination}.go have no `default:` arm, so
//     the leaf is silently dropped. That route is now closed by flipping the
//     three `match` subtrees closedWorld in setSchema;
//   - a VALUELESS supported leaf (`source-address;`) or an entirely empty
//     `match { }` — the leaf IS recognised, so no allowlist can see it.
//
// This gate is deliberately written against the COMPILED match rather than the
// AST, because that is what binds the harm. The issue's own words: a cell that
// asserts the typo is rejected proves the allowlist and passes for a fix that
// leaves the valueless route open. Checking the compiled set catches every
// route into it, including ones nobody has thought of.
//
// An operator who genuinely wants a catch-all writes it explicitly
// (`match { source-address 0.0.0.0/0; }`), which is constrained and passes.
// The rejection is of the IMPLICIT empty set only.
//
// AND ONLY WHEN A `match` CONTAINER WAS AUTHORED. A rule with no `match` at all
// is a SCOPE-ONLY rule — `from zone trust; to zone untrust;` with no match
// translates everything in that scope, which is a common and legitimate shape
// the rule-set's own from/to already constrains. Rejecting it was the first
// version of this gate and it false-rejected NINE existing cells across
// compiler_nat_scope_3079, compiler_nat_mixed_scope_4881 and dup_names_6455.
// That is the difference the compiled NATMatch cannot express and matchAuthored
// exists to carry.
//
// Static NAT is not checked here: its rule shape (StaticNATRule) is a different
// struct with no match container of the same kind, and the closedWorld flip on
// its `match` subtree already closes the typo route that motivated this issue.

// natMatchIsConstrained reports whether a compiled NAT match restricts traffic
// on at least one axis. It reads the plural slices AND the back-compat scalars,
// because a NATMatch can arrive with either populated (natMatchValues has the
// same contract) — reading only the plurals would call a scalar-only match
// unconstrained and reject a valid rule.
func natMatchIsConstrained(m NATMatch) bool {
	switch {
	case len(m.SourceAddresses) > 0 || m.SourceAddress != "":
		return true
	case len(m.SourceAddressNames) > 0 || m.SourceAddressName != "":
		return true
	case len(m.DestinationAddresses) > 0 || m.DestinationAddress != "":
		return true
	case len(m.DestinationAddressNames) > 0 || m.DestinationAddressName != "":
		return true
	case len(m.DestinationPorts) > 0 || m.DestinationPort != 0:
		return true
	case len(m.Protocols) > 0 || m.Protocol != "":
		return true
	case len(m.Applications) > 0 || m.Application != "":
		return true
	}
	// A match that parsed NOTHING valid but recorded invalid tokens is still
	// unconstrained; validateNATMatchDestinationPortStrict (#3446/#4422) owns
	// the diagnostic for those, and reporting them here too would give the
	// operator two errors for one mistake.
	return false
}

// validateNATRuleMatchConstrainedStrict rejects a NAT rule whose match set is
// empty, in every direction that has one.
func validateNATRuleMatchConstrainedStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	emit := func(kind, ruleSet, rule string) error {
		return fmt.Errorf("security nat %s rule-set %q rule %q: the match block "+
			"constrains nothing, and the dataplane reads an EMPTY match set as "+
			"UNCONSTRAINED — this rule would translate EVERY packet reaching it, "+
			"not none. A leaf with no value (`source-address;`) and an empty "+
			"`match { }` both land here. Give the rule at least one match "+
			"criterion; if a catch-all is intended, say so explicitly with "+
			"`match { source-address 0.0.0.0/0; }` (#8430)",
			kind, ruleSet, rule)
	}
	// #9877: rules carrying unknown match leaves are skipped here — the #9877
	// gate (which runs first) reports them precisely by naming the dropped
	// leaves, so reporting them here too would give the operator two warnings
	// for one mistake.
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, r := range rs.Rules {
			if r != nil && r.matchAuthored && !natMatchIsConstrained(r.Match) && len(r.UnknownMatchLeaves) == 0 {
				return emit("source", rs.Name, r.Name)
			}
		}
	}
	if d := cfg.Security.NAT.Destination; d != nil {
		for _, rs := range d.RuleSets {
			if rs == nil {
				continue
			}
			for _, r := range rs.Rules {
				if r != nil && r.matchAuthored && !natMatchIsConstrained(r.Match) && len(r.UnknownMatchLeaves) == 0 {
					return emit("destination", rs.Name, r.Name)
				}
			}
		}
	}
	return nil
}
