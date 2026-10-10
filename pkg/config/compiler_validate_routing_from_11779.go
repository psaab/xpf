package config

import (
	"fmt"
	"sort"
	"strings"
)

// validatePolicyFromUnknownStrict11779 rejects routing-policy `from` leaves
// the compiler does not represent and malformed bracketed lists that obscure
// clause boundaries. Without a marker, dropping one leaves the remaining
// match constraints broader than authored (an accept over-permits, a reject
// over-drops). The five compiled match types are protocol, prefix-list,
// route-filter, community, and as-path.
func validatePolicyFromUnknownStrict11779(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	var problems []string
	for _, stmtName := range names {
		stmt := cfg.PolicyOptions.PolicyStatements[stmtName]
		if stmt == nil {
			continue
		}
		if len(stmt.UnknownFrom) > 0 {
			problems = append(problems, fmt.Sprintf(
				"policy-options policy-statement %q: policy-level `from %s` is not enforced by the routing-policy compiler (#11779)",
				stmtName, strings.Join(stmt.UnknownFrom, ", ")))
		}
		for _, term := range stmt.Terms {
			if term == nil {
				continue
			}
			if term.invalidFromSyntax11779 != "" {
				problems = append(problems, fmt.Sprintf(
					"policy-options policy-statement %q term %q: %s (#11779)",
					stmtName, term.Name, term.invalidFromSyntax11779))
			}
			if len(term.UnknownFrom) > 0 {
				problems = append(problems, fmt.Sprintf(
					"policy-options policy-statement %q term %q: `from %s` is not enforced by the routing-policy compiler (#11779); supported `from` clauses are protocol, prefix-list, route-filter `<prefix> <match-type>`, community, and as-path",
					stmtName, term.Name, strings.Join(term.UnknownFrom, ", ")))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// failClosedUnknownPolicyFrom11779 prevents a tolerant load from publishing a
// routing-policy term with an unsupported predicate or malformed bracketed
// list. Rejecting the route is conservative for both permit and reject terms;
// continuing with an empty match set could widen either action.
func failClosedUnknownPolicyFrom11779(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, stmt := range cfg.PolicyOptions.PolicyStatements {
		if stmt == nil {
			continue
		}
		if len(stmt.UnknownFrom) > 0 {
			stmt.DefaultAction = "reject"
		}
		for _, term := range stmt.Terms {
			if term != nil && (len(stmt.UnknownFrom) > 0 ||
				len(term.UnknownFrom) > 0 || term.invalidFromSyntax11779 != "") {
				term.NextPolicy = false
				term.Action = "reject"
			}
		}
	}
}
