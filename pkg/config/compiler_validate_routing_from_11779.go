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
//
// #16569 extends the same gate to the sibling `to` match clause (recorded on
// UnknownTo) and to unmodelled `then` action keywords (UnknownThen): Junos
// treats `to neighbor X` in a BGP import policy as `from neighbor X`, so
// dropping `to` widens the term to every peer exactly as dropping `from`
// does, and dropping a `then` modifier such as `preference` loses the
// action's effect while keeping its accept.
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
		if len(stmt.UnknownTo) > 0 {
			problems = append(problems, fmt.Sprintf(
				"policy-options policy-statement %q: policy-level `to %s` is not enforced by the routing-policy compiler (#16569)",
				stmtName, strings.Join(stmt.UnknownTo, ", ")))
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
			if len(term.UnknownTo) > 0 {
				problems = append(problems, fmt.Sprintf(
					"policy-options policy-statement %q term %q: `to %s` is not enforced by the routing-policy compiler (#16569); `to` match conditions (for BGP import, `to neighbor` is equivalent to `from neighbor`) are not compiled, so the term would match more broadly than authored",
					stmtName, term.Name, strings.Join(term.UnknownTo, ", ")))
			}
			if len(term.UnknownThen) > 0 {
				problems = append(problems, fmt.Sprintf(
					"policy-options policy-statement %q term %q: `then %s` is not enforced by the routing-policy compiler (#16569); supported `then` actions are accept, reject, next, next-hop, load-balance, local-preference, metric, metric-type, community, as-path-prepend, and origin",
					stmtName, term.Name, strings.Join(term.UnknownThen, ", ")))
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
// continuing with an empty match set could widen either action. #16569:
// UnknownTo / UnknownThen and statement-level UnknownTo fail closed the same
// way (statement-level markers force the default and every term to reject).
func failClosedUnknownPolicyFrom11779(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, stmt := range cfg.PolicyOptions.PolicyStatements {
		if stmt == nil {
			continue
		}
		if len(stmt.UnknownFrom) > 0 || len(stmt.UnknownTo) > 0 {
			stmt.DefaultAction = "reject"
		}
		for _, term := range stmt.Terms {
			if term != nil && (len(stmt.UnknownFrom) > 0 || len(stmt.UnknownTo) > 0 ||
				len(term.UnknownFrom) > 0 || len(term.UnknownTo) > 0 ||
				len(term.UnknownThen) > 0 || term.invalidFromSyntax11779 != "") {
				term.NextPolicy = false
				term.Action = "reject"
			}
		}
	}
}
