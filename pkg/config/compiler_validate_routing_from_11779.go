package config

import (
	"fmt"
	"sort"
)

// validatePolicyFromUnknownStrict11779 rejects routing-policy `from` match
// leaves that the compiler does not represent. Without a marker, dropping one
// leaves the remaining match constraints broader than authored (an accept
// over-permits, a reject over-drops). The five compiled match types are
// protocol, prefix-list, route-filter, community, and as-path.
func validatePolicyFromUnknownStrict11779(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, stmtName := range names {
		stmt := cfg.PolicyOptions.PolicyStatements[stmtName]
		if stmt == nil {
			continue
		}
		for _, term := range stmt.Terms {
			if term == nil || len(term.UnknownFrom) == 0 {
				continue
			}
			return fmt.Errorf(
				"policy-options policy-statement %q term %q: `from %s` is not enforced by the routing-policy compiler (#11779); supported `from` types are protocol, prefix-list, route-filter, community, and as-path",
				stmtName, term.Name, term.UnknownFrom[0])
		}
	}
	return nil
}

// failClosedUnknownPolicyFrom11779 prevents a tolerant load from publishing a
// routing-policy term whose unsupported match predicate was dropped. Rejecting
// the route is conservative for both permit and reject terms; continuing with
// an empty match set could widen either action.
func failClosedUnknownPolicyFrom11779(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, stmt := range cfg.PolicyOptions.PolicyStatements {
		if stmt == nil {
			continue
		}
		for _, term := range stmt.Terms {
			if term != nil && len(term.UnknownFrom) > 0 {
				term.NextPolicy = false
				term.Action = "reject"
			}
		}
	}
}
