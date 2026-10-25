package config

import (
	"fmt"
	"sort"
)

func validatePolicyNextPolicyActions11780(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := cfg.PolicyOptions.PolicyStatements[name]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			if term.invalidNextPolicy11780 {
				value := term.invalidNextPolicyValue11780
				if value == "" {
					value = "<missing>"
				}
				return fmt.Errorf("policy-statement %q term %q: then next %q must be `then next policy` or `then next term`", name, term.Name, value)
			}
			if term.NextTerm && term.NextPolicy {
				return fmt.Errorf("policy-statement %q term %q: `then next term` conflicts with `then next policy` (specify one flow-control action)", name, term.Name)
			}
			if term.NextPolicy && term.Action != "" {
				return fmt.Errorf("policy-statement %q term %q: `then next policy` conflicts with terminal action `then %s`", name, term.Name, term.Action)
			}
			if term.NextTerm && term.Action != "" {
				return fmt.Errorf("policy-statement %q term %q: `then next term` conflicts with terminal action `then %s`", name, term.Name, term.Action)
			}
		}
	}
	return nil
}

// failClosedMalformedNextPolicyActions11780 makes every contradictory
// continuation state fail closed on the tolerant path: malformed
// `then next <value>`, `next term`/`next policy` beside a terminal, and
// mixed `next term` + `next policy` all force the term to `reject`
// with both continuation markers cleared, so no consumer (renderer,
// sequence counting, narrowed-survivor, redistribute) can treat the
// term as a valid fall-through or jump. Authored fields are NOT
// retained here — unlike the security-policy poison model, routing
// terms have no LenientContentDropped sentinel, so the compiled term
// itself must be the fail-closed one (mirrors
// failClosedRoutingTermTerminalConflicts).
func failClosedMalformedNextPolicyActions11780(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, ps := range cfg.PolicyOptions.PolicyStatements {
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			if term.invalidNextPolicy11780 || (term.NextTerm && term.Action != "") ||
				(term.NextTerm && term.NextPolicy) {
				term.NextPolicy = false
				term.NextTerm = false
				term.Action = "reject"
			}
		}
	}
}
