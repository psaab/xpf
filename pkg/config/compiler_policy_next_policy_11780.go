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
				return fmt.Errorf("policy-statement %q term %q: then next %q must be exactly `then next policy`", name, term.Name, value)
			}
			if term.NextPolicy && term.Action != "" {
				return fmt.Errorf("policy-statement %q term %q: `then next policy` conflicts with terminal action `then %s`", name, term.Name, term.Action)
			}
		}
	}
	return nil
}
func failClosedMalformedNextPolicyActions11780(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, ps := range cfg.PolicyOptions.PolicyStatements {
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term != nil && term.invalidNextPolicy11780 {
				term.NextPolicy = false
				term.Action = "reject"
			}
		}
	}
}
