package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateRoutingStatementDefaultConflictStrict rejects a policy-statement
// whose statement-level `then` nodes carry both accept and reject (#14433).
// Distinct actions are recorded on DefaultActionsSeen across merged group
// containers, duplicate `then` blocks, same-name statement blocks, and
// packed/flat spellings; repeating one action is not a conflict.
func validateRoutingStatementDefaultConflictStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	var problems []string
	for _, name := range names {
		stmt := cfg.PolicyOptions.PolicyStatements[name]
		if stmt == nil || len(stmt.DefaultActionsSeen) < 2 {
			continue
		}
		hasAccept, hasReject := false, false
		for _, action := range stmt.DefaultActionsSeen {
			switch action {
			case "accept":
				hasAccept = true
			case "reject":
				hasReject = true
			}
		}
		if hasAccept && hasReject {
			problems = append(problems, fmt.Sprintf(
				"policy-options policy-statement %q: conflicting default actions %s — "+
					"a statement may have at most one default action (accept and reject are mutually exclusive) (#14433)",
				name, strings.Join(stmt.DefaultActionsSeen, " and ")))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// failClosedRoutingStatementDefaultConflicts14433 forces a tolerantly loaded
// conflicting statement's default to reject, regardless of last-wins order.
func failClosedRoutingStatementDefaultConflicts14433(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, stmt := range cfg.PolicyOptions.PolicyStatements {
		if stmt == nil {
			continue
		}
		hasAccept, hasReject := false, false
		for _, action := range stmt.DefaultActionsSeen {
			switch action {
			case "accept":
				hasAccept = true
			case "reject":
				hasReject = true
			}
		}
		if hasAccept && hasReject {
			stmt.DefaultAction = "reject"
		}
	}
}
