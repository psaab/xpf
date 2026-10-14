package config

import "fmt"

func policyStatsValue12825(value string) (bool, bool) {
	switch value {
	case "enable", "enabled":
		return true, true
	case "disable", "disabled":
		return false, true
	default:
		return false, false
	}
}

// validatePolicyStatsSystemWide12825 checks every system-wide leaf across
// repeated policy-stats blocks and security roots. Invalid or contradictory
// values are rejected on strict ingress and warned on tolerant ingress.
func validatePolicyStatsSystemWide12825(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	var firstSet, firstEnabled bool
	var firstValue string
	for _, security := range nodes {
		if security == nil || security.Name() != "security" {
			continue
		}
		for _, stats := range security.FindChildren("policy-stats") {
			for _, leaf := range stats.FindChildren("system-wide") {
				value := nodeVal(leaf)
				enabled, ok := policyStatsValue12825(value)
				if !ok {
					diagnostic := fmt.Sprintf("security policy-stats system-wide: invalid value %q; expected enable|enabled|disable|disabled (#12825)", value)
					if !lenient {
						return nil, fmt.Errorf("%s", diagnostic)
					}
					warnings = append(warnings, diagnostic+"; tolerant compilation disables policy statistics")
					continue
				}
				if !firstSet {
					firstSet, firstEnabled, firstValue = true, enabled, value
					continue
				}
				if enabled != firstEnabled {
					diagnostic := fmt.Sprintf("security policy-stats system-wide: conflicting values %q and %q (#12825)", firstValue, value)
					if !lenient {
						return nil, fmt.Errorf("%s", diagnostic)
					}
					warnings = append(warnings, diagnostic+"; tolerant compilation disables policy statistics")
				}
			}
		}
	}
	return warnings, nil
}

func hasInvalidOrConflictingPolicyStatsSystemWide12825(nodes []*Node) bool {
	var firstSet, firstEnabled bool
	for _, security := range nodes {
		if security == nil || security.Name() != "security" {
			continue
		}
		for _, stats := range security.FindChildren("policy-stats") {
			for _, leaf := range stats.FindChildren("system-wide") {
				enabled, ok := policyStatsValue12825(nodeVal(leaf))
				if !ok {
					return true
				}
				if !firstSet {
					firstSet, firstEnabled = true, enabled
					continue
				}
				if enabled != firstEnabled {
					return true
				}
			}
		}
	}
	return false
}
