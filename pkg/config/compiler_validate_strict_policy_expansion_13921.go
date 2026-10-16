package config

import "fmt"

// MaxPolicyRulesPerSet is the wire/runtime namespace capacity shared with
// pkg/dataplane.MaxRulesPerPolicy. Policy rule IDs reserve one 256-ID block
// per zone-pair set and one for global policies.
const MaxPolicyRulesPerSet = 256

// validatePolicyExpandedRuleCountStrict rejects a policy set whose application
// expansion cannot fit its policy-ID block. The snapshot builder has the same
// guard, but reaching it only during apply makes commit report success while
// leaving the previous dataplane snapshot active.
func validatePolicyExpandedRuleCountStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	memo := newAppSetMemo()
	count := func(pol *Policy) int {
		if pol == nil {
			return 0
		}
		if len(pol.Match.Applications) == 0 {
			return 1
		}
		seen := make(map[string]struct{})
		for _, name := range pol.Match.Applications {
			if name == "" || name == "any" {
				return 1
			}
			if _, ok := ResolveApplication(name, cfg.Applications.Applications); ok {
				seen[name] = struct{}{}
				continue
			}
			if _, ok := ResolveApplicationSet(name, cfg.Applications.ApplicationSets); ok {
				expanded, err := expandAppSetMemo(name, &cfg.Applications, 0, memo)
				if err == nil {
					for _, app := range expanded {
						seen[app] = struct{}{}
					}
				}
			}
		}
		if len(seen) == 0 {
			return 1
		}
		return len(seen)
	}
	check := func(scope string, policies []*Policy) error {
		total := 0
		for _, pol := range policies {
			span := count(pol)
			if span > MaxPolicyRulesPerSet-total {
				return fmt.Errorf("%s: expanded rules exceed MaxRulesPerPolicy (%d)", scope, MaxPolicyRulesPerSet)
			}
			total += span
		}
		return nil
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		if err := check(fmt.Sprintf("policy %s->%s", zpp.FromZone, zpp.ToZone), zpp.Policies); err != nil {
			return err
		}
	}
	return check("global policy", cfg.Security.GlobalPolicies)
}
