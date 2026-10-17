package config

import "fmt"

// MaxPolicyRulesPerSet is the wire/runtime namespace capacity shared with
// pkg/dataplane.MaxRulesPerPolicy. Policy rule IDs reserve one 256-ID block
// per zone-pair set and one for global policies.
const MaxPolicyRulesPerSet = 256

// MaxTotalPolicyRuleExpansion mirrors
// pkg/dataplane/userspace.MaxTotalPolicyRuleExpansion (#11081): the TOTAL
// expanded rule count across all non-quarantined zone-pair sets and
// globals. pkg/config cannot import the dataplane package (the dataplane
// imports config), so the value is mirrored here; the dataplane walker
// remains fail-closed at apply if the two ever diverge.
const MaxTotalPolicyRuleExpansion = 65536

// expandedPolicyApplicationCount14353 is the config-side span of one
// policy, mirroring userspacePolicyRuleExpansionCount
// (pkg/dataplane/userspace/policies_ids.go) bit-for-bit: no applications,
// an empty token, or `any` spans 1; a name resolving to an application
// spans 1; a name resolving to an application-set spans its deduplicated
// expansion; an unresolved name or an expansion error falls back to
// span 1 (the dataplane's `!ok || len == 0 -> 1` arm). The undefined-name
// reject itself belongs to validatePolicyMatchApplicationsStrict
// (#3144), not to the counting.
func expandedPolicyApplicationCount14353(cfg *Config, memo *appSetMemo, pol *Policy) int {
	if pol == nil || len(pol.Match.Applications) == 0 {
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
			if err != nil || len(expanded) == 0 {
				return 1
			}
			for _, app := range expanded {
				seen[app] = struct{}{}
			}
		}
		// An unresolved name falls through: the walker's resolver also
		// fails it to span 1, and #3144 rejects/warns it independently.
	}
	if len(seen) == 0 {
		return 1
	}
	return len(seen)
}

// validatePolicyExpandedRuleCountStrict rejects a policy set whose
// application expansion cannot fit its policy-ID block, or a config
// whose total expansion across all sets exceeds
// MaxTotalPolicyRuleExpansion. The snapshot builder (walkPolicyRuleSlots)
// has the same guards, but reaching them only during apply makes commit
// report success while leaving the previous dataplane snapshot active.
//
// Accounting mirrors walkPolicyRuleSlots exactly so commit and apply
// cannot diverge: zone-pair sets touching a quarantined zone
// (ZoneQuarantineExclusionsForConfig, with the reserved sentinels
// junos-global / any / junos-host deleted — dedicated poison paths govern
// them, #14329) are skipped, and a global rule whose configured match
// side is fully quarantined (ScopedGlobalQuarantineDropped over the
// non-reserved quarantined set, as the walker's
// globalScopeFullyQuarantined computes it) is skipped. Per-set overflow
// is reported before the total: the walker returns it while walking, so
// a config violating both gets the per-set error at apply too.
func validatePolicyExpandedRuleCountStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	quarantined := ZoneQuarantineExclusionsForConfig(cfg)
	// #14329: reserved policy sentinels are never policy-quarantine
	// members (same unconditional delete as walkPolicyRuleSlots).
	for _, name := range []string{JunosGlobalZoneName, ReservedWildcardZoneName, "junos-host"} {
		delete(quarantined, name)
	}
	// The walker's scoped-global test uses quarantinedZoneNamesForConfig:
	// collision losers + poisoned zones, reserved sentinels excluded.
	policyQuarantined := make(map[string]struct{}, len(quarantined))
	for name := range quarantined {
		if IsReservedZoneName(name) {
			continue
		}
		policyQuarantined[name] = struct{}{}
	}

	memo := newAppSetMemo()
	total := 0
	addSet := func(scope string, policies []*Policy) error {
		setTotal := 0
		for _, pol := range policies {
			if pol == nil {
				continue
			}
			span := expandedPolicyApplicationCount14353(cfg, memo, pol)
			if span > MaxPolicyRulesPerSet-setTotal {
				return fmt.Errorf("%s: expanded rules exceed MaxRulesPerPolicy (%d)", scope, MaxPolicyRulesPerSet)
			}
			setTotal += span
		}
		total += setTotal
		return nil
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		if _, drop := quarantined[zpp.FromZone]; drop {
			continue
		}
		if _, drop := quarantined[zpp.ToZone]; drop {
			continue
		}
		if err := addSet(fmt.Sprintf("policy %s->%s", zpp.FromZone, zpp.ToZone), zpp.Policies); err != nil {
			return err
		}
	}
	globals := make([]*Policy, 0, len(cfg.Security.GlobalPolicies))
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		if ScopedGlobalQuarantineDropped(pol.Match.FromZones, pol.Match.ToZones, policyQuarantined) {
			continue
		}
		globals = append(globals, pol)
	}
	if err := addSet("global policy", globals); err != nil {
		return err
	}
	if total > MaxTotalPolicyRuleExpansion {
		return fmt.Errorf("policy: total expanded rules %d exceed MaxTotalPolicyRuleExpansion (%d); the dataplane evaluates tiers linearly per new flow — split, prune, or collapse application expansions",
			total, MaxTotalPolicyRuleExpansion)
	}
	return nil
}
