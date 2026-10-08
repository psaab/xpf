package userspace

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// poisonZonePairDefinedAny poisons a zone-pair policy that names the reserved
// `any` token while a zone definition with that name is present. The definition
// is omitted from the zone snapshot, but Rust otherwise indexes the policy as a
// wildcard; the application sentinel makes current helpers reject the whole
// snapshot and prevents older helpers from enforcing the widened rule.
func poisonZonePairDefinedAny(rule *PolicyRuleSnapshot, side string) {
	if rule == nil || side == "" {
		return
	}
	rule.zonePairDefinedAnySide = side
	rule.ApplicationTerms = []PolicyApplicationSnapshot{{
		Name:     unsupportedApplicationSentinel,
		Protocol: unsupportedApplicationSentinel,
	}}
}

func definedAnyZonePairRejectionReason12249(rule *PolicyRuleSnapshot) string {
	return fmt.Sprintf(
		"policy %s names %q as its %s while a zone definition named %q is quarantined: this legacy zone-pair spelling would be indexed as a wildcard, so the userspace helper REJECTS THE WHOLE POLICY SNAPSHOT rather than broaden the rule; remove the reserved zone definition or rename it and the policy scope",
		policyRejectionScope(rule), config.ReservedWildcardZoneName, rule.zonePairDefinedAnySide,
		config.ReservedWildcardZoneName)
}

func poisonDefinedAnyZonePairPolicies(policies []PolicyRuleSnapshot, definedAny bool) {
	if !definedAny {
		return
	}
	for i := range policies {
		rule := &policies[i]
		// #9570's poison takes precedence if both reserved tokens appear.
		if rule.zonePairGlobalSentinelSide != "" || rule.zonePairDefinedAnySide != "" {
			continue
		}
		side := config.ZonePairDefinedAnySide(rule.FromZone, rule.ToZone, true)
		poisonZonePairDefinedAny(rule, side)
	}
}
