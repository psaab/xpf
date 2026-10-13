package config

import (
	"errors"
	"fmt"
)

type unknownSecurityPoliciesChildSchemaError12217 struct {
	path    string
	keyword string
}

func (e *unknownSecurityPoliciesChildSchemaError12217) Error() string {
	return fmt.Sprintf("%s: unknown configuration keyword %q under closed-world subtree", e.path, e.keyword)
}

// IsUnknownSecurityPoliciesChildSchemaError12217 reports a strict closed-world
// rejection for a direct child of `security policies`, so tolerant Store
// ingestion can identify the diagnostic instead of logging it as a typed leaf.
func IsUnknownSecurityPoliciesChildSchemaError12217(err error) bool {
	var target *unknownSecurityPoliciesChildSchemaError12217
	return errors.As(err, &target)
}

func securityPoliciesSchema12217() *schemaNode {
	if schemaSecurity == nil {
		return nil
	}
	return schemaSecurity.children["policies"]
}

// These Junos-valid statements are not policy rulebases. They are currently
// accepted but not consumed at this hierarchy by the policy compiler, so
// tolerant compilation warns without poisoning the forwarding snapshot.
func nonEnforcementSecurityPoliciesChild12628(keyword string) bool {
	switch keyword {
	case "traceoptions", "policy-stats", "pre-id-default-policy":
		return true
	default:
		return false
	}
}

func enforcementSecurityPoliciesChildren12217(sec *SecurityConfig) []string {
	if sec == nil || len(sec.UnknownPoliciesChildren) == 0 {
		return nil
	}
	var unknown []string
	for _, keyword := range sec.UnknownPoliciesChildren {
		if !nonEnforcementSecurityPoliciesChild12628(keyword) {
			unknown = append(unknown, keyword)
		}
	}
	return unknown
}

// Apply statements are valid at any Junos hierarchy point, so they are not
// unknown policy-context children even though the compiler does not expand
// apply-macro or apply-groups-except here. Context walks may pass a qualified
// location (for example, `global policies polcy`) rather than a bare keyword.
func recordUnknownSecurityPoliciesChild12217(sec *SecurityConfig, keyword string) {
	if sec == nil || keyword == "" || isApplyStatementKeyword(keyword) {
		return
	}
	for _, existing := range sec.UnknownPoliciesChildren {
		if existing == keyword {
			return
		}
	}
	sec.UnknownPoliciesChildren = append(sec.UnknownPoliciesChildren, keyword)
}

func validateUnknownSecurityPoliciesChild12217(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	children := enforcementSecurityPoliciesChildren12217(&cfg.Security)
	if len(children) == 0 {
		return nil
	}
	return fmt.Errorf("security policies: unknown child keyword %q is unsupported and would be silently dropped", children[0])
}

func toleratedUnknownSecurityPoliciesChildWarnings12217(cfg *Config) []string {
	if cfg == nil || len(cfg.Security.UnknownPoliciesChildren) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(cfg.Security.UnknownPoliciesChildren))
	for _, keyword := range cfg.Security.UnknownPoliciesChildren {
		if nonEnforcementSecurityPoliciesChild12628(keyword) {
			warnings = append(warnings, fmt.Sprintf(
				"security policies: Junos-valid non-enforcement child %q is accepted but not consumed by the policy compiler (issue #12628)", keyword))
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"security policies: unknown child keyword %q was dropped; the incomplete rulebase is quarantined and the userspace policy snapshot is refused (tolerant path; strict commit rejects this; issue #12217)",
			keyword))
	}
	return warnings
}
