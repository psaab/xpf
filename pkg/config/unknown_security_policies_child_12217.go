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

// Apply statements are valid at any Junos hierarchy point, so they are not
// unknown policy-container children even though the compiler does not expand
// apply-macro or apply-groups-except here.
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
	if cfg == nil || len(cfg.Security.UnknownPoliciesChildren) == 0 {
		return nil
	}
	return fmt.Errorf("security policies: unknown child keyword %q is unsupported and would be silently dropped",
		cfg.Security.UnknownPoliciesChildren[0])
}

func toleratedUnknownSecurityPoliciesChildWarnings12217(cfg *Config) []string {
	if cfg == nil || len(cfg.Security.UnknownPoliciesChildren) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(cfg.Security.UnknownPoliciesChildren))
	for _, keyword := range cfg.Security.UnknownPoliciesChildren {
		warnings = append(warnings, fmt.Sprintf(
			"security policies: unknown child keyword %q was dropped; the incomplete rulebase is quarantined and the userspace policy snapshot is refused (tolerant path; strict commit rejects this; issue #12217)",
			keyword))
	}
	return warnings
}

// ToleratedUnknownSecurityPoliciesChildWarnings returns deterministic
// diagnostics for unknown direct children of `security policies`. Store.Load
// and Store.SyncApply use the same records to retain warnings on tolerant
// ingestion.
func ToleratedUnknownSecurityPoliciesChildWarnings12217(cfg *Config) []string {
	return toleratedUnknownSecurityPoliciesChildWarnings12217(cfg)
}
