package config

import (
	"strings"
	"testing"
)

// TestDestinationNATFromZoneUndefinedWarns12245 proves a typo'd DNAT from-zone
// gets the same warning as source and static NAT instead of producing a
// never-matching rule without an operator diagnostic.
func TestDestinationNATFromZoneUndefinedWarns12245(t *testing.T) {
	cfg, err := CompileConfig(buildNATScopeTree(t,
		"set security zones security-zone trust",
		"set security nat source rule-set snat-typo from zone untrsut",
		"set security nat static rule-set static-typo from zone untrsut",
		"set security nat static rule-set static-typo rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set static-typo rule R1 then static-nat prefix 10.0.0.5/32",
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set dnat-typo from zone untrsut",
		"set security nat destination rule-set dnat-typo rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set dnat-typo rule R1 then destination-nat pool P1",
	))
	if err != nil {
		t.Fatalf("strict compile should accept the configuration with advisory, got: %v", err)
	}

	warnings := ValidateConfig(cfg)
	for _, want := range []string{
		`source-nat ruleset "snat-typo": from-zone "untrsut" not defined`,
		`static-nat ruleset "static-typo": from-zone "untrsut" not defined`,
		`destination-nat ruleset "dnat-typo": from-zone "untrsut" not defined`,
	} {
		found := false
		for _, warning := range warnings {
			if warning == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing zone warning %q; warnings=%v", want, warnings)
		}
	}
}

// A defined DNAT from-zone is a positive control: it must stay warning-free.
func TestDestinationNATFromZoneDefinedNoWarn12245(t *testing.T) {
	cfg, err := CompileConfig(buildNATScopeTree(t,
		"set security zones security-zone untrust",
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set dnat-valid from zone untrust",
		"set security nat destination rule-set dnat-valid rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set dnat-valid rule R1 then destination-nat pool P1",
	))
	if err != nil {
		t.Fatalf("CompileConfig rejected a defined DNAT from-zone: %v", err)
	}
	for _, warning := range ValidateConfig(cfg) {
		if strings.Contains(warning, `destination-nat ruleset "dnat-valid"`) &&
			strings.Contains(warning, "from-zone") {
			t.Fatalf("defined DNAT from-zone emitted a zone warning: %q", warning)
		}
	}
}
