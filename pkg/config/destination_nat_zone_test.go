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

// Global, interface-scoped, and routing-instance-scoped DNAT rule-sets have
// no FromZone and must not be reported as references to an undefined zone.
func TestDestinationNATNonZoneFromScopesNoWarn12245(t *testing.T) {
	tests := []struct {
		name                string
		from                string
		wantInterface       string
		wantRoutingInstance string
	}{
		{name: "global"},
		{
			name:          "interface",
			from:          "from interface ge-0/0/0.0",
			wantInterface: "ge-0/0/0.0",
		},
		{
			name:                "routing-instance",
			from:                "from routing-instance blue",
			wantRoutingInstance: "blue",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ruleSet := "dnat-" + tc.name
			cmds := []string{
				"set security nat destination pool P1 address 10.0.30.100",
			}
			if tc.from != "" {
				cmds = append(cmds, "set security nat destination rule-set "+ruleSet+" "+tc.from)
			}
			cmds = append(cmds,
				"set security nat destination rule-set "+ruleSet+" rule R1 match destination-address 198.51.100.5/32",
				"set security nat destination rule-set "+ruleSet+" rule R1 then destination-nat pool P1",
			)
			cfg, err := CompileConfig(buildNATScopeTree(t, cmds...))
			if err != nil {
				t.Fatalf("CompileConfig rejected %s DNAT: %v", tc.name, err)
			}

			if len(cfg.Security.NAT.Destination.RuleSets) != 1 {
				t.Fatalf("got %d DNAT rule-sets, want 1", len(cfg.Security.NAT.Destination.RuleSets))
			}
			rs := cfg.Security.NAT.Destination.RuleSets[0]
			if rs.FromZone != "" {
				t.Fatalf("FromZone = %q, want empty for %s DNAT", rs.FromZone, tc.name)
			}
			if rs.FromInterface != tc.wantInterface {
				t.Fatalf("FromInterface = %q, want %q", rs.FromInterface, tc.wantInterface)
			}
			if rs.FromRoutingInstance != tc.wantRoutingInstance {
				t.Fatalf("FromRoutingInstance = %q, want %q", rs.FromRoutingInstance, tc.wantRoutingInstance)
			}

			for _, warning := range ValidateConfig(cfg) {
				if strings.Contains(warning, `destination-nat ruleset "`+ruleSet+`"`) &&
					strings.Contains(warning, "from-zone") {
					t.Fatalf("%s DNAT emitted a from-zone warning: %q", tc.name, warning)
				}
			}
		})
	}
}
