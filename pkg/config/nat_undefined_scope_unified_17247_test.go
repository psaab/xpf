package config

import (
	"reflect"
	"testing"
)

// #17247: strict rejection and tolerant warning strings project the same
// finding walk. The per-axis diagnostics and their historical ordering remain
// intact, without an unused tolerant record or a changed dataplane snapshot.
func TestNATUndefinedScopeUnifiedProjections17247(t *testing.T) {
	cfg := &Config{Security: SecurityConfig{NAT: NATConfig{
		Source: []*NATRuleSet{nil, {
			Name:                "shared",
			FromInterface:       "ge-0/0/9.0",
			ToInterface:         "ge-0/0/10.0",
			FromRoutingInstance: "missing-source-from",
			ToRoutingInstance:   "missing-source-to",
		}},
		Destination: &DestinationNATConfig{RuleSets: []*NATRuleSet{nil, {
			Name:                "shared",
			FromInterface:       "ge-0/0/11.0",
			FromRoutingInstance: "missing-destination",
		}}},
		Static: []*StaticNATRuleSet{nil, {
			Name:                "shared",
			FromInterface:       "ge-0/0/12.0",
			FromRoutingInstance: "missing-static",
		}},
	}}}

	want := []string{
		`source-nat rule-set "shared": from interface "ge-0/0/9.0" not defined`,
		`source-nat rule-set "shared": to interface "ge-0/0/10.0" not defined`,
		`source-nat rule-set "shared": from routing-instance "missing-source-from" not defined`,
		`source-nat rule-set "shared": to routing-instance "missing-source-to" not defined`,
		`destination-nat rule-set "shared": from interface "ge-0/0/11.0" not defined`,
		`destination-nat rule-set "shared": from routing-instance "missing-destination" not defined`,
		`static-nat rule-set "shared": from interface "ge-0/0/12.0" not defined`,
		`static-nat rule-set "shared": from routing-instance "missing-static" not defined`,
	}
	findings := natUndefinedScopeFindings(cfg)
	if len(findings) != len(want) {
		t.Fatalf("findings = %d, want %d", len(findings), len(want))
	}
	wantRefs := []NATRuleSetRef{
		{Kind: "source", Name: "shared"},
		{Kind: "source", Name: "shared"},
		{Kind: "source", Name: "shared"},
		{Kind: "source", Name: "shared"},
		{Kind: "destination", Name: "shared"},
		{Kind: "destination", Name: "shared"},
		{Kind: "static", Name: "shared"},
		{Kind: "static", Name: "shared"},
	}
	gotRefs := make([]NATRuleSetRef, len(findings))
	for i, finding := range findings {
		if message := finding.message(); message != want[i] {
			t.Fatalf("finding %d = %q, want %q", i, message, want[i])
		}
		gotRefs[i] = finding.Ref
	}
	if !reflect.DeepEqual(gotRefs, wantRefs) {
		t.Fatalf("finding refs = %v, want %v", gotRefs, wantRefs)
	}
	offenders := natUndefinedScopeOffenders(cfg)
	if !reflect.DeepEqual(offenders, want) {
		t.Fatalf("offenders = %v, want %v", offenders, want)
	}
	strictErr := validateNATUndefinedScopeStrict(cfg)
	if (strictErr != nil) != (len(offenders) > 0) || strictErr == nil || strictErr.Error() != want[0] {
		t.Fatalf("strict error = %v, want first offender %q for %v", strictErr, want[0], offenders)
	}
	fullyDefined := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/1": {Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		RoutingInstances: []*RoutingInstanceConfig{{Name: "blue"}},
		Security: SecurityConfig{NAT: NATConfig{
			Source: []*NATRuleSet{{
				Name:                "source-ok",
				FromInterface:       "ge-0/0/1.0",
				ToInterface:         "ge-0/0/1.0",
				FromRoutingInstance: "blue",
				ToRoutingInstance:   "default",
			}},
			Destination: &DestinationNATConfig{RuleSets: []*NATRuleSet{{
				Name:                "destination-ok",
				FromInterface:       "ge-0/0/1.0",
				FromRoutingInstance: "blue",
			}}},
			Static: []*StaticNATRuleSet{{
				Name:                "static-ok",
				FromInterface:       "ge-0/0/1.0",
				FromRoutingInstance: "blue",
			}},
		}},
	}
	for _, tc := range []struct {
		name string
		cfg  *Config
	}{
		{name: "nil", cfg: nil},
		{name: "empty", cfg: &Config{}},
		{name: "fully defined", cfg: fullyDefined},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offenders := natUndefinedScopeOffenders(tc.cfg)
			err := validateNATUndefinedScopeStrict(tc.cfg)
			if (err != nil) != (len(offenders) > 0) {
				t.Fatalf("strict/offender disagreement: strict error=%v offenders=%v", err, offenders)
			}
			if err != nil || len(offenders) != 0 {
				t.Fatalf("defined config must have no findings: strict error=%v offenders=%v", err, offenders)
			}
		})
	}
}
