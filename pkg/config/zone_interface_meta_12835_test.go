package config

import (
	"reflect"
	"testing"
)

func TestZoneInterfacePackedMemberKeysSkipApplyMeta12835(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
	}{
		{"apply-macro", []string{"ge-0/0/0.0", "apply-macro", "M"}},
		{"apply-groups", []string{"ge-0/0/0.0", "apply-groups", "G"}},
		{"apply-groups-except", []string{"ge-0/0/0.0", "apply-groups-except", "G"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := zoneInterfaceMembers(&Node{Keys: tc.keys})
			if !reflect.DeepEqual(got, []string{"ge-0/0/0.0"}) {
				t.Fatalf("zoneInterfaceMembers = %v, want [ge-0/0/0.0]", got)
			}
		})
	}
	if got := zoneInterfaceMembers(&Node{Keys: []string{"ge-0/0/0.0", "host-inbound-traffic", "system-services"}}); !reflect.DeepEqual(got, []string{"ge-0/0/0.0"}) {
		t.Fatalf("ordinary body boundary changed membership: got %v", got)
	}
}

func TestZoneInterfacePackedApplyMacroOwnKeysCompiles12835(t *testing.T) {
	src := `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { security-zone Z { interfaces { ge-0/0/0.0 apply-macro M { host-inbound-traffic system-services ssh; } } } } }`
	tree, errs := NewParser(src).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	for _, compile := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{
		{"strict", CompileConfig},
		{"lenient", CompileConfigLenient},
	} {
		t.Run(compile.name, func(t *testing.T) {
			cfg, err := compile.fn(tree)
			if err != nil {
				t.Fatalf("compile rejected in-key apply-macro: %v", err)
			}
			if got := cfg.Security.Zones["Z"].Interfaces; !reflect.DeepEqual(got, []string{"ge-0/0/0.0"}) {
				t.Fatalf("zone membership = %v, want only the authored interface", got)
			}
		})
	}
}
