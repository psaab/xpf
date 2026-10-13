package config

import (
	"fmt"
	"strings"
	"testing"
)

// #12656: family mpls/any policer bindings and packed unknown-family bindings
// have no InterfaceUnit consumer but previously committed without a diagnostic.
func TestInterfaceUnsupportedFamilyPolicersRejected12656(t *testing.T) {
	for _, family := range []string{"mpls", "any"} {
		for _, direction := range []string{"input", "output"} {
			for _, shape := range []struct {
				name string
				build func(*testing.T, string, string) *ConfigTree
			}{
				{"flat", func(t *testing.T, family, direction string) *ConfigTree {
					return flatTreeFromSets(t, fmt.Sprintf("set interfaces ge-0/0/0 unit 0 family %s policer %s p1", family, direction))
				}},
				{"braced", func(t *testing.T, family, direction string) *ConfigTree {
					return hierTree(t, fmt.Sprintf("interfaces { ge-0/0/0 { unit 0 { family %s { policer { %s p1; } } } } }", family, direction))
				}},
			} {
				t.Run(family+"/"+direction+"/"+shape.name, func(t *testing.T) {
					assertRejectInterfaceFamily12656(t, shape.build(t, family, direction), family, "policer "+direction)
				})
			}
		}
	}
}

func TestInterfaceUnknownFamilyBindingsRejected12656(t *testing.T) {
	for _, tc := range []struct {
		name, setPath, label string
	}{
		{"flat filter", "set interfaces ge-0/0/0 unit 0 family foo filter input f", "filter input"},
		{"flat policer", "set interfaces ge-0/0/0 unit 0 family foo policer output p1", "policer output"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertRejectInterfaceFamily12656(t, flatTreeFromSets(t, tc.setPath), "foo", tc.label)
		})
	}
}

func assertRejectInterfaceFamily12656(t *testing.T, tree *ConfigTree, family, binding string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict compile accepted unconsumed family %s %s binding", family, binding)
	}
	if !strings.Contains(err.Error(), "#12656") || !strings.Contains(err.Error(), family) || !strings.Contains(err.Error(), binding) {
		t.Fatalf("strict error %q must name #12656, family %s, and %s", err, family, binding)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#12656") && strings.Contains(warning, family) && strings.Contains(warning, binding) {
			return
		}
	}
	t.Fatalf("lenient warnings %q lack #12656 for family %s %s", cfg.Warnings, family, binding)
}
