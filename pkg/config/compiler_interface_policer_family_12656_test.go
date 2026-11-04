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
				name  string
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

// #12656 + #17196 (re-pinned by #18881): a braced filter under an UNKNOWN
// family `foo` draws exactly two lenient diagnostics — the #12090
// filter-binding warning and the #17196 unknown-family skip warning
// naming `foo`. Before #17196 (c4e12aafc3) this pinned exactly one; the
// shared extractor added the second, and the count re-pin keeps the cell
// failing if either diagnostic regresses.
func TestInterfaceUnknownFamilyBracedFilterEmitsSingleDiagnostic12656(t *testing.T) {
	tree := hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family foo { filter { input f; } } } } }")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.Warnings) != 2 {
		t.Fatalf("lenient warnings = %q, want exactly two diagnostics: one #12090 filter binding, one #17196 unknown family", cfg.Warnings)
	}
	saw12090, saw17196 := false, false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#12090") && strings.Contains(w, "filter input") {
			saw12090 = true
		}
		if strings.Contains(w, "#17196") && strings.Contains(w, `"foo"`) {
			saw17196 = true
		}
	}
	if !saw12090 || !saw17196 {
		t.Fatalf("lenient warnings %q must carry the #12090 filter-binding diagnostic and the #17196 diagnostic naming family \"foo\"", cfg.Warnings)
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
