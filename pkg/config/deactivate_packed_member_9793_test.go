package config

import (
	"strings"
	"testing"
)

func parseTree9793(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

// toggle9793 applies one deactivate/activate line the way configstore does
// (ParseSetVerbGrouped, then the grouped tree verb).
func toggle9793(t *testing.T, tree *ConfigTree, line string) error {
	t.Helper()
	verb, path, _, grouped, err := ParseSetVerbGrouped(line)
	if err != nil {
		t.Fatalf("ParseSetVerbGrouped(%q): %v", line, err)
	}
	switch verb {
	case "deactivate":
		return tree.DeactivatePathGrouped(path, grouped)
	case "activate":
		return tree.ActivatePathGrouped(path, grouped)
	}
	t.Fatalf("unexpected verb %q in %q", verb, line)
	return nil
}

// zoneStatements9793 maps each security-zone statement's names to its
// Inactive flag.
func zoneStatements9793(t *testing.T, tree *ConfigTree) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, sec := range tree.Children {
		if len(sec.Keys) != 1 || sec.Keys[0] != "security" {
			continue
		}
		for _, zones := range sec.Children {
			if len(zones.Keys) != 1 || zones.Keys[0] != "zones" {
				continue
			}
			for _, z := range zones.Children {
				if len(z.Keys) > 1 && z.Keys[0] == "security-zone" {
					out[strings.Join(z.Keys[1:], " ")] = z.Inactive
				}
			}
		}
	}
	return out
}

// TestToggleOfOneGroupMemberIsRefused9793: a deactivate or activate naming one
// zone of a `security-zone [ a b ]` group used to toggle the whole grouped
// statement, silently changing the other zone. It must be refused and leave
// the statement as it was.
func TestToggleOfOneGroupMemberIsRefused9793(t *testing.T) {
	cases := []struct {
		name, text, line string
		wantInactive     bool
	}{
		{"deactivate one member of a braced group",
			"security { zones { security-zone [ zga zgb ] { tcp-rst; } } }",
			"deactivate security zones security-zone zga", false},
		{"deactivate one member of a leaf group",
			"security { zones { security-zone [ zga zgb ]; } }",
			"deactivate security zones security-zone zga", false},
		{"activate one member of an inactive group",
			"security { zones { inactive: security-zone [ zga zgb ] { tcp-rst; } } }",
			"activate security zones security-zone zga", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseTree9793(t, tc.text)
			err := toggle9793(t, tree, tc.line)
			if err == nil {
				t.Fatalf("%q: want a refusal, got nil; zones now %v", tc.line, zoneStatements9793(t, tree))
			}
			for _, want := range []string{`"security-zone zga zgb"`, "zga", "#9793"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not contain %q", err, want)
				}
			}
			if got := zoneStatements9793(t, tree); len(got) != 1 || got["zga zgb"] != tc.wantInactive {
				t.Errorf("a refused toggle changed the tree: want zga zgb inactive=%v, got %v", tc.wantInactive, got)
			}
		})
	}
}

// TestToggleOfAWholeStatementStillWorks9793 pins the two addresses the refusal
// must leave alone: the grouped line `show | display set` emits for an inactive
// group (#6668), and a zone whose own content is packed behind its name.
func TestToggleOfAWholeStatementStillWorks9793(t *testing.T) {
	cases := []struct {
		name, text, line, zone string
	}{
		{"the display-set line for a whole group",
			"security { zones { security-zone [ zga zgb ] { tcp-rst; } } }",
			"deactivate security zones security-zone [ zga zgb ]", "zga zgb"},
		{"a braced single zone",
			"security { zones { security-zone zc { tcp-rst; } } }",
			"deactivate security zones security-zone zc", "zc"},
		{"a zone whose content is packed behind its name",
			"security { zones { security-zone trust screen edge tcp-rst; } }",
			"deactivate security zones security-zone trust", "trust screen edge tcp-rst"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseTree9793(t, tc.text)
			if err := toggle9793(t, tree, tc.line); err != nil {
				t.Fatalf("CONTROL BROKE: %q must toggle the whole statement, got %v", tc.line, err)
			}
			if got := zoneStatements9793(t, tree); !got[tc.zone] {
				t.Fatalf("%q did not mark %q inactive: %v", tc.line, tc.zone, got)
			}
		})
	}
}
