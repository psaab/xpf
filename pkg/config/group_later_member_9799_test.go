package config

import (
	"errors"
	"strings"
	"testing"
)

func groupTree9799(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

const zoneGroup9799 = "security { zones { security-zone [ zga zgb ] { tcp-rst; } } }"

func zonePath9799(name string) []string {
	return []string{"security", "zones", "security-zone", name}
}

// TestShowOfALaterGroupMemberShowsTheGroup9799: `show ... security-zone zgb`
// printed nothing while `... zga` printed the group.
func TestShowOfALaterGroupMemberShowsTheGroup9799(t *testing.T) {
	tree := groupTree9799(t, zoneGroup9799)
	first := tree.FormatPath(zonePath9799("zga"))
	later := tree.FormatPath(zonePath9799("zgb"))
	if first == "" || !strings.Contains(first, "zgb") {
		t.Fatalf("CONTROL BROKE: the first member must show the group, got %q", first)
	}
	if later != first {
		t.Fatalf("a later member must show the same group as the first: got %q, want %q", later, first)
	}
	if got := tree.FormatPath(zonePath9799("zgc")); got != "" {
		t.Fatalf("a name the group does not carry must show nothing, got %q", got)
	}
}

// TestLaterMemberNeedsBracketProvenance9799 pins the two shapes that carry keys
// past a name without being a group: a packed body, and a node with no
// provenance at all.
func TestLaterMemberNeedsBracketProvenance9799(t *testing.T) {
	packed := groupTree9799(t, "security { zones { security-zone trust screen edge; } }")
	if got := packed.FormatPath(zonePath9799("edge")); got != "" {
		t.Fatalf("a packed body is not a member list: show of `edge` printed %q", got)
	}
	synthesized := &ConfigTree{Children: []*Node{{Keys: []string{"security"}, Children: []*Node{
		{Keys: []string{"zones"}, Children: []*Node{
			{Keys: []string{"security-zone", "zga", "zgb"}, Children: []*Node{{Keys: []string{"tcp-rst"}, IsLeaf: true}}},
		}},
	}}}}
	if got := synthesized.FormatPath(zonePath9799("zgb")); got != "" {
		t.Fatalf("a node with no bracket provenance must not be claimed as a group, got %q", got)
	}
}

// TestFlatSetGroupResolvesALaterMember9799: a group built from a `set` line
// carries the same provenance.
func TestFlatSetGroupResolvesALaterMember9799(t *testing.T) {
	tree := &ConfigTree{}
	verb, path, quoted, grouped, err := ParseSetVerbGrouped("set security zones security-zone [ zga zgb ] tcp-rst")
	if err != nil || verb != "set" {
		t.Fatalf("ParseSetVerbGrouped: %v %q", err, verb)
	}
	if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
		t.Fatalf("SetPathQuotedGrouped: %v", err)
	}
	if got := tree.FormatPath(zonePath9799("zgb")); !strings.Contains(got, "zga") || !strings.Contains(got, "tcp-rst") {
		t.Fatalf("a flat-set group must show for its later member, got %q", got)
	}
}

// TestEditsOfALaterGroupMemberAreRefused9799: delete, deactivate and activate
// of a later member reported no node; they must refuse with guidance and
// leave the tree alone.
func TestEditsOfALaterGroupMemberAreRefused9799(t *testing.T) {
	cases := []struct {
		name string
		text string
		edit func(*ConfigTree) error
		sen  bool // wraps ErrPathNotFound, as #8992's delete refusal does
	}{
		{"delete", zoneGroup9799, func(tr *ConfigTree) error { return tr.DeletePath(zonePath9799("zgb")) }, true},
		{"deactivate", zoneGroup9799, func(tr *ConfigTree) error { return tr.DeactivatePath(zonePath9799("zgb")) }, false},
		{"activate", "security { zones { inactive: security-zone [ zga zgb ] { tcp-rst; } } }",
			func(tr *ConfigTree) error { return tr.ActivatePath(zonePath9799("zgb")) }, false},
		{"deactivate inside the member's body", zoneGroup9799,
			func(tr *ConfigTree) error { return tr.DeactivatePath(append(zonePath9799("zgb"), "tcp-rst")) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := groupTree9799(t, tc.text)
			before := tree.Format()
			err := tc.edit(tree)
			if err == nil || !strings.Contains(err.Error(), "#9799") || !strings.Contains(err.Error(), "security-zone zga zgb") {
				t.Fatalf("want a #9799 refusal naming the group, got %v", err)
			}
			if tc.sen && !errors.Is(err, ErrPathNotFound) {
				t.Errorf("the delete refusal must wrap ErrPathNotFound like #8992's, got %v", err)
			}
			if after := tree.Format(); after != before {
				t.Fatalf("a refused edit changed the tree:\nbefore %q\nafter  %q", before, after)
			}
		})
	}
}
