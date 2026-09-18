package config

import (
	"fmt"
	"testing"
)

// #10053 — per-member `apply-groups-except` for cross-group leaf-list unions.
//
// #9862 made nested exclusions node-atomic for leaf-lists: when a nested
// expansion unions members across groups into one node (mergeLeafListInto),
// per-member provenance is lost, so excluding one contributor keeps the whole
// union. Junos unions per member: excluding H2 must drop exactly H2's members.
//
// Fixture is the issue's measured case: G { apply-groups [ H1 H2 ]; } with
// H1/H2 contributing one name-server each, top-level `apply-groups G`, and
// `system { apply-groups-except H2; }`.
func TestApplyGroupsExceptNestedLeafListPerMember10053(t *testing.T) {
	const tmpl = `groups {
  H1 { system { name-server { 1.1.1.1; } } }
  H2 { system { name-server { 2.2.2.2; } } }
  G { apply-groups [ H1 H2 ]; }
}
apply-groups G;
system { %s }`
	ctrl := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "domain-name example.com;")))
	if got := ctrl.System.NameServers; !contains9862(got, "1.1.1.1") || !contains9862(got, "2.2.2.2") {
		t.Fatalf("POSITIVE CONTROL broken: NameServers=%v, want both members", got)
	}
	t.Run("except-H2 keeps exactly H1", func(t *testing.T) {
		got := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except H2;"))).System.NameServers
		if !equalStrs9862(got, []string{"1.1.1.1"}) {
			t.Fatalf("NameServers=%v, want [1.1.1.1] (H2's member must drop)", got)
		}
	})
	t.Run("except-H1 keeps exactly H2", func(t *testing.T) {
		got := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except H1;"))).System.NameServers
		if !equalStrs9862(got, []string{"2.2.2.2"}) {
			t.Fatalf("NameServers=%v, want [2.2.2.2] (H1's member must drop)", got)
		}
	})
}

// Collapsed-shape twin (#4070 posture: block and collapsed shapes behave
// identically). The collapsed union carries members on Keys with no node to
// tag, so this is the shape that forces normalize-before-filter.
func TestApplyGroupsExceptNestedLeafListCollapsedPerMember10053(t *testing.T) {
	const tmpl = `groups {
  H1 { system { name-server 1.1.1.1; } }
  H2 { system { name-server 2.2.2.2; } }
  G { apply-groups [ H1 H2 ]; }
}
apply-groups G;
system { %s }`
	ctrl := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "domain-name example.com;")))
	if got := ctrl.System.NameServers; !contains9862(got, "1.1.1.1") || !contains9862(got, "2.2.2.2") {
		t.Fatalf("POSITIVE CONTROL broken: NameServers=%v, want both members", got)
	}
	got := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except H2;"))).System.NameServers
	if !equalStrs9862(got, []string{"1.1.1.1"}) {
		t.Fatalf("NameServers=%v, want [1.1.1.1] (collapsed shape must match block)", got)
	}
}

// Direct-shape control: applied without nesting the same exclusion already
// filters per group (outer veto, no union collapse). Must not move.
func TestApplyGroupsExceptDirectLeafListControl10053(t *testing.T) {
	got := compile9422(t, parseTree9422(t, `groups {
  H1 { system { name-server { 1.1.1.1; } } }
  H2 { system { name-server { 2.2.2.2; } } }
}
apply-groups [ H1 H2 ];
system { apply-groups-except H2; }`)).System.NameServers
	if !equalStrs9862(got, []string{"1.1.1.1"}) {
		t.Fatalf("direct per-group filtering moved: NameServers=%v, want [1.1.1.1]", got)
	}
}

// Duplicate ownership across the nesting: both groups own .1, only H2 owns
// .2. Excluding H1 must keep .1 (H2 still owns it) — never over-excludes —
// and excluding both drops both.
func TestApplyGroupsExceptNestedLeafListSharedMember10053(t *testing.T) {
	const tmpl = `groups {
  H1 { system { name-server { 1.1.1.1; } } }
  H2 { system { name-server { 1.1.1.1; 2.2.2.2; } } }
  G { apply-groups [ H1 H2 ]; }
}
apply-groups G;
system { %s }`
	got1 := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except H1;"))).System.NameServers
	if !contains9862(got1, "1.1.1.1") || !contains9862(got1, "2.2.2.2") {
		t.Fatalf("except-H1 over-excluded H2's members: NameServers=%v", got1)
	}
	gotBoth := compile9422(t, parseTree9422(t, fmt.Sprintf(tmpl, "apply-groups-except [ H1 H2 ];"))).System.NameServers
	if len(gotBoth) != 0 {
		t.Fatalf("except-[H1 H2] kept members: NameServers=%v, want none", gotBoth)
	}
}

// Quote provenance through the per-member path: the surviving member keeps
// the quote its own authoring gave it (KeysQuoted invariant, #9862/#9899).
// Asserted on the merged AST, where the mask is observable.
func TestApplyGroupsExceptNestedLeafListQuote10053(t *testing.T) {
	text := `groups {
  H1 { system { name-server "1.1.1.1"; } }
  H2 { system { name-server 2.2.2.2; } }
  G { apply-groups [ H1 H2 ]; }
}
apply-groups G;
system { apply-groups-except H2; }`
	tree := parseTree9422(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	var found bool
	var walk func(nodes []*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			if n == nil {
				continue
			}
			if len(n.Keys) > 0 && n.Keys[0] == "name-server" {
				found = true
				for _, m := range leafListMembers9627(n) {
					switch m.value {
					case "1.1.1.1":
						if !m.quoted {
							t.Fatalf("surviving member lost its quote: members=%v", leafListMembers9627(n))
						}
					case "2.2.2.2":
						t.Fatalf("excluded member survived: members=%v", leafListMembers9627(n))
					}
				}
			}
			walk(n.Children)
		}
	}
	walk(tree.Children)
	if !found {
		t.Fatal("merged tree lost the name-server node")
	}
}

// Inline/unknown ownership stays conservative when it duplicates a group
// member. Excluding the group must not delete the authored inline value.
func TestApplyGroupsExceptNestedLeafListInlineDuplicateKeeps10053(t *testing.T) {
	const text = `groups {
  H1 { system { name-server { 1.1.1.1; } } }
  H2 { system { name-server { 1.1.1.1; 2.2.2.2; } } }
  G { apply-groups [ H1 H2 ]; }
}
apply-groups G;
system { name-server 1.1.1.1; apply-groups-except H2; }`
	got := compile9422(t, parseTree9422(t, text)).System.NameServers
	if !equalStrs9862(got, []string{"1.1.1.1"}) {
		t.Fatalf("inline duplicate was over-excluded: NameServers=%v, want [1.1.1.1]", got)
	}
}
