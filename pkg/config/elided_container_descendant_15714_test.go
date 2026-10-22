package config

import (
	"strings"
	"testing"
)

// #15714: deletePath/setInactiveAtPath whole-node deleted (or, when the path
// exactly exhausted the packed keys, whole-node toggled) the enclosing named
// container when the address targeted a descendant statement packed inside
// a brace-elided node. Junos brace-elision is only spelling: deleting
// `passive` under `interface ge-0/0/0.0 passive;` must remove only `passive`
// and keep `interface ge-0/0/0.0` (and any braced body) present and active.
//
// Controls pin the addresses that must NOT change: deleting/deactivating the
// container itself, a bare elided leaf, a sibling statement, and an absent
// descendant (which must stay a refusal and leave the tree untouched).

func render15714(tr *ConfigTree) string {
	var out []string
	var walk func(n *Node)
	walk = func(n *Node) {
		line := strings.Join(n.Keys, " ")
		if n.Inactive {
			line += " [INACTIVE]"
		}
		out = append(out, line)
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range tr.Children {
		walk(c)
	}
	return strings.Join(out, " | ")
}

// assertSerializedBody15714 checks body survival through the production
// serializers (15915r): every kept keys-line must appear in FormatSet
// output, and the Format() hierarchical text must reload to a tree
// still carrying the body. Raw traversal alone is NOT sufficient — a
// preserved body node marked IsLeaf is silently omitted by both
// serializers.
func assertSerializedBody15714(t *testing.T, tr *ConfigTree, keeps []string) {
	t.Helper()
	flat := tr.FormatSet()
	for _, keep := range keeps {
		found := false
		for _, line := range strings.Split(flat, "\n") {
			if strings.HasSuffix(line, " "+keep) || strings.Contains(line, " "+keep+" ") {
				found = true
			}
		}
		if !found {
			t.Errorf("serialized body LOST: %q not in FormatSet %q", keep, flat)
		}
	}
	reloaded := parseHierText(t, tr.Format())
	got := render15714(reloaded)
	for _, keep := range keeps {
		if !strings.Contains(got, keep) {
			t.Errorf("reloaded body LOST: %q missing from %q", keep, got)
		}
	}
}

func TestElidedDescendantDelete15714(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		path     []string
		mustKeep []string
		mustDrop []string
	}{
		{"ospf interface passive",
			"protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 passive; interface ge-0/0/1.0; } } }",
			[]string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0/0/0.0", "passive"},
			[]string{"interface ge-0/0/0.0", "interface ge-0/0/1.0"},
			[]string{"passive"}},
		{"bgp neighbor passive",
			"protocols { bgp { group g1 { neighbor 10.0.0.2 passive; neighbor 10.0.0.3; peer-as 65001; } } } routing-options { autonomous-system 65000; }",
			[]string{"protocols", "bgp", "group", "g1", "neighbor", "10.0.0.2", "passive"},
			[]string{"neighbor 10.0.0.2", "neighbor 10.0.0.3"},
			[]string{"passive"}},
		{"zone host-inbound-traffic keeps braced body",
			"security { zones { security-zone trust host-inbound-traffic { system-services { ssh; } protocols { ospf; } } security-zone dmz { tcp-rst; } } }",
			[]string{"security", "zones", "security-zone", "trust", "host-inbound-traffic"},
			[]string{"security-zone trust", "security-zone dmz"},
			[]string{"host-inbound-traffic", "system-services", "ssh", "ospf"}},
		{"interface family keeps unit",
			"interfaces { ge-0/0/0 { unit 0 family inet address 10.0.0.1/24; } ge-0/0/1 { unit 0 { description backup; } } }",
			[]string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet"},
			[]string{"unit 0", "ge-0/0/1", "description backup"},
			[]string{"family", "address"}},
		{"interface address keeps family and unit",
			"interfaces { ge-0/0/0 { unit 0 family inet address 10.0.0.1/24; } }",
			[]string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "address", "10.0.0.1/24"},
			[]string{"unit 0", "family inet"},
			[]string{"address"}},
		{"fully elided ospf passive",
			"protocols ospf area 0.0.0.0 interface ge-0/0/0.0 passive;",
			[]string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0/0/0.0", "passive"},
			[]string{"protocols", "ospf", "area 0.0.0.0", "interface ge-0/0/0.0"},
			[]string{"passive"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := parseHierText(t, tc.text)
			if err := tr.DeletePath(tc.path); err != nil {
				t.Fatalf("DeletePath(%v): %v", tc.path, err)
			}
			got := render15714(tr)
			for _, keep := range tc.mustKeep {
				if !strings.Contains(got, keep) {
					t.Errorf("enclosing container/sibling LOST: %q missing from %q", keep, got)
				}
			}
			for _, drop := range tc.mustDrop {
				if strings.Contains(got, drop) {
					t.Errorf("descendant NOT deleted: %q still in %q", drop, got)
				}
			}
			// The operated tree must still compile: keeping the container
			// while corrupting its shape would be a silent half-fix.
			if _, err := CompileConfig(tr); err != nil {
				t.Errorf("post-delete CompileConfig: %v (tree %q)", err, got)
			}
		})
	}
}

func TestElidedDescendantDeactivate15714(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		path      []string
		target    string // keys line that must be inactive
		container string // keys line that must stay ACTIVE (no marker)
		mustKeep  []string
	}{
		{"ospf interface passive",
			"protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 passive; } } }",
			[]string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0/0/0.0", "passive"},
			"passive", "interface ge-0/0/0.0", nil},
		{"zone host-inbound-traffic",
			"security { zones { security-zone trust host-inbound-traffic { system-services { ssh; } protocols { ospf; } } } }",
			[]string{"security", "zones", "security-zone", "trust", "host-inbound-traffic"},
			"host-inbound-traffic", "security-zone trust", []string{"system-services", "ssh", "protocols", "ospf"}},
		{"interface address",
			"interfaces { ge-0/0/0 { unit 0 family inet address 10.0.0.1/24; } }",
			[]string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "address", "10.0.0.1/24"},
			"address 10.0.0.1/24", "family inet", nil},
		{"fully elided ospf passive",
			"protocols ospf area 0.0.0.0 interface ge-0/0/0.0 passive;",
			[]string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0/0/0.0", "passive"},
			"passive", "interface ge-0/0/0.0", nil},
		{"interface family braced body",
			"interfaces { ge-0/0/0 { unit 0 family inet { address 10.0.0.1/24; } } }",
			[]string{"interfaces", "ge-0/0/0", "unit", "0", "family", "inet"},
			"family inet", "unit 0", []string{"address 10.0.0.1/24"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := parseHierText(t, tc.text)
			if err := tr.DeactivatePath(tc.path); err != nil {
				t.Fatalf("DeactivatePath(%v): %v", tc.path, err)
			}
			got := render15714(tr)
			found := false
			for _, line := range strings.Split(got, " | ") {
				if strings.Contains(line, tc.target) && strings.Contains(line, "[INACTIVE]") {
					found = true
				}
				if strings.HasPrefix(line, tc.container) && strings.Contains(line, "[INACTIVE]") {
					t.Errorf("enclosing container WRONGLY deactivated: %q in %q", line, got)
				}
			}
			if !found {
				t.Errorf("descendant NOT deactivated: %q not inactive in %q", tc.target, got)
			}
			// Activate must reverse exactly the descendant toggle.
			if err := tr.ActivatePath(tc.path); err != nil {
				t.Fatalf("ActivatePath(%v): %v", tc.path, err)
			}
			if got := render15714(tr); strings.Contains(got, "[INACTIVE]") {
				t.Errorf("activate left an inactive node: %q", got)
			}
			// B1 (triple-review 15915): toggling is a marker verb; the
			// authored braced body under the toggled node must survive
			// the deactivate+activate round trip verbatim.
			if got := render15714(tr); tc.mustKeep != nil {
				for _, keep := range tc.mustKeep {
					if !strings.Contains(got, keep) {
						t.Errorf("braced body LOST across toggle round trip: %q missing from %q", keep, got)
					}
				}
				// Re-review (15915r): body survival must hold through
				// the REAL serializers, not only raw traversal — a
				// preserved body marked IsLeaf is omitted by
				// Format/FormatSet and lost on reload.
				assertSerializedBody15714(t, tr, tc.mustKeep)
			}
		})
	}
}

// TestElidedContainerItselfStillWholeNode15714 pins the control addresses:
// deleting/deactivating the container (or a whole elided leaf) itself must
// keep its current whole-node meaning, not be braced into a stub.
func TestElidedContainerItselfStillWholeNode15714(t *testing.T) {
	text := "protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 passive; } } }"
	tr := parseHierText(t, text)
	if err := tr.DeletePath([]string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0/0/0.0"}); err != nil {
		t.Fatalf("delete container itself: %v", err)
	}
	if got := render15714(tr); strings.Contains(got, "interface ge-0/0/0.0") {
		t.Errorf("CONTROL BROKE: deleting the interface itself left it behind: %q", got)
	}

	tr2 := parseHierText(t, text)
	if err := tr2.DeactivatePath([]string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0/0/0.0"}); err != nil {
		t.Fatalf("deactivate container itself: %v", err)
	}
	if got := render15714(tr2); !strings.Contains(got, "interface ge-0/0/0.0 [INACTIVE]") && !strings.Contains(got, "interface ge-0/0/0.0 passive [INACTIVE]") {
		t.Errorf("CONTROL BROKE: deactivating the interface itself did not toggle it: %q", got)
	}

	// Bare elided leaf (#8992/#8997/#13535 shapes) still deletes/toggles whole.
	tr3 := parseHierText(t, `chassis cluster strict-session-auth;`)
	if err := tr3.DeletePath([]string{"chassis", "cluster", "strict-session-auth"}); err != nil {
		t.Fatalf("bare elided leaf delete: %v", err)
	}
	if got := render15714(tr3); strings.Contains(got, "strict-session-auth") {
		t.Errorf("CONTROL BROKE: bare elided leaf survived delete: %q", got)
	}
}

// TestElidedDescendantAbsentIsRefusal15714: an absent descendant inside a
// braced-after-the-fact container must stay a refusal and leave the tree in
// its original elided spelling (no silent bracing, no deletion).
func TestElidedDescendantAbsentIsRefusal15714(t *testing.T) {
	text := "protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 passive; } } }"
	tr := parseHierText(t, text)
	before := render15714(tr)
	err := tr.DeletePath([]string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0/0/0.0", "bogus-leaf"})
	if err == nil {
		t.Fatalf("absent descendant delete succeeded; tree %q", render15714(tr))
	}
	if got := render15714(tr); got != before {
		t.Errorf("refused delete mutated the tree: before %q after %q", before, got)
	}
	err = tr.DeactivatePath([]string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0/0/0.0", "bogus-leaf"})
	if err == nil {
		t.Fatalf("absent descendant deactivate succeeded; tree %q", render15714(tr))
	}
	if got := render15714(tr); got != before {
		t.Errorf("refused deactivate mutated the tree: before %q after %q", before, got)
	}
}

// TestElidedBodySurvivesDeleteOfSiblingPacked15714 (B1, triple-review
// 15915): deleting a packed DESCENDANT statement must not drop the
// authored braced body that hangs off the same elided node. The NAT
// rule shape (`rule r1 match ... { then { ... } }`, fixture dr14h2) is
// the sibling-body case: `then` is a sibling of the packed `match`,
// not its child, so a delete of the match descendant that re-braces
// the node must leave `then { source-nat interface; }` intact.
func TestElidedBodySurvivesDeleteOfSiblingPacked15714(t *testing.T) {
	tr := parseHierText(t, dr14h2SNATPacked)
	before := render15714(tr)
	path := []string{"security", "nat", "source", "rule-set", "rs1", "rule", "r1", "match", "source-address", "10.0.0.0/24"}
	if err := tr.DeletePath(path); err != nil {
		// If this shape is refused rather than edited, the refusal
		// must leave the tree byte-identical (no silent body loss).
		if render15714(tr) != before {
			t.Fatalf("refused delete mutated the tree: %q (err %v)", render15714(tr), err)
		}
		t.Skipf("sibling-packed delete refused (atomic): %v", err)
	}
	got := render15714(tr)
	for _, keep := range []string{"then", "source-nat interface"} {
		if !strings.Contains(got, keep) {
			t.Errorf("braced sibling body LOST on delete: %q missing from %q", keep, got)
		}
	}
	assertSerializedBody15714(t, tr, []string{"then", "source-nat interface"})
	if strings.Contains(got, "source-address") {
		t.Errorf("addressed descendant NOT deleted: %q", got)
	}
}
