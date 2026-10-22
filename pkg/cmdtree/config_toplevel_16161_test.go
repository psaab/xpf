package cmdtree

import "testing"

// #16161 regrowth guard: ConfigTopLevel carries description-only
// top-level keywords. `set` (and every other verb) MUST NOT grow
// descendants again — config grammar below the top level lives in
// pkg/config's setSchema. The issue's acceptance form: no `set`
// descendants beyond depth 1 (the keyword itself).
func TestConfigTopLevelSetIsDescriptionOnly16161(t *testing.T) {
	setNode, ok := ConfigTopLevel["set"]
	if !ok {
		t.Fatal("ConfigTopLevel is missing `set`")
	}
	if setNode.Desc == "" {
		t.Error("ConfigTopLevel[\"set\"] lost its description")
	}
	if len(setNode.Children) != 0 {
		t.Errorf("ConfigTopLevel[\"set\"] has %d children %v; config grammar belongs in pkg/config setSchema (#16161)",
			len(setNode.Children), KeysFromTree(setNode.Children))
	}
	// Every ConfigTopLevel entry that still carries children may do
	// so only one level deep (commit/load sub-keywords); nothing may
	// re-grow a config-grammar subtree under any verb.
	for verb, node := range ConfigTopLevel {
		for child, sub := range node.Children {
			if len(sub.Children) != 0 {
				t.Errorf("ConfigTopLevel[%q][%q] has descendants %v; only depth-1 sub-keywords are allowed (#16161)",
					verb, child, KeysFromTree(sub.Children))
			}
		}
	}
}

// #16161: with the overlay deleted, LookupDesc in config mode must
// describe the former overlay knobs from pkg/config's schema. Every
// former overlay knob resolves a non-empty description.
func TestLookupDescConfigDataplaneFromSchema16161(t *testing.T) {
	cases := []struct {
		words []string
		name  string
	}{
		{[]string{"set", "system"}, "dataplane"},
		{[]string{"set", "system", "dataplane"}, "rss-indirection"},
		{[]string{"set", "system", "dataplane"}, "claim-host-tunables"},
		{[]string{"set", "system", "dataplane"}, "cpu-governor"},
		{[]string{"set", "system", "dataplane"}, "netdev-budget"},
		{[]string{"set", "system", "dataplane"}, "coalescence"},
		{[]string{"set", "system", "dataplane", "coalescence"}, "adaptive"},
		{[]string{"set", "system", "dataplane", "coalescence"}, "rx-usecs"},
		{[]string{"set", "system", "dataplane", "coalescence"}, "tx-usecs"},
		// delete/show/edit share the same schema grammar.
		{[]string{"delete", "system", "dataplane"}, "rss-indirection"},
		// Abbreviated consumed words still resolve (unique prefix).
		{[]string{"set", "sys", "dataplane"}, "netdev-budget"},
	}
	for _, tc := range cases {
		if got := LookupDesc(tc.words, tc.name, true); got == "" {
			t.Errorf("LookupDesc(%v, %q, config) = \"\"; former overlay knob must resolve via schema (#16161)",
				tc.words, tc.name)
		}
	}
	// A knob that does not exist describes nothing.
	if got := LookupDesc([]string{"set", "system", "dataplane"}, "no-such-knob", true); got != "" {
		t.Errorf("LookupDesc(no-such-knob) = %q, want \"\"", got)
	}
	// Top-level and commit/load help are untouched by the fallback.
	if got := LookupDesc(nil, "set", true); got != "Set a configuration parameter" {
		t.Errorf("LookupDesc(nil, set, config) = %q", got)
	}
	if got := LookupDesc([]string{"com"}, "confirmed", true); got != "Automatically rollback if not confirmed" {
		t.Errorf("LookupDesc(commit confirmed) = %q", got)
	}
}
