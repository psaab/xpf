package config

import "testing"

// #13097 (D1-15): `tcp-rst disable;` must not silently enable TCP RST.
func TestZoneTCPRstTrailingTokenPoisons13097(t *testing.T) {
	for _, text := range []string{
		"security { zones { security-zone trust { tcp-rst disable; } } }",
		"security { zones { security-zone trust { tcp-rst no; } } }",
		"security { zones { security-zone trust { tcp-rst { disable; } } } }",
	} {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse %q: %v", text, perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			continue // strict rejection is the fail-closed outcome
		}
		zone := cfg.Security.Zones["trust"]
		if zone == nil {
			t.Fatalf("%q: zone missing", text)
		}
		if zone.TCPRst {
			t.Fatalf("%q: trailing token silently enabled TCPRst", text)
		}
		if !zone.DroppedEnforcementChild {
			t.Fatalf("%q: trailing token must poison the zone (DroppedEnforcementChild)", text)
		}
	}
	// Control: bare tcp-rst; still enables.
	tree, perrs := NewParser("security { zones { security-zone trust { tcp-rst; } } }").Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse control: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("control compile: %v", err)
	}
	if !cfg.Security.Zones["trust"].TCPRst {
		t.Fatal("bare tcp-rst; must still set TCPRst")
	}
}
