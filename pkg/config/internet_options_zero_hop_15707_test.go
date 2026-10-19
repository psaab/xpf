package config

import (
	"strings"
	"testing"
)

// #15707: `system internet-options no-ipv6-reject-zero-hop-limit` must
// compile identically in every spelling. The compact one-liner
// `system internet-options no-ipv6-reject-zero-hop-limit;` packed the leaf
// onto the internet-options node's Keys, where compileSystem's
// FindChild-only reader dropped it, and the flat-set chain nested an
// `internet-options` extra under the modelled leaf where
// collectInternetOptionsExtras13089 never scanned Keys[1:].

func compile15707(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", text, perrs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", text, err)
	}
	return cfg
}

func TestInternetOptionsZeroHopLimitSpellings15707(t *testing.T) {
	for name, text := range map[string]string{
		"braced":            "system {\n internet-options {\n  no-ipv6-reject-zero-hop-limit;\n }\n}\n",
		"compact top-level": "system internet-options no-ipv6-reject-zero-hop-limit;\n",
		"compact in braces": "system {\n internet-options no-ipv6-reject-zero-hop-limit;\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := compile15707(t, text)
			io := cfg.System.InternetOptions
			if io == nil {
				t.Fatalf("%s: InternetOptions is nil, want flag set", name)
			}
			if !io.NoIPv6RejectZeroHopLimit {
				t.Errorf("%s: NoIPv6RejectZeroHopLimit = false, want true (spelling dropped)", name)
			}
		})
	}
}

func TestInternetOptionsExtrasScanKeys15707(t *testing.T) {
	// The modelled leaf carrying a packed tail on its Keys (the shape the
	// flat-set chain / compact spelling produces) must surface the tail's
	// head as an unmodelled extra.
	node := &Node{Keys: []string{"no-ipv6-reject-zero-hop-limit", "tcp-mss", "1400"}}
	parent := &Node{Keys: []string{"internet-options"}, Children: []*Node{node}}
	var extra []string
	collectInternetOptionsExtras13089(parent, &extra)
	if len(extra) != 1 || extra[0] != "tcp-mss" {
		t.Errorf("extras = %v, want [tcp-mss] (Keys[1:] of the modelled leaf must be scanned)", extra)
	}
}

func TestInternetOptionsCompactExtraWarns15707(t *testing.T) {
	c := compileText13089(t, "system internet-options no-ipv6-reject-zero-hop-limit tcp-mss 1400;")
	all := strings.Join(c.Warnings, "\n")
	if !strings.Contains(all, "internet-options [tcp-mss]") {
		t.Errorf("warnings = %q, want internet-options [tcp-mss] advisory", all)
	}
	if c.System.InternetOptions == nil || !c.System.InternetOptions.NoIPv6RejectZeroHopLimit {
		t.Errorf("compact+extra: flag = %+v, want true", c.System.InternetOptions)
	}
}
