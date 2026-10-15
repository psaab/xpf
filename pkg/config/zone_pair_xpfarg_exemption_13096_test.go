package config

import (
	"strings"
	"testing"
)

// #13096 (D1-13): `from-zone xpfarg xpfarg to-zone untrust` is not a
// census placeholder — the malformed-pair poison must fire.
func TestZonePairXpfargTrailingRealZoneNotExempt13096(t *testing.T) {
	text := "security { zones { security-zone untrust { } } policies { from-zone xpfarg xpfarg to-zone untrust { policy p1 { match { source-address any; destination-address any; application any; } then permit; } } } }"
	tree, perrs := NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	found := false
	for _, mp := range cfg.Security.MalformedZonePairs {
		if strings.Contains(mp, "xpfarg") {
			found = true
		}
	}
	if !found {
		t.Fatalf("phantom pair xpfarg->to-zone must be poisoned, MalformedZonePairs=%v", cfg.Security.MalformedZonePairs)
	}
	// Controls: pure census shapes stay exempt (no poison).
	for _, ctl := range []string{
		"security { policies { from-zone xpfarg xpfarg xpfarg { } } }",
		"security { policies { from-zone xpfarg xpfarg to-zone xpfarg { } } }",
	} {
		tree, perrs := NewParser(ctl).Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse control: %v", perrs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("control compile: %v", err)
		}
		if len(cfg.Security.MalformedZonePairs) != 0 {
			t.Fatalf("census control must stay exempt, got %v", cfg.Security.MalformedZonePairs)
		}
	}
}
