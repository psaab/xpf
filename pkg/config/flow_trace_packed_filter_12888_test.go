package config

import (
	"strings"
	"testing"
)

// #12888: a packed packet-filter's invalid prefix must be caught by the
// validator (strict reject / lenient warn), matching compileFlow's
// expanded read.
func TestFlowTracePackedPacketFilterValidated12888(t *testing.T) {
	text := "security { flow { traceoptions { packet-filter f1 source-prefix 10.0.0.999/32; } } }"
	tree, perrs := NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := validateFlowTraceFlagsAndFiltersAST(tree.Children, "", false); err == nil ||
		!strings.Contains(err.Error(), "source-prefix") {
		t.Fatalf("packed invalid prefix must be rejected, got err=%v", err)
	}
	warns, err := validateFlowTraceFlagsAndFiltersAST(tree.Children, "", true)
	if err != nil || len(warns) == 0 {
		t.Fatalf("lenient must warn on packed invalid prefix, warns=%v err=%v", warns, err)
	}
	// Control: valid packed prefix passes.
	text2 := "security { flow { traceoptions { packet-filter f1 source-prefix 10.0.0.0/8; } } }"
	tree2, perrs := NewParser(text2).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse2: %v", perrs)
	}
	if _, err := validateFlowTraceFlagsAndFiltersAST(tree2.Children, "", false); err != nil {
		t.Fatalf("valid packed prefix must pass, got %v", err)
	}
}
