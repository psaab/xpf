package config

import (
	"strings"
	"testing"
)

// #10072: the term-level packed valueless shape must use the same packed view
// as the #8480 gate and the #9875 tolerant marker.
func TestFilterTermPackedValuelessStrict10072(t *testing.T) {
	tree, perrs := NewParser(`firewall { family inet { filter F { term T from protocol; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("strict compile must reject packed valueless protocol naming the leaf, got %v", err)
	}
	lenient, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must warn, not fail: %v", err)
	}
	term := firstInetTerm(t, lenient, "F")
	if len(term.ValuelessFrom) != 1 || term.ValuelessFrom[0] != "protocol" {
		t.Fatalf("ValuelessFrom = %v, want [protocol]", term.ValuelessFrom)
	}

	// The from-level packed spelling was already covered by #8480 and must
	// remain rejected while this regression closes the term-level escape.
	fromPacked, perrs := NewParser(`firewall { family inet { filter F { term T { from protocol; then discard; } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("from-packed control did not parse: %v", perrs)
	}
	if _, err := CompileConfig(fromPacked); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("from-level valueless protocol must remain rejected, got %v", err)
	}

	multi, perrs := NewParser(`firewall { family inet { filter F { term T from protocol from source-port; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("multi-segment packed valueless fixture did not parse: %v", perrs)
	}
	if _, err := CompileConfig(multi); err == nil ||
		!strings.Contains(err.Error(), "protocol") ||
		!strings.Contains(err.Error(), "source-port") {
		t.Fatalf("multi-segment packed valueless must reject both leaves, got %v", err)
	}
	multiLenient, err := CompileConfigLenient(multi)
	if err != nil {
		t.Fatalf("multi-segment packed valueless must warn, not fail: %v", err)
	}
	multiTerm := firstInetTerm(t, multiLenient, "F")
	if len(multiTerm.Protocols) != 0 || len(multiTerm.SourcePorts) != 0 {
		t.Fatalf("multi-segment valueless leaves must not compile values: protocols=%v source ports=%v",
			multiTerm.Protocols, multiTerm.SourcePorts)
	}
	want := []string{"protocol", "source-port"}
	if len(multiTerm.ValuelessFrom) != len(want) ||
		multiTerm.ValuelessFrom[0] != want[0] ||
		multiTerm.ValuelessFrom[1] != want[1] {
		t.Fatalf("multi-segment ValuelessFrom = %v, want %v", multiTerm.ValuelessFrom, want)
	}

	clean, perrs := NewParser(`firewall { family inet { filter F { term T from protocol tcp; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("clean control did not parse: %v", perrs)
	}
	if _, err := CompileConfig(clean); err != nil {
		t.Fatalf("supported packed protocol control must remain clean: %v", err)
	}
}
