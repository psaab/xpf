package config

import (
	"strings"
	"testing"
)

// #10071: schema-unknown from leaves must survive both packed levels and feed
// the existing UnknownFrom strict gate rather than disappearing in packedBody.
func TestFilterPackedUnknownFromStrict10071(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "term-packed",
			src:  `firewall { family inet { filter F { term T from ttl 64; } } }`,
		},
		{
			name: "from-packed",
			src:  `firewall { family inet { filter F { term T { from ttl 64; then accept; } } } }`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, perrs := NewParser(tc.src).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture did not parse: %v", perrs)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "ttl") {
				t.Fatalf("strict compile must reject packed ttl naming the leaf, got %v", err)
			}

			lenient, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile must warn, not fail: %v", err)
			}
			term := firstInetTerm(t, lenient, "F")
			if len(term.UnknownFrom) != 1 || term.UnknownFrom[0] != "ttl" {
				t.Fatalf("UnknownFrom = %v, want [ttl]", term.UnknownFrom)
			}
		})
	}

	clean, perrs := NewParser(`firewall { family inet { filter F { term T { from protocol tcp; then accept; } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("clean control did not parse: %v", perrs)
	}
	if _, err := CompileConfig(clean); err != nil {
		t.Fatalf("supported valued from control must remain clean: %v", err)
	}

	mixed, perrs := NewParser(`firewall { family inet { filter F { term T { from flexible-match-range range r byte-offset 9 ttl 64; then accept; } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("mixed known/unknown packed from fixture did not parse: %v", perrs)
	}
	if _, err := CompileConfig(mixed); err == nil || !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("mixed packed from must reject naming ttl, got %v", err)
	}
	mixedLenient, err := CompileConfigLenient(mixed)
	if err != nil {
		t.Fatalf("mixed known/unknown packed from must warn, not fail: %v", err)
	}
	mixedTerm := firstInetTerm(t, mixedLenient, "F")
	if len(mixedTerm.UnknownFrom) != 1 || mixedTerm.UnknownFrom[0] != "ttl" {
		t.Fatalf("mixed packed UnknownFrom = %v, want [ttl]", mixedTerm.UnknownFrom)
	}

	// P1: every packed `from` segment must reach the gate, not just the first.
	twoSeg, perrs := NewParser(`firewall { family inet { filter F { term T from protocol tcp from ttl 64; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("two-segment packed from fixture did not parse: %v", perrs)
	}
	if _, err := CompileConfig(twoSeg); err == nil || !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("two-segment packed from must reject naming ttl, got %v", err)
	} else if strings.Contains(err.Error(), "from range") {
		t.Fatalf("two-segment packed from misidentified a nested leaf: %v", err)
	}
	twoSegLenient, err := CompileConfigLenient(twoSeg)
	if err != nil {
		t.Fatalf("two-segment packed from must warn, not fail: %v", err)
	}
	twoSegTerm := firstInetTerm(t, twoSegLenient, "F")
	if len(twoSegTerm.UnknownFrom) != 1 || twoSegTerm.UnknownFrom[0] != "ttl" {
		t.Fatalf("two-segment packed UnknownFrom = %v, want [ttl]", twoSegTerm.UnknownFrom)
	}

	// P2: bracket provenance must survive segment recovery, or the bracketed
	// values mis-scan as the unknown leaf and swallow the real one.
	bracket, perrs := NewParser(`firewall { family inet { filter F { term T from source-address [ 10.0.0.0/8 20.0.0.0/8 ] ttl 64; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("bracketed packed from fixture did not parse: %v", perrs)
	}
	if _, err := CompileConfig(bracket); err == nil || !strings.Contains(err.Error(), "ttl") {
		t.Fatalf("bracketed packed from must reject naming ttl, got %v", err)
	} else if strings.Contains(err.Error(), "from range") {
		t.Fatalf("bracketed packed from misidentified a nested leaf: %v", err)
	}
	bracketLenient, err := CompileConfigLenient(bracket)
	if err != nil {
		t.Fatalf("bracketed packed from must warn, not fail: %v", err)
	}
	bracketTerm := firstInetTerm(t, bracketLenient, "F")
	if len(bracketTerm.UnknownFrom) != 1 || bracketTerm.UnknownFrom[0] != "ttl" {
		t.Fatalf("bracketed packed UnknownFrom = %v, want [ttl]", bracketTerm.UnknownFrom)
	}

	// #6818 is the adjacent packed-tail control: a known nested firewall
	// chain must not be mistaken for an opaque unknown `from` leaf.
	known, perrs := NewParser(`firewall { family inet { filter F { term T { from flexible-match-range range r { byte-offset 9; } } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("known nested packed-tail control did not parse: %v", perrs)
	}
	if _, err := CompileConfig(known); err != nil {
		t.Fatalf("known nested packed-tail control must remain clean: %v", err)
	}
}
