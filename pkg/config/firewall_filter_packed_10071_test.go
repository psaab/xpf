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
}
