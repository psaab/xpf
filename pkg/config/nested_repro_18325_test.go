package config

import (
	"strings"
	"testing"
)

func assertNestedMultiValueRejected18325(t *testing.T, err error, leaf string) {
	t.Helper()
	if err == nil {
		t.Fatalf("nested content under %s was accepted", leaf)
	}
	if !strings.Contains(err.Error(), leaf) || !strings.Contains(err.Error(), "nested content") {
		t.Fatalf("error %q must name %s and identify nested content", err, leaf)
	}
}

func TestNestedMultiValueContentRejected18325(t *testing.T) {
	cases := []struct {
		name, leaf, nested, valid string
	}{
		{
			name:   "system domain-search",
			leaf:   "domain-search",
			nested: "system { domain-search { example.com { x; } } }",
			valid:  "system { domain-search { example.com; example.org; } }",
		},
		{
			name:   "firewall protocol",
			leaf:   "protocol",
			nested: "firewall { family inet { filter f { term t { from { protocol { tcp { x; } } } then accept; } } } }",
			valid:  "firewall { family inet { filter f { term t { from { protocol { tcp; } } then accept; } } } }",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nested := parseHierText(t, tc.nested)
			assertNestedMultiValueRejected18325(t, SchemaValidate(nested), tc.leaf)
			_, err := CompileConfig(nested)
			assertNestedMultiValueRejected18325(t, err, tc.leaf)
			_, err = CompileConfigLenient(nested)
			assertNestedMultiValueRejected18325(t, err, tc.leaf)

			valid := parseHierText(t, tc.valid)
			if err := SchemaValidate(valid); err != nil {
				t.Fatalf("valid flat-list control rejected: %v", err)
			}
			if _, err := CompileConfig(valid); err != nil {
				t.Fatalf("valid flat-list control did not compile: %v", err)
			}
			if _, err := CompileConfigLenient(valid); err != nil {
				t.Fatalf("valid lenient flat-list control did not compile: %v", err)
			}
		})
	}
}
