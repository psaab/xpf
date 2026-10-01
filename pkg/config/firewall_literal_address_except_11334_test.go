package config

import (
	"strings"
	"testing"
)

func TestFirewallLiteralAddressExceptNamedUnsupported11334(t *testing.T) {
	hierarchical := func(t *testing.T, body string) *ConfigTree {
		t.Helper()
		tree, errs := NewParser("firewall { family inet { filter f { term t { from { " +
			body + " } then accept; } } } }").Parse()
		if len(errs) > 0 {
			t.Fatalf("parse errors: %v", errs)
		}
		return tree
	}
	cases := []struct {
		name  string
		tree  func(*testing.T) *ConfigTree
		leaf  string
		value string
	}{
		{
			name: "flat source leaf",
			tree: func(t *testing.T) *ConfigTree {
				return buildFilterTree(t,
					"set firewall family inet filter f term t from source-address 10.0.0.0/8 except",
					"set firewall family inet filter f term t then accept")
			},
			leaf: "source-address", value: "10.0.0.0/8",
		},
		{
			name: "hierarchical source leaf",
			tree: func(t *testing.T) *ConfigTree {
				return hierarchical(t, "source-address 10.0.0.0/8 except;")
			},
			leaf: "source-address", value: "10.0.0.0/8",
		},
		{
			name: "hierarchical source block",
			tree: func(t *testing.T) *ConfigTree {
				return hierarchical(t, "source-address { 10.0.0.0/8 except; 192.168.0.0/16; }")
			},
			leaf: "source-address", value: "10.0.0.0/8",
		},
		{
			name: "flat destination leaf",
			tree: func(t *testing.T) *ConfigTree {
				return buildFilterTree(t,
					"set firewall family inet filter f term t from destination-address 192.168.0.0/16 except",
					"set firewall family inet filter f term t then accept")
			},
			leaf: "destination-address", value: "192.168.0.0/16",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatal("literal-address except must be refused until its matching " +
					"semantics are implemented")
			}
			for _, want := range []string{
				tc.leaf + " " + tc.value,
				"except (unsupported literal-address except construct)",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("strict diagnostic %q does not name unsupported construct %q", err, want)
				}
			}

			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compilation must warn instead of hard-failing: %v", err)
			}
			if !hasSubstring11334(cfg.Warnings, "unsupported literal-address except construct") {
				t.Fatalf("tolerant warnings %q do not name unsupported literal-address except", cfg.Warnings)
			}
			term := firstInetTerm(t, cfg, "f")
			if len(term.UnknownFrom) != 1 ||
				!strings.Contains(term.UnknownFrom[0], "unsupported literal-address except construct") {
				t.Fatalf("UnknownFrom = %v, want a named unsupported literal-address except marker",
					term.UnknownFrom)
			}
			if len(term.UnknownAddresses) != 0 {
				t.Fatalf("`except` was misclassified as a malformed address: UnknownAddresses=%v",
					term.UnknownAddresses)
			}
			addresses := term.SourceAddresses
			if tc.leaf == "destination-address" {
				addresses = term.DestAddresses
			}
			if len(addresses) == 0 || addresses[0] != tc.value {
				t.Fatalf("representable literal was not preserved separately from `except`: %v",
					addresses)
			}
		})
	}
}

func hasSubstring11334(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}
