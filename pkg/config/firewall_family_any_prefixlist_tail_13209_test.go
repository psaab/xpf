package config

import (
	"strings"
	"testing"
)

// #13209 (D3-01): firewallPrefixListFamilies ignored instanceValueTail, so
// compact and bracketed single-family prefix-lists under `family any` escaped
// the #4426 gate even though compilePolicyOptions loads their prefixes.

func familyAnyPLTailTree(pl, ref string) string {
	return `
policy-options {
    ` + pl + `
}
firewall {
    family any {
        filter blockNet {
            term t {
                from {
                    source-prefix-list {
                        ` + ref + `
                    }
                }
                then {
                    discard;
                }
            }
        }
    }
}
`
}

func TestFirewallFamilyAnyPrefixListCompactAndBracketed13209(t *testing.T) {
	cases := []struct {
		name string
		pl   string
		list string
	}{
		{"compact v4", "prefix-list v4-only 10.0.0.0/8;", "v4-only"},
		{"bracketed v4", "prefix-list v4-bracket [ 10.0.0.0/8 192.168.0.0/16 ];", "v4-bracket"},
		{"compact v6", "prefix-list v6-only 2001:db8::/32;", "v6-only"},
		{"block-name compact v4", "prefix-list { v4-block 10.0.0.0/8; }", "v4-block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := tc.list
			tree := parseHier(t, familyAnyPLTailTree(tc.pl, list+";"))
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig: expected #4426 rejection of single-family %s prefix-list under family any, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "#4426") || !strings.Contains(err.Error(), list) {
				t.Fatalf("unexpected error text: %v", err)
			}
		})
	}
}

func TestFirewallFamilyAnyPrefixListCompactExcept13209(t *testing.T) {
	tree := parseHier(t, familyAnyPLTailTree("prefix-list v4-only 10.0.0.0/8;", "v4-only except;"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected #4426 rejection of v4-only except prefix-list under family any, got nil")
	}
	if !strings.Contains(err.Error(), "#4426") || !strings.Contains(err.Error(), "v4-only") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

func TestFirewallFamilyAnyPrefixListCompactLenientWarns13209(t *testing.T) {
	tree := parseHier(t, familyAnyPLTailTree("prefix-list v4-only 10.0.0.0/8;", "v4-only;"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4426") && strings.Contains(w, "v4-only") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected #4426 warning, got: %v", cfg.Warnings)
	}
}

func TestFirewallFamilyAnyPrefixListCompactMixedCommits13209(t *testing.T) {
	tree := parseHier(t, familyAnyPLTailTree("prefix-list mixed [ 10.0.0.0/8 2001:db8::/32 ];", "mixed;"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: mixed compact/bracketed list must commit, got: %v", err)
	}
}
