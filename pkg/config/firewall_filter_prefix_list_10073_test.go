package config

import (
	"fmt"
	"strings"
	"testing"
)

func prefixListTerm10073(t *testing.T, cfg *Config, family string) *FirewallFilterTerm {
	t.Helper()
	filters := cfg.Firewall.FiltersInet
	if family == "inet6" {
		filters = cfg.Firewall.FiltersInet6
	}
	filter := filters["F"]
	if filter == nil || len(filter.Terms) != 1 {
		t.Fatalf("family %s filter F terms = %+v, want one term", family, filter)
	}
	return filter.Terms[0]
}

// #10073: from-level one-liner prefix-list values must survive packing and
// populate the typed scope used by every firewall family and direction.
func TestFilterPrefixListOneLinerRefs10073(t *testing.T) {
	for _, family := range []string{"any", "inet", "inet6"} {
		for _, leaf := range []string{"source-prefix-list", "destination-prefix-list"} {
			t.Run(family+"/"+leaf, func(t *testing.T) {
				src := fmt.Sprintf(`policy-options { prefix-list PL { 10.0.0.0/8; 2001:db8::/32; } }
firewall { family %s { filter F { term T { from %s PL; then accept; } } } }`, family, leaf)
				tree, perrs := NewParser(src).Parse()
				if len(perrs) > 0 {
					t.Fatalf("fixture did not parse: %v", perrs)
				}
				cfg, err := CompileConfig(tree)
				if err != nil {
					t.Fatalf("valued one-liner must compile: %v", err)
				}
				term := prefixListTerm10073(t, cfg, family)
				refs := term.SourcePrefixLists
				if leaf == "destination-prefix-list" {
					refs = term.DestPrefixLists
				}
				if len(refs) != 1 || refs[0].Name != "PL" || refs[0].Except {
					t.Fatalf("%s refs = %+v, want [{Name:PL Except:false}]", leaf, refs)
				}
			})
		}
	}
}

// The same six family/direction sites must not turn a valueless compact leaf
// into an unconstrained term after the schema gains its required argument.
func TestFilterPrefixListValuelessCompactRejected10073(t *testing.T) {
	for _, family := range []string{"any", "inet", "inet6"} {
		for _, leaf := range []string{"source-prefix-list", "destination-prefix-list"} {
			t.Run(family+"/"+leaf, func(t *testing.T) {
				src := fmt.Sprintf(`firewall { family %s { filter F { term T { from %s; then accept; } } } }`, family, leaf)
				tree, perrs := NewParser(src).Parse()
				if len(perrs) > 0 {
					t.Fatalf("fixture did not parse: %v", perrs)
				}
				_, err := CompileConfig(tree)
				if err == nil || !strings.Contains(err.Error(), leaf) {
					t.Fatalf("valueless compact leaf must be rejected naming %s, got %v", leaf, err)
				}
			})
		}
	}
}
