package config

import (
	"reflect"
	"testing"
)

// #3904 (fable-161 F-162): RIP `redistribute [ a b ]`, group `export [ a b ]`,
// and `neighbor [ i1 i2 ]` bracket lists used to truncate to the FIRST value —
// the compiler read only child.Keys[1]. The schema now marks the declared RIP
// list-leaves multi: true and the compiler accumulates EVERY value via
// firewallMatchValues (Keys[1:] + child nodes), in both AST shapes (#2419).
//
// fail-on-revert: restoring the `child.Keys[1]`-only read leaves each slice
// with one element, so the two-element assertions go RED.

func TestRIPMultiValueFlat(t *testing.T) {
	tree := buildTree(t, []string{
		"set policy-options policy-statement pa term t1 then accept",
		"set policy-options policy-statement pb term t1 then accept",
		"set protocols rip redistribute [ static connected ]",
		"set protocols rip neighbor [ ge-0/0/1 ge-0/0/2 ]",
		"set protocols rip passive-interface [ ge-0/0/3 ge-0/0/4 ]",
		"set protocols rip group g1 export [ pa pb ]",
		"set protocols rip group g1 neighbor [ ge-0/0/5 ge-0/0/6 ]",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (flat RIP multi-value): %v", err)
	}
	rip := cfg.Protocols.RIP
	if rip == nil {
		t.Fatal("RIP config missing after compile")
	}
	// redistribute [static connected] + group export [pa pb] both feed
	// RIP.Redistribute.
	if got, want := rip.Redistribute, []string{"static", "connected", "pa", "pb"}; !reflect.DeepEqual(got, want) {
		t.Errorf("RIP.Redistribute = %v, want %v (bracket list truncated)", got, want)
	}
	// neighbor [ge-0/0/1 ge-0/0/2] + group neighbor [ge-0/0/5 ge-0/0/6] both
	// feed RIP.Interfaces.
	if got, want := rip.Interfaces, []string{"ge-0/0/1", "ge-0/0/2", "ge-0/0/5", "ge-0/0/6"}; !reflect.DeepEqual(got, want) {
		t.Errorf("RIP.Interfaces = %v, want %v (bracket list truncated)", got, want)
	}
	if got, want := rip.Passive, []string{"ge-0/0/3", "ge-0/0/4"}; !reflect.DeepEqual(got, want) {
		t.Errorf("RIP.Passive = %v, want %v (bracket list truncated)", got, want)
	}
}

func TestRIPMultiValueHierarchical(t *testing.T) {
	tree := parseHierText(t, `policy-options {
    policy-statement pa {
        term t1 {
            then accept;
        }
    }
    policy-statement pb {
        term t1 {
            then accept;
        }
    }
}
protocols {
    rip {
        redistribute [ static connected ];
        neighbor [ ge-0/0/1 ge-0/0/2 ];
        group g1 {
            export [ pa pb ];
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (hierarchical RIP multi-value): %v", err)
	}
	rip := cfg.Protocols.RIP
	if rip == nil {
		t.Fatal("RIP config missing after compile")
	}
	if got, want := rip.Redistribute, []string{"static", "connected", "pa", "pb"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hierarchical RIP.Redistribute = %v, want %v", got, want)
	}
	if got, want := rip.Interfaces, []string{"ge-0/0/1", "ge-0/0/2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hierarchical RIP.Interfaces = %v, want %v", got, want)
	}
}
