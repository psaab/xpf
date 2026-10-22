package config

import (
	"reflect"
	"testing"
)

// #3431 (Codex audit 095 H04/H05/H06): a NAT `match` clause carrying a
// bracket list / repeated value for application, protocol (DNAT), or
// source-/destination-address-name used to collapse to ONE scalar — the
// parser read only nodeVal(m) (the first token) and silently dropped the
// rest. The schema advertises these leaves as multi: true, so the lexer
// strips the brackets and the full list lands on the leaf's Keys[1:] (and/or
// child nodes) in BOTH the hierarchical and flat-set AST shapes (#2419). The
// fix accumulates EVERY value via firewallMatchValues into the new plural
// slices (Applications / Protocols / SourceAddressNames /
// DestinationAddressNames), keeping the scalar = first for backward compat.
//
// fail-on-revert: restoring the old `rule.Match.X = nodeVal(m)` assignment
// leaves the plural slices empty (or one element), so every multi-value
// assertion below goes RED.
//
// Both AST shapes are exercised: flat `set` commands via buildTree
// (ParseSetCommand + SetPath, the only correct way per CLAUDE.md) AND a
// hierarchical block with bracket lists via parseHierText (NewParser).

func natMultiAppsSNAT(t *testing.T) *Config {
	t.Helper()
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address a1 198.51.100.0/24",
		"set security address-book global address a2 198.51.101.0/24",
		"set security address-book global address d1 203.0.113.0/24",
		"set security address-book global address d2 203.0.113.128/25",
		"set applications application app-a protocol tcp",
		"set applications application app-a destination-port 80",
		"set applications application app-b protocol udp",
		"set applications application app-b destination-port 53",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name [ a1 a2 ]",
		"set security nat source rule-set rs1 rule r1 match destination-address-name [ d1 d2 ]",
		"set security nat source rule-set rs1 rule r1 match application [ app-a app-b ]",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (flat SNAT multi-value match): %v", err)
	}
	return cfg
}

// TestNATSourceMatchMultiValueFlat asserts every value of a SNAT
// `match application` / `source-address-name` / `destination-address-name`
// bracket list survives compilation, in the flat-set AST shape.
func TestNATSourceMatchMultiValueFlat(t *testing.T) {
	cfg := natMultiAppsSNAT(t)
	if len(cfg.Security.NAT.Source) == 0 || len(cfg.Security.NAT.Source[0].Rules) == 0 {
		t.Fatal("source NAT rule missing after compile")
	}
	m := cfg.Security.NAT.Source[0].Rules[0].Match

	if got, want := m.SourceAddressNames, []string{"a1", "a2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SourceAddressNames = %v, want %v (multi-value list collapsed)", got, want)
	}
	if got, want := m.DestinationAddressNames, []string{"d1", "d2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DestinationAddressNames = %v, want %v (multi-value list collapsed)", got, want)
	}
	if got, want := m.Applications, []string{"app-a", "app-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Applications = %v, want %v (multi-value list collapsed)", got, want)
	}
	// Scalars keep the first value for backward compat.
	if m.SourceAddressName != "a1" || m.DestinationAddressName != "d1" || m.Application != "app-a" {
		t.Errorf("scalar back-compat broken: src-name=%q dst-name=%q app=%q",
			m.SourceAddressName, m.DestinationAddressName, m.Application)
	}
}

// TestNATDestMatchMultiValueFlat asserts every value of a DNAT
// `match protocol` / `application` / address-name bracket list survives
// compilation, in the flat-set AST shape (H04/H05/H06).
func TestNATDestMatchMultiValueFlat(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security address-book global address a1 198.51.100.0/24",
		"set security address-book global address a2 198.51.101.0/24",
		"set security address-book global address d1 203.0.113.10/32",
		"set security address-book global address d2 203.0.113.11/32",
		"set applications application app-a protocol tcp",
		"set applications application app-a destination-port 80",
		"set applications application app-b protocol tcp",
		"set applications application app-b destination-port 8080",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule rp match source-address-name [ a1 a2 ]",
		"set security nat destination rule-set rs1 rule rp match destination-address-name [ d1 d2 ]",
		"set security nat destination rule-set rs1 rule rp match protocol [ tcp udp ]",
		"set security nat destination rule-set rs1 rule rp then destination-nat pool dp",
		"set security nat destination rule-set rs1 rule ra match destination-address 203.0.113.20/32",
		"set security nat destination rule-set rs1 rule ra match application [ app-a app-b ]",
		"set security nat destination rule-set rs1 rule ra then destination-nat pool dp",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (flat DNAT multi-value match): %v", err)
	}
	if cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		t.Fatal("destination NAT rule-set missing after compile")
	}
	rules := cfg.Security.NAT.Destination.RuleSets[0].Rules
	if len(rules) < 2 {
		t.Fatalf("expected 2 DNAT rules, got %d", len(rules))
	}
	rp := rules[0].Match
	if got, want := rp.SourceAddressNames, []string{"a1", "a2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DNAT SourceAddressNames = %v, want %v", got, want)
	}
	if got, want := rp.DestinationAddressNames, []string{"d1", "d2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DNAT DestinationAddressNames = %v, want %v", got, want)
	}
	if got, want := rp.Protocols, []string{"tcp", "udp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DNAT Protocols = %v, want %v (H05 collapse)", got, want)
	}
	ra := rules[1].Match
	if got, want := ra.Applications, []string{"app-a", "app-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DNAT Applications = %v, want %v (H04 collapse)", got, want)
	}
}

// TestNATMatchMultiValueHierarchical asserts the same accumulation in the
// hierarchical (NewParser) AST shape, where a bracket list also lands on
// Keys[1:] of the single leaf (#2419).
func TestNATMatchMultiValueHierarchical(t *testing.T) {
	tree := parseHierText(t, `security {
    zones {
        security-zone untrust;
    }
    address-book {
        global {
            address a1 198.51.100.0/24;
            address a2 198.51.101.0/24;
            address d1 203.0.113.10/32;
            address d2 203.0.113.11/32;
        }
    }
    nat {
        destination {
            pool dp {
                address 10.0.0.5;
            }
            rule-set rs1 {
                from zone untrust;
                rule rp {
                    match {
                        source-address-name [ a1 a2 ];
                        destination-address-name [ d1 d2 ];
                        protocol [ tcp udp ];
                    }
                    then {
                        destination-nat pool dp;
                    }
                }
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (hierarchical DNAT multi-value match): %v", err)
	}
	if cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		t.Fatal("destination NAT rule-set missing after compile")
	}
	m := cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Match
	if got, want := m.SourceAddressNames, []string{"a1", "a2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hierarchical SourceAddressNames = %v, want %v", got, want)
	}
	if got, want := m.DestinationAddressNames, []string{"d1", "d2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hierarchical DestinationAddressNames = %v, want %v", got, want)
	}
	if got, want := m.Protocols, []string{"tcp", "udp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hierarchical Protocols = %v, want %v", got, want)
	}
}

// TestNATDestMatchMultiProtocolBadValueRejected pins H05's validator gap:
// the strict commit gate must reject a NON-FIRST bad protocol in a bracket
// list. Pre-#3431 the validator only checked the (first) scalar, so a bad
// trailing protocol committed silently. fail-on-revert: a validator that
// reads only rule.Match.Protocol passes this and goes RED.
func TestNATDestMatchMultiProtocolBadValueRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security address-book global address d1 203.0.113.10/32",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule rp match destination-address-name d1",
		"set security nat destination rule-set rs1 rule rp match protocol [ tcp bogusproto ]",
		"set security nat destination rule-set rs1 rule rp then destination-nat pool dp",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a DNAT match protocol list with a bad trailing value must be rejected at commit")
	}
}
