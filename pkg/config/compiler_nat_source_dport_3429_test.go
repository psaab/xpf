package config

import (
	"strings"
	"testing"
)

// #3429 (H03): source-NAT `match destination-port` must be parsed through the
// shared DNAT port-list parser so a bracket list or a `low to high` range is
// fully captured. Before the fix the scalar path read only nodeVal, so a
// flat-set `destination-port 20000 to 20003` (lexer-collapsed onto
// Keys=[destination-port 20000 to 20003], no children) kept ONLY the first port
// (20000). Reverting compiler_nat.go to the scalar path turns these RED.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never NewParser
// (the parser merges newline-separated set lines into one giant node).

func compileSourceNATDPort(t *testing.T, dportCmd string) *NATRule {
	t.Helper()
	tree := &ConfigTree{}
	cmds := []string{
		"set security zones security-zone lan",
		"set security zones security-zone wan",
		"set security nat source rule-set RS from zone lan",
		"set security nat source rule-set RS to zone wan",
		dportCmd,
		"set security nat source rule-set RS rule R1 then source-nat interface",
	}
	for _, cmd := range cmds {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 || len(cfg.Security.NAT.Source[0].Rules) != 1 {
		t.Fatalf("unexpected source NAT shape: %+v", cfg.Security.NAT.Source)
	}
	return cfg.Security.NAT.Source[0].Rules[0]
}

func TestSourceNATDestinationPortRangeParsed_3429(t *testing.T) {
	rule := compileSourceNATDPort(t,
		"set security nat source rule-set RS rule R1 match destination-port 20000 to 20003")
	want := []int{20000, 20001, 20002, 20003}
	if len(rule.Match.DestinationPorts) != len(want) {
		t.Fatalf("DestinationPorts = %v, want %v (range must expand, not collapse to first)",
			rule.Match.DestinationPorts, want)
	}
	for i, p := range want {
		if rule.Match.DestinationPorts[i] != p {
			t.Fatalf("DestinationPorts[%d] = %d, want %d", i, rule.Match.DestinationPorts[i], p)
		}
	}
}

func TestSourceNATDestinationPortBracketListParsed_3429(t *testing.T) {
	rule := compileSourceNATDPort(t,
		"set security nat source rule-set RS rule R1 match destination-port [ 80 443 8080 ]")
	want := map[int]bool{80: true, 443: true, 8080: true}
	if len(rule.Match.DestinationPorts) != len(want) {
		t.Fatalf("DestinationPorts = %v, want the 3-element bracket list",
			rule.Match.DestinationPorts)
	}
	for _, p := range rule.Match.DestinationPorts {
		if !want[p] {
			t.Fatalf("unexpected port %d in %v", p, rule.Match.DestinationPorts)
		}
	}
}

func TestSourceNATDestinationPortScalarStillWorks_3429(t *testing.T) {
	rule := compileSourceNATDPort(t,
		"set security nat source rule-set RS rule R1 match destination-port 8080")
	if len(rule.Match.DestinationPorts) != 1 || rule.Match.DestinationPorts[0] != 8080 {
		t.Fatalf("DestinationPorts = %v, want [8080]", rule.Match.DestinationPorts)
	}
}
